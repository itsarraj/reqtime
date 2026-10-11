use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use rustls::{ClientConnection, StreamOwned};
use url::Url;

use crate::{connect, httpio, resolve, tls};

/// Either a plain TCP socket or a TLS-wrapped one, behind one `Read +
/// Write` surface — lets `timed_request` share a single request/response
/// code path for both `http` and `https` instead of duplicating it.
enum Transport {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.read(buf),
            Transport::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.write(buf),
            Transport::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Transport::Plain(s) => s.flush(),
            Transport::Tls(s) => s.flush(),
        }
    }
}

/// Every duration here is **cumulative from the start of this hop**,
/// matching the convention `curl -w`/`httpstat` use (`time_connect`,
/// `time_starttransfer`, etc. are all "since the request started," not
/// deltas from the previous phase) — this is what makes them directly
/// meaningful on their own, and `render.rs` derives per-phase deltas
/// from these when drawing the waterfall.
#[derive(Debug, Clone)]
pub struct HopTiming {
    pub url: Url,
    pub remote_addr: SocketAddr,
    pub dns_lookup: Duration,
    pub tcp_connect: Duration,
    pub tls_handshake: Option<Duration>,
    pub time_to_first_byte: Duration,
    pub total: Duration,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body_len: usize,
}

impl HopTiming {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self.status, 301 | 302 | 303 | 307 | 308)
    }
}

fn path_and_query(url: &Url) -> String {
    let mut p = url.path().to_string();
    if p.is_empty() {
        p.push('/');
    }
    if let Some(q) = url.query() {
        p.push('?');
        p.push_str(q);
    }
    p
}

/// Times one full request/response cycle against `url`: DNS, TCP
/// connect, TLS handshake (if `https`), request send, and response
/// read (headers + body). No redirects are followed here — that's
/// `follow_redirects`'s job, one call to this per hop.
pub fn timed_request(url: &Url, connect_timeout: Duration) -> Result<HopTiming, String> {
    let hop_start = Instant::now();

    let host = url
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?
        .to_string();
    let is_https = match url.scheme() {
        "https" => true,
        "http" => false,
        other => return Err(format!("unsupported scheme '{other}' — only http/https")),
    };
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "could not determine a port".to_string())?;

    let (addrs, _) = resolve::resolve(&host, port)?;
    let dns_lookup = hop_start.elapsed();

    let (stream, _, remote_addr) = connect::connect(&addrs, connect_timeout)?;
    let tcp_connect = hop_start.elapsed();

    let (mut transport, tls_handshake) = if is_https {
        let config = tls::real_client_config();
        let (tls_stream, _) = tls::handshake(stream, &host, config)?;
        let elapsed = hop_start.elapsed();
        (Transport::Tls(Box::new(tls_stream)), Some(elapsed))
    } else {
        (Transport::Plain(stream), None)
    };

    let target = path_and_query(url);
    httpio::write_request(&mut transport, "GET", &target, &host, &[])
        .map_err(|e| format!("sending request: {e}"))?;

    let marker = httpio::FirstByteMarker::new();
    let timing_reader = httpio::TimingReader::new(transport, marker.clone());
    let mut buffered = BufReader::new(timing_reader);
    let response =
        httpio::read_response(&mut buffered).map_err(|e| format!("reading response: {e}"))?;

    let time_to_first_byte = marker
        .get()
        .map(|t| t.saturating_duration_since(hop_start))
        .unwrap_or_else(|| hop_start.elapsed());
    let total = hop_start.elapsed();

    Ok(HopTiming {
        url: url.clone(),
        remote_addr,
        dns_lookup,
        tcp_connect,
        tls_handshake,
        time_to_first_byte,
        total,
        status: response.status,
        reason: response.reason,
        headers: response.headers,
        body_len: response.body.len(),
    })
}

/// Times a request, following redirects (3xx with a `Location`
/// header) up to `max_redirects` additional hops when `follow` is
/// true. Each hop is a fresh connection with its own full timing
/// breakdown — real per-hop measurements, not one number amortized
/// across the whole chain. Stops (without erroring) rather than
/// following further once `max_redirects` is reached, leaving the
/// last hop's redirect response as the final entry — the caller can
/// tell a chain was cut short because that last hop's `is_redirect()`
/// is still true.
pub fn follow_redirects(
    start_url: &Url,
    follow: bool,
    max_redirects: usize,
    connect_timeout: Duration,
) -> Result<Vec<HopTiming>, String> {
    let mut hops = Vec::new();
    let mut current = start_url.clone();

    for _ in 0..=max_redirects {
        let hop = timed_request(&current, connect_timeout)?;
        let next_url = if follow && hop.is_redirect() {
            hop.header("location")
                .and_then(|loc| current.join(loc).ok())
        } else {
            None
        };
        hops.push(hop);
        match next_url {
            Some(u) => current = u,
            None => break,
        }
    }

    Ok(hops)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// Reads until the blank line ending the request's headers (a GET
    /// with no body ends there) rather than one arbitrary-sized
    /// `read()` call. This matters more than it looks: a single
    /// `read()` isn't guaranteed to capture every byte the client
    /// wrote in one shot, and if the server closes the socket (as
    /// `spawn_server` does, once per response, by letting `sock` drop)
    /// while bytes the client sent are still unread in the kernel's
    /// receive buffer, TCP sends a **RST** instead of a clean FIN —
    /// which was caught live causing the *next* sequential connection
    /// on this same test's server (reusing an ephemeral port) to fail
    /// with "Connection reset by peer" on write, intermittently,
    /// roughly 40% of runs even fully serially with no other test
    /// running at all. Draining fully avoids ever leaving that
    /// trailing unread data behind.
    fn drain_request<R: Read>(sock: &mut R) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            match sock.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                break;
            }
        }
    }

    /// A minimal real HTTP/1.1 server: accepts one connection at a
    /// time, fully drains each request, and sends back whatever raw
    /// response bytes it's told to. Enough to exercise the whole
    /// `timed_request`/`follow_redirects` pipeline — DNS "resolution"
    /// of a literal IP, a real TCP connect, a real request write, a
    /// real response read — over loopback, without needing the
    /// internet.
    fn spawn_server(responses: Vec<&'static [u8]>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for response in responses {
                let (mut sock, _) = listener.accept().unwrap();
                drain_request(&mut sock);
                sock.write_all(response).unwrap();
            }
        });
        addr
    }

    #[test]
    fn times_a_real_request_against_a_real_local_server() {
        let addr = spawn_server(vec![b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"]);
        let url = Url::parse(&format!("http://{addr}/")).unwrap();

        let hop = timed_request(&url, Duration::from_secs(2)).unwrap();

        assert_eq!(hop.status, 200);
        assert_eq!(hop.body_len, 5);
        assert!(
            hop.tls_handshake.is_none(),
            "plain http must not attempt TLS"
        );
        assert!(hop.total >= hop.time_to_first_byte);
        assert!(hop.time_to_first_byte >= hop.tcp_connect);
        assert!(hop.tcp_connect >= hop.dns_lookup);
    }

    #[test]
    fn follows_a_redirect_chain_and_records_every_hop() {
        let addr = spawn_server(vec![
            b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ]);
        let url = Url::parse(&format!("http://{addr}/start")).unwrap();

        let hops = follow_redirects(&url, true, 5, Duration::from_secs(2)).unwrap();

        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].status, 302);
        assert!(hops[0].is_redirect());
        assert_eq!(hops[1].status, 200);
        assert!(!hops[1].is_redirect());
    }

    #[test]
    fn without_follow_a_redirect_response_is_returned_as_is() {
        let addr = spawn_server(vec![
            b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n",
        ]);
        let url = Url::parse(&format!("http://{addr}/start")).unwrap();

        let hops = follow_redirects(&url, false, 5, Duration::from_secs(2)).unwrap();

        assert_eq!(hops.len(), 1);
        assert!(hops[0].is_redirect());
    }

    #[test]
    fn a_redirect_chain_longer_than_max_redirects_stops_without_erroring() {
        let addr = spawn_server(vec![
            b"HTTP/1.1 302 Found\r\nLocation: /a\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 302 Found\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 302 Found\r\nLocation: /c\r\nContent-Length: 0\r\n\r\n",
        ]);
        let url = Url::parse(&format!("http://{addr}/start")).unwrap();

        let hops = follow_redirects(&url, true, 1, Duration::from_secs(2)).unwrap();

        // Initial hop + 1 allowed redirect = 2 hops, then it stops.
        assert_eq!(hops.len(), 2);
        assert!(hops.last().unwrap().is_redirect());
    }

    #[test]
    fn an_unsupported_scheme_is_a_clean_error() {
        let url = Url::parse("ftp://example.com/").unwrap();
        let err = timed_request(&url, Duration::from_secs(1)).unwrap_err();
        assert!(err.contains("ftp"));
    }
}
