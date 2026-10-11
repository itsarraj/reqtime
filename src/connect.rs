use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Tries each address in turn (the same fallback behavior a real
/// browser/`curl` uses for multi-A-record hosts) and times however
/// long it took to establish the connection that succeeded —
/// including any time burned on earlier addresses that failed or
/// timed out, since that's real time a client actually spent getting
/// connected, not just the winning attempt in isolation.
pub fn connect(
    addrs: &[SocketAddr],
    timeout: Duration,
) -> Result<(TcpStream, Duration, SocketAddr), String> {
    let start = Instant::now();
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(stream) => return Ok((stream, start.elapsed(), *addr)),
            Err(e) => last_err = Some(e),
        }
    }
    Err(format!(
        "could not connect to any of {} address(es): {}",
        addrs.len(),
        last_err.map(|e| e.to_string()).unwrap_or_default()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, TcpListener};

    #[test]
    fn connects_to_a_real_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let (stream, elapsed, connected_addr) = connect(&[addr], Duration::from_secs(2)).unwrap();
        assert_eq!(connected_addr, addr);
        assert!(elapsed < Duration::from_secs(2));
        drop(stream);
    }

    #[test]
    fn falls_back_to_a_later_address_when_an_earlier_one_is_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let good_addr = listener.local_addr().unwrap();
        // Port 1 on loopback is a real, essentially-guaranteed-closed
        // port (privileged, nothing binds it) — a genuine connection
        // refusal, not a fake/mocked failure.
        let bad_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1);

        let (_, _, connected_addr) =
            connect(&[bad_addr, good_addr], Duration::from_secs(2)).unwrap();
        assert_eq!(connected_addr, good_addr);
    }

    #[test]
    fn every_address_unreachable_is_a_clean_error() {
        let bad_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1);
        let err = connect(&[bad_addr], Duration::from_secs(2)).unwrap_err();
        assert!(err.contains("1 address"));
    }
}
