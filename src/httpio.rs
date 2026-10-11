use std::cell::Cell;
use std::io::{self, BufRead, Read, Write};
use std::rc::Rc;
use std::time::Instant;

/// A shared handle for recording "when did the first byte of the
/// response arrive" from inside a `TimingReader`, separately
/// retrievable by the caller after that reader has been moved into a
/// `BufReader` (which owns it from that point on) — `Rc<Cell<...>>`
/// rather than a return value specifically because the timestamp
/// needs to be readable *during* `read_response`'s call, not just
/// after it returns.
#[derive(Clone, Default)]
pub struct FirstByteMarker(Rc<Cell<Option<Instant>>>);

impl FirstByteMarker {
    pub fn new() -> Self {
        Self(Rc::new(Cell::new(None)))
    }

    pub fn get(&self) -> Option<Instant> {
        self.0.get()
    }

    fn mark(&self) {
        if self.0.get().is_none() {
            self.0.set(Some(Instant::now()));
        }
    }
}

/// Wraps a reader, recording the instant of its first non-empty
/// `read()` call — the genuine "first byte off the wire" moment,
/// regardless of how much buffering happens on layers above this one
/// (a `BufReader` wrapped around this only calls through to the
/// underlying `read()` when its own buffer is empty, so the timing
/// captured here isn't skewed by buffer-fill size).
pub struct TimingReader<R> {
    inner: R,
    marker: FirstByteMarker,
}

impl<R> TimingReader<R> {
    pub fn new(inner: R, marker: FirstByteMarker) -> Self {
        Self { inner, marker }
    }
}

impl<R: Read> Read for TimingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.marker.mark();
        }
        Ok(n)
    }
}

/// Writes a minimal, complete HTTP/1.1 request line + headers.
/// `Connection: close` is always sent — this tool measures exactly
/// one request, so a persistent connection is never useful and always
/// sending it means every server (even ones that'd otherwise keep the
/// connection open) closes cleanly after responding, which makes a
/// plain read-to-EOF a safe body-reading fallback (see
/// `read_body`) when a server sends neither `Content-Length` nor
/// `Transfer-Encoding: chunked`.
pub fn write_request<W: Write>(
    w: &mut W,
    method: &str,
    path_and_query: &str,
    host: &str,
    extra_headers: &[(String, String)],
) -> io::Result<()> {
    write!(w, "{method} {path_and_query} HTTP/1.1\r\n")?;
    write!(w, "Host: {host}\r\n")?;
    write!(w, "User-Agent: reqtime/0.1\r\n")?;
    write!(w, "Accept: */*\r\n")?;
    for (k, v) in extra_headers {
        write!(w, "{k}: {v}\r\n")?;
    }
    write!(w, "Connection: close\r\n")?;
    write!(w, "\r\n")?;
    w.flush()
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Reads one CRLF- (or bare-LF-) terminated line. `Ok(None)` means the
/// connection closed with no bytes at all — a real, distinct
/// condition from "line is empty" (which is exactly how the
/// header/body boundary is signaled, so it must not be confused with
/// an unexpected connection close).
fn read_line<R: BufRead>(r: &mut R) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    let n = r.read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

fn parse_status_line(line: &str) -> io::Result<(u16, String)> {
    let mut parts = line.splitn(3, ' ');
    parts.next().ok_or_else(|| invalid("empty status line"))?;
    let code = parts
        .next()
        .ok_or_else(|| invalid(format!("missing status code in: {line}")))?;
    let reason = parts.next().unwrap_or("").to_string();
    let status: u16 = code
        .parse()
        .map_err(|_| invalid(format!("invalid status code: {code}")))?;
    Ok((status, reason))
}

fn read_headers<R: BufRead>(r: &mut R) -> io::Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    loop {
        match read_line(r)? {
            None => return Err(invalid("connection closed while reading headers")),
            Some(line) if line.is_empty() => break,
            Some(line) => {
                let (k, v) = line
                    .split_once(':')
                    .ok_or_else(|| invalid(format!("malformed header line: {line}")))?;
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
    }
    Ok(headers)
}

fn read_chunked_body<R: BufRead>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let size_line =
            read_line(r)?.ok_or_else(|| invalid("connection closed while reading a chunk size"))?;
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| invalid(format!("invalid chunk size: '{size_line}'")))?;
        if size == 0 {
            // Trailing headers (rare in practice) up to the final blank line.
            loop {
                match read_line(r)? {
                    None => break,
                    Some(line) if line.is_empty() => break,
                    Some(_) => continue,
                }
            }
            break;
        }
        let mut chunk = vec![0u8; size];
        r.read_exact(&mut chunk)?;
        body.extend_from_slice(&chunk);
        let mut trailing_crlf = [0u8; 2];
        r.read_exact(&mut trailing_crlf)?;
    }
    Ok(body)
}

fn read_body<R: BufRead>(r: &mut R, headers: &[(String, String)]) -> io::Result<Vec<u8>> {
    let is_chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });
    if is_chunked {
        return read_chunked_body(r);
    }

    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok());

    match content_length {
        Some(len) => {
            let mut buf = vec![0u8; len];
            r.read_exact(&mut buf)?;
            Ok(buf)
        }
        None => {
            let mut buf = Vec::new();
            r.read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

/// Parses a full HTTP/1.1 response: status line, headers, and body
/// (respecting `Transfer-Encoding: chunked` first, then
/// `Content-Length`, then falling back to read-until-close). `r` is
/// expected to already be a `BufRead` — callers building precise
/// timing wrap a `TimingReader` in a `BufReader` themselves first
/// (see `httpio`'s `FirstByteMarker` docs for why that split exists).
pub fn read_response<R: BufRead>(r: &mut R) -> io::Result<HttpResponse> {
    let status_line =
        read_line(r)?.ok_or_else(|| invalid("connection closed before sending any response"))?;
    let (status, reason) = parse_status_line(&status_line)?;
    let headers = read_headers(r)?;
    let body = read_body(r, &headers)?;
    Ok(HttpResponse {
        status,
        reason,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn writes_a_well_formed_request() {
        let mut buf = Vec::new();
        write_request(&mut buf, "GET", "/path?x=1", "example.com", &[]).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.starts_with("GET /path?x=1 HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn extra_headers_are_included() {
        let mut buf = Vec::new();
        write_request(
            &mut buf,
            "GET",
            "/",
            "example.com",
            &[("Authorization".to_string(), "Bearer xyz".to_string())],
        )
        .unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("Authorization: Bearer xyz\r\n"));
    }

    #[test]
    fn parses_a_realistic_content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        let mut r = BufReader::new(Cursor::new(raw.to_vec()));
        let resp = read_response(&mut r).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.header("Content-Type"), Some("text/plain"));
        assert_eq!(resp.body, b"hello");
    }

    #[test]
    fn parses_a_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut r = BufReader::new(Cursor::new(raw.to_vec()));
        let resp = read_response(&mut r).unwrap();
        assert_eq!(resp.body, b"hello world");
    }

    #[test]
    fn chunked_response_with_trailing_headers_is_parsed_correctly() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Trailer: value\r\n\r\n";
        let mut r = BufReader::new(Cursor::new(raw.to_vec()));
        let resp = read_response(&mut r).unwrap();
        assert_eq!(resp.body, b"abc");
    }

    #[test]
    fn falls_back_to_read_to_end_when_neither_length_nor_chunked_is_present() {
        let raw = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nwhatever is left in the stream";
        let mut r = BufReader::new(Cursor::new(raw.to_vec()));
        let resp = read_response(&mut r).unwrap();
        assert_eq!(resp.body, b"whatever is left in the stream");
    }

    #[test]
    fn a_404_with_no_body_parses_cleanly() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let mut r = BufReader::new(Cursor::new(raw.to_vec()));
        let resp = read_response(&mut r).unwrap();
        assert_eq!(resp.status, 404);
        assert!(resp.body.is_empty());
    }

    #[test]
    fn a_malformed_header_line_is_a_clean_error_not_a_panic() {
        let raw = b"HTTP/1.1 200 OK\r\nnot-a-valid-header-line\r\n\r\n";
        let mut r = BufReader::new(Cursor::new(raw.to_vec()));
        assert!(read_response(&mut r).is_err());
    }

    #[test]
    fn connection_closed_before_any_response_is_a_clean_error() {
        let mut r = BufReader::new(Cursor::new(Vec::<u8>::new()));
        assert!(read_response(&mut r).is_err());
    }

    #[test]
    fn timing_reader_marks_the_first_nonempty_read_only_once() {
        let marker = FirstByteMarker::new();
        assert!(marker.get().is_none());

        let data = b"hello world, this is more than one buffer's worth of data".to_vec();
        let mut timing = TimingReader::new(Cursor::new(data), marker.clone());

        let mut buf = [0u8; 4];
        timing.read_exact(&mut buf).unwrap();
        let first_mark = marker.get();
        assert!(first_mark.is_some());

        // A second read must not move the mark.
        timing.read_exact(&mut buf).unwrap();
        assert_eq!(marker.get(), first_mark);
    }

    #[test]
    fn timing_reader_survives_being_wrapped_in_a_bufreader() {
        // This is the actual usage shape: the marker is cloned out
        // before the TimingReader is moved into a BufReader, which
        // then owns it — proving the marker handle still works after
        // that move is the whole point of it being an Rc<Cell<...>>
        // rather than a field read back off the reader itself.
        let marker = FirstByteMarker::new();
        let timing = TimingReader::new(
            Cursor::new(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
            marker.clone(),
        );
        let mut buffered = BufReader::new(timing);

        assert!(marker.get().is_none());
        let _ = read_line(&mut buffered).unwrap();
        assert!(marker.get().is_some());
    }
}
