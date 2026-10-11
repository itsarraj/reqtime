use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Resolves `host:port` via `resolver`, timing the call precisely
/// around the resolver invocation only — not around argument setup or
/// error formatting, so the reported duration is the DNS lookup
/// itself, nothing else. Parameterized over the resolver function
/// specifically so this can be exercised with a fake, deterministic
/// resolver in tests instead of depending on a real DNS round trip.
pub fn resolve_with<F>(
    host: &str,
    port: u16,
    resolver: F,
) -> Result<(Vec<SocketAddr>, Duration), String>
where
    F: FnOnce(&str, u16) -> io::Result<Vec<SocketAddr>>,
{
    let start = Instant::now();
    let addrs = resolver(host, port).map_err(|e| format!("resolving {host}: {e}"))?;
    let elapsed = start.elapsed();
    if addrs.is_empty() {
        return Err(format!("no addresses found for {host}"));
    }
    Ok((addrs, elapsed))
}

/// Real DNS resolution via the OS resolver (`getaddrinfo` under the
/// hood on most platforms, through `std`'s `ToSocketAddrs`).
pub fn resolve(host: &str, port: u16) -> Result<(Vec<SocketAddr>, Duration), String> {
    resolve_with(host, port, |h, p| {
        (h, p).to_socket_addrs().map(|it| it.collect())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread;

    #[test]
    fn returns_the_resolvers_addresses() {
        let (addrs, _) = resolve_with("example.com", 443, |_, port| {
            Ok(vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                port,
            )])
        })
        .unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 443);
    }

    #[test]
    fn measured_duration_reflects_real_time_spent_in_the_resolver() {
        let (_, elapsed) = resolve_with("slow.example", 80, |_, port| {
            thread::sleep(Duration::from_millis(30));
            Ok(vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                port,
            )])
        })
        .unwrap();
        assert!(
            elapsed >= Duration::from_millis(30),
            "expected at least 30ms, got {elapsed:?}"
        );
    }

    #[test]
    fn a_resolver_error_is_propagated_with_the_hostname() {
        let err = resolve_with("nope.invalid", 80, |_, _| {
            Err(io::Error::new(io::ErrorKind::NotFound, "no such host"))
        })
        .unwrap_err();
        assert!(err.contains("nope.invalid"));
    }

    #[test]
    fn zero_addresses_is_a_clean_error_not_a_panic() {
        let err = resolve_with("empty.example", 80, |_, _| Ok(vec![])).unwrap_err();
        assert!(err.contains("empty.example"));
    }
}
