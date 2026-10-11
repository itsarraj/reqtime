use std::net::TcpStream;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

static CRYPTO_PROVIDER_INSTALLED: OnceLock<()> = OnceLock::new();

fn ensure_crypto_provider() {
    CRYPTO_PROVIDER_INSTALLED.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// A real trust store of public CAs (Mozilla's list, via
/// `webpki-roots`) — this tool is timing a normal HTTPS request, not
/// inspecting a certificate, so it validates the chain for real
/// rather than accepting anything, unlike a cert-inspection tool that
/// deliberately wants to see even an untrusted/expired certificate.
pub fn real_client_config() -> Arc<ClientConfig> {
    ensure_crypto_provider();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Performs a real TLS handshake over `stream`, timing only the
/// handshake itself — connection setup already happened in
/// `connect::connect`, so that time isn't double-counted here.
///
/// `ClientConnection::new` does no I/O by itself; a handshake only
/// actually runs when bytes are pushed through the connection, which
/// `complete_io` does explicitly and completely (its own doc: "If the
/// connection is handshaking, then IO is performed until the
/// handshake is complete") — driven directly here rather than via
/// `Stream`'s `Read`/`Write` impls, specifically so the timer stops
/// right when the handshake itself finishes, not whenever some later
/// incidental read/write happens to trigger it lazily.
pub fn handshake(
    mut stream: TcpStream,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> Result<(StreamOwned<ClientConnection, TcpStream>, Duration), String> {
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|e| format!("invalid server name '{server_name}': {e}"))?;

    let start = Instant::now();
    let mut conn =
        ClientConnection::new(config, name).map_err(|e| format!("starting TLS connection: {e}"))?;

    while conn.is_handshaking() {
        conn.complete_io(&mut stream)
            .map_err(|e| format!("TLS handshake: {e}"))?;
    }
    let elapsed = start.elapsed();

    Ok((StreamOwned::new(conn, stream), elapsed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::ServerConfig;

    fn install_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    /// A single self-signed cert, usable directly as its own trust
    /// anchor (no separate CA needed) — the same simplification
    /// `rcgen::generate_simple_self_signed` is meant for.
    fn self_signed_cert(sans: &[&str]) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let names: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
        let generated = rcgen::generate_simple_self_signed(names).unwrap();
        let cert_der = generated.cert.der().clone();
        let key_pem = generated.key_pair.serialize_pem();
        let key_der = rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_bytes()))
            .unwrap()
            .expect("a private key must be present");
        (cert_der, key_der)
    }

    fn client_config_trusting(cert: &CertificateDer<'static>) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    fn run_server(
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        listener: TcpListener,
    ) {
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        );
        let (sock, _) = listener.accept().unwrap();
        let conn = rustls::ServerConnection::new(server_config).unwrap();
        let mut tls = StreamOwned::new(conn, sock);
        tls.write_all(b"hello from reqtime's test server\n").ok();
    }

    #[test]
    fn a_real_handshake_against_a_trusted_local_server_succeeds() {
        install_provider();
        let (cert, key) = self_signed_cert(&["localhost"]);
        let client_trust_cert = cert.clone();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_thread = thread::spawn(move || run_server(cert, key, listener));

        let stream = TcpStream::connect(addr).unwrap();
        let config = client_config_trusting(&client_trust_cert);
        let (tls_stream, elapsed) = handshake(stream, "localhost", config)
            .expect("handshake against a trusted, matching-hostname cert should succeed");

        assert!(elapsed < Duration::from_secs(5));
        drop(tls_stream);
        server_thread.join().unwrap();
    }

    #[test]
    fn a_handshake_against_an_untrusted_cert_fails() {
        install_provider();
        let (server_cert, server_key) = self_signed_cert(&["localhost"]);
        // A different, unrelated cert — the client trusts *this* one,
        // not the one the server actually presents.
        let (unrelated_cert, _) = self_signed_cert(&["localhost"]);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_thread = thread::spawn(move || run_server(server_cert, server_key, listener));

        let stream = TcpStream::connect(addr).unwrap();
        let config = client_config_trusting(&unrelated_cert);
        let result = handshake(stream, "localhost", config);

        assert!(
            result.is_err(),
            "a cert not signed by (or equal to) the trusted root must fail validation"
        );
        // The server thread will error out trying to write to a
        // connection the client aborted mid-handshake — that's
        // expected, not something to assert on.
        let _ = server_thread.join();
    }

    #[test]
    fn a_hostname_not_covered_by_the_cert_is_rejected() {
        install_provider();
        // Cert is only valid for "localhost", not "impostor.test".
        let (cert, key) = self_signed_cert(&["localhost"]);
        let client_trust_cert = cert.clone();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_thread = thread::spawn(move || run_server(cert, key, listener));

        let stream = TcpStream::connect(addr).unwrap();
        let config = client_config_trusting(&client_trust_cert);
        let result = handshake(stream, "impostor.test", config);

        assert!(
            result.is_err(),
            "a hostname outside the cert's SANs must fail even with the right root trusted"
        );
        let _ = server_thread.join();
    }
}
