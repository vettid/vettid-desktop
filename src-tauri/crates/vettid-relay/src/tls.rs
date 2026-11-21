//! TLS for every HTTP client this crate builds, and rustls's process
//! default for the rest of the app.
//!
//! rustls with the **aws-lc-rs** provider and its default key-exchange
//! groups. A handshake offers the hybrid post-quantum `X25519MLKEM768`
//! first (rustls's `prefer-post-quantum`), then `X25519`, `secp256r1` and
//! `secp384r1`, so a server without ML-KEM still connects with a classical
//! group. There is no custom group list.
//!
//! This crate's clients get the provider explicitly
//! (`use_preconfigured_tls`), never from rustls's process default. The
//! calls build also compiles ring, which dtls turns on in rustls, and
//! with two providers compiled in rustls has no automatic default:
//! anything that builds a rustls configuration without naming a provider
//! then panics ("no process-level CryptoProvider available"). dtls does
//! exactly that for its certificate verifiers, at every DTLS setup, and so
//! would a plain `reqwest::Client::new()`. So the app also installs
//! aws-lc-rs as the process default first thing at startup
//! ([`install_default_provider`]). dtls's own record crypto stays on ring;
//! only its certificate verifiers use the default.
//!
//! Otherwise the configuration is the one reqwest builds itself: rustls's
//! safe default protocol versions (TLS 1.2 and 1.3), ALPN `http/1.1` (this
//! crate's reqwest has no HTTP/2), SNI on. No certificate or CRL settings
//! of our own.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};

use crate::client::RelayError;

/// Makes aws-lc-rs rustls's process-wide default provider, for code that
/// builds a rustls configuration without naming one (dtls's certificate
/// verifiers in the calls build; any plain `reqwest::Client::new()`).
/// Call it first thing at startup, before anything uses TLS. Calling it
/// again, or after a default is already installed, changes nothing.
///
/// Returns whether the process default now offers `X25519MLKEM768`: false
/// means another provider was installed first (nothing in the app does
/// that). This crate doesn't log; the caller says so.
pub fn install_default_provider() -> bool {
    // Err means a default is already installed: the first call's, or one
    // installed before this.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    rustls::crypto::CryptoProvider::get_default()
        .is_some_and(|p| p.kx_groups.iter().any(|g| g.name() == rustls::NamedGroup::X25519MLKEM768))
}

/// The client configuration: aws-lc-rs, its default groups, `roots` as
/// the only trust anchors.
fn config(roots: RootCertStore) -> Result<ClientConfig, RelayError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut c = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| RelayError::Invalid)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(c)
}

/// The public web roots (webpki-roots), the set reqwest's `rustls-tls`
/// trusted before.
fn public_roots() -> RootCertStore {
    RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }
}

/// A reqwest client builder whose TLS trusts `roots` only.
pub(crate) fn builder_with(roots: RootCertStore) -> Result<reqwest::ClientBuilder, RelayError> {
    Ok(reqwest::Client::builder().use_preconfigured_tls(config(roots)?))
}

/// A reqwest client builder whose TLS trusts the public web roots: the
/// relay's.
pub fn public_builder() -> Result<reqwest::ClientBuilder, RelayError> {
    builder_with(public_roots())
}

/// **DEVELOPMENT ONLY** (`dev-relay`, and tests): a reqwest client builder
/// for plain `http://` on loopback (the dev stack's control port). Its TLS
/// trusts nothing, so an `https://` request through it fails closed.
#[cfg(any(test, feature = "dev-relay"))]
pub fn plain_http_builder() -> Result<reqwest::ClientBuilder, RelayError> {
    builder_with(RootCertStore::empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConnection, NamedGroup, ServerConfig, ServerConnection};

    /// A TEST-ONLY CA and a leaf for `relay.test` signed by it, made fresh
    /// each run: the CA's certificate, and the leaf's server configuration
    /// offering only `server_groups` (all of aws-lc-rs's when `None`).
    fn test_pki(server_groups: Option<Vec<NamedGroup>>) -> (CertificateDer<'static>, ServerConfig) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["relay.test".to_string()]).unwrap().signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let mut server_provider = rustls::crypto::aws_lc_rs::default_provider();
        if let Some(groups) = server_groups {
            server_provider.kx_groups.retain(|g| groups.contains(&g.name()));
        }
        let server_cfg = ServerConfig::builder_with_provider(Arc::new(server_provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())))
            .unwrap();
        (ca.der().clone(), server_cfg)
    }

    /// The group a client with [`config`] negotiates, in memory, with a
    /// server offering only `server_groups`.
    fn negotiate(server_groups: Option<Vec<NamedGroup>>) -> Result<NamedGroup, rustls::Error> {
        let (ca, server_cfg) = test_pki(server_groups);
        let mut roots = RootCertStore::empty();
        roots.add(ca).unwrap();
        let mut client = ClientConnection::new(Arc::new(config(roots).unwrap()), ServerName::try_from("relay.test").unwrap()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
        for _ in 0..20 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            let mut rd = &buf[..];
            while !rd.is_empty() {
                server.read_tls(&mut rd).unwrap();
                server.process_new_packets()?;
            }
            let mut buf = Vec::new();
            server.write_tls(&mut buf).unwrap();
            let mut rd = &buf[..];
            while !rd.is_empty() {
                client.read_tls(&mut rd).unwrap();
                client.process_new_packets()?;
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                let c = client.negotiated_key_exchange_group().expect("a group").name();
                assert_eq!(Some(c), server.negotiated_key_exchange_group().map(|g| g.name()));
                return Ok(c);
            }
        }
        panic!("the handshake didn't finish");
    }

    #[test]
    fn offers_x25519mlkem768_first_then_classical_groups() {
        let c = config(RootCertStore::empty()).unwrap();
        let groups: Vec<NamedGroup> = c.crypto_provider().kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(groups, vec![NamedGroup::X25519MLKEM768, NamedGroup::X25519, NamedGroup::secp256r1, NamedGroup::secp384r1]);
        assert_eq!(c.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(c.enable_sni);
    }

    #[test]
    fn the_provider_is_aws_lc_rs_not_the_process_default() {
        // Nothing in this test binary installs a process default, and the
        // configuration still builds: it never asks for one.
        assert!(CryptoProvider::get_default().is_none());
        let c = config(RootCertStore::empty()).unwrap();
        // Only aws-lc-rs's provider has an ML-KEM group (ring's has none).
        assert!(c.crypto_provider().kx_groups.iter().any(|g| g.name() == NamedGroup::X25519MLKEM768));
        // reqwest takes it: every builder here builds a client.
        public_builder().unwrap().build().unwrap();
        plain_http_builder().unwrap().build().unwrap();
    }

    #[test]
    fn negotiates_x25519mlkem768_with_a_server_that_has_it() {
        assert_eq!(negotiate(None).unwrap(), NamedGroup::X25519MLKEM768);
    }

    #[test]
    fn falls_back_to_a_classical_group_with_a_server_without_ml_kem() {
        assert_eq!(negotiate(Some(vec![NamedGroup::X25519])).unwrap(), NamedGroup::X25519);
        assert_eq!(negotiate(Some(vec![NamedGroup::secp256r1])).unwrap(), NamedGroup::secp256r1);
        assert_eq!(negotiate(Some(vec![NamedGroup::secp384r1])).unwrap(), NamedGroup::secp384r1);
    }

    /// Through reqwest, end to end over loopback: a server that offers
    /// only X25519MLKEM768 answers a client built by [`builder_with`] (what
    /// [`public_builder`] wraps; the test CA stands in for the web roots).
    #[tokio::test]
    async fn a_reqwest_client_connects_to_a_server_that_offers_only_x25519mlkem768() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (ca, server_cfg) = test_pki(Some(vec![NamedGroup::X25519MLKEM768]));
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let group = tls.get_ref().1.negotiated_key_exchange_group().map(|g| g.name());
            let mut buf = [0u8; 4096];
            let _ = tls.read(&mut buf).await.unwrap();
            tls.write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n").await.unwrap();
            let _ = tls.shutdown().await;
            group
        });
        let mut roots = RootCertStore::empty();
        roots.add(ca).unwrap();
        let client = builder_with(roots).unwrap().resolve("relay.test", addr).build().unwrap();
        let resp = client.get(format!("https://relay.test:{}/", addr.port())).send().await.unwrap();
        assert_eq!(resp.status(), 204);
        assert_eq!(server.await.unwrap(), Some(NamedGroup::X25519MLKEM768));
    }

    /// Live: the relay's TLS front, with the configuration the relay client
    /// uses. Network, so not in the normal run:
    /// `cargo test -p vettid-relay -- --ignored live_relay --nocapture`.
    #[test]
    #[ignore = "network: connects to relay.vettid.org"]
    fn live_relay_negotiates_x25519mlkem768() {
        use std::io::Write;
        let mut conn = ClientConnection::new(Arc::new(config(public_roots()).unwrap()), ServerName::try_from("relay.vettid.org").unwrap()).unwrap();
        let mut sock = std::net::TcpStream::connect(("relay.vettid.org", 443)).unwrap();
        sock.set_read_timeout(Some(std::time::Duration::from_secs(15))).unwrap();
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).unwrap();
        }
        let group = conn.negotiated_key_exchange_group().expect("a group").name();
        println!(
            "relay.vettid.org: {:?}, {:?}, key exchange group {:?}",
            conn.protocol_version().unwrap(),
            conn.negotiated_cipher_suite().unwrap().suite(),
            group
        );
        conn.send_close_notify();
        let _ = conn.complete_io(&mut sock);
        let _ = sock.flush();
        assert_eq!(group, NamedGroup::X25519MLKEM768);
    }
}
