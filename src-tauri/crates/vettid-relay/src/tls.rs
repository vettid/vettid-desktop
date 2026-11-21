//! TLS for every HTTP client this crate builds.
//!
//! rustls with the **aws-lc-rs** provider and its default key-exchange
//! groups. A handshake offers the hybrid post-quantum `X25519MLKEM768`
//! first (rustls's `prefer-post-quantum`), then `X25519`, `secp256r1` and
//! `secp384r1`, so a server without ML-KEM still connects with a classical
//! group. There is no custom group list.
//!
//! The provider is passed to each configuration explicitly, never taken
//! from rustls's process-wide default. A build that also compiles ring
//! (the calls build, through dtls) has no automatic default, and reqwest
//! would then fail to build a client.
//!
//! Otherwise the configuration is the one reqwest builds itself: rustls's
//! safe default protocol versions (TLS 1.2 and 1.3), ALPN `http/1.1` (this
//! crate's reqwest has no HTTP/2), SNI on. No certificate or CRL settings
//! of our own.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};

use crate::client::RelayError;

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

/// A reqwest client builder for plain `http://` on loopback (the dev
/// stack's control port, tests). Its TLS trusts nothing, so an `https://`
/// request through it fails closed.
pub fn plain_http_builder() -> Result<reqwest::ClientBuilder, RelayError> {
    builder_with(RootCertStore::empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConnection, NamedGroup, ServerConfig, ServerConnection};

    /// The group a client with [`config`] negotiates with a server offering
    /// only `server_groups` (all of aws-lc-rs's when `None`).
    fn negotiate(server_groups: Option<Vec<NamedGroup>>) -> Result<NamedGroup, rustls::Error> {
        // A TEST-ONLY CA and a leaf for `relay.test`, made fresh each run.
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
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let client_cfg = config(roots).unwrap();

        let mut client = ClientConnection::new(Arc::new(client_cfg), ServerName::try_from("relay.test").unwrap()).unwrap();
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
        // No process default is installed in this test binary, and the
        // configuration still builds: it never asks for one.
        assert!(CryptoProvider::get_default().is_none());
        let c = config(RootCertStore::empty()).unwrap();
        let aws = rustls::crypto::aws_lc_rs::default_provider();
        assert_eq!(c.crypto_provider().cipher_suites.len(), aws.cipher_suites.len());
        assert!(c.crypto_provider().cipher_suites.iter().zip(aws.cipher_suites.iter()).all(|(a, b)| a.suite() == b.suite()));
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
