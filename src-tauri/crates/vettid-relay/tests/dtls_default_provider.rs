//! The calls build compiles rustls with two providers: ring (dtls turns it
//! on) and aws-lc-rs (ours). With two, rustls has no automatic process
//! default, and dtls builds its certificate verifiers without naming a
//! provider, in every `DTLSConn::new`. Without a default that panics; with
//! [`vettid_relay::tls::install_default_provider`], which the app calls first
//! at startup, the handshake completes.
//!
//! This test builds dtls as a dev-dependency, so this crate's test build has
//! both providers, as the calls build does. It runs in its own process
//! (an integration test), because the process default can be installed only
//! once and the first half needs none.

use std::sync::Arc;

use dtls::config::Config;
use dtls::conn::DTLSConn;
use dtls::crypto::Certificate;
use rustls::crypto::CryptoProvider;
use rustls::NamedGroup;

/// One DTLS client and server handshake over an in-memory pipe.
async fn dtls_handshake() -> Result<(), String> {
    let (a, b) = webrtc_util::conn::conn_pipe::pipe();
    let client_cfg = Config {
        certificates: vec![Certificate::generate_self_signed(vec!["localhost".to_owned()]).unwrap()],
        // TEST-ONLY: the peer's certificate is self-signed here. The
        // verifier is built in DTLSConn::new either way.
        insecure_skip_verify: true,
        ..Default::default()
    };
    let server_cfg = Config { certificates: vec![Certificate::generate_self_signed(vec!["localhost".to_owned()]).unwrap()], ..Default::default() };
    let (c, s) = tokio::join!(DTLSConn::new(Arc::new(a), client_cfg, true, None), DTLSConn::new(Arc::new(b), server_cfg, false, None));
    let (c, s) = (c.map_err(|e| e.to_string())?, s.map_err(|e| e.to_string())?);
    let _ = c.close().await;
    let _ = s.close().await;
    Ok(())
}

#[tokio::test]
async fn dtls_needs_the_process_default_and_works_once_it_is_installed() {
    // Both providers are compiled into this test build, so rustls can't
    // choose a default by itself.
    assert!(CryptoProvider::get_default().is_none());

    // 1. Without a default, dtls's verifier setup panics (the bug).
    let without = tokio::spawn(dtls_handshake()).await;
    let panic = match without {
        Err(e) if e.is_panic() => e.into_panic(),
        other => panic!("expected dtls to panic without a process default, got {other:?}"),
    };
    let msg = panic.downcast_ref::<String>().cloned().or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
    assert!(msg.contains("CryptoProvider"), "the panic is rustls's missing provider: {msg}");

    // 2. With aws-lc-rs installed as the default, the handshake completes.
    assert!(vettid_relay::tls::install_default_provider(), "the default offers X25519MLKEM768");
    let p = CryptoProvider::get_default().expect("installed");
    assert!(p.kx_groups.iter().any(|g| g.name() == NamedGroup::X25519MLKEM768), "the default is aws-lc-rs (ring's has no ML-KEM)");
    tokio::spawn(dtls_handshake()).await.expect("no panic").expect("the handshake completes");

    // 3. Installing again changes nothing, and code that names no provider
    //    now works: a plain reqwest client, a rustls verifier.
    assert!(vettid_relay::tls::install_default_provider());
    assert!(std::ptr::eq(Arc::as_ptr(p), Arc::as_ptr(CryptoProvider::get_default().unwrap())));
    reqwest::Client::new();
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    rustls::client::WebPkiServerVerifier::builder(Arc::new(roots)).build().expect("a verifier from the default provider");
}
