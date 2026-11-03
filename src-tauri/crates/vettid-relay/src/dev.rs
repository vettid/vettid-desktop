//! **DEVELOPMENT ONLY**: reaching the relay of vettid-vault's local dev
//! stack (`cmd/devstack`), behind the non-default `dev-relay` feature,
//! which no release build compiles (lib.rs, build.rs and a CI check refuse
//! it).
//!
//! The dev stack's tokens and invitations name the relay
//! `https://relay.vettid.test`. Its TLS front for that name listens on
//! loopback, with a certificate from the stack's TEST-ONLY root. A
//! [`DevRelay`] holds the front's address and that root, read from the
//! stack's control port on loopback ([`DevRelay::from_stack`]: `GET
//! /dev/info` for `relay_tls`, `GET /dev/trust` for `tls_root_pem`), and
//! [`RelayClient::new_dev`](crate::client::RelayClient::new_dev) builds a
//! client that:
//! - talks only to `https://relay.vettid.test`, resolved to that loopback
//!   front, whatever DNS says;
//! - trusts **only** the test root (the built-in web roots are off), so it
//!   can reach nothing else either: no other name resolves to the front,
//!   and no real certificate chains to the test root;
//! - uses no proxy and follows no redirect.
//!
//! The root is never read from anywhere but a loopback control port, and
//! the front must be a loopback address.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::Deserialize;

use crate::client::RelayError;

/// The dev stack's relay host name (a `.test` name: never a real host).
pub const DEV_RELAY_HOST: &str = "relay.vettid.test";
/// The dev stack's relay base URL, as its tokens and invitations name it.
pub const DEV_RELAY_URL: &str = "https://relay.vettid.test";

/// The longest answer read from the control port.
const MAX_CONTROL_BODY: usize = 64 * 1024;

/// The dev stack's relay front and TEST-ONLY TLS root. `Debug` shows the
/// front only.
#[derive(Clone)]
pub struct DevRelay {
    front: SocketAddr,
    root_pem: Vec<u8>,
}

impl std::fmt::Debug for DevRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevRelay").field("front", &self.front).finish_non_exhaustive()
    }
}

/// A control-port URL: `http://` on a loopback address (`127.0.0.1`, `::1`
/// or `localhost`), with a port, and no user, path, query or fragment.
fn check_control_url(ctl: &str) -> Result<String, RelayError> {
    let u = reqwest::Url::parse(ctl).map_err(|_| RelayError::Invalid)?;
    let loopback = match u.host_str() {
        Some("localhost") => true,
        Some(h) => h.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().is_ok_and(|a| a.is_loopback()),
        None => false,
    };
    if u.scheme() != "http"
        || !loopback
        || u.port().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || !(u.path() == "/" || u.path().is_empty())
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(RelayError::Invalid);
    }
    Ok(ctl.trim_end_matches('/').to_string())
}

impl DevRelay {
    /// The relay front and root of the dev stack whose control port is at
    /// `ctl` (for example `http://127.0.0.1:18082`): see the module doc.
    pub async fn from_stack(ctl: &str) -> Result<Self, RelayError> {
        let ctl = check_control_url(ctl)?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| RelayError::Invalid)?;
        let get = |path: &'static str| {
            let (http, url) = (http.clone(), format!("{ctl}{path}"));
            async move {
                let r = http.get(url).send().await.map_err(|_| RelayError::Connect)?;
                if r.status() != 200 {
                    return Err(RelayError::Malformed);
                }
                let b = r.bytes().await.map_err(|_| RelayError::Transport)?;
                if b.len() > MAX_CONTROL_BODY {
                    return Err(RelayError::TooLarge);
                }
                Ok(b)
            }
        };
        #[derive(Deserialize)]
        struct Info {
            relay_tls: String,
        }
        #[derive(Deserialize)]
        struct Trust {
            tls_root_pem: String,
        }
        let info: Info = serde_json::from_slice(&get("/dev/info").await?).map_err(|_| RelayError::Malformed)?;
        let trust: Trust = serde_json::from_slice(&get("/dev/trust").await?).map_err(|_| RelayError::Malformed)?;
        let front: SocketAddr = info.relay_tls.parse().map_err(|_| RelayError::Malformed)?;
        Self::new(front, trust.tls_root_pem.into_bytes())
    }

    /// From a front (a loopback address) and one PEM certificate.
    fn new(front: SocketAddr, root_pem: Vec<u8>) -> Result<Self, RelayError> {
        if !front.ip().is_loopback() || front.port() == 0 {
            return Err(RelayError::Invalid);
        }
        let d = Self { front, root_pem };
        d.root()?;
        Ok(d)
    }

    /// The front (`relay.vettid.test` resolves to it).
    pub fn front(&self) -> SocketAddr {
        self.front
    }

    pub(crate) fn root(&self) -> Result<reqwest::Certificate, RelayError> {
        // Exactly one certificate.
        let n = self.root_pem.windows(27).filter(|w| *w == b"-----BEGIN CERTIFICATE-----").count();
        if n != 1 {
            return Err(RelayError::Invalid);
        }
        reqwest::Certificate::from_pem(&self.root_pem).map_err(|_| RelayError::Invalid)
    }

    /// A client builder for the dev relay only (see the module doc).
    pub(crate) fn builder(&self) -> Result<reqwest::ClientBuilder, RelayError> {
        Ok(reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(self.root()?)
            .resolve(DEV_RELAY_HOST, self.front)
            .https_only(true)
            .no_proxy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_urls_must_be_loopback_http() {
        for ok in ["http://127.0.0.1:18082", "http://127.0.0.1:18082/", "http://localhost:1", "http://[::1]:18082"] {
            assert!(check_control_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "https://127.0.0.1:18082",
            "http://10.0.0.1:18082",
            "http://relay.vettid.test:18082",
            "http://127.0.0.1",
            "http://u:p@127.0.0.1:18082",
            "http://127.0.0.1:18082/dev",
            "http://127.0.0.1:18082/?x",
            "http://127.0.0.1:18082/#x",
            "http://localhost.example.com:1",
            "file:///tmp/ca.pem",
        ] {
            assert_eq!(check_control_url(bad).unwrap_err(), RelayError::Invalid, "{bad}");
        }
    }

    #[test]
    fn the_front_must_be_loopback_and_the_root_one_certificate() {
        let pem = b"-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n".to_vec();
        assert_eq!(DevRelay::new("10.0.0.1:443".parse().unwrap(), pem.clone()).unwrap_err(), RelayError::Invalid);
        assert_eq!(DevRelay::new("127.0.0.1:0".parse().unwrap(), pem.clone()).unwrap_err(), RelayError::Invalid);
        assert_eq!(DevRelay::new("127.0.0.1:1".parse().unwrap(), Vec::new()).unwrap_err(), RelayError::Invalid, "no certificate");
        let two = [pem.clone(), pem].concat();
        assert_eq!(DevRelay::new("127.0.0.1:1".parse().unwrap(), two).unwrap_err(), RelayError::Invalid, "two");
    }

    #[tokio::test]
    async fn a_stack_that_is_not_there() {
        assert_eq!(DevRelay::from_stack("http://127.0.0.1:1").await.unwrap_err(), RelayError::Connect);
        assert_eq!(DevRelay::from_stack("http://192.0.2.1:18082").await.unwrap_err(), RelayError::Invalid, "refused before any request");
    }
}
