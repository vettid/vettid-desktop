//! **G: the desktop against vettid-vault's local dev stack**, through the
//! real relay (development builds only: `dev-relay`). It pairs with the
//! stack's peer vault, whose owner device the stack's control port drives,
//! then runs a session: a request and its response, collected from the
//! relay.
//!
//! Run the stack (vettid-vault, on Linux, e.g. in WSL):
//!
//! ```text
//! go run -tags devenclave ./cmd/devstack
//! ```
//!
//! then, here (WSL's localhost ports are forwarded to Windows):
//!
//! ```text
//! VETTID_DEVSTACK=http://127.0.0.1:18082 cargo test -p vettid-device --features dev-relay --test devstack -- --ignored --nocapture
//! ```
//!
//! Every key in the stack is TEST-ONLY; nothing here is a real vault.
#![cfg(feature = "dev-relay")]

use std::time::Duration;

use chrono::TimeDelta;
use serde_json::{json, Value};
use vettid_device::pairing::{start, SystemClock};
use vettid_device::session::Session;
use vettid_device::store::{Persist, StoreError};
use vettid_device::transport::Http;
use vettid_relay::dev::DevRelay;
use vettid_vms::envelope::Status;
use zeroize::Zeroizing;

/// The device state, in memory only (nothing of the test is kept).
#[derive(Default)]
struct Mem(Option<Zeroizing<Vec<u8>>>);

impl Persist for Mem {
    fn save(&mut self, data: &[u8]) -> Result<(), StoreError> {
        self.0 = Some(Zeroizing::new(data.to_vec()));
        Ok(())
    }
    fn load(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        Ok(self.0.clone())
    }
    fn clear(&mut self) -> Result<(), StoreError> {
        self.0 = None;
        Ok(())
    }
}

/// The stack's control port, driving the peer vault's owner device.
struct Control {
    url: String,
    http: reqwest::Client,
}

impl Control {
    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let r = self
            .http
            .post(format!("{}{path}", self.url))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .expect("the control port");
        let status = r.status().as_u16();
        let bytes = r.bytes().await.unwrap_or_default();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    /// `vaultctl request TYPE BODY` on the peer: `{status, body, error?}`.
    async fn request(&self, kind: &str, body: Value) -> Value {
        let (status, v) = self.post("/dev/peer/request", json!({ "type": kind, "body": body })).await;
        assert_eq!(status, 200, "{kind}: {v}");
        assert!(v.get("error").is_none(), "{kind}: {v}");
        v
    }

    /// Wait for a peer event of `kind` whose body matches `m`.
    async fn event(&self, kind: &str, m: Value) -> Value {
        let (status, v) = self.post("/dev/peer/event", json!({ "type": kind, "match": m, "timeout_s": 120 })).await;
        assert_eq!(status, 200, "{kind}: {v}");
        v
    }
}

#[tokio::test]
#[ignore = "needs the dev stack: set VETTID_DEVSTACK and run with --ignored"]
async fn pairs_and_collects_on_the_dev_stack() {
    let Ok(url) = std::env::var("VETTID_DEVSTACK") else {
        panic!("set VETTID_DEVSTACK to the dev stack's control port, e.g. http://127.0.0.1:18082");
    };
    let ctl = Control {
        url: url.trim_end_matches('/').to_string(),
        http: reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(150)).build().unwrap(),
    };
    let dev = DevRelay::from_stack(&ctl.url).await.expect("the stack's relay front and TEST-ONLY root");
    println!("relay front: {}", dev.front());

    // 1. The peer's owner device asks its vault for a desktop pairing code.
    let created = ctl.request("device.pair.create", json!({ "role": "desktop" })).await;
    let link = created["body"]["link"].as_str().expect("a link").to_string();
    let pairing_id = created["body"]["pairing_id"].as_str().expect("a pairing id").to_string();

    // 2. The desktop pairs through the relay and shows the SAS.
    let mut store = Mem::default();
    let d = dev.clone();
    let pairing = start(&link, "Devstack desktop", move |k| Http::dev(k, d), &mut store, SystemClock).await.expect("the handshake");
    println!("the desktop shows {}", pairing.sas());

    // 3. The owner's device shows the same SAS.
    let pending = ctl.event("device.pair.pending", json!({ "pairing_id": pairing_id })).await;
    assert_eq!(pending["body"]["sas"].as_str(), Some(pairing.sas()), "both sides show the same code");
    assert_eq!(pending["body"]["role"].as_str(), Some("desktop"));

    // 4. The owner approves; the desktop gets device.paired.
    ctl.request("device.pair.approve", json!({ "pairing_id": pairing_id, "session_seconds": 600 })).await;
    let (paired, _) = pairing.wait_for_approval(&mut store).await.expect("device.paired");
    println!("paired as {paired:?}");

    // 5. A session: a request to the vault, and its response collected
    //    from the relay.
    let d = dev.clone();
    let mut s = Session::open(&mut store, move |k| Http::dev(k, d), SystemClock).unwrap().expect("a paired session");
    let answer = s.request(&mut store, "vault.status", "{}", TimeDelta::seconds(60)).await.expect("the vault's response");
    println!("vault.status: {:?} {}", answer.response.as_ref().map(|r| &r.status), answer.body.as_str());
    assert_eq!(answer.kind, "vault.status");
    assert_eq!(answer.response.as_ref().map(|r| &r.status), Some(&Status::Ok), "an ok answer");
    let body: Value = serde_json::from_str(&answer.body).unwrap();
    assert_eq!(body["vault_id"].as_str(), paired.vault_id.as_deref(), "the vault it paired with");
    assert!(!s.is_refused());
}
