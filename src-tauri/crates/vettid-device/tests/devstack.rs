//! **G: the desktop against vettid-vault's local dev stack**, through the
//! real relay (development builds only: `dev-relay`). It pairs with the
//! stack's peer vault, whose owner device the stack's control port drives,
//! then runs a session: a request and its response, collected from the
//! relay. Then access sessions (§6.8): the one granted with the pairing
//! ended by its id, a new one requested, approved on the peer and granted,
//! and ended without an id.
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

use chrono::{TimeDelta, Utc};
use serde_json::{json, Value};
use vettid_device::access::{Access, AccessEvent, EndOutcome, RequestOutcome, StatusSession};
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
    // The same checks as the relay root's: a loopback IP literal, its origin.
    let origin = vettid_relay::dev::check_control_url(&url).expect("a loopback http:// control URL with a port");
    let ctl = Control {
        url: origin,
        http: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(150))
            .build()
            .unwrap(),
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
    // The status only: the body carries ids (unlock_id, session_id) that a log has no use for.
    println!("vault.status: {:?}", answer.response.as_ref().map(|r| &r.status));
    assert_eq!(answer.kind, "vault.status");
    assert_eq!(answer.response.as_ref().map(|r| &r.status), Some(&Status::Ok), "an ok answer");
    let body: Value = serde_json::from_str(&answer.body).unwrap();
    assert_eq!(body["vault_id"].as_str(), paired.vault_id.as_deref(), "the vault it paired with");
    assert!(!s.is_refused());

    // 6. Access sessions (§6.8, the V6 exit flow). The pairing granted
    //    one (session_seconds: 600): vault.status shows it.
    let mut access = Access::with_timeout(TimeDelta::seconds(60));
    let first = match access.read_status(&mut s, &mut store).await.expect("vault.status").session {
        StatusSession::Session(x) => x,
        other => panic!("no session after a pairing with session_seconds: {other:?}"),
    };
    println!("access session from the pairing, expires {}", first.expires_at);
    assert!(access.active_at(Utc::now()));

    // 7. End it by its session_id: vault.status reads null.
    assert_eq!(access.end(&mut s, &mut store, Some(&first.session_id)).await, Ok(EndOutcome::Ended));
    assert!(!access.active_at(Utc::now()));
    assert_eq!(access.read_status(&mut s, &mut store).await.map(|r| r.session), Ok(StatusSession::None), "ended by its id");
    println!("ended by session_id; vault.status session: null");

    // 8. Ask for a new one.
    let request_id = match access.request(&mut s, &mut store, Some(300)).await.expect("device.session.request") {
        RequestOutcome::Requested { request_id, exp } => {
            println!("requested, until {exp}");
            request_id
        }
        other => panic!("not requested: {other:?}"),
    };

    // 9. The owner's device is asked, and approves.
    let pending = ctl.event("device.session.pending", json!({ "request_id": request_id })).await;
    assert_eq!(pending["body"]["seconds"].as_u64(), Some(300));
    let approved = ctl.request("device.session.approve", json!({ "request_id": request_id })).await;
    let approved_id = approved["body"]["session_id"].as_str().expect("the approved session's id").to_string();

    // 10. The desktop is told, and vault.status shows the new session.
    let deadline = Utc::now() + TimeDelta::seconds(90);
    let granted = 'wait: loop {
        assert!(Utc::now() < deadline, "no device.session.granted");
        let msgs = match s.poll(&mut store).await {
            Ok(m) => m,
            Err(e) => {
                println!("poll: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        for m in &msgs {
            if let Ok(Some(AccessEvent::Granted(g))) = access.observe(&mut s, &mut store, m) {
                break 'wait g;
            }
        }
    };
    println!("granted, expires {}", granted.expires_at);
    assert_eq!(granted.session_id, approved_id);
    assert_ne!(granted.session_id, first.session_id);
    assert!(access.active_at(Utc::now()));
    match access.read_status(&mut s, &mut store).await.expect("vault.status").session {
        StatusSession::Session(x) => assert_eq!(x, granted),
        other => panic!("vault.status doesn't show the grant: {other:?}"),
    }

    // 11. End without a session_id (the person's End access): null.
    assert_eq!(access.end(&mut s, &mut store, None).await, Ok(EndOutcome::Ended));
    assert_eq!(access.read_status(&mut s, &mut store).await.map(|r| r.session), Ok(StatusSession::None), "all access ended");
    assert!(!access.active_at(Utc::now()));
    assert!(s.access_end().is_none());
    println!("ended without session_id; vault.status session: null");
}
