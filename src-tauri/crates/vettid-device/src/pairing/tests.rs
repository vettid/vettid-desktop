//! Pairing end to end against an in-memory relay and a test vault written
//! from VAULT-MESSAGING §6.3/§6.4/§6.7 with the vault's test keys.

use chrono::{TimeDelta, Utc};
use ed25519_dalek::SigningKey;
use vettid_relay::token::Token;
use vettid_vms::envelope::{new_ulid, Envelope, Inner};
use vettid_vms::handshake::{Epoch, Role, Schedule, POLICY_VAULT_TO_DEVICE};
use vettid_vms::invite::Kind;
use vettid_vms::strict_json::Builder;
use zeroize::Zeroizing;
use std::sync::{Arc, Mutex};

use super::*;
use crate::store::MemStore;
use crate::testutil::*;

/// The whole flow: the code, the handshake, the SAS both sides agree on,
/// the owner's approval, and a stored, active, paired state, in that
/// order.
#[tokio::test]
async fn pairs_end_to_end() {
    let (relay, mut vault, faults) = setup();
    let mut store = LoggingStore { inner: MemStore::default(), relay: relay.clone() };
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    assert_eq!(pairing.instruction(), CONFIRM_ON_PHONE);
    assert_eq!(pairing.inviter_name(), Some("Al's vault"));
    assert_eq!(relay.lock().unwrap().fetches, 1, "the claim is fetched once");
    let pending = DeviceState::load(&mut store).unwrap().unwrap();
    assert_eq!((pending.phase, pending.epoch.active), (Phase::Pending, false));

    let body = vault.paired_body(&vault.device_relay_key());
    vault.send(DEVICE_PAIRED, body).await;
    let (paired, state) = pairing.wait_for_approval(&mut store).await.unwrap();
    assert_eq!(paired, Paired { device_id: "dev-1".into(), vault_id: Some("vault-1".into()) });
    // The order: hs.init out, stored, hs.fin out; the vault's device.paired
    // in, stored.
    let log: Vec<String> = relay.lock().unwrap().log.iter().filter(|l| !l.starts_with("vault") && !l.ends_with(" ack")).cloned().collect();
    assert_eq!(log, ["desktop deposit", "save", "desktop deposit", "save"]);
    let stored = DeviceState::load_paired(&mut store).unwrap().unwrap();
    assert_eq!((stored.phase, stored.epoch.active, stored.device_id.as_deref()), (Phase::Paired, true, Some("dev-1")));
    assert_eq!(stored.vault_token.as_str(), state.vault_token.as_str());
    assert!(!format!("{stored:?}").contains("seed"));
    // The stored epoch talks to the vault.
    let mut epoch = Epoch::restore(stored.epoch);
    let mut ping = Inner { id: new_ulid(Utc::now()).unwrap(), kind: "test.ping".into(), ts: Utc::now(), seq: None, response: None, exp: None, body: Zeroizing::new("{}".into()) };
    let env = Envelope::parse(&epoch.seal(&mut ping).unwrap()).unwrap();
    assert_eq!(vault.handshake.as_mut().unwrap().1.open(&env).unwrap().kind, "test.ping");
    // Everything collected was acked.
    assert!(relay.lock().unwrap().mailboxes[&vault.device_mailbox()].is_empty());
}

#[tokio::test]
async fn a_rejection_ends_it_and_forgets_it() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    vault.send(DEVICE_PAIR_REJECTED, "{}".into()).await;
    assert_eq!(pairing.wait_for_approval(&mut store).await.unwrap_err(), PairError::Rejected);
    assert!(store.data.is_none(), "nothing kept");
}

/// Fail secure: messages that aren't the vault's answer are dropped, and
/// with no answer the window ends "not paired" with nothing kept.
#[tokio::test]
async fn only_the_vault_can_answer() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    // A properly sealed device.paired, deposited by another relay key, and
    // plain junk: both dropped.
    let body = vault.paired_body(&vault.device_relay_key());
    let sealed = vault.seal(DEVICE_PAIRED, body);
    let stranger = Mem { relay: relay.clone(), key: SigningKey::from_bytes(&[8; 32]), name: "stranger", faults: Default::default() };
    let to = vault.device_mailbox();
    stranger.deposit(URL, &to, &Token::from_received("x".into()), &sealed).await.unwrap();
    stranger.deposit(URL, &to, &Token::from_received("x".into()), b"junk").await.unwrap();
    assert_eq!(pairing.wait_for_approval(&mut store).await.unwrap_err(), PairError::TimedOut);
    assert!(store.data.is_none(), "the pending pairing is forgotten");
}

/// A device.paired from the vault that doesn't check out ends the pairing
/// at once, not paired.
#[tokio::test]
async fn a_bad_device_paired_ends_it() {
    for case in ["token for another device", "role agent", "no token"] {
        let (relay, mut vault, faults) = setup();
        let mut store = MemStore::default();
        let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
        let body = match case {
            "token for another device" => vault.paired_body(&SigningKey::from_bytes(&[9; 32]).verifying_key()),
            "role agent" => vault.paired_body(&vault.device_relay_key()).replace(r#""desktop""#, r#""agent""#),
            _ => Builder::new().string("device_id", "dev-1").string("role", "desktop").finish(),
        };
        vault.send(DEVICE_PAIRED, body).await;
        assert_eq!(pairing.wait_for_approval(&mut store).await.unwrap_err(), PairError::BadAnswer, "{case}");
        assert!(store.data.is_none(), "{case}: nothing kept");
    }
}

/// Temporary relay failures while waiting are retried; a failed ack after
/// the answer is stored doesn't undo the pairing.
#[tokio::test]
async fn relay_blips_do_not_end_a_pairing() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    let body = vault.paired_body(&vault.device_relay_key());
    vault.send(DEVICE_PAIRED, body).await;
    {
        let mut f = faults.lock().unwrap();
        f.collects = 2;
        f.acks = 100;
    }
    let (paired, _) = pairing.wait_for_approval(&mut store).await.unwrap();
    assert_eq!(paired.device_id, "dev-1");
    assert_eq!(DeviceState::load_paired(&mut store).unwrap().unwrap().phase, Phase::Paired);
}

/// An hs.fin that certainly wasn't delivered ends the pairing and removes
/// the pending state, keys included.
#[tokio::test]
async fn an_undelivered_hs_fin_leaves_nothing() {
    let (relay, mut vault, faults) = setup();
    faults.lock().unwrap().deposit = Some(1); // the desktop's second deposit: hs.fin
    let code = vault.invite(Kind::Desktop, Utc::now() + TimeDelta::minutes(10), None);
    let mut store = LoggingStore { inner: MemStore::default(), relay: relay.clone() };
    let (result, ()) = tokio::join!(start(&code, "x", mem(&relay, &faults), &mut store, Ticking::new()), vault.answer_init());
    assert!(matches!(result.unwrap_err(), PairError::NotSent(_)));
    assert!(store.inner.data.is_none());
    assert!(relay.lock().unwrap().log.ends_with(&["save".to_string(), "clear".to_string()]));
}

/// A desktop clock 4 minutes slow still pairs (the vault backdates its
/// tokens' iat by only 60 s).
#[tokio::test]
async fn a_slow_clock_still_pairs() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::offset(-240)).await;
    let body = vault.paired_body(&vault.device_relay_key());
    vault.send(DEVICE_PAIRED, body).await;
    assert!(pairing.wait_for_approval(&mut store).await.is_ok());
}

/// After a restart mid-pairing, a pending state is no pairing: it is
/// removed.
#[tokio::test]
async fn a_pending_state_after_restart_is_not_a_pairing() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    drop(pairing); // the app stops
    assert_eq!(DeviceState::load(&mut store).unwrap().unwrap().phase, Phase::Pending);
    assert!(DeviceState::load_paired(&mut store).unwrap().is_none());
    assert!(store.data.is_none(), "removed, keys included");
}

/// A paired desktop is never re-paired over its keys: refused before
/// anything is spent. A pending state left behind is removed, and pairing
/// proceeds.
#[tokio::test]
async fn an_already_paired_desktop_is_not_overwritten() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    let body = vault.paired_body(&vault.device_relay_key());
    vault.send(DEVICE_PAIRED, body).await;
    pairing.wait_for_approval(&mut store).await.unwrap();
    let before = store.data.clone().unwrap();
    let code = vault.invite(Kind::Desktop, Utc::now() + TimeDelta::minutes(10), None);
    let fetches = relay.lock().unwrap().fetches;
    assert_eq!(start(&code, "x", mem(&relay, &faults), &mut store, Ticking::new()).await.unwrap_err(), PairError::AlreadyPaired);
    assert_eq!(relay.lock().unwrap().fetches, fetches, "no claim spent");
    assert_eq!(store.data.as_ref().map(|d| d.as_slice()), Some(before.as_slice()), "the pairing is untouched");
}

/// Cancelling a pending pairing removes it.
#[tokio::test]
async fn cancel_removes_the_pending_pairing() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    assert!(store.data.is_some());
    pairing.cancel(&mut store).unwrap();
    assert!(store.data.is_none());
}

#[tokio::test]
async fn codes_are_checked_before_anything_is_spent() {
    let (relay, vault, faults) = setup();
    let mut store = MemStore::default();
    let agent = vault.invite(Kind::Agent, Utc::now() + TimeDelta::minutes(10), None);
    assert_eq!(start(&agent, "x", mem(&relay, &faults), &mut store, Ticking::new()).await.unwrap_err(), PairError::NotForDesktop);
    let expired = vault.invite(Kind::Desktop, Utc::now() - TimeDelta::seconds(5), None);
    assert_eq!(start(&expired, "x", mem(&relay, &faults), &mut store, Ticking::new()).await.unwrap_err(), PairError::Expired);
    assert_eq!(start("not a code", "x", mem(&relay, &faults), &mut store, Ticking::new()).await.unwrap_err(), PairError::Code(InviteError::Qr));
    assert_eq!(relay.lock().unwrap().fetches, 0, "no claim spent");
    assert!(store.data.is_none());
}

/// No hs.resp: the window ends, nothing is stored.
#[tokio::test]
async fn no_answer_times_out() {
    let (relay, vault, faults) = setup();
    let code = vault.invite(Kind::Desktop, Utc::now() + TimeDelta::minutes(10), None);
    let mut store = MemStore::default();
    assert_eq!(start(&code, "x", mem(&relay, &faults), &mut store, Ticking::new()).await.unwrap_err(), PairError::TimedOut);
    assert!(store.data.is_none());
}

#[test]
fn stored_state_round_trips() {
    let s = Schedule::derive(&[1; 32], &[2; 32], [3; 32], [4; 32]);
    let epoch = Epoch::new(&s, Role::Initiator, 2, POLICY_VAULT_TO_DEVICE, Utc::now());
    let v = Vault::new(&Arc::new(Mutex::new(Relay::default())));
    let p = v.principal();
    let state = DeviceState {
        ik_seed: Zeroizing::new([1; 32]),
        kem_seed: Zeroizing::new([2; 32]),
        relay_seed: Zeroizing::new([3; 32]),
        relay_url: URL.into(),
        vault: VaultRecord { ik: p.ik, kem: p.kem, relay: p.relay },
        vault_token: Zeroizing::new("v4.public.abc".into()),
        vault_token_exp: vettid_vms::envelope::parse_ts("2026-10-31T12:00:00.000Z").unwrap(),
        issued_exp: vettid_vms::envelope::parse_ts("2026-10-31T11:59:00.000Z").unwrap(),
        phase: Phase::Pending,
        pairing_deadline: vettid_vms::envelope::parse_ts("2026-10-01T12:10:00.000Z").unwrap(),
        device_id: None,
        vault_id: Some("vault-1".into()),
        epoch: epoch.snapshot(),
        retired: vec![({
            let mut old = epoch.snapshot();
            old.send = None;
            old.rk = None;
            old
        }, vettid_vms::envelope::parse_ts("2026-10-17T12:00:00.000Z").unwrap())],
        awaiting: Vec::new(),
        seen: [("01JB2Z6V9K3M4N5P6Q7R8S9T0V".to_string(), vettid_vms::envelope::parse_ts("2026-10-01T12:00:00.000Z").unwrap())].into(),
        seen_inner: Default::default(),
        outbox: vec![crate::store::OutboxEntry { kind: "test.ping".into(), payload: vec![1, 2, 3], created: vettid_vms::envelope::parse_ts("2026-10-01T12:00:00.000Z").unwrap(), exp: vettid_vms::envelope::parse_ts("2026-10-01T12:01:00.000Z"), re: Some("01JB2Z6V9K3M4N5P6Q7R8S9T0X".into()) }],
        asked: [("01JB2Z6V9K3M4N5P6Q7R8S9T0W".to_string(), vettid_vms::envelope::parse_ts("2026-10-02T12:00:00.000Z").unwrap())].into(),
        asked_kinds: [("01JB2Z6V9K3M4N5P6Q7R8S9T0W".to_string(), "test.ask".to_string())].into(),
        refused: true,
        unlinked: Some("removed".into()),
        inbox: vec![vettid_vms::envelope::Inner::parse(
            br#"{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0Y","type":"device.unlinked","ts":"2026-10-01T12:00:00.000Z","seq":3,"body":{"reason":"removed"}}"#,
            vettid_vms::envelope::Mode::Session,
        )
        .unwrap()],
    };
    let json = state.to_json();
    let back = DeviceState::from_json(json.as_bytes()).unwrap();
    assert_eq!(back.to_json().as_str(), json.as_str());
    assert_eq!(Epoch::restore(back.epoch).id(), epoch.id());
    assert_eq!(DeviceState::from_json(b"{}").unwrap_err(), StoreError::Corrupt);
}
