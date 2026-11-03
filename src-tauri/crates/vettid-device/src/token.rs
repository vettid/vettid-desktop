//! Deposit tokens between a device and its vault (VAULT-MESSAGING §7.1).
//!
//! **The standing token this device mints for its vault** ("Device | its
//! vault | standing | ≤ 30 d | none" in §7.1's table), exactly as the
//! vault's Go device client mints it (`client.mintForVault` over
//! `relayclient.MintToken`): `iss` this device's mailbox, `sub` the vault's
//! relay key, `aud` this device's own relay URL, scope `deposit`, `iat` now
//! truncated to the second less 60 s (RELAY-PROTOCOL §5.2), `exp` = `iat` +
//! 30 days, a random 26-character `jti`, no quota, and no `owner_device`
//! (§7.1 "Device tokens are marked": the vault's tokens for its app only).
//! One addition the spec requires and Go leaves out: the lifetime is capped
//! by the relay's advertised `max_token_lifetime_seconds` (§7.1, "every
//! lifetime is also capped by the relay's advertised policy").

use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use vettid_relay::auth::{encode_key, mailbox_id};
use vettid_relay::token::{mint_token, parse_token, Claims, Token, SCOPE_DEPOSIT};
use vettid_vms::envelope::MAX_CLOCK_SKEW_FUTURE;

/// A standing token's lifetime (§7.1).
pub const STANDING_LIFETIME: TimeDelta = TimeDelta::days(30);
/// How far `iat` is backdated (RELAY-PROTOCOL §5.2).
pub const IAT_BACKDATE: TimeDelta = TimeDelta::seconds(60);

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Why a token was refused. Carries no token material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRefused {
    /// It couldn't be minted.
    Mint,
    /// It isn't the vault's, for this device, unexpired.
    Invalid,
}

/// A random `jti`, as Go's `randomID`: 26 characters of Crockford base32.
fn random_jti() -> String {
    let mut b = [0u8; 26];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| CROCKFORD[(x & 31) as usize] as char).collect()
}

/// Mint the standing token for the vault, see the module doc.
/// `relay_max_secs` is the relay's `max_token_lifetime_seconds` (0: not
/// advertised).
pub fn mint_for_vault(
    own_relay_key: &SigningKey,
    own_relay_url: &str,
    vault_relay_key: &VerifyingKey,
    now: DateTime<Utc>,
    relay_max_secs: u64,
) -> Result<(Token, DateTime<Utc>), TokenRefused> {
    let iat = DateTime::from_timestamp(now.timestamp(), 0).ok_or(TokenRefused::Mint)? - IAT_BACKDATE;
    let mut lifetime = STANDING_LIFETIME;
    if relay_max_secs > 0 {
        lifetime = lifetime.min(TimeDelta::seconds(i64::try_from(relay_max_secs).unwrap_or(i64::MAX)));
    }
    let exp = iat + lifetime;
    let claims = Claims {
        iss: mailbox_id(&own_relay_key.verifying_key()),
        sub: encode_key(vault_relay_key),
        aud: own_relay_url.to_string(),
        iat,
        exp,
        jti: random_jti(),
        scope: SCOPE_DEPOSIT.to_string(),
        quota: None,
        owner_device: false,
    };
    let token = mint_token(own_relay_key, &claims).map_err(|_| TokenRefused::Mint)?;
    Ok((token, exp))
}

/// Check a token the vault handed this device (a request token in
/// `hs.resp`, a standing token in `device.paired`): signed by the vault's
/// relay key, `iss` the vault's mailbox, `sub` this device's relay key, a
/// deposit token, unexpired. Returns its `exp`.
///
/// `iat` may be up to 5 minutes ahead of this device's clock (the inner
/// `ts` rule, §8.4): the vault backdates `iat` by only 60 s, and a desktop
/// clock a little slow must not throw away a valid approval. The relay
/// itself checks `iat` against its own clock when the token is used.
pub fn check_from_vault(
    token: &str,
    vault_relay_key: &VerifyingKey,
    own_relay_key: &VerifyingKey,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, TokenRefused> {
    let c = parse_token(token, vault_relay_key).map_err(|_| TokenRefused::Invalid)?;
    if c.iss != mailbox_id(vault_relay_key) || c.sub != encode_key(own_relay_key) || c.scope != SCOPE_DEPOSIT {
        return Err(TokenRefused::Invalid);
    }
    if c.iat > now + MAX_CLOCK_SKEW_FUTURE || now >= c.exp {
        return Err(TokenRefused::Invalid);
    }
    Ok(c.exp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vettid_relay::token::parse_token;

    fn keys() -> (SigningKey, SigningKey) {
        (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]))
    }

    #[test]
    fn the_standing_token_is_go_shaped() {
        let (own, vault) = keys();
        let now = DateTime::parse_from_rfc3339("2026-10-01T12:00:00.750Z").unwrap().with_timezone(&Utc);
        let (t, exp) = mint_for_vault(&own, "https://relay.vettid.org", &vault.verifying_key(), now, 0).unwrap();
        let c = parse_token(t.as_str(), &own.verifying_key()).unwrap();
        assert_eq!(c.iss, mailbox_id(&own.verifying_key()));
        assert_eq!(c.sub, encode_key(&vault.verifying_key()));
        assert_eq!(c.aud, "https://relay.vettid.org");
        assert_eq!(c.iat.to_rfc3339(), "2026-10-01T11:59:00+00:00", "truncated, less 60 s");
        assert_eq!(c.exp - c.iat, TimeDelta::days(30));
        assert_eq!(exp, c.exp);
        assert_eq!((c.scope.as_str(), c.quota, c.owner_device), ("deposit", None, false));
        assert!(c.jti.len() == 26 && c.jti.bytes().all(|b| CROCKFORD.contains(&b)));
        // Capped by the relay's advertised limit.
        let (t, _) = mint_for_vault(&own, "https://relay.vettid.org", &vault.verifying_key(), now, 86_400).unwrap();
        let c = parse_token(t.as_str(), &own.verifying_key()).unwrap();
        assert_eq!(c.exp - c.iat, TimeDelta::days(1));
        assert!(!format!("{t:?}").contains("v4.public"));
    }

    #[test]
    fn vault_tokens_are_checked() {
        let (own, vault) = keys();
        let now = DateTime::parse_from_rfc3339("2026-10-01T12:00:00Z").unwrap().with_timezone(&Utc);
        // The vault mints for this device (sub = our relay key).
        let (good, _) = mint_for_vault(&vault, "https://relay.vettid.org", &own.verifying_key(), now, 0).unwrap();
        assert!(check_from_vault(good.as_str(), &vault.verifying_key(), &own.verifying_key(), now).is_ok());
        // Another signer, another subject, or expired: refused.
        assert_eq!(check_from_vault(good.as_str(), &own.verifying_key(), &own.verifying_key(), now), Err(TokenRefused::Invalid));
        let (for_other, _) = mint_for_vault(&vault, "https://relay.vettid.org", &vault.verifying_key(), now, 0).unwrap();
        assert_eq!(check_from_vault(for_other.as_str(), &vault.verifying_key(), &own.verifying_key(), now), Err(TokenRefused::Invalid));
        assert_eq!(
            check_from_vault(good.as_str(), &vault.verifying_key(), &own.verifying_key(), now + TimeDelta::days(31)),
            Err(TokenRefused::Invalid)
        );
        assert_eq!(check_from_vault("v4.public.x", &vault.verifying_key(), &own.verifying_key(), now), Err(TokenRefused::Invalid));
        // A clock up to 5 minutes slow still accepts it (iat is backdated
        // only 60 s); more than that doesn't.
        let slow = now - TimeDelta::minutes(4);
        assert!(check_from_vault(good.as_str(), &vault.verifying_key(), &own.verifying_key(), slow).is_ok());
        let too_slow = now - TimeDelta::minutes(7);
        assert_eq!(check_from_vault(good.as_str(), &vault.verifying_key(), &own.verifying_key(), too_slow), Err(TokenRefused::Invalid));
    }
}
