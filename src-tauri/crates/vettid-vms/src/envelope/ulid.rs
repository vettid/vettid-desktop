//! ULIDs (§5.3): 26 upper-case Crockford base32 characters, the first in
//! `0`–`7` (128 bits): 48 bits of milliseconds, then 80 random bits.

use chrono::{DateTime, Utc};

use crate::suite::{random, SuiteError};

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The length of a ULID.
pub const ULID_LEN: usize = 26;

/// Whether `s` is a canonical ULID.
pub fn valid_ulid(s: &str) -> bool {
    s.len() == ULID_LEN && s.as_bytes()[0] <= b'7' && s.bytes().all(|c| CROCKFORD.contains(&c))
}

/// A new ULID for `t`, with 80 bits from the OS. A time before 1970 counts
/// as 1970.
pub fn new_ulid(t: DateTime<Utc>) -> Result<String, SuiteError> {
    let mut r = [0u8; 10];
    random(&mut r)?;
    Ok(encode(t.timestamp_millis().max(0) as u64, &r))
}

fn encode(ms: u64, r: &[u8; 10]) -> String {
    let mut v: u128 = u128::from(ms & 0xFFFF_FFFF_FFFF) << 80;
    for (i, b) in r.iter().enumerate() {
        v |= u128::from(*b) << (72 - 8 * i);
    }
    (0..ULID_LEN).rev().map(|i| CROCKFORD[((v >> (5 * i)) & 31) as usize] as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape() {
        assert!(valid_ulid("01JB2Z6V9K3M4N5P6Q7R8S9T0V"));
        assert!(valid_ulid("7ZZZZZZZZZZZZZZZZZZZZZZZZZ"));
        for bad in [
            "81JB2Z6V9K3M4N5P6Q7R8S9T0V",
            "01jb2z6v9k3m4n5p6q7r8s9t0v",
            "01JB2Z6V9K3M4N5P6Q7R8S9T0",
            "01JB2Z6V9K3M4N5P6Q7R8S9T0VV",
            "01JB2Z6V9K3M4N5P6Q7R8S9T0I",
            "01JB2Z6V9K3M4N5P6Q7R8S9T0L",
            "01JB2Z6V9K3M4N5P6Q7R8S9T0O",
            "01JB2Z6V9K3M4N5P6Q7R8S9T0U",
            "",
        ] {
            assert!(!valid_ulid(bad), "{bad}");
        }
    }

    #[test]
    fn encoding() {
        assert_eq!(encode(0, &[0; 10]), "00000000000000000000000000");
        assert_eq!(encode(0xFFFF_FFFF_FFFF, &[0xFF; 10]), "7ZZZZZZZZZZZZZZZZZZZZZZZZZ");
        // The time prefix sorts by time.
        let t = DateTime::from_timestamp_millis(1_790_856_000_000).unwrap();
        let (a, b) = (new_ulid(t).unwrap(), new_ulid(t + chrono::Duration::milliseconds(1)).unwrap());
        assert!(valid_ulid(&a) && valid_ulid(&b));
        assert!(a[..10] < b[..10]);
        assert_eq!(&a[..10], &encode(1_790_856_000_000, &[0; 10])[..10]);
        assert_ne!(new_ulid(t).unwrap()[10..], a[10..], "random part");
    }
}
