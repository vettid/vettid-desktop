//! Padding (VAULT-MESSAGING §5.4): `json || 0x80 || 0x00*`, to the next
//! multiple of 512 bytes up to 16 KiB and of 16 KiB above that; the bucket
//! is for `len(json) + 1`, and a padded length must be exactly it.

use subtle::{ConditionallySelectable, ConstantTimeEq};

use super::{EnvelopeError, MAX_PADDED, MIN_PADDED, SMALL_BUCKET_LIMIT};

/// The padded length for a JSON inner plaintext of `n` bytes, or
/// `TooLarge` above [`MAX_PADDED`] (§5.5).
pub fn padded_len(n: usize) -> Result<usize, EnvelopeError> {
    let m = n.checked_add(1).ok_or(EnvelopeError::TooLarge)?;
    let bucket = if m <= SMALL_BUCKET_LIMIT { MIN_PADDED } else { SMALL_BUCKET_LIMIT };
    let p = m.div_ceil(bucket) * bucket;
    if p > MAX_PADDED {
        return Err(EnvelopeError::TooLarge);
    }
    Ok(p)
}

/// Whether `p` is a padded size some JSON length maps to: a multiple of
/// 512 in [512, 16384], or of 16384 in (16384, 245760].
pub fn valid_padded_len(p: usize) -> bool {
    match p {
        p if !(MIN_PADDED..=MAX_PADDED).contains(&p) => false,
        p if p <= SMALL_BUCKET_LIMIT => p % MIN_PADDED == 0,
        p => p % SMALL_BUCKET_LIMIT == 0,
    }
}

/// Pad a JSON inner plaintext to its bucket.
pub fn pad(json: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    Ok(pad_to(json, padded_len(json.len())?))
}

/// Pad to exactly `n` bytes, a valid padded size large enough for the
/// JSON: the alternate channel's fixed sizes.
pub fn pad_fixed(json: &[u8], n: usize) -> Result<Vec<u8>, EnvelopeError> {
    if !valid_padded_len(n) {
        return Err(EnvelopeError::Length);
    }
    if json.len() + 1 > n {
        return Err(EnvelopeError::TooLarge);
    }
    Ok(pad_to(json, n))
}

fn pad_to(json: &[u8], n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    out[..json.len()].copy_from_slice(json);
    out[json.len()] = 0x80;
    out
}

/// Remove bucket padding strictly: a valid padded size, ending in `0x80`
/// and zeros only, of exactly the length [`padded_len`] gives for what is
/// left (no over-padding).
pub fn unpad(padded: &[u8]) -> Result<&[u8], EnvelopeError> {
    let json = unpad_any(padded)?;
    match padded_len(json.len()) {
        Ok(p) if p == padded.len() => Ok(json),
        _ => Err(EnvelopeError::Padding),
    }
}

/// Remove fixed-size padding of exactly `n` bytes.
pub fn unpad_fixed(padded: &[u8], n: usize) -> Result<&[u8], EnvelopeError> {
    if padded.len() != n {
        return Err(EnvelopeError::Padding);
    }
    unpad_any(padded)
}

/// Find the `0x80` marker scanning the whole buffer with no early exit,
/// so the time taken doesn't depend on where the plaintext ends.
fn unpad_any(padded: &[u8]) -> Result<&[u8], EnvelopeError> {
    if !valid_padded_len(padded.len()) {
        return Err(EnvelopeError::Padding);
    }
    // marker: the index of the marker, or u64::MAX if there is none or the
    // last non-zero byte isn't 0x80.
    let mut marker = u64::MAX;
    let mut trailing_zero = subtle::Choice::from(1u8);
    for (i, &b) in padded.iter().enumerate().rev() {
        let is_zero = b.ct_eq(&0);
        let is_marker = b.ct_eq(&0x80);
        // The first non-zero byte from the end must be the marker.
        let first = trailing_zero & !is_zero;
        marker = u64::conditional_select(&marker, &(i as u64), first & is_marker);
        marker = u64::conditional_select(&marker, &u64::MAX, first & !is_marker);
        trailing_zero &= is_zero;
    }
    if marker == u64::MAX {
        return Err(EnvelopeError::Padding);
    }
    Ok(&padded[..marker as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets() {
        for (n, p) in [(0, 512), (511, 512), (512, 1024), (16383, 16384), (16384, 32768), (245_759, 245_760)] {
            assert_eq!(padded_len(n), Ok(p), "{n}");
        }
        assert_eq!(padded_len(245_760), Err(EnvelopeError::TooLarge));
        assert_eq!(padded_len(usize::MAX), Err(EnvelopeError::TooLarge));
        for p in [512, 1024, 16384, 32768, 245_760] {
            assert!(valid_padded_len(p), "{p}");
        }
        for p in [0, 511, 513, 16384 + 512, 245_760 + 16384, 262_144] {
            assert!(!valid_padded_len(p), "{p}");
        }
    }

    #[test]
    fn pad_and_unpad_round_trip() {
        for n in [0, 1, 510, 511, 512, 16383, 16384, 100_000] {
            let json = vec![b'x'; n];
            let p = pad(&json).unwrap();
            assert_eq!(p.len(), padded_len(n).unwrap());
            assert_eq!(unpad(&p).unwrap(), json.as_slice(), "{n}");
        }
        let fixed = pad_fixed(b"{}", 4096).unwrap();
        assert_eq!(fixed.len(), 4096);
        assert_eq!(unpad_fixed(&fixed, 4096).unwrap(), b"{}");
        assert_eq!(pad_fixed(&[b'x'; 4096], 4096), Err(EnvelopeError::TooLarge));
        assert_eq!(pad_fixed(b"{}", 4000), Err(EnvelopeError::Length));
    }

    #[test]
    fn malformed_padding_is_refused() {
        let good = pad(b"{}").unwrap();
        let mut no_marker = good.clone();
        no_marker[2] = 0;
        assert_eq!(unpad(&no_marker), Err(EnvelopeError::Padding));
        let mut wrong_last = good.clone();
        wrong_last[511] = 1;
        assert_eq!(unpad(&wrong_last), Err(EnvelopeError::Padding));
        let mut other_marker = good.clone();
        other_marker[2] = 0x81;
        assert_eq!(unpad(&other_marker), Err(EnvelopeError::Padding));
        // Over-padding: a 2-byte JSON in a 1024-byte bucket.
        let mut over = vec![0u8; 1024];
        over[..2].copy_from_slice(b"{}");
        over[2] = 0x80;
        assert_eq!(unpad(&over), Err(EnvelopeError::Padding));
        assert_eq!(unpad_fixed(&over, 1024).unwrap(), b"{}", "fixed sizes may be larger");
        assert_eq!(unpad(&good[..511]), Err(EnvelopeError::Padding));
        assert_eq!(unpad_fixed(&good, 4096), Err(EnvelopeError::Padding));
        // A 0x80 inside the JSON is fine; only the last non-zero byte counts.
        let p = pad(b"{\x80}").unwrap();
        assert_eq!(unpad(&p).unwrap(), b"{\x80}");
        assert_eq!(unpad(&[0u8; 512]), Err(EnvelopeError::Padding));
    }
}
