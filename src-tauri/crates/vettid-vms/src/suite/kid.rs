//! Kids (VAULT-MESSAGING §4.4): `kid = SHA-256("vettid/vms/2/kid" ‖ ek)[0:8]`.
//! A kid is a lookup hint only: never trial-decrypt under another
//! principal's keys because a kid matched.

use super::{labeled_hash, KID_SIZE, LABEL_KID};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kid(pub [u8; KID_SIZE]);

/// The anonymous kid (all zeros).
pub const ANONYMOUS: Kid = Kid([0; KID_SIZE]);

/// The kid of an encapsulation key.
pub fn kid_of(ek: &[u8]) -> Kid {
    let h = labeled_hash(LABEL_KID, &[ek]);
    let mut k = [0u8; KID_SIZE];
    k.copy_from_slice(&h[..KID_SIZE]);
    Kid(k)
}

impl Kid {
    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Kid) -> bool {
        super::ct_eq(&self.0, &other.0)
    }

    pub fn is_anonymous(&self) -> bool {
        self.ct_eq(&ANONYMOUS)
    }

    /// Parse 16 lowercase hex digits.
    pub fn parse_hex(s: &str) -> Option<Kid> {
        if s.len() != 2 * KID_SIZE || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return None;
        }
        let mut k = [0u8; KID_SIZE];
        hex_decode(s, &mut k)?;
        Some(Kid(k))
    }
}

fn hex_decode(s: &str, out: &mut [u8]) -> Option<()> {
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        out[i] = v(pair[0])? << 4 | v(pair[1])?;
    }
    Some(())
}

impl std::fmt::Display for Kid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for Kid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Kid({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kids_parse_and_print_in_one_spelling() {
        let k = Kid::parse_hex("40d6c2c8471844a9").unwrap();
        assert_eq!(k.to_string(), "40d6c2c8471844a9");
        for bad in ["40D6C2C8471844A9", "40d6c2c8471844a", "40d6c2c8471844a9a", "40d6c2c8471844ag"] {
            assert!(Kid::parse_hex(bad).is_none(), "{bad}");
        }
        assert!(ANONYMOUS.is_anonymous());
        assert!(!k.is_anonymous());
    }
}
