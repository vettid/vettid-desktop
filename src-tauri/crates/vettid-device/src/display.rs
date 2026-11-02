//! What the desktop shows during pairing, and how it shows text the other
//! side wrote.
//!
//! The bundle's `hint.name` is the inviter's self-asserted display name
//! (§6.4): anyone who holds the code can read it, and anyone who makes a
//! code can write it. It is shown as plain text only, with control,
//! bidirectional-override and zero-width characters removed (so it can't
//! reorder or hide the text around it), and cut to [`MAX_SHOWN_NAME`]
//! characters.
//!
//! A paired desktop proves nothing by itself: a malicious code can point
//! it at an attacker's vault, and only the member comparing the SAS on
//! their phone catches that (§6.7). So the desktop always asks the member
//! to confirm on their phone, and never says "paired" before the vault's
//! `device.paired` has arrived and checked out.

/// The longest name shown, in characters.
pub const MAX_SHOWN_NAME: usize = 64;

/// Shown with the SAS while waiting for the owner's approval.
pub const CONFIRM_ON_PHONE: &str = "Check that your phone shows this same code, then confirm on your phone.";
/// Shown when the owner rejected the pairing on their phone (§6.7).
pub const REJECTED_ON_PHONE: &str = "Rejected on your phone";
/// Shown when the pairing window ended without an answer: the desktop is
/// not paired.
pub const NOT_CONFIRMED: &str = "Not paired: the pairing was not confirmed in time. Start again from your phone.";

/// Whether `c` is removed from shown text: control characters, the
/// bidirectional marks, embeddings, overrides and isolates, zero-width
/// characters, and the byte order mark. Whitespace (tabs and line breaks
/// included) is kept, then collapsed to single spaces.
fn hidden(c: char) -> bool {
    let u = c as u32;
    (c.is_control() && !c.is_whitespace())
        || matches!(u, 0x061C | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x2069 | 0xFEFF)
}

/// `name` as plain text to show: hidden characters removed, whitespace
/// runs collapsed, cut to [`MAX_SHOWN_NAME`] characters. `None` if
/// nothing is left.
pub fn shown_name(name: &str) -> Option<String> {
    let visible: String = name.chars().filter(|c| !hidden(*c)).collect();
    let words: Vec<&str> = visible.split_whitespace().collect();
    let joined: String = words.join(" ").chars().take(MAX_SHOWN_NAME).collect();
    let out = joined.trim_end().to_string();
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(u: u32) -> char {
        char::from_u32(u).unwrap()
    }

    #[test]
    fn names_are_plain_text() {
        assert_eq!(shown_name("Test Vault").as_deref(), Some("Test Vault"));
        // A right-to-left override would show "Test" backwards, and an
        // isolate or zero-width space could hide or reorder text.
        let tricky = format!("{}Test{} Vault{}{}", ch(0x202E), ch(0x2066), ch(0x200B), ch(0x1));
        assert_eq!(shown_name(&tricky).as_deref(), Some("Test Vault"));
        assert_eq!(shown_name(&format!("  a{}{}b  ", ch(0xA), ch(0x9))).as_deref(), Some("a b"));
        assert_eq!(shown_name(&format!("{}{}", ch(0x200E), ch(0xFEFF))), None);
        assert_eq!(shown_name(&"n".repeat(200)).unwrap().chars().count(), MAX_SHOWN_NAME);
        // Other scripts are kept.
        let greek = format!("{}{}", ch(0x3A9), ch(0x3B1));
        assert_eq!(shown_name(&greek).as_deref(), Some(greek.as_str()));
    }

    #[test]
    fn the_wording_never_claims_a_pairing() {
        for text in [CONFIRM_ON_PHONE, REJECTED_ON_PHONE, NOT_CONFIRMED] {
            assert!(!text.to_lowercase().starts_with("paired"), "{text}");
        }
        assert!(CONFIRM_ON_PHONE.contains("phone"));
    }
}
