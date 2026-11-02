//! Strict JSON for the messaging wire format (VAULT-MESSAGING §5.3), the
//! rules the vault's `strictjson` and the apps' parsers apply:
//!
//! - valid UTF-8, with no byte order mark;
//! - exactly one object, with only JSON whitespace around it;
//! - no duplicate member names at any depth (names compared after
//!   unescaping, case-sensitive);
//! - nesting at most [`MAX_DEPTH`] (the top object is level 1);
//! - no `\u` escape of an unpaired surrogate, in a name or a string at
//!   any depth (0.83.1; I-JSON's rule, its noncharacter rule not adopted);
//! - RFC 8259's grammar otherwise: no control characters in strings, no
//!   leading zeros, no trailing commas, lower-case literals.
//!
//! [`parse_object`] checks the whole text once, then gives the top
//! object's members as raw text; the accessors read one member with its
//! exact type and form. Errors never carry input text.

use std::collections::HashSet;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// The deepest nesting of objects and arrays, the top object included.
pub const MAX_DEPTH: usize = 32;

/// The largest integer every implementation in use represents exactly:
/// 2^53 − 1.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Why a text or a member was refused. Carries no input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    /// Not valid UTF-8.
    Utf8,
    /// Begins with a byte order mark.
    Bom,
    /// Not RFC 8259 JSON, or data after the object.
    Syntax,
    /// The text, or a member that must be one, isn't an object.
    NotObject,
    /// A member name appears twice in one object.
    Duplicate,
    /// Nesting deeper than [`MAX_DEPTH`].
    Depth,
    /// A `\u` escape of an unpaired surrogate.
    Surrogate,
    /// A member has the wrong type or form.
    Type,
    /// A required member is missing.
    Missing,
    /// A member's value is out of range.
    Value,
    /// Not canonical standard base64 with padding.
    Base64,
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Utf8 => "strict json: invalid UTF-8",
            Self::Bom => "strict json: byte order mark",
            Self::Syntax => "strict json: malformed",
            Self::NotObject => "strict json: not an object",
            Self::Duplicate => "strict json: duplicate member name",
            Self::Depth => "strict json: nesting too deep",
            Self::Surrogate => "strict json: unpaired surrogate escape",
            Self::Type => "strict json: member has the wrong type",
            Self::Missing => "strict json: required member missing",
            Self::Value => "strict json: member value out of range",
            Self::Base64 => "strict json: invalid base64",
        })
    }
}

impl std::error::Error for JsonError {}

/// A checked object: its members, in order, as raw JSON text.
#[derive(Clone, PartialEq, Eq)]
pub struct Object<'a> {
    members: Vec<(String, &'a str)>,
}

impl std::fmt::Debug for Object<'_> {
    /// Member names only: values may be secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.members.iter().map(|(n, _)| n)).finish()
    }
}

/// Parse `b` as exactly one strict JSON object (the rules above).
pub fn parse_object(b: &[u8]) -> Result<Object<'_>, JsonError> {
    if b.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(JsonError::Bom);
    }
    let text = std::str::from_utf8(b).map_err(|_| JsonError::Utf8)?;
    parse_text(text, 1)
}

/// Parse `text` as an object at nesting `level` (1 for a whole message):
/// its own depth plus `level − 1` must be at most [`MAX_DEPTH`].
fn parse_text(text: &str, level: usize) -> Result<Object<'_>, JsonError> {
    let mut p = Parser { s: text.as_bytes(), text, i: 0 };
    p.ws();
    if p.peek() != Some(b'{') {
        return Err(if p.i == p.s.len() { JsonError::Syntax } else { JsonError::NotObject });
    }
    let members = p.object(level)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(JsonError::Syntax);
    }
    Ok(Object { members })
}

/// Check `raw` (a value already inside a checked text) as an object at
/// nesting `level`.
fn nested_object(raw: &str, level: usize) -> Result<Object<'_>, JsonError> {
    if !raw.starts_with('{') {
        return Err(JsonError::Type);
    }
    parse_text(raw, level)
}

impl<'a> Object<'a> {
    /// The raw text of member `name`, if present (`null` included).
    pub fn get(&self, name: &str) -> Option<&'a str> {
        self.members.iter().find(|(n, _)| n == name).map(|(_, v)| *v)
    }

    /// Whether member `name` is present (`null` included).
    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Member names, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.members.iter().map(|(n, _)| n.as_str())
    }

    fn required(&self, name: &str) -> Result<&'a str, JsonError> {
        self.get(name).ok_or(JsonError::Missing)
    }

    /// A required string member.
    pub fn string(&self, name: &str) -> Result<String, JsonError> {
        as_string(self.required(name)?)
    }

    /// An optional string member.
    pub fn opt_string(&self, name: &str) -> Result<Option<String>, JsonError> {
        self.get(name).map(as_string).transpose()
    }

    /// A required integer member in `[min, max]` (and at most 2^53 − 1),
    /// written as a plain JSON integer: no sign, fraction or exponent.
    pub fn uint(&self, name: &str, min: u64, max: u64) -> Result<u64, JsonError> {
        as_uint(self.required(name)?, min, max)
    }

    /// An optional integer member, as [`Object::uint`].
    pub fn opt_uint(&self, name: &str, min: u64, max: u64) -> Result<Option<u64>, JsonError> {
        self.get(name).map(|raw| as_uint(raw, min, max)).transpose()
    }

    /// A required boolean member.
    pub fn bool(&self, name: &str) -> Result<bool, JsonError> {
        match self.required(name)? {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(JsonError::Type),
        }
    }

    /// A required object member, at `level` + 1 where this object is at
    /// `level` (1 for a whole message).
    pub fn object(&self, name: &str, level: usize) -> Result<Object<'a>, JsonError> {
        nested_object(self.required(name)?, level + 1)
    }

    /// A required array member's elements, as raw text.
    pub fn array(&self, name: &str) -> Result<Vec<&'a str>, JsonError> {
        as_array(self.required(name)?)
    }

    /// A required member of canonical standard base64 with padding that
    /// decodes to exactly `n` bytes (`None`: any length).
    pub fn base64(&self, name: &str, n: Option<usize>) -> Result<Vec<u8>, JsonError> {
        decode_std(&self.string(name)?, n)
    }
}

/// Read a raw value as a string.
pub fn as_string(raw: &str) -> Result<String, JsonError> {
    if !raw.starts_with('"') {
        return Err(JsonError::Type);
    }
    let mut p = Parser { s: raw.as_bytes(), text: raw, i: 0 };
    let s = p.string().map_err(|_| JsonError::Type)?;
    if p.i != raw.len() {
        return Err(JsonError::Type);
    }
    Ok(s)
}

/// Read a raw value as an integer in `[min, max]`, written as a plain JSON
/// integer.
pub fn as_uint(raw: &str, min: u64, max: u64) -> Result<u64, JsonError> {
    let b = raw.as_bytes();
    if b.is_empty() || b.len() > 16 || !b.iter().all(u8::is_ascii_digit) || (b.len() > 1 && b[0] == b'0') {
        return Err(JsonError::Type);
    }
    let v: u64 = raw.parse().map_err(|_| JsonError::Type)?;
    if v < min || v > max || v > MAX_SAFE_INTEGER {
        return Err(JsonError::Value);
    }
    Ok(v)
}

/// Read a raw value as an array's elements, as raw text.
pub fn as_array(raw: &str) -> Result<Vec<&str>, JsonError> {
    if !raw.starts_with('[') {
        return Err(JsonError::Type);
    }
    let mut p = Parser { s: raw.as_bytes(), text: raw, i: 0 };
    // Depth was checked with the whole text; the elements are values in it.
    let elements = p.array_elements(1).map_err(|_| JsonError::Type)?;
    if p.i != raw.len() {
        return Err(JsonError::Type);
    }
    Ok(elements)
}

/// Decode canonical standard base64 with padding, of exactly `n` bytes
/// (`None`: any length). CR, LF and any non-canonical spelling (non-zero
/// trailing bits, missing padding) are refused.
pub fn decode_std(s: &str, n: Option<usize>) -> Result<Vec<u8>, JsonError> {
    let b = STANDARD.decode(s).map_err(|_| JsonError::Base64)?;
    if n.is_some_and(|n| b.len() != n) || STANDARD.encode(&b) != s {
        return Err(JsonError::Base64);
    }
    Ok(b)
}

/// Check `raw` as a strict object at nesting `level` and return it
/// compact: whitespace outside strings removed, nothing else changed (as
/// Go's `json.Compact`).
pub fn compact_object(raw: &str, level: usize) -> Result<String, JsonError> {
    if raw.as_bytes().starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(JsonError::Bom);
    }
    let trimmed = raw.trim_matches(|c| matches!(c, ' ' | '\t' | '\n' | '\r'));
    nested_object(trimmed, level).map_err(|e| if e == JsonError::Type { JsonError::NotObject } else { e })?;
    let mut out = String::with_capacity(trimmed.len());
    let mut in_string = false;
    let mut escaped = false;
    for c in trimmed.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if !matches!(c, ' ' | '\t' | '\n' | '\r') {
            out.push(c);
        }
    }
    Ok(out)
}

/// Encode `s` as a JSON string: `"` and `\` escaped, `\n`, `\r`, `\t`,
/// `\b` and `\f` by their short escapes, other control characters and
/// U+2028/U+2029 as `\u00xx`/`\u2028`/`\u2029` (as Go writes them), and
/// nothing else escaped (no HTML escaping).
pub fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Writes a compact JSON object with members in call order.
#[derive(Debug)]
pub struct Builder {
    out: String,
    first: bool,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    /// Start an object.
    pub fn new() -> Self {
        Builder { out: String::from("{"), first: true }
    }

    fn name(&mut self, n: &str) {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        write_string(&mut self.out, n);
        self.out.push(':');
    }

    /// A string member.
    pub fn string(mut self, n: &str, v: &str) -> Self {
        self.name(n);
        write_string(&mut self.out, v);
        self
    }

    /// An integer member.
    pub fn uint(mut self, n: &str, v: u64) -> Self {
        self.name(n);
        self.out.push_str(&v.to_string());
        self
    }

    /// A boolean member.
    pub fn bool(mut self, n: &str, v: bool) -> Self {
        self.name(n);
        self.out.push_str(if v { "true" } else { "false" });
        self
    }

    /// A standard-base64 member.
    pub fn base64(self, n: &str, v: &[u8]) -> Self {
        self.string(n, &STANDARD.encode(v))
    }

    /// A member whose value is already-encoded JSON; the caller vouches for
    /// it.
    pub fn raw(mut self, n: &str, v: &str) -> Self {
        self.name(n);
        self.out.push_str(v);
        self
    }

    /// Close the object.
    pub fn finish(mut self) -> String {
        self.out.push('}');
        self.out
    }
}

/// A recursive-descent checker over UTF-8 text (recursion is bounded by
/// [`MAX_DEPTH`]).
struct Parser<'a> {
    s: &'a [u8],
    text: &'a str,
    i: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn expect(&mut self, c: u8) -> Result<(), JsonError> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(JsonError::Syntax)
        }
    }

    /// One value; `depth` is the nesting of its container (0 at the top).
    fn value(&mut self, depth: usize) -> Result<(), JsonError> {
        match self.peek() {
            Some(b'{') => self.object(depth + 1).map(drop),
            Some(b'[') => self.array_elements(depth + 1).map(drop),
            Some(b'"') => self.string().map(drop),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(JsonError::Syntax),
        }
    }

    fn literal(&mut self, lit: &[u8]) -> Result<(), JsonError> {
        if self.s[self.i..].starts_with(lit) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(JsonError::Syntax)
        }
    }

    /// An object at nesting `depth` (1-based): its members, raw.
    fn object(&mut self, depth: usize) -> Result<Vec<(String, &'a str)>, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::Depth);
        }
        self.expect(b'{')?;
        let mut members = Vec::new();
        let mut seen = HashSet::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(members);
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(JsonError::Syntax);
            }
            let name = self.string()?;
            if !seen.insert(name.clone()) {
                return Err(JsonError::Duplicate);
            }
            self.ws();
            self.expect(b':')?;
            self.ws();
            let start = self.i;
            self.value(depth)?;
            members.push((name, &self.text[start..self.i]));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(members);
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    /// An array at nesting `depth` (1-based): its elements, raw.
    fn array_elements(&mut self, depth: usize) -> Result<Vec<&'a str>, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::Depth);
        }
        self.expect(b'[')?;
        let mut elements = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(elements);
        }
        loop {
            self.ws();
            let start = self.i;
            self.value(depth)?;
            elements.push(&self.text[start..self.i]);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(elements);
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    /// A number in RFC 8259's grammar.
    fn number(&mut self) -> Result<(), JsonError> {
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(JsonError::Syntax),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::Syntax);
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::Syntax);
            }
            self.digits();
        }
        Ok(())
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let h = self.s.get(self.i..self.i + 4).ok_or(JsonError::Syntax)?;
        let h = std::str::from_utf8(h).map_err(|_| JsonError::Syntax)?;
        if !h.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(JsonError::Syntax);
        }
        self.i += 4;
        u32::from_str_radix(h, 16).map_err(|_| JsonError::Syntax)
    }

    /// A string, unescaped. A surrogate escape must be a high one followed
    /// at once by a `\u` escape of a low one.
    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.i;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            // The run is whole UTF-8 characters: it ends before an ASCII byte.
            out.push_str(&self.text[start..self.i]);
            match self.peek() {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let e = self.peek().ok_or(JsonError::Syntax)?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let u = self.hex4()?;
                            let c = match u {
                                0xD800..=0xDBFF => {
                                    if !self.s[self.i..].starts_with(b"\\u") {
                                        return Err(JsonError::Surrogate);
                                    }
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&lo) {
                                        return Err(JsonError::Surrogate);
                                    }
                                    0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00)
                                }
                                0xDC00..=0xDFFF => return Err(JsonError::Surrogate),
                                u => u,
                            };
                            out.push(char::from_u32(c).ok_or(JsonError::Syntax)?);
                        }
                        _ => return Err(JsonError::Syntax),
                    }
                }
                // A control character, or the end of the text.
                _ => return Err(JsonError::Syntax),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(s: &str) -> JsonError {
        parse_object(s.as_bytes()).unwrap_err()
    }

    #[test]
    fn accepts_strict_objects() {
        let o = parse_object(br#" {"a":1,"b":"x\u00e9\ud83d\ude00\n","c":[true,false,null,-1.5e+3,{}],"d":{"a":0}} "#).unwrap();
        assert_eq!(o.names().collect::<Vec<_>>(), ["a", "b", "c", "d"]);
        assert_eq!(o.uint("a", 0, 10), Ok(1));
        assert_eq!(o.string("b").unwrap(), "x\u{e9}\u{1F600}\n");
        assert_eq!(o.array("c").unwrap(), ["true", "false", "null", "-1.5e+3", "{}"]);
        assert_eq!(o.object("d", 1).unwrap().uint("a", 0, 0), Ok(0));
        assert_eq!(o.get("c"), Some(r#"[true,false,null,-1.5e+3,{}]"#));
        // Noncharacters are accepted (I-JSON's rule on them isn't adopted).
        assert!(parse_object(br#"{"a":"\ufdd0\uffff\ud83f\udffe"}"#).is_ok());
        // Duplicate-looking names that differ in case are distinct.
        assert!(parse_object(br#"{"a":1,"A":2}"#).is_ok());
    }

    #[test]
    fn refuses_what_the_spec_refuses() {
        for (why, text, want) in [
            ("bom", "\u{feff}{}", JsonError::Bom),
            ("duplicate", r#"{"a":1,"a":2}"#, JsonError::Duplicate),
            ("duplicate after unescaping", r#"{"a":1,"\u0061":2}"#, JsonError::Duplicate),
            ("nested duplicate", r#"{"b":[{"x":1,"x":1}]}"#, JsonError::Duplicate),
            ("trailing data", r#"{}{}"#, JsonError::Syntax),
            ("trailing comma", r#"{"a":1,}"#, JsonError::Syntax),
            ("array top", "[]", JsonError::NotObject),
            ("string top", r#""x""#, JsonError::NotObject),
            ("empty", "", JsonError::Syntax),
            ("lone high", r#"{"a":"\ud800"}"#, JsonError::Surrogate),
            ("high then non-low", r#"{"a":"\ud800\u0041"}"#, JsonError::Surrogate),
            ("high at the end", r#"{"a":"x\ud800"}"#, JsonError::Surrogate),
            ("high then char", r#"{"a":"\ud800x"}"#, JsonError::Surrogate),
            ("lone low", r#"{"a":"\udc00"}"#, JsonError::Surrogate),
            ("low after a pair", r#"{"a":"\ud83d\ude00\ude00"}"#, JsonError::Surrogate),
            ("surrogate in a name", r#"{"\ud800":1}"#, JsonError::Surrogate),
            ("surrogate deep", r#"{"a":[[{"b":"\udfff"}]]}"#, JsonError::Surrogate),
            ("control char", "{\"a\":\"\u{1}\"}", JsonError::Syntax),
            ("bad escape", r#"{"a":"\x"}"#, JsonError::Syntax),
            ("short unicode escape", r#"{"a":"\u12"}"#, JsonError::Syntax),
            ("leading zero", r#"{"a":01}"#, JsonError::Syntax),
            ("bare minus", r#"{"a":-}"#, JsonError::Syntax),
            ("bare fraction", r#"{"a":1.}"#, JsonError::Syntax),
            ("bare exponent", r#"{"a":1e}"#, JsonError::Syntax),
            ("plus sign", r#"{"a":+1}"#, JsonError::Syntax),
            ("upper-case literal", r#"{"a":True}"#, JsonError::Syntax),
            ("single quotes", r#"{'a':1}"#, JsonError::Syntax),
            ("unterminated", r#"{"a":"x"#, JsonError::Syntax),
            ("unclosed", r#"{"a":1"#, JsonError::Syntax),
            ("no colon", r#"{"a" 1}"#, JsonError::Syntax),
            ("non-string name", r#"{1:2}"#, JsonError::Syntax),
            ("nbsp as whitespace", "{\u{a0}}", JsonError::Syntax),
        ] {
            assert_eq!(err(text), want, "{why}");
        }
        assert_eq!(parse_object(b"{\"a\":\"\xff\"}").unwrap_err(), JsonError::Utf8);
        // An encoded surrogate (ED A0 80) is invalid UTF-8.
        assert_eq!(parse_object(b"{\"a\":\"\xed\xa0\x80\"}").unwrap_err(), JsonError::Utf8);
    }

    #[test]
    fn depth_is_bounded_at_32() {
        let nest = |n: usize| format!("{}{}", "{\"a\":".repeat(n - 1) + "{", "}".repeat(n));
        assert!(parse_object(nest(32).as_bytes()).is_ok());
        assert_eq!(parse_object(nest(33).as_bytes()).unwrap_err(), JsonError::Depth);
        let arrays = |n: usize| format!("{{\"a\":{}{}}}", "[".repeat(n - 1), "]".repeat(n - 1));
        assert!(parse_object(arrays(32).as_bytes()).is_ok());
        assert_eq!(parse_object(arrays(33).as_bytes()).unwrap_err(), JsonError::Depth);
        // A nested object read at its level keeps the whole message's limit.
        let n32 = nest(32);
        let o = parse_object(n32.as_bytes()).unwrap();
        assert!(o.object("a", 1).is_ok());
        assert_eq!(nested_object(&nest(32), 2).unwrap_err(), JsonError::Depth);
        // Deep input fails without exhausting the stack.
        let deep = "[".repeat(100_000);
        assert_eq!(parse_object(format!("{{\"a\":{deep}").as_bytes()).unwrap_err(), JsonError::Depth);
    }

    #[test]
    fn integers_are_plain_and_safe() {
        let o = parse_object(br#"{"z":0,"a":1,"big":9007199254740991,"over":9007199254740992,"neg":-1,"frac":1.0,"exp":1e2,"str":"1","lz":0,"nul":null}"#).unwrap();
        assert_eq!(o.uint("z", 0, u64::MAX), Ok(0));
        assert_eq!(o.uint("big", 0, u64::MAX), Ok(MAX_SAFE_INTEGER));
        assert_eq!(o.uint("over", 0, u64::MAX), Err(JsonError::Value));
        assert_eq!(o.uint("a", 2, 3), Err(JsonError::Value));
        for t in ["neg", "frac", "exp", "str", "nul"] {
            assert_eq!(o.uint(t, 0, u64::MAX), Err(JsonError::Type), "{t}");
        }
        assert_eq!(o.uint("missing", 0, 1), Err(JsonError::Missing));
        assert_eq!(o.opt_uint("missing", 0, 1), Ok(None));
        assert_eq!(as_uint("12345678901234567", 0, u64::MAX), Err(JsonError::Type), "over 16 digits");
    }

    #[test]
    fn typed_accessors_check_the_type() {
        let o = parse_object(br#"{"s":"x","n":1,"b":true,"o":{},"a":[],"nul":null}"#).unwrap();
        assert_eq!(o.string("n"), Err(JsonError::Type));
        assert_eq!(o.string("nul"), Err(JsonError::Type));
        assert_eq!(o.opt_string("nul"), Err(JsonError::Type), "null is present, and not a string");
        assert!(o.has("nul"));
        assert_eq!(o.bool("s"), Err(JsonError::Type));
        assert!(o.bool("b").unwrap());
        assert_eq!(o.object("a", 1).unwrap_err(), JsonError::Type);
        assert_eq!(o.array("o").unwrap_err(), JsonError::Type);
        assert!(o.array("a").unwrap().is_empty());
    }

    #[test]
    fn base64_is_canonical() {
        assert_eq!(decode_std("AQID", Some(3)).unwrap(), [1, 2, 3]);
        assert_eq!(decode_std("AQI=", None).unwrap(), [1, 2]);
        for bad in ["AQI", "AQJ=", "AQ==\n", "AQ\r\nID", " AQID", "AQID=", "AQ-_", "AQ=="] {
            let want = if bad == "AQ==" { Some(2) } else { None };
            assert_eq!(decode_std(bad, want), Err(JsonError::Base64), "{bad:?}");
        }
        assert_eq!(decode_std("AQID", Some(4)), Err(JsonError::Base64));
    }

    #[test]
    fn compact_keeps_strings_and_drops_whitespace() {
        let raw = " { \"a b\" : [ 1 , \"x \\\" y\" ] ,\n\"c\":{ } } ";
        assert_eq!(compact_object(raw, 2).unwrap(), r#"{"a b":[1,"x \" y"],"c":{}}"#);
        assert_eq!(compact_object("[]", 2), Err(JsonError::NotObject));
        assert_eq!(compact_object(r#"{"a":1,"a":1}"#, 2), Err(JsonError::Duplicate));
        assert_eq!(compact_object("\u{feff}{}", 2), Err(JsonError::Bom));
    }

    #[test]
    fn builder_writes_what_the_parser_reads() {
        let tricky = "q\"b\\s/\n\r\t\u{8}\u{c}\u{1}\u{1f}\u{2028}\u{2029}<>&\u{e9}\u{1F600}";
        let j = Builder::new().uint("v", 1).string("s", tricky).bool("t", true).base64("b", &[0xff, 0]).raw("o", "{}").finish();
        assert_eq!(
            j,
            r#"{"v":1,"s":"q\"b\\s/\n\r\t\b\f\u0001\u001f\u2028\u2029<>&é😀","t":true,"b":"/wA=","o":{}}"#
        );
        let o = parse_object(j.as_bytes()).unwrap();
        assert_eq!(o.string("s").unwrap(), tricky);
        assert_eq!(o.base64("b", Some(2)).unwrap(), [0xff, 0]);
    }

    #[test]
    fn errors_and_debug_carry_no_input() {
        let o = parse_object(br#"{"secret":"hunter2"}"#).unwrap();
        assert!(!format!("{o:?}").contains("hunter2"));
        assert!(!err(r#"{"hunter2":1,"hunter2":2}"#).to_string().contains("hunter2"));
    }

    /// Random mutations of valid texts never panic, and whatever is
    /// accepted is also valid JSON to serde_json, with the same names.
    #[test]
    fn mutations_never_panic() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed);
        let seeds: [&[u8]; 4] = [
            br#"{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"test.ping","ts":"2026-10-01T12:00:00.000Z","body":{}}"#,
            br#"{"a":[1,-2.5e3,true,null,{"b":"\u00e9\ud83d\ude00"}],"c":"\\\"","d":{}}"#,
            br#"{"e":[[[[{}]]]],"f":"x","g":0}"#,
            b"{\"h\":\"\xc3\xa9\xf0\x9f\x98\x80\"}",
        ];
        let alphabet = b"{}[]:,\"\\u0123456789abcdefABCDEF.eE+-tfn \t\n\r\xc3\xa9\xed\xa0\x80\xef\xbb\xbf";
        for _ in 0..20_000 {
            let mut b = seeds[rng.gen_range(0..seeds.len())].to_vec();
            for _ in 0..rng.gen_range(1..4) {
                let at = rng.gen_range(0..=b.len());
                match rng.gen_range(0..3) {
                    0 if at < b.len() => {
                        b.remove(at);
                    }
                    1 if at < b.len() => b[at] = alphabet[rng.gen_range(0..alphabet.len())],
                    _ => b.insert(at, alphabet[rng.gen_range(0..alphabet.len())]),
                }
            }
            if let Ok(o) = parse_object(&b) {
                let v: serde_json::Value = serde_json::from_slice(&b).expect("accepted text is JSON");
                let m = v.as_object().expect("an object");
                assert_eq!(m.len(), o.names().count());
                assert!(o.names().all(|n| m.contains_key(n)));
            }
        }
    }
}
