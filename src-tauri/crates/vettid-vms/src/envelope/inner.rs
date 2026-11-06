//! The inner plaintext (§5.3): a strict JSON object with `v`, `id`,
//! `type`, `ts`, `seq` (session mode only), `re` and `status` (responses),
//! `error` (iff `status` is `error`), `exp` and `body`.

use chrono::{DateTime, NaiveDate, TimeDelta, Utc};
use zeroize::Zeroizing;

use super::{pad, unpad, EnvelopeError, Mode};
use crate::strict_json::{self, Builder, Object, MAX_SAFE_INTEGER};

/// The inner format version `v`.
pub const INNER_VERSION: u64 = 1;

/// How far in the future `ts` may be (§8.4).
pub const MAX_CLOCK_SKEW_FUTURE: TimeDelta = TimeDelta::minutes(5);
/// How far in the past a durable type's `ts` may be (§8.4).
pub const MAX_DURABLE_AGE: TimeDelta = TimeDelta::days(16);

/// The longest `type` (§5.3).
pub const MAX_TYPE_LEN: usize = 64;
/// The longest `error.code` (§5.3).
pub const MAX_ERROR_CODE_LEN: usize = 64;
/// The longest `error.message`. The spec sets no bound; this is the
/// vault's, generous, so parsers don't carry unbounded strings.
pub const MAX_ERROR_MESSAGE_LEN: usize = 1024;

/// What a response says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// `"status":"ok"`.
    Ok,
    /// `"status":"error"` with its `error`.
    Error { code: String, message: Option<String> },
}

/// A response's members: `re` (the request answered) and `status`, which
/// appear together or not at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub re: String,
    pub status: Status,
}

/// The inner plaintext. `Debug` leaves out the body.
#[derive(Clone, PartialEq, Eq)]
pub struct Inner {
    /// ULID: the message id and the idempotency key.
    pub id: String,
    /// The registry name (`type`).
    pub kind: String,
    /// The sender's clock, millisecond precision, UTC.
    pub ts: DateTime<Utc>,
    /// Session mode only, ≥ 1.
    pub seq: Option<u64>,
    /// For responses.
    pub response: Option<Response>,
    /// Discard after this time if still unprocessed.
    pub exp: Option<DateTime<Utc>>,
    /// The type-specific body: a JSON object, as text. Wiped when dropped
    /// (it can carry secrets).
    pub body: Zeroizing<String>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("id", &self.id)
            .field("type", &self.kind)
            .field("ts", &format_ts(self.ts))
            .field("seq", &self.seq)
            .field("re", &self.response.as_ref().map(|r| &r.re))
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// `ts` and `exp`: `YYYY-MM-DDTHH:MM:SS.mmmZ`, UTC, exactly three
/// fractional digits (truncated, not rounded).
pub fn format_ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Parse a timestamp strictly: exactly the [`format_ts`] form, a real date
/// and time (no leap second), and it formats back to the same text.
pub fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    let b = s.as_bytes();
    if b.len() != 24 {
        return None;
    }
    for (i, c) in b.iter().enumerate() {
        let ok = match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            19 => *c == b'.',
            23 => *c == b'Z',
            _ => c.is_ascii_digit(),
        };
        if !ok {
            return None;
        }
    }
    let n = |r: std::ops::Range<usize>| s[r].parse::<u32>().ok();
    let date = NaiveDate::from_ymd_opt(n(0..4)? as i32, n(5..7)?, n(8..10)?)?;
    let (h, m, sec, ms) = (n(11..13)?, n(14..16)?, n(17..19)?, n(20..23)?);
    if sec > 59 {
        return None;
    }
    let t = date.and_hms_milli_opt(h, m, sec, ms)?.and_utc();
    (format_ts(t) == s).then_some(t)
}

/// 0001-01-01T00:00:00.000Z, Go's zero time.
fn zero_time() -> DateTime<Utc> {
    NaiveDate::from_ymd_opt(1, 1, 1).expect("valid").and_hms_opt(0, 0, 0).expect("valid").and_utc()
}

/// Whether `s` is a registry name: dot-separated segments of
/// `[a-z][a-z0-9-]*`, at most 64 bytes.
pub fn valid_type(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_TYPE_LEN
        && s.split('.').all(|seg| {
            let b = seg.as_bytes();
            !b.is_empty() && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        })
}

/// `[a-z_][a-z0-9_]*`, at most 64 bytes.
fn valid_error_code(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_ERROR_CODE_LEN
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

impl Inner {
    /// The rules shared by [`Inner::marshal`] and [`Inner::parse`].
    fn validate(&self, mode: Mode) -> Result<(), EnvelopeError> {
        let bad = |c: bool| if c { Err(EnvelopeError::Inner) } else { Ok(()) };
        bad(!super::valid_ulid(&self.id) || !valid_type(&self.kind))?;
        // The zero time (0001-01-01T00:00:00.000Z) is no sender's clock; the
        // vault refuses it too.
        bad(self.ts == zero_time())?;
        match mode {
            Mode::Session => bad(!self.seq.is_some_and(|s| (1..=MAX_SAFE_INTEGER).contains(&s)))?,
            Mode::Sealed => bad(self.seq.is_some())?,
        }
        if let Some(r) = &self.response {
            bad(!super::valid_ulid(&r.re))?;
            if let Status::Error { code, message } = &r.status {
                bad(!valid_error_code(code) || message.as_ref().is_some_and(|m| m.len() > MAX_ERROR_MESSAGE_LEN))?;
            }
        }
        Ok(())
    }

    /// Compact JSON with members in the order v, id, type, ts, seq, re,
    /// exp, status, error, body. An empty body is `{}`; a body must be a
    /// strict JSON object (checked, and compacted). `seq` is written in
    /// session mode, and must be absent in sealed mode.
    pub fn marshal(&self, mode: Mode) -> Result<String, EnvelopeError> {
        self.validate(mode)?;
        // The body may be secret (a held inner, #60): its compacted copy is
        // wiped, and the builder is sized once for everything, so it never
        // reallocates (each reallocation would leave a copy of the body).
        let body = Zeroizing::new(if self.body.is_empty() {
            "{}".to_string()
        } else {
            strict_json::compact_object(&self.body, 2).map_err(|_| EnvelopeError::Inner)?
        });
        let cap = self.marshal_capacity(body.len());
        let mut b = Builder::with_capacity(cap).uint("v", INNER_VERSION).string("id", &self.id).string("type", &self.kind).string("ts", &format_ts(self.ts));
        if let Some(seq) = self.seq {
            b = b.uint("seq", seq);
        }
        if let Some(r) = &self.response {
            b = b.string("re", &r.re);
        }
        if let Some(exp) = self.exp {
            b = b.string("exp", &format_ts(exp));
        }
        if let Some(r) = &self.response {
            match &r.status {
                Status::Ok => b = b.string("status", "ok"),
                Status::Error { code, message } => {
                    let mut e = Builder::new().string("code", code);
                    // An empty message is left out, as the vault writes it.
                    if let Some(m) = message.as_deref().filter(|m| !m.is_empty()) {
                        e = e.string("message", m);
                    }
                    b = b.string("status", "error").raw("error", &e.finish());
                }
            }
        }
        let out = b.raw("body", &body).finish();
        debug_assert!(out.len() <= cap, "marshal_capacity too small: a regrowth left a copy");
        Ok(out)
    }

    /// Room for [`Inner::marshal`]'s output with a compacted body of
    /// `body_len` bytes: every string member at its longest escaped form
    /// (6 bytes for each byte, a control character's escape), the fixed
    /// members and names, the error object and the closing brace.
    fn marshal_capacity(&self, body_len: usize) -> usize {
        let response = self.response.as_ref().map_or(0, |r| {
            let error = match &r.status {
                Status::Ok => 0,
                Status::Error { code, message } => code.len() + message.as_deref().map_or(0, str::len),
            };
            r.re.len() + error
        });
        256 + body_len + 6 * (self.id.len() + self.kind.len() + response)
    }

    /// Parse an (unpadded) inner plaintext strictly (§5.3): unknown members
    /// are ignored, known ones must have exactly their type and form, and
    /// the text follows the strict JSON rules at every depth.
    pub fn parse(b: &[u8], mode: Mode) -> Result<Self, EnvelopeError> {
        let inner = |_| EnvelopeError::Inner;
        let o: Object<'_> = strict_json::parse_object(b).map_err(inner)?;
        o.uint("v", INNER_VERSION, INNER_VERSION).map_err(inner)?;
        let id = o.string("id").map_err(inner)?;
        let kind = o.string("type").map_err(inner)?;
        let ts = parse_ts(&o.string("ts").map_err(inner)?).ok_or(EnvelopeError::Inner)?;
        let seq = o.opt_uint("seq", 1, MAX_SAFE_INTEGER).map_err(inner)?;
        let re = o.opt_string("re").map_err(inner)?;
        let exp = match o.opt_string("exp").map_err(inner)? {
            Some(e) => Some(parse_ts(&e).ok_or(EnvelopeError::Inner)?),
            None => None,
        };
        let status = o.opt_string("status").map_err(inner)?;
        let error = if o.has("error") {
            let e = o.object("error", 1).map_err(inner)?;
            Some((e.string("code").map_err(inner)?, e.opt_string("message").map_err(inner)?))
        } else {
            None
        };
        let response = match (re, status.as_deref(), error) {
            (None, None, None) => None,
            (Some(re), Some("ok"), None) => Some(Response { re, status: Status::Ok }),
            (Some(re), Some("error"), Some((code, message))) => Some(Response { re, status: Status::Error { code, message } }),
            _ => return Err(EnvelopeError::Inner),
        };
        o.object("body", 1).map_err(inner)?;
        let body = Zeroizing::new(o.get("body").expect("checked above").to_string());
        let parsed = Inner { id, kind, ts, seq, response, exp, body };
        parsed.validate(mode)?;
        Ok(parsed)
    }

    /// The freshness rules (§8.4, §5.3): `ts` at most 5 minutes in the
    /// future; for durable types at most 16 days in the past; for
    /// ephemeral types `exp` present (§5.3 requires it, and it is their
    /// only staleness bound, §8.5); and `exp` not passed.
    pub fn check_time(&self, now: DateTime<Utc>, durable: bool) -> Result<(), EnvelopeError> {
        if !durable && self.exp.is_none() {
            return Err(EnvelopeError::NoExpiry);
        }
        if self.ts - now > MAX_CLOCK_SKEW_FUTURE {
            return Err(EnvelopeError::ClockFuture);
        }
        if durable && now - self.ts > MAX_DURABLE_AGE {
            return Err(EnvelopeError::ClockPast);
        }
        if self.exp.is_some_and(|exp| now > exp) {
            return Err(EnvelopeError::Expired);
        }
        Ok(())
    }

    /// Marshal and bucket-pad.
    pub fn encode(&self, mode: Mode) -> Result<Vec<u8>, EnvelopeError> {
        // #60 (lead review M1): the plaintext inner is wiped once padded;
        // `pad` copies it once into an exactly sized buffer, which callers
        // wrap in `Zeroizing`.
        let m = Zeroizing::new(self.marshal(mode)?);
        pad(m.as_bytes())
    }

    /// Strictly unpad and parse.
    pub fn decode(padded: &[u8], mode: Mode) -> Result<Self, EnvelopeError> {
        Self::parse(unpad(padded)?, mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_INNER: &str = r#"{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"test.ping","ts":"2026-10-01T12:00:00.000Z","body":{}}"#;
    const ID: &str = "01JB2Z6V9K3M4N5P6Q7R8S9T0V";
    const RE: &str = "01JB2Z6V9K3M4N5P6Q7R8S9T0W";

    fn ping() -> Inner {
        Inner::parse(SPEC_INNER.as_bytes(), Mode::Sealed).unwrap()
    }

    #[test]
    fn the_spec_inner_round_trips() {
        let i = ping();
        assert_eq!((i.id.as_str(), i.kind.as_str(), i.seq, i.body.as_str()), (ID, "test.ping", None, "{}"));
        assert_eq!(format_ts(i.ts), "2026-10-01T12:00:00.000Z");
        assert_eq!(i.marshal(Mode::Sealed).unwrap(), SPEC_INNER);
        let mut s = i.clone();
        s.seq = Some(1);
        assert_eq!(s.marshal(Mode::Session).unwrap(), SPEC_INNER.replacen(r#","body""#, r#","seq":1,"body""#, 1));
        assert_eq!(Inner::decode(&i.encode(Mode::Sealed).unwrap(), Mode::Sealed).unwrap(), i);
    }

    #[test]
    fn responses_and_order() {
        let mut i = ping();
        i.seq = Some(7);
        i.exp = parse_ts("2026-10-01T12:05:00.000Z");
        i.response = Some(Response { re: RE.into(), status: Status::Error { code: "not_found".into(), message: Some("no \"x\"".into()) } });
        i.body = Zeroizing::new(r#" { "a" : [ 1 , 2 ] } "#.into());
        let j = i.marshal(Mode::Session).unwrap();
        assert_eq!(
            j,
            r#"{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"test.ping","ts":"2026-10-01T12:00:00.000Z","seq":7,"re":"01JB2Z6V9K3M4N5P6Q7R8S9T0W","exp":"2026-10-01T12:05:00.000Z","status":"error","error":{"code":"not_found","message":"no \"x\""},"body":{"a":[1,2]}}"#
        );
        let back = Inner::parse(j.as_bytes(), Mode::Session).unwrap();
        assert_eq!(back.response, i.response);
        assert_eq!(back.body.as_str(), r#"{"a":[1,2]}"#);
        let ok = r#"{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"x","ts":"2026-10-01T12:00:00.000Z","re":"01JB2Z6V9K3M4N5P6Q7R8S9T0W","status":"ok","body":{}}"#;
        assert_eq!(Inner::parse(ok.as_bytes(), Mode::Sealed).unwrap().response.unwrap().status, Status::Ok);
        // Unknown members are ignored.
        let extra = SPEC_INNER.replacen(r#""body""#, r#""future":[1],"body""#, 1);
        assert!(Inner::parse(extra.as_bytes(), Mode::Sealed).is_ok());
    }

    /// #60: marshal sizes its buffer once: the output never regrew (each
    /// regrowth would leave an unwiped copy of a possibly secret body), for
    /// a large body and the longest response members.
    #[test]
    fn marshal_never_regrows() {
        let mut i = ping();
        i.seq = Some(7);
        i.exp = parse_ts("2026-10-01T12:05:00.000Z");
        i.response = Some(Response { re: RE.into(), status: Status::Error { code: "not_found".into(), message: Some("m".repeat(500)) } });
        let body = format!(r#"{{"secret":"{}"}}"#, "s".repeat(10_000));
        i.body = Zeroizing::new(body.clone());
        let j = i.marshal(Mode::Session).unwrap();
        assert_eq!(j.capacity(), i.marshal_capacity(body.len()), "allocated once");
        assert!(j.len() <= j.capacity());
        for b in ["", "{}"] {
            let mut p = ping();
            p.body = Zeroizing::new(b.into());
            let j = p.marshal(Mode::Sealed).unwrap();
            assert_eq!(j.capacity(), p.marshal_capacity(2));
        }
    }

    /// Every must-reject form of §5.3 the vault's tests and the 0.83.1
    /// erratum list.
    #[test]
    fn malformed_inners_are_refused() {
        let swap = |from: &str, to: &str| {
            assert!(SPEC_INNER.contains(from), "{from}");
            SPEC_INNER.replacen(from, to, 1)
        };
        let cases = [
            ("v 2", swap(r#""v":1"#, r#""v":2"#)),
            ("v string", swap(r#""v":1"#, r#""v":"1""#)),
            ("v 1.0", swap(r#""v":1"#, r#""v":1.0"#)),
            ("no v", swap(r#""v":1,"#, "")),
            ("lower-case id", swap(ID, &ID.to_lowercase())),
            ("id over 128 bits", swap(ID, "81JB2Z6V9K3M4N5P6Q7R8S9T0V")),
            ("bad type", swap("test.ping", "Test.ping")),
            ("type ends in dot", swap("test.ping", "test.")),
            ("type empty segment", swap("test.ping", "test..ping")),
            ("type digit start", swap("test.ping", "test.1ping")),
            ("ts no millis", swap("12:00:00.000Z", "12:00:00Z")),
            ("ts offset", swap("12:00:00.000Z", "12:00:00.000+00:00")),
            ("ts lower z", swap("12:00:00.000Z", "12:00:00.000z")),
            ("ts micros", swap("12:00:00.000Z", "12:00:00.0000Z")),
            ("ts bad date", swap("2026-10-01", "2026-02-30")),
            ("ts leap second", swap("12:00:00.000Z", "23:59:60.000Z")),
            ("seq in sealed", swap(r#","body""#, r#","seq":1,"body""#)),
            ("re without status", swap(r#","body""#, &format!(r#","re":"{RE}","body""#))),
            ("status without re", swap(r#","body""#, r#","status":"ok","body""#)),
            ("error with ok", swap(r#","body""#, &format!(r#","re":"{RE}","status":"ok","error":{{"code":"x"}},"body""#))),
            ("error status without error", swap(r#","body""#, &format!(r#","re":"{RE}","status":"error","body""#))),
            ("bad status", swap(r#","body""#, &format!(r#","re":"{RE}","status":"OK","body""#))),
            ("bad error code", swap(r#","body""#, &format!(r#","re":"{RE}","status":"error","error":{{"code":"Not"}},"body""#))),
            ("error code digit start", swap(r#","body""#, &format!(r#","re":"{RE}","status":"error","error":{{"code":"1x"}},"body""#))),
            ("body array", swap(r#""body":{}"#, r#""body":[]"#)),
            ("body null", swap(r#""body":{}"#, r#""body":null"#)),
            ("no body", swap(r#","body":{}"#, "")),
            ("duplicate", swap(r#""v":1"#, r#""v":1,"v":1"#)),
            ("duplicate in body", swap(r#""body":{}"#, r#""body":{"a":1,"a":2}"#)),
            ("trailing data", format!("{SPEC_INNER} x")),
            ("bom", format!("\u{feff}{SPEC_INNER}")),
            ("lone high", swap(r#""body":{}"#, r#""body":{"a":"\ud800"}"#)),
            ("high then non-low", swap(r#""body":{}"#, r#""body":{"a":"\ud800\u0041"}"#)),
            ("high at the end", swap(r#""body":{}"#, r#""body":{"a":"x\ud800"}"#)),
            ("lone low", swap(r#""body":{}"#, r#""body":{"a":"\udc00"}"#)),
            ("low after a pair", swap(r#""body":{}"#, r#""body":{"a":"\ud83d\ude00\udc00"}"#)),
            ("re not a ulid", swap(r#","body""#, r#","re":"x","status":"ok","body""#)),
            ("bad exp", swap(r#","body""#, r#","exp":"2026-10-01T12:00:00Z","body""#)),
            ("error null", swap(r#","body""#, &format!(r#","re":"{RE}","status":"error","error":null,"body""#))),
            ("error string", swap(r#","body""#, &format!(r#","re":"{RE}","status":"error","error":"x","body""#))),
            ("message not a string", swap(r#","body""#, &format!(r#","re":"{RE}","status":"error","error":{{"code":"x","message":1}},"body""#))),
            ("message too long", swap(r#","body""#, &format!(r#","re":"{RE}","status":"error","error":{{"code":"x","message":"{}"}},"body""#, "m".repeat(1025)))),
            ("empty status", swap(r#","body""#, &format!(r#","re":"{RE}","status":"","body""#))),
            ("too deep", swap(r#""body":{}"#, &format!(r#""body":{}{}"#, "{\"a\":".repeat(31) + "{", "}".repeat(32)))),
        ];
        for (why, text) in cases {
            assert_eq!(Inner::parse(text.as_bytes(), Mode::Sealed).unwrap_err(), EnvelopeError::Inner, "{why}");
        }
        // A valid pair is accepted; the deepest body allowed is level 31
        // below the inner (32 in all).
        assert!(Inner::parse(swap(r#""body":{}"#, r#""body":{"a":"\ud83d\ude00"}"#).as_bytes(), Mode::Sealed).is_ok());
        let deep = swap(r#""body":{}"#, &format!(r#""body":{}{}"#, "{\"a\":".repeat(30) + "{", "}".repeat(31)));
        assert!(Inner::parse(deep.as_bytes(), Mode::Sealed).is_ok());
        // Session mode needs seq ≥ 1.
        assert_eq!(Inner::parse(SPEC_INNER.as_bytes(), Mode::Session).unwrap_err(), EnvelopeError::Inner);
        for seq in ["0", "9007199254740992", r#""1""#, "1.0", "-1"] {
            let t = swap(r#","body""#, &format!(r#","seq":{seq},"body""#));
            assert_eq!(Inner::parse(t.as_bytes(), Mode::Session).unwrap_err(), EnvelopeError::Inner, "seq {seq}");
        }
        let max = swap(r#","body""#, r#","seq":9007199254740991,"body""#);
        assert_eq!(Inner::parse(max.as_bytes(), Mode::Session).unwrap().seq, Some(9_007_199_254_740_991));
        // The zero time is refused as ts, as the vault does.
        let zero_ts = swap("2026-10-01T12:00:00.000Z", "0001-01-01T00:00:00.000Z");
        assert_eq!(Inner::parse(zero_ts.as_bytes(), Mode::Sealed).unwrap_err(), EnvelopeError::Inner);
        // A zero exp is a time long past: expired, never "no expiry".
        let zero_exp = swap(r#","body""#, r#","exp":"0001-01-01T00:00:00.000Z","body""#);
        let z = Inner::parse(zero_exp.as_bytes(), Mode::Sealed).unwrap();
        assert_eq!(z.check_time(z.ts, true), Err(EnvelopeError::Expired));
    }

    #[test]
    fn marshal_refuses_what_parse_refuses() {
        let mut i = ping();
        assert_eq!(i.marshal(Mode::Session).unwrap_err(), EnvelopeError::Inner, "no seq");
        i.seq = Some(1);
        assert_eq!(i.marshal(Mode::Sealed).unwrap_err(), EnvelopeError::Inner, "seq in sealed");
        i.seq = None;
        i.body = Zeroizing::new(r#"{"a":1,"a":2}"#.into());
        assert_eq!(i.marshal(Mode::Sealed).unwrap_err(), EnvelopeError::Inner);
        i.body = Zeroizing::new("[]".into());
        assert_eq!(i.marshal(Mode::Sealed).unwrap_err(), EnvelopeError::Inner);
        i.body = Zeroizing::new(String::new());
        assert!(i.marshal(Mode::Sealed).unwrap().ends_with(r#""body":{}}"#));
        // Only an empty string means {}: Unicode or JSON whitespace isn't a body.
        for ws in [char::from_u32(0x3000).unwrap().to_string(), char::from_u32(0xa0).unwrap().to_string(), " ".to_string()] {
            i.body = Zeroizing::new(ws.clone());
            assert_eq!(i.marshal(Mode::Sealed).unwrap_err(), EnvelopeError::Inner, "{ws:?}");
        }
        let mut empty = ping();
        empty.response = Some(Response { re: RE.into(), status: Status::Error { code: "x".into(), message: Some(String::new()) } });
        assert!(empty.marshal(Mode::Sealed).unwrap().contains(r#""error":{"code":"x"}"#), "an empty message is left out");
        i.kind = "Bad".into();
        assert_eq!(i.marshal(Mode::Sealed).unwrap_err(), EnvelopeError::Inner);
        let mut r = ping();
        r.response = Some(Response { re: RE.into(), status: Status::Error { code: "x".into(), message: Some("m".repeat(1025)) } });
        assert_eq!(r.marshal(Mode::Sealed).unwrap_err(), EnvelopeError::Inner);
    }

    #[test]
    fn timestamps() {
        let t = parse_ts("2026-10-01T12:00:00.123Z").unwrap();
        assert_eq!(t.timestamp_millis() % 1000, 123);
        assert_eq!(format_ts(t + TimeDelta::microseconds(999)), "2026-10-01T12:00:00.123Z", "truncated");
        for bad in ["2026-10-01 12:00:00.000Z", "2026-13-01T12:00:00.000Z", "2026-10-01T24:00:00.000Z", "+026-10-01T12:00:00.000Z", "2026-10-01T12:00:00.00AZ"] {
            assert!(parse_ts(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn freshness() {
        let mut i = ping();
        let now = i.ts;
        assert_eq!(i.check_time(now, true), Ok(()));
        assert_eq!(i.check_time(now - TimeDelta::minutes(5), true), Ok(()));
        assert_eq!(i.check_time(now - TimeDelta::minutes(5) - TimeDelta::milliseconds(1), true), Err(EnvelopeError::ClockFuture));
        assert_eq!(i.check_time(now + TimeDelta::days(16), true), Ok(()));
        assert_eq!(i.check_time(now + TimeDelta::days(16) + TimeDelta::milliseconds(1), true), Err(EnvelopeError::ClockPast));
        assert_eq!(i.check_time(now, false), Err(EnvelopeError::NoExpiry), "ephemeral types need exp");
        i.exp = Some(now + TimeDelta::days(18));
        assert_eq!(i.check_time(now + TimeDelta::days(17), false), Ok(()), "ephemeral types have no age limit");
        i.exp = Some(now + TimeDelta::seconds(10));
        assert_eq!(i.check_time(now + TimeDelta::seconds(10), false), Ok(()));
        assert_eq!(i.check_time(now + TimeDelta::seconds(11), false), Err(EnvelopeError::Expired));
    }

    #[test]
    fn debug_leaves_out_the_body() {
        let mut i = ping();
        i.body = Zeroizing::new(r#"{"secret":"hunter2"}"#.into());
        assert!(!format!("{i:?}").contains("hunter2"));
    }
}
