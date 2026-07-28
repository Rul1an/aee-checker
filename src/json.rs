//! Strict JSON parsing and RFC 8785 (JCS) canonical serialization.
//!
//! The parser is deliberately strict: it preserves object member order,
//! rejects duplicate member names (RFC 7493 I-JSON), rejects lone
//! surrogates in string escapes, and keeps the raw source text of every
//! number so canonical-form and safe-integer checks can be made against
//! the exact bytes the producer wrote.

use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Raw source token plus parsed double value.
    Number { raw: String, value: f64 },
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Object(members) => Some(members),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Integer view of a number: Some(i) only when the raw token is an
    /// integer literal (no fraction, no exponent) inside the I-JSON safe
    /// range (|i| < 2^53).
    pub fn as_safe_integer(&self) -> Option<i64> {
        match self {
            Value::Number { raw, .. } => parse_safe_integer(raw),
            _ => None,
        }
    }
}

pub fn parse_safe_integer(raw: &str) -> Option<i64> {
    if raw.contains(['.', 'e', 'E']) {
        return None;
    }
    let v: i64 = raw.parse().ok()?;
    if v.unsigned_abs() >= (1u64 << 53) {
        return None;
    }
    Some(v)
}

#[derive(Debug)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

/// Maximum JSON nesting depth. A statement, or a record payload, whose depth
/// exceeds this is malformed.
///
/// Depth is the number of arrays and objects open at a given point, with the
/// outermost `{` at depth 1; scalar values do not increase it. Both halves are
/// load-bearing. An implementation that increments per parsed value instead of
/// per open container sits one level away from this one at an identical
/// constant, and disagrees with it on any document whose deepest path ends in a
/// scalar -- which, in the conformance corpus, is every document.
const MAX_DEPTH: usize = 128;

pub fn parse(input: &[u8]) -> Result<Value, ParseError> {
    let text = std::str::from_utf8(input)
        .map_err(|_| ParseError("input is not valid UTF-8".into()))?;
    let mut p = Parser {
        bytes: text.as_bytes(),
        pos: 0,
        depth: 0,
    };
    p.skip_ws();
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(ParseError("trailing bytes after JSON value".into()));
    }
    Ok(v)
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), ParseError> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(ParseError(format!(
                "expected '{}' at byte {}",
                b as char, self.pos
            )))
        }
    }

    fn parse_value(&mut self) -> Result<Value, ParseError> {
        let opens_container = matches!(self.peek(), Some(b'{' | b'['));
        if opens_container {
            self.depth += 1;
            if self.depth > MAX_DEPTH {
                return Err(ParseError("nesting too deep".into()));
            }
        }
        let v = match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b't') => self.parse_lit("true", Value::Bool(true)),
            Some(b'f') => self.parse_lit("false", Value::Bool(false)),
            Some(b'n') => self.parse_lit("null", Value::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number(),
            _ => Err(ParseError(format!("unexpected byte at {}", self.pos))),
        };
        if opens_container {
            self.depth -= 1;
        }
        v
    }

    fn parse_lit(&mut self, lit: &str, v: Value) -> Result<Value, ParseError> {
        if self.bytes[self.pos..].starts_with(lit.as_bytes()) {
            self.pos += lit.len();
            Ok(v)
        } else {
            Err(ParseError(format!("invalid literal at byte {}", self.pos)))
        }
    }

    fn parse_object(&mut self) -> Result<Value, ParseError> {
        self.expect(b'{')?;
        let mut members: Vec<(String, Value)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            if members.iter().any(|(k, _)| *k == key) {
                return Err(ParseError(format!("duplicate object member \"{key}\"")));
            }
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let val = self.parse_value()?;
            members.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(members));
                }
                _ => return Err(ParseError(format!("expected ',' or '}}' at byte {}", self.pos))),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Value, ParseError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(ParseError(format!("expected ',' or ']' at byte {}", self.pos))),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = self
                .peek()
                .ok_or_else(|| ParseError("unterminated string".into()))?;
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = self
                        .peek()
                        .ok_or_else(|| ParseError("unterminated escape".into()))?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cu = self.parse_hex4()?;
                            if (0xD800..0xDC00).contains(&cu) {
                                // high surrogate: a low surrogate must follow
                                if self.peek() != Some(b'\\') {
                                    return Err(ParseError("lone high surrogate".into()));
                                }
                                self.pos += 1;
                                if self.peek() != Some(b'u') {
                                    return Err(ParseError("lone high surrogate".into()));
                                }
                                self.pos += 1;
                                let lo = self.parse_hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(ParseError("invalid surrogate pair".into()));
                                }
                                let c = 0x10000 + ((cu as u32 - 0xD800) << 10) + (lo as u32 - 0xDC00);
                                let c = char::from_u32(c)
                                    .ok_or_else(|| ParseError("invalid surrogate pair".into()))?;
                                Self::push_scalar(&mut out, c)?;
                            } else if (0xDC00..0xE000).contains(&cu) {
                                return Err(ParseError("lone low surrogate".into()));
                            } else {
                                let c = char::from_u32(cu as u32)
                                    .ok_or_else(|| ParseError("invalid \\u escape".into()))?;
                                Self::push_scalar(&mut out, c)?;
                            }
                        }
                        _ => return Err(ParseError("invalid escape".into())),
                    }
                }
                0x00..=0x1F => return Err(ParseError("raw control character in string".into())),
                _ => {
                    // consume one UTF-8 encoded char
                    let s = std::str::from_utf8(&self.bytes[self.pos..])
                        .map_err(|_| ParseError("invalid UTF-8".into()))?;
                    let c = s.chars().next().unwrap();
                    Self::push_scalar(&mut out, c)?;
                    self.pos += c.len_utf8();
                }
            }
        }
    }

    /// Append one resolved scalar value to a string being parsed, rejecting the
    /// Unicode noncharacters.
    ///
    /// Both routes into a string body pass through here, the escape and the raw
    /// UTF-8 byte, because the exclusion is over code points and a producer can
    /// reach any of them either way.
    fn push_scalar(out: &mut String, c: char) -> Result<(), ParseError> {
        if is_noncharacter(c) {
            return Err(ParseError(format!(
                "Unicode noncharacter U+{:04X} in string",
                c as u32
            )));
        }
        out.push(c);
        Ok(())
    }

    fn parse_hex4(&mut self) -> Result<u16, ParseError> {
        if self.pos + 4 > self.bytes.len() {
            return Err(ParseError("truncated \\u escape".into()));
        }
        let s = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
            .map_err(|_| ParseError("invalid \\u escape".into()))?;
        let v = u16::from_str_radix(s, 16).map_err(|_| ParseError("invalid \\u escape".into()))?;
        self.pos += 4;
        Ok(v)
    }

    fn parse_number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        // int part
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(c) if c.is_ascii_digit() => {
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return Err(ParseError("invalid number".into())),
        }
        // fraction
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(ParseError("invalid number fraction".into()));
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        // exponent
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(ParseError("invalid number exponent".into()));
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let raw = std::str::from_utf8(&self.bytes[start..self.pos])
            .unwrap()
            .to_string();
        let value: f64 = raw
            .parse()
            .map_err(|_| ParseError("unparseable number".into()))?;
        if !value.is_finite() {
            return Err(ParseError("number overflows double".into()));
        }
        Ok(Value::Number { raw, value })
    }
}

/// UTF-16 code units of a string, for RFC 8785 member ordering and
/// vocabulary sort checks.
pub fn utf16_units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// True for the sixty-six Unicode noncharacters: U+FDD0 through U+FDEF, and
/// U+nFFFE and U+nFFFF in each of the seventeen planes.
///
/// These are valid Unicode scalar values, so unlike an ill-formed sequence
/// nothing substitutes for them and no decoder splits on them. RFC 7493
/// section 2.1 forbids them in the same sentence as surrogates, and the
/// predicate excludes them wherever a string literal appears so that a verifier
/// implementing the I-JSON label does not reject a record another verifier
/// accepts. The plane-end pairs differ only in their lowest bit, so one mask
/// covers all thirty-four of them.
pub fn is_noncharacter(c: char) -> bool {
    let u = c as u32;
    (0xFDD0..=0xFDEF).contains(&u) || (u & 0xFFFE) == 0xFFFE
}

/// True when every code point of `s` is in the Basic Multilingual Plane.
pub fn is_bmp_only(s: &str) -> bool {
    s.chars().all(|c| (c as u32) <= 0xFFFF)
}

/// RFC 8785 canonical serialization of a value.
///
/// Object members are sorted by UTF-16 code units of their names; strings
/// use the JCS minimal-escape rules; numbers use the ECMAScript
/// Number::toString algorithm.
pub fn to_canonical_bytes(v: &Value) -> Result<Vec<u8>, ParseError> {
    let mut out = String::new();
    write_canonical(v, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical(v: &Value, out: &mut String) -> Result<(), ParseError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number { value, .. } => out.push_str(&es_number_to_string(*value)?),
        Value::String(s) => write_jcs_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut sorted: Vec<&(String, Value)> = members.iter().collect();
            sorted.sort_by(|a, b| utf16_units(&a.0).cmp(&utf16_units(&b.0)));
            out.push('{');
            for (i, (k, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs_string(k, out);
                out.push(':');
                write_canonical(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// ECMAScript Number::toString(10) for a finite double (ECMA-262 6.1.6.1.20),
/// which is what RFC 8785 Section 3.2.2.3 requires.
pub fn es_number_to_string(v: f64) -> Result<String, ParseError> {
    if !v.is_finite() {
        return Err(ParseError("non-finite number".into()));
    }
    if v == 0.0 {
        return Ok("0".to_string()); // covers -0 as well
    }
    let (sign, v) = if v < 0.0 { ("-", -v) } else { ("", v) };
    // Shortest round-trip decimal digits and exponent via Rust's LowerExp,
    // which emits the shortest representation that round-trips.
    let exp_form = format!("{:e}", v); // e.g. "1.2345e3", "5e-7"
    let (mantissa, exp_str) = exp_form
        .split_once('e')
        .ok_or_else(|| ParseError("bad exponent form".into()))?;
    let e10: i32 = exp_str
        .parse()
        .map_err(|_| ParseError("bad exponent".into()))?;
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let k = digits.len() as i32; // number of significant digits
    let n = e10 + 1; // decimal point position: value = 0.digits * 10^n
    let mut out = String::from(sign);
    if k <= n && n <= 21 {
        out.push_str(digits);
        for _ in 0..(n - k) {
            out.push('0');
        }
    } else if 0 < n && n <= 21 {
        out.push_str(&digits[..n as usize]);
        out.push('.');
        out.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(digits);
    } else {
        // exponential form d.ddd e(n-1)
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        let e = n - 1;
        if e >= 0 {
            out.push('+');
        }
        let _ = write!(out, "{}", e);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn es_numbers() {
        assert_eq!(es_number_to_string(0.0).unwrap(), "0");
        assert_eq!(es_number_to_string(-0.0).unwrap(), "0");
        assert_eq!(es_number_to_string(1.0).unwrap(), "1");
        assert_eq!(es_number_to_string(-5.0).unwrap(), "-5");
        assert_eq!(es_number_to_string(0.5).unwrap(), "0.5");
        assert_eq!(es_number_to_string(1e21).unwrap(), "1e+21");
        assert_eq!(es_number_to_string(1e-7).unwrap(), "1e-7");
        assert_eq!(es_number_to_string(0.000001).unwrap(), "0.000001");
        assert_eq!(es_number_to_string(123456789.0).unwrap(), "123456789");
        assert_eq!(es_number_to_string(1.5e2).unwrap(), "150");
    }

    #[test]
    fn duplicate_members_rejected() {
        assert!(parse(br#"{"a":1,"a":2}"#).is_err());
    }

    #[test]
    fn jcs_sorting_utf16() {
        // RFC 8785 sorts by UTF-16 code units.
        let v = parse("{\"\u{20AC}\":1,\"a\":2}".as_bytes()).unwrap();
        let c = to_canonical_bytes(&v).unwrap();
        assert_eq!(String::from_utf8(c).unwrap(), "{\"a\":2,\"\u{20AC}\":1}");
    }

    #[test]
    fn safe_integer_bounds() {
        assert_eq!(parse_safe_integer("9007199254740991"), Some(9007199254740991));
        assert_eq!(parse_safe_integer("9007199254740992"), None);
        assert_eq!(parse_safe_integer("-9007199254740992"), None);
        assert_eq!(parse_safe_integer("1.5"), None);
    }

    /// `n` nested objects around `leaf`, so the document's depth is exactly `n`
    /// under the spec rule: the outermost `{` is depth 1 and the leaf, being a
    /// scalar, does not add one.
    fn nest_objects(n: usize, leaf: &str) -> String {
        let mut s = String::new();
        for _ in 0..n {
            s.push_str("{\"a\":");
        }
        s.push_str(leaf);
        for _ in 0..n {
            s.push('}');
        }
        s
    }

    #[test]
    fn depth_bound_is_counted_over_open_containers() {
        // The boundary the corpus does not reach. Depth 128 with a scalar leaf
        // is valid; an implementation that increments per parsed value rejects
        // it at the same constant, because the leaf pushes its counter to 129.
        assert!(parse(nest_objects(128, "1").as_bytes()).is_ok());
        assert!(parse(nest_objects(129, "1").as_bytes()).is_err());

        // The other side of that offset: a leaf that is itself an empty
        // container does add a level, so 127 wrappers around `{}` is the same
        // depth as 128 around a scalar.
        assert!(parse(nest_objects(127, "{}").as_bytes()).is_ok());
        assert!(parse(nest_objects(128, "{}").as_bytes()).is_err());

        // Arrays open a container on the same footing as objects.
        let deep_array = format!("{}1{}", "[".repeat(128), "]".repeat(128));
        assert!(parse(deep_array.as_bytes()).is_ok());
        let too_deep_array = format!("{}1{}", "[".repeat(129), "]".repeat(129));
        assert!(parse(too_deep_array.as_bytes()).is_err());
    }

    #[test]
    fn noncharacter_set_is_exactly_sixty_six() {
        let n = (0..=0x10FFFFu32)
            .filter_map(char::from_u32)
            .filter(|c| is_noncharacter(*c))
            .count();
        assert_eq!(n, 66);
        // The two shapes, and the code points on either side of each boundary.
        assert!(is_noncharacter('\u{FDD0}') && is_noncharacter('\u{FDEF}'));
        assert!(!is_noncharacter('\u{FDCF}') && !is_noncharacter('\u{FDF0}'));
        assert!(is_noncharacter('\u{FFFE}') && is_noncharacter('\u{FFFF}'));
        assert!(is_noncharacter('\u{10FFFE}') && is_noncharacter('\u{10FFFF}'));
        assert!(!is_noncharacter('\u{FFFD}') && !is_noncharacter('\u{10000}'));
    }

    #[test]
    fn noncharacters_rejected_by_either_route() {
        // Raw UTF-8 in a value, in a member name, and nested.
        assert!(parse("{\"a\":\"x\u{FFFF}y\"}".as_bytes()).is_err());
        assert!(parse("{\"a\u{FDD0}b\":1}".as_bytes()).is_err());
        assert!(parse("{\"a\":[{\"b\":\"\u{1FFFE}\"}]}".as_bytes()).is_err());
        // The same code points as escapes, including via a surrogate pair,
        // since the exclusion is over code points and not over spelling.
        assert!(parse(br#"{"a":"\uFFFF"}"#).is_err());
        assert!(parse(br#"{"a":"\uFDD0"}"#).is_err());
        assert!(parse(br#"{"a":"\uD83F\uDFFE"}"#).is_err()); // U+1FFFE via a surrogate pair
        assert!(parse(br#"{"a":"\uFDEF"}"#).is_err());
        // Immediate neighbours still parse, so this rejects the noncharacters
        // rather than the neighbourhood they sit in.
        assert!(parse(br#"{"a":"\uFFFD"}"#).is_ok());
        assert!(parse(br#"{"a":"\uFDCF"}"#).is_ok());
        assert!(parse(br#"{"a":"\uFDF0"}"#).is_ok());
        assert!(parse(br#"{"a":"\uD83D\uDE00"}"#).is_ok()); // U+1F600
    }

    #[test]
    fn scalars_do_not_consume_depth() {
        // Breadth is not depth: a shallow object with many scalar members must
        // parse regardless of how many there are.
        let members: Vec<String> = (0..2000).map(|i| format!("\"k{i}\":{i}")).collect();
        let wide = format!("{{{}}}", members.join(","));
        assert!(parse(wide.as_bytes()).is_ok());
    }
}
