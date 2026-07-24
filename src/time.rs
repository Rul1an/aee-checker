//! Minimal RFC 3339 timestamp parsing, enough to validate `issuedAt` and
//! `armedAt` and to compare the two as instants.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    /// Seconds since 1970-01-01T00:00:00Z (proleptic Gregorian).
    pub epoch_seconds: i64,
    /// Sub-second fraction in nanoseconds.
    pub nanos: u32,
}

pub struct Parsed {
    pub instant: Instant,
    /// True when the offset was `Z`, `z`, `+00:00`, or `-00:00`.
    pub utc_offset: bool,
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    // Howard Hinnant's days_from_civil algorithm.
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parse an RFC 3339 `date-time`. Returns None on any grammar or range
/// violation.
pub fn parse_rfc3339(s: &str) -> Option<Parsed> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let digit = |i: usize| -> Option<i64> {
        let c = *b.get(i)?;
        if c.is_ascii_digit() {
            Some((c - b'0') as i64)
        } else {
            None
        }
    };
    let num = |start: usize, len: usize| -> Option<i64> {
        let mut v = 0i64;
        for i in start..start + len {
            v = v * 10 + digit(i)?;
        }
        Some(v)
    };
    let year = num(0, 4)?;
    if b[4] != b'-' {
        return None;
    }
    let month = num(5, 2)? as u32;
    if b[7] != b'-' {
        return None;
    }
    let day = num(8, 2)? as u32;
    if !(b[10] == b'T' || b[10] == b't') {
        return None;
    }
    let hour = num(11, 2)?;
    if b[13] != b':' {
        return None;
    }
    let minute = num(14, 2)?;
    if b[16] != b':' {
        return None;
    }
    let second = num(17, 2)?;
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    // Allow leap second 60 per RFC 3339 grammar.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut pos = 19;
    let mut nanos: u32 = 0;
    if b.get(pos) == Some(&b'.') {
        pos += 1;
        let frac_start = pos;
        while b.get(pos).is_some_and(|c| c.is_ascii_digit()) {
            pos += 1;
        }
        if pos == frac_start {
            return None;
        }
        let frac = &s[frac_start..pos];
        let mut ns = 0u32;
        for (i, c) in frac.chars().take(9).enumerate() {
            ns += (c as u32 - '0' as u32) * 10u32.pow(8 - i as u32);
        }
        nanos = ns;
    }
    let (offset_seconds, utc_offset) = match b.get(pos) {
        Some(b'Z') | Some(b'z') => {
            pos += 1;
            (0i64, true)
        }
        Some(b'+') | Some(b'-') => {
            let sign = if b[pos] == b'+' { 1i64 } else { -1i64 };
            let oh = num(pos + 1, 2)?;
            if b.get(pos + 3) != Some(&b':') {
                return None;
            }
            let om = num(pos + 4, 2)?;
            if oh > 23 || om > 59 {
                return None;
            }
            pos += 6;
            (sign * (oh * 3600 + om * 60), oh == 0 && om == 0)
        }
        _ => return None,
    };
    if pos != b.len() {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let epoch_seconds = days * 86400 + hour * 3600 + minute * 60 + second - offset_seconds;
    Some(Parsed {
        instant: Instant {
            epoch_seconds,
            nanos,
        },
        utc_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let a = parse_rfc3339("2026-01-01T00:00:00Z").unwrap();
        assert!(a.utc_offset);
        let b = parse_rfc3339("2026-01-01T01:00:00+01:00").unwrap();
        assert_eq!(a.instant, b.instant);
        assert!(parse_rfc3339("2026-13-01T00:00:00Z").is_none());
        assert!(parse_rfc3339("not a date").is_none());
        assert!(parse_rfc3339("2026-01-01 00:00:00Z").is_none());
        let c = parse_rfc3339("2026-01-01T00:00:00.5Z").unwrap();
        assert!(c.instant > a.instant);
    }
}
