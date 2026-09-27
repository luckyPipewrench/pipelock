// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! The recorder entry hash chain, ported from the Go reference
//! `internal/recorder` (`ComputeHash`, `ValidateEntrySchema`, `VerifyChain`).
//! Every recorder entry carries `hash` = sha256 over a NUL-separated
//! projection of its fields, and `prev_hash` naming the entry before it
//! (`genesis` for the first). The chain is unkeyed: it detects an edit that
//! was not followed by recomputing the hashes, and anything that recomputes
//! them passes. Receipt and checkpoint signatures remain the authenticity
//! boundary. The Go finding for a break is `outer_chain_broken`.
//!
//! The projection hashes the field values the way Go's `encoding/json`
//! decodes them, so this reads the raw line again: `ts` is re-rendered in UTC
//! as RFC3339Nano, and `detail` is the exact source bytes of the value.

use crate::rawjson::object_member_span;
use crate::util::sha256_hex;
use serde_json::Value;

pub const FINDING_OUTER_CHAIN_BROKEN: &str = "outer_chain_broken";

const GENESIS_HASH: &str = "genesis";

/// The fields Go decodes from a recorder line. Go's `encoding/json` matches
/// keys case-insensitively, so `Summary` would fill `summary`; such a key is
/// refused here instead of hashed as a different field.
const ENTRY_FIELDS: [&str; 15] = [
    "v",
    "seq",
    "ts",
    "session_id",
    "chain_kind",
    "writer_instance_id",
    "trace_id",
    "type",
    "event_kind",
    "transport",
    "summary",
    "detail",
    "raw_ref",
    "prev_hash",
    "hash",
];

fn fold_key(key: &str) -> String {
    key.chars()
        .map(|ch| match ch {
            '\u{017f}' => 's',
            '\u{212a}' => 'k',
            _ => ch.to_ascii_lowercase(),
        })
        .collect()
}

/// The Go `Entry` as the hash sees it.
struct Projected {
    version: u64,
    seq: u64,
    ts: String,
    session_id: String,
    chain_kind: String,
    writer_instance_id: String,
    trace_id: String,
    entry_type: String,
    event_kind: String,
    transport: String,
    summary: String,
    detail: String,
    raw_ref: String,
    prev_hash: String,
    hash: String,
}

fn project(line: &str) -> Result<Projected, String> {
    let value: Value = serde_json::from_str(line).map_err(|err| err.to_string())?;
    let obj = value
        .as_object()
        .ok_or_else(|| "recorder entry is not a JSON object".to_string())?;
    for key in obj.keys() {
        if ENTRY_FIELDS.contains(&key.as_str()) {
            continue;
        }
        let folded = fold_key(key);
        if let Some(alias) = ENTRY_FIELDS.iter().find(|f| **f == folded) {
            return Err(format!("case-folded key {key:?} aliases {alias:?}"));
        }
    }
    let text = |field: &str| -> Result<String, String> {
        match obj.get(field) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(s)) => Ok(s.clone()),
            Some(_) => Err(format!("{field} must be a string")),
        }
    };
    let version = match obj.get("v").and_then(Value::as_u64) {
        Some(v @ 1..=3) => v,
        _ => return Err("unsupported entry version".to_string()),
    };
    let seq = match obj.get("seq") {
        None | Some(Value::Null) => 0,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| "seq must be an unsigned 64-bit integer".to_string())?,
    };
    let ts = match obj.get("ts") {
        None | Some(Value::Null) => "0001-01-01T00:00:00Z".to_string(),
        Some(Value::String(s)) => go_utc_rfc3339_nano(s)?,
        Some(_) => return Err("ts is not a JSON string".to_string()),
    };
    let start = line.find('{').unwrap_or(0);
    let detail = match object_member_span(line, start, "detail") {
        Some((s, e)) => line[s..e].to_string(),
        None => "null".to_string(),
    };
    let e = Projected {
        version,
        seq,
        ts,
        session_id: text("session_id")?,
        chain_kind: text("chain_kind")?,
        writer_instance_id: text("writer_instance_id")?,
        trace_id: text("trace_id")?,
        entry_type: text("type")?,
        event_kind: text("event_kind")?,
        transport: text("transport")?,
        summary: text("summary")?,
        detail,
        raw_ref: text("raw_ref")?,
        prev_hash: text("prev_hash")?,
        hash: text("hash")?,
    };
    validate_entry_schema(&e)?;
    Ok(e)
}

/// Mirrors Go `ValidateEntrySchema`: the namespace fields fit the version, and
/// no projected string contains the NUL separator.
fn validate_entry_schema(e: &Projected) -> Result<(), String> {
    if e.version == 3 {
        if e.chain_kind.is_empty() {
            return Err("v3 chain_kind required".to_string());
        }
        if e.writer_instance_id.is_empty() {
            return Err("v3 writer_instance_id required".to_string());
        }
    } else if !e.chain_kind.is_empty() || !e.writer_instance_id.is_empty() {
        return Err("legacy entry cannot carry v3 recorder namespace fields".to_string());
    }
    for (name, value) in [
        ("session_id", &e.session_id),
        ("trace_id", &e.trace_id),
        ("type", &e.entry_type),
        ("transport", &e.transport),
        ("summary", &e.summary),
        ("raw_ref", &e.raw_ref),
        ("prev_hash", &e.prev_hash),
        ("event_kind", &e.event_kind),
        ("chain_kind", &e.chain_kind),
        ("writer_instance_id", &e.writer_instance_id),
    ] {
        if value.contains('\0') {
            return Err(format!("v{} {name} cannot contain NUL", e.version));
        }
    }
    Ok(())
}

fn hash_projection(e: &Projected) -> String {
    let version = e.version.to_string();
    let seq = e.seq.to_string();
    let mut fields: Vec<&str> = vec![&version, &seq, &e.ts, &e.session_id];
    if e.version == 3 {
        fields.push(&e.chain_kind);
        fields.push(&e.writer_instance_id);
    }
    fields.push(&e.trace_id);
    fields.push(&e.entry_type);
    if e.version >= 2 {
        fields.push(&e.event_kind);
    }
    fields.extend([
        e.transport.as_str(),
        &e.summary,
        &e.detail,
        &e.raw_ref,
        &e.prev_hash,
    ]);
    sha256_hex(fields.join("\0").as_bytes())
}

/// Go's `recorder.ComputeHash` for one recorder line. Errors when Go would
/// refuse to read the line.
pub fn recorder_entry_hash(line: &str) -> Result<String, String> {
    project(line).map(|e| hash_projection(&e))
}

/// Mirrors Go `recorder.VerifyChain` (without checkpoint signatures): returns
/// the first break, with Go's wording, or `None` when the chain holds.
pub fn verify_recorder_chain<S: AsRef<str>>(lines: &[S]) -> Option<String> {
    let mut namespace: Option<(String, String, String)> = None;
    let mut prev: Option<Projected> = None;
    for line in lines {
        let e = match project(line.as_ref()) {
            Ok(e) => e,
            Err(err) => return Some(format!("entry: {err}")),
        };
        if e.version == 3 {
            if prev.as_ref().is_some_and(|p| p.version != 3) {
                return Some(format!(
                    "entry seq {}: v3 chain cannot continue a legacy recorder namespace",
                    e.seq
                ));
            }
            match &namespace {
                None => {
                    namespace = Some((
                        e.session_id.clone(),
                        e.chain_kind.clone(),
                        e.writer_instance_id.clone(),
                    ));
                }
                Some((s, k, w)) => {
                    if &e.session_id != s || &e.chain_kind != k || &e.writer_instance_id != w {
                        return Some(format!("entry seq {}: v3 chain namespace changed", e.seq));
                    }
                }
            }
        } else if namespace.is_some() {
            return Some(format!(
                "entry seq {}: legacy entry cannot continue a v3 recorder namespace",
                e.seq
            ));
        }
        let computed = hash_projection(&e);
        if computed != e.hash {
            return Some(format!(
                "entry seq {}: hash mismatch: computed {computed}, stored {}",
                e.seq, e.hash
            ));
        }
        match &prev {
            None if e.prev_hash != GENESIS_HASH => {
                return Some(format!(
                    "entry seq {}: first entry PrevHash should be \"{GENESIS_HASH}\", got \"{}\"",
                    e.seq, e.prev_hash
                ));
            }
            Some(p) if e.prev_hash != p.hash => {
                return Some(format!(
                    "entry seq {}: chain break: PrevHash {} != previous Hash {}",
                    e.seq, e.prev_hash, p.hash
                ));
            }
            _ => {}
        }
        prev = Some(e);
    }
    None
}

/// Parses `ts` the way Go's `time.Time.UnmarshalJSON` does (strict RFC 3339:
/// upper-case T and Z, two-digit fields in range, a real calendar day, a
/// numeric offset of at most 23:59, a fraction truncated to nanoseconds) and
/// formats the instant as Go's `UTC().Format(RFC3339Nano)`: trailing
/// fractional zeros dropped, `Z` for the zone.
pub fn go_utc_rfc3339_nano(ts: &str) -> Result<String, String> {
    let fail = || format!("parsing time {ts:?}: not RFC 3339");
    let b = ts.as_bytes();
    let num = |s: &[u8], min: i64, max: i64| -> Result<i64, String> {
        if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
            return Err(fail());
        }
        let n = s.iter().fold(0i64, |acc, d| acc * 10 + i64::from(d - b'0'));
        if n < min || n > max {
            return Err(fail());
        }
        Ok(n)
    };
    if b.len() < 19
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(fail());
    }
    let year = num(&b[0..4], 0, 9999)?;
    let month = num(&b[5..7], 1, 12)?;
    let day = num(&b[8..10], 1, days_in(year, month))?;
    let hour = num(&b[11..13], 0, 23)?;
    let minute = num(&b[14..16], 0, 59)?;
    let second = num(&b[17..19], 0, 59)?;
    let mut rest = &b[19..];
    let mut frac: &[u8] = &[];
    if rest.len() >= 2 && rest[0] == b'.' && rest[1].is_ascii_digit() {
        let mut n = 1;
        while n < rest.len() && rest[n].is_ascii_digit() {
            n += 1;
        }
        frac = &rest[1..n.min(10)];
        rest = &rest[n..];
    }
    let mut offset_minutes = 0i64;
    if rest != b"Z" {
        if rest.len() != 6 || (rest[0] != b'+' && rest[0] != b'-') || rest[3] != b':' {
            return Err(fail());
        }
        let oh = num(&rest[1..3], 0, 23)?;
        let om = num(&rest[4..6], 0, 59)?;
        offset_minutes = (oh * 60 + om) * if rest[0] == b'-' { -1 } else { 1 };
    }
    let total = days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second
        - offset_minutes * 60;
    let utc_days = total.div_euclid(86400);
    let sec_of_day = total.rem_euclid(86400);
    let (y, m, d) = civil_from_days(utc_days);
    if !(0..=9999).contains(&y) {
        return Err(format!("time {ts:?} is outside the four-digit year range"));
    }
    let mut nanos = String::from_utf8_lossy(frac).to_string();
    while nanos.len() < 9 {
        nanos.push('0');
    }
    let nanos = nanos.trim_end_matches('0');
    let fraction = if nanos.is_empty() {
        String::new()
    } else {
        format!(".{nanos}")
    };
    Ok(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}{fraction}Z",
        sec_of_day / 3600,
        (sec_of_day % 3600) / 60,
        sec_of_day % 60
    ))
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Howard Hinnant's proleptic Gregorian day count relative to 1970-01-01.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}
