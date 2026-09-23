// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! Source-faithful encoding of the unsigned receipt `ext` bag.
//!
//! The Go reference verifier hashes a v1 receipt as `json.Marshal(Receipt)`.
//! The top-level `ext` bag is a `json.RawMessage`, so its bytes in that
//! preimage are the SOURCE bytes of the ext value, compacted and HTML-escaped
//! by `encoding/json`, with key order, number spelling, and string escape
//! spelling kept verbatim. Re-serializing a parsed `serde_json::Value` cannot
//! reproduce that: number text and escape spelling are lost at parse time.
//! This module recovers the ext value's source span from the recorder line and
//! re-encodes it the way Go does, so the chain link hash matches the Go
//! producer byte for byte. The ext VALUE stays unsigned and advisory; only its
//! bytes join the link hash.

use serde_json::Value;

/// Reserved top-level key under which receipt extraction records the
/// Go-encoded ext bytes of a receipt read from a recorder line. It is added
/// only after the strict unknown-field check has passed, and it is honored
/// only while the recorded bytes still parse to the receipt's current `ext`
/// value, so a stale or hand-built entry falls back to re-serialization.
pub const EXT_SOURCE_KEY: &str = "\u{0}pipelock.ext_go_bytes";

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

fn skip_string(bytes: &[u8], mut i: usize) -> Option<usize> {
    i += 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

fn skip_value(bytes: &[u8], mut i: usize) -> Option<usize> {
    match bytes.get(i)? {
        b'"' => skip_string(bytes, i),
        b'{' | b'[' => {
            let mut depth = 0usize;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' => {
                        i = skip_string(bytes, i)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            return Some(i + 1);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            None
        }
        _ => {
            while i < bytes.len()
                && !matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r' | b',' | b'}' | b']')
            {
                i += 1;
            }
            Some(i)
        }
    }
}

/// Returns the source byte span of the value stored under `key` in the JSON
/// object that starts at `object_start`, or `None` when it is absent. The text
/// must already have passed a strict parse and the duplicate-key check.
pub fn object_member_span(text: &str, object_start: usize, key: &str) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut i = skip_ws(bytes, object_start);
    if bytes.get(i) != Some(&b'{') {
        return None;
    }
    i = skip_ws(bytes, i + 1);
    if bytes.get(i) == Some(&b'}') {
        return None;
    }
    while i < bytes.len() {
        if bytes[i] != b'"' {
            return None;
        }
        let key_end = skip_string(bytes, i)?;
        let name: String = serde_json::from_str(text.get(i..key_end)?).ok()?;
        i = skip_ws(bytes, key_end);
        if bytes.get(i) != Some(&b':') {
            return None;
        }
        let start = skip_ws(bytes, i + 1);
        let end = skip_value(bytes, start)?;
        if name == key {
            return Some((start, end));
        }
        i = skip_ws(bytes, end);
        match bytes.get(i) {
            Some(b',') => i = skip_ws(bytes, i + 1),
            _ => return None,
        }
    }
    None
}

/// Reproduces `encoding/json`'s output for a `json.RawMessage`: insignificant
/// whitespace removed, and `<`, `>`, `&`, U+2028, U+2029 written as six-byte
/// lowercase-hex unicode escapes, exactly as Go does. Every other character, including
/// existing escape sequences and number text, is copied verbatim.
pub fn go_raw_message_bytes(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_string = false;
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if in_string {
            if ch == '\\' {
                out.push(ch);
                if let Some(next) = chars.next() {
                    out.push(next);
                }
                continue;
            }
            if ch == '"' {
                in_string = false;
            }
        } else {
            if matches!(ch, ' ' | '\t' | '\n' | '\r') {
                continue;
            }
            if ch == '"' {
                in_string = true;
            }
        }
        match ch {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            _ => out.push(ch),
        }
    }
    out
}

/// Returns the Go-encoded ext source bytes of the receipt carried in a
/// recorder line's `detail` member, or `None` when there is no ext member.
pub fn recorder_line_ext_bytes(line: &str) -> Option<String> {
    let (detail_start, _) = object_member_span(line, 0, "detail")?;
    let (start, end) = object_member_span(line, detail_start, "ext")?;
    Some(go_raw_message_bytes(line.get(start..end)?))
}

/// Returns the recorded Go-encoded ext bytes for a receipt when they are
/// present and still describe the receipt's current `ext` value.
pub fn ext_source_bytes(receipt: &Value) -> Option<&str> {
    let recorded = receipt.get(EXT_SOURCE_KEY)?.as_str()?;
    let ext = receipt.get("ext")?;
    let mut de = serde_json::Deserializer::from_str(recorded);
    de.disable_recursion_limit();
    let parsed: Value = serde::Deserialize::deserialize(&mut de).ok()?;
    de.end().ok()?;
    (parsed == *ext).then_some(recorded)
}
