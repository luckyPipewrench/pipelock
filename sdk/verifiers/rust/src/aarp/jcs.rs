// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//! RFC 8785 JCS canonicalization and I-JSON number safety, ported byte-for-byte
//! from `internal/contract/canonicalize.go` and `internal/aarp/numbers.go`.
//!
//! The AARP path uses a self-contained strict JSON parser (not serde_json's
//! number decoding) so that:
//!
//!   * raw number literals are preserved exactly for I-JSON safety checks (Go
//!     decodes with `json.Number`, which keeps the source text);
//!   * duplicate object keys at any depth are rejected (a parser-differential
//!     smuggling vector);
//!   * trailing non-whitespace tokens after the value are rejected.
//!
//! Strings and object keys are NFC-normalized; keys are sorted ascending by
//! Unicode code point (equivalently, by UTF-8 byte order for valid UTF-8).
//! Floats and exponent forms are rejected outright. Output escapes `<`, `>`,
//! `&`, U+2028, and U+2029 the way Go's HTML-escaping `json.Marshal` does.

use std::collections::BTreeMap;
use std::fmt;

use unicode_normalization::UnicodeNormalization;

/// JcsError is the fatal-classed failure set for the canonical JSON path. Every
/// variant maps to an envelope-fatal outcome (exit 1) in the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JcsError {
    /// A duplicate object key was found during strict parse (any depth).
    DuplicateKey(String),
    /// Valid JSON was followed by additional non-whitespace tokens.
    TrailingTokens(String),
    /// The input is not well-formed JSON.
    Parse(String),
    /// A raw JSON number is a float, exponent, negative zero, or out of the
    /// I-JSON safe-integer range [-(2^53-1), 2^53-1].
    UnsafeNumber(String),
    /// A float appeared where canonicalization requires an integer.
    FloatNotAllowed(String),
}

impl fmt::Display for JcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey(msg) => write!(f, "duplicate key in JSON object: {msg}"),
            Self::TrailingTokens(msg) => write!(f, "trailing tokens after JSON value: {msg}"),
            Self::Parse(msg) => write!(f, "malformed JSON: {msg}"),
            Self::UnsafeNumber(msg) => write!(f, "unsafe JSON number: {msg}"),
            Self::FloatNotAllowed(msg) => write!(f, "float not allowed in canonicalization: {msg}"),
        }
    }
}

impl std::error::Error for JcsError {}

/// Json is the strict-parse tree. Numbers retain their exact source literal so
/// I-JSON safety is checked on the text before any lossy conversion, matching
/// Go's `json.Number`.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// The raw number literal exactly as it appeared in the source.
    Number(String),
    String(String),
    Array(Vec<Json>),
    /// Object insertion order is irrelevant: canonicalization sorts by key.
    Object(BTreeMap<String, Json>),
}

/// The I-JSON safe-integer range. Outside it, a JavaScript or other-language
/// parser silently rounds to float64, changing the canonical bytes.
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;
const MIN_SAFE_INTEGER: i64 = -((1 << 53) - 1);

/// parse_strict decodes JSON rejecting duplicate keys at any depth and trailing
/// tokens after the value. Mirrors `contract.ParseJSONStrict`.
pub fn parse_strict(data: &str) -> Result<Json, JcsError> {
    let mut parser = Parser::new(data);
    parser.skip_ws();
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos < parser.bytes.len() {
        return Err(JcsError::TrailingTokens(format!("byte {}", parser.pos)));
    }
    Ok(value)
}

/// enforce_safe_numbers walks a parsed tree and rejects any number that is not a
/// safe integer. Mirrors `aarp.EnforceSafeNumbers`.
pub fn enforce_safe_numbers(tree: &Json) -> Result<(), JcsError> {
    enforce_inner(tree, "$")
}

fn enforce_inner(value: &Json, path: &str) -> Result<(), JcsError> {
    match value {
        Json::Number(lit) => check_safe_number(lit, path),
        Json::Object(map) => {
            for (key, val) in map {
                enforce_inner(val, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
        Json::Array(items) => {
            for (index, val) in items.iter().enumerate() {
                enforce_inner(val, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// check_safe_number validates a single raw JSON number literal exactly as Go's
/// `checkSafeNumber` does: float/exponent forms forbidden, negative zero
/// forbidden, integer within the I-JSON safe range.
fn check_safe_number(lit: &str, path: &str) -> Result<(), JcsError> {
    if lit.is_empty() {
        return Err(JcsError::UnsafeNumber(format!("empty number at {path}")));
    }
    if lit.contains(['.', 'e', 'E']) {
        return Err(JcsError::UnsafeNumber(format!(
            "float or exponent form {lit:?} at {path}"
        )));
    }
    if lit == "-0" {
        return Err(JcsError::UnsafeNumber(format!("negative zero at {path}")));
    }
    // The literal has already passed the JSON number grammar, so it is a
    // base-10 integer here. Parse to i128 to range-check without overflow.
    let n: i128 = lit
        .parse()
        .map_err(|_| JcsError::UnsafeNumber(format!("non-integer literal {lit:?} at {path}")))?;
    if n > i128::from(MAX_SAFE_INTEGER) || n < i128::from(MIN_SAFE_INTEGER) {
        return Err(JcsError::UnsafeNumber(format!(
            "{lit:?} outside I-JSON safe range at {path}"
        )));
    }
    Ok(())
}

/// canonicalize_tree renders a strict-parse tree to RFC 8785 JCS bytes. Strings
/// and keys are NFC-normalized; keys are sorted by NFC code point; floats are
/// rejected. Mirrors `contract.Canonicalize`.
pub fn canonicalize_tree(value: &Json) -> Result<Vec<u8>, JcsError> {
    let mut out = String::new();
    canonicalize_into(&mut out, value)?;
    Ok(out.into_bytes())
}

fn canonicalize_into(out: &mut String, value: &Json) -> Result<(), JcsError> {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Number(lit) => {
            // Integer-only: reject any float/exponent form, matching the
            // json.Number Int64() check in Go's Canonicalize.
            if lit.contains(['.', 'e', 'E']) {
                return Err(JcsError::FloatNotAllowed(format!(
                    "non-integer json number {lit:?}"
                )));
            }
            out.push_str(lit);
        }
        Json::String(s) => out.push_str(&encode_string(s)),
        Json::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                canonicalize_into(out, item)?;
            }
            out.push(']');
        }
        Json::Object(map) => {
            // BTreeMap already orders by raw key; but Go sorts by the NFC form
            // and rejects NFC collisions. Build the NFC-normalized, sorted set.
            let mut pairs: Vec<(String, &Json)> = Vec::with_capacity(map.len());
            for (key, val) in map {
                pairs.push((nfc(key), val));
            }
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            for index in 1..pairs.len() {
                if pairs[index].0 == pairs[index - 1].0 {
                    return Err(JcsError::DuplicateKey(format!(
                        "NFC collision on key {:?}",
                        pairs[index].0
                    )));
                }
            }
            out.push('{');
            for (index, (key, val)) in pairs.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&encode_string(key));
                out.push(':');
                canonicalize_into(out, val)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// nfc returns the NFC normalization of s, matching Go's norm.NFC.String.
pub fn nfc(s: &str) -> String {
    s.nfc().collect()
}

/// encode_string NFC-normalizes then JSON-encodes a string with Go's
/// HTML-escaping behaviour: `<`, `>`, `&`, U+2028, U+2029 become `\uXXXX`.
fn encode_string(s: &str) -> String {
    let normalized = nfc(s);
    let mut out = String::with_capacity(normalized.len() + 2);
    out.push('"');
    for ch in normalized.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// canonicalize_value builds a Json tree from an in-memory map/array structure
/// and canonicalizes it. Used to emit the comparable appraisal output.
pub fn canonicalize_value(value: &Json) -> Result<Vec<u8>, JcsError> {
    canonicalize_tree(value)
}

// ---- strict recursive-descent parser ----

struct Parser<'a> {
    bytes: &'a [u8],
    src: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            bytes: src.as_bytes(),
            src,
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn parse_value(&mut self) -> Result<Json, JcsError> {
        self.skip_ws();
        let Some(&b) = self.bytes.get(self.pos) else {
            return Err(JcsError::Parse("unexpected end of input".to_string()));
        };
        match b {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => Ok(Json::String(self.parse_string()?)),
            b't' => self.parse_literal("true", Json::Bool(true)),
            b'f' => self.parse_literal("false", Json::Bool(false)),
            b'n' => self.parse_literal("null", Json::Null),
            b'-' | b'0'..=b'9' => self.parse_number(),
            other => Err(JcsError::Parse(format!(
                "unexpected byte {:?} at {}",
                other as char, self.pos
            ))),
        }
    }

    fn parse_literal(&mut self, lit: &str, value: Json) -> Result<Json, JcsError> {
        if self.src[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(value)
        } else {
            Err(JcsError::Parse(format!(
                "invalid literal at {}, expected {lit}",
                self.pos
            )))
        }
    }

    fn parse_object(&mut self) -> Result<Json, JcsError> {
        self.pos += 1; // consume '{'
        let mut map: BTreeMap<String, Json> = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(JcsError::Parse(format!(
                    "expected string key at {}",
                    self.pos
                )));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(JcsError::Parse(format!("expected ':' at {}", self.pos)));
            }
            self.pos += 1;
            let val = self.parse_value()?;
            if map.contains_key(&key) {
                return Err(JcsError::DuplicateKey(key));
            }
            map.insert(key, val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(map));
                }
                _ => {
                    return Err(JcsError::Parse(format!(
                        "expected ',' or '}}' at {}",
                        self.pos
                    )))
                }
            }
        }
    }

    fn parse_array(&mut self) -> Result<Json, JcsError> {
        self.pos += 1; // consume '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            let val = self.parse_value()?;
            items.push(val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => {
                    return Err(JcsError::Parse(format!(
                        "expected ',' or ']' at {}",
                        self.pos
                    )))
                }
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, JcsError> {
        self.pos += 1; // consume opening quote
        let mut out = String::new();
        loop {
            let Some(&b) = self.bytes.get(self.pos) else {
                return Err(JcsError::Parse("unterminated string".to_string()));
            };
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let Some(&esc) = self.bytes.get(self.pos) else {
                        return Err(JcsError::Parse("unterminated escape".to_string()));
                    };
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let decoded = self.parse_unicode_escape()?;
                            out.push_str(&decoded);
                            continue;
                        }
                        other => {
                            return Err(JcsError::Parse(format!(
                                "invalid escape \\{}",
                                other as char
                            )))
                        }
                    }
                    self.pos += 1;
                }
                _ => {
                    // Copy one UTF-8 codepoint from the source.
                    let rest = &self.src[self.pos..];
                    let ch = rest
                        .chars()
                        .next()
                        .ok_or_else(|| JcsError::Parse("invalid UTF-8".to_string()))?;
                    if (ch as u32) < 0x20 {
                        return Err(JcsError::Parse("control character in string".to_string()));
                    }
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<String, JcsError> {
        // self.pos points at 'u'
        let high = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&high) {
            // High surrogate. Go's encoding/json (and Python's json) only pair it
            // with an immediately following LOW-surrogate escape; otherwise the
            // high alone decodes to U+FFFD and the next escape is reprocessed
            // independently. This must be NON-GREEDY: a following \u that is not a
            // low surrogate is left in place, not consumed. A greedy consume would
            // mis-handle a high,high,low escape run (e.g. \uD800 \uDBFF \uDC00) as
            // three U+FFFD, while Go/Python emit U+FFFD followed by the valid
            // astral pair built from the 2nd and 3rd escapes -- a cross-language
            // canonical-bytes differential the whole corpus exists to prevent.
            if self.bytes.get(self.pos) == Some(&b'\\')
                && self.bytes.get(self.pos + 1) == Some(&b'u')
            {
                let saved = self.pos;
                self.pos += 1; // tentatively consume '\'
                let low = self.read_hex4()?;
                if (0xDC00..=0xDFFF).contains(&low) {
                    let combined = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
                    return char::from_u32(combined)
                        .map(|ch| ch.to_string())
                        .ok_or_else(|| JcsError::Parse("invalid surrogate pair".to_string()));
                }
                // Not a low surrogate: rewind so the second escape is reprocessed.
                self.pos = saved;
            }
            return Ok(char::REPLACEMENT_CHARACTER.to_string());
        }
        if (0xDC00..=0xDFFF).contains(&high) {
            return Ok(char::REPLACEMENT_CHARACTER.to_string());
        }
        char::from_u32(high)
            .map(|ch| ch.to_string())
            .ok_or_else(|| JcsError::Parse("invalid \\u escape".to_string()))
    }

    fn read_hex4(&mut self) -> Result<u32, JcsError> {
        // self.pos points at 'u'; consume it then read 4 hex digits.
        self.pos += 1;
        if self.pos + 4 > self.bytes.len() {
            return Err(JcsError::Parse("truncated \\u escape".to_string()));
        }
        let hex = &self.src[self.pos..self.pos + 4];
        let value = u32::from_str_radix(hex, 16)
            .map_err(|_| JcsError::Parse("invalid hex in \\u escape".to_string()))?;
        self.pos += 4;
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Json, JcsError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        // Integer part.
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(JcsError::Parse(format!("invalid number at {}", self.pos))),
        }
        // Fraction.
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JcsError::Parse("invalid fraction".to_string()));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        // Exponent.
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JcsError::Parse("invalid exponent".to_string()));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        Ok(Json::Number(self.src[start..self.pos].to_string()))
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
}
