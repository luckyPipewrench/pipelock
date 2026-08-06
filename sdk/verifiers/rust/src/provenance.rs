// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! The pinned, fixture-only evidence provenance transform interpreter.

use base64::{alphabet, engine::general_purpose, Engine};
use data_encoding::BASE32;
use percent_encoding::percent_decode_str;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};
use url::Url;

pub const PROFILE_DIGEST: &str =
    "sha256:3de14968449593cae58da869cfc97855cb098e491494390a12ba742cb0b70f94";
const MAX_INPUT: usize = 2 * 1024 * 1024;
const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_OPERATIONS: usize = 32;
const MAX_CUMULATIVE_PROCESSED_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Recipe {
    digest: String,
    operations: Vec<Operation>,
}

#[derive(Clone, Debug)]
struct Operation {
    kind: String,
    fields: Map<String, Value>,
}

impl Recipe {
    /// Builds a strict recipe from its signed JSON representation. `operations`
    /// must be an array; each operation rejects unknown, missing, and forbidden
    /// fields, including explicit false/zero values.
    pub fn from_json(digest: &str, operations: &Value) -> Result<Self, String> {
        validate_digest(digest)?;
        let operations = operations
            .as_array()
            .ok_or_else(|| "recipe operations must be an array".to_string())?;
        if operations.len() > MAX_OPERATIONS {
            return Err(format!("recipe: exceeds {MAX_OPERATIONS} operations"));
        }
        let operations = operations
            .iter()
            .enumerate()
            .map(|(i, v)| Operation::from_json(v).map_err(|e| format!("recipe operation {i}: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            digest: digest.to_string(),
            operations,
        })
    }

    pub fn apply_bytes(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        let input =
            std::str::from_utf8(input).map_err(|_| "recipe input: invalid UTF-8".to_string())?;
        let mut budget = ProcessingBudget::new(MAX_CUMULATIVE_PROCESSED_BYTES);
        self.apply_with_budget_impl(input, &mut budget)
            .map(String::into_bytes)
    }

    pub(crate) fn apply_with_budget(
        &self,
        input: &str,
        total_budget: &mut ProcessingBudget,
    ) -> Result<String, String> {
        let mut per_recipe_budget = ProcessingBudget::new(MAX_CUMULATIVE_PROCESSED_BYTES);
        let mut budget = CombinedBudget {
            per_recipe: &mut per_recipe_budget,
            total: total_budget,
        };
        self.apply_with_budget_impl(input, &mut budget)
    }

    fn apply_with_budget_impl<B: Budget>(
        &self,
        input: &str,
        budget: &mut B,
    ) -> Result<String, String> {
        let mut value = input.to_string();
        if input.len() > MAX_INPUT {
            return Err("recipe input: exceeds profile byte limit".to_string());
        }
        validate_digest(&self.digest)?;
        for (i, operation) in self.operations.iter().enumerate() {
            budget.charge(&value)?;
            value = operation
                .apply(&value, budget)
                .map_err(|e| format!("recipe operation {i} ({}): {e}", operation.kind))?;
            if value.len() > MAX_OUTPUT {
                return Err(format!(
                    "recipe operation {i} ({}): output exceeds profile byte limit",
                    operation.kind
                ));
            }
        }
        Ok(value)
    }

    pub fn apply(&self, input: &str) -> Result<String, String> {
        String::from_utf8(self.apply_bytes(input.as_bytes())?)
            .map_err(|_| "recipe output: invalid UTF-8".to_string())
    }
}

pub(crate) struct ProcessingBudget {
    remaining: usize,
    exhausted: bool,
}

impl ProcessingBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exhausted: false,
        }
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.exhausted
    }
}

trait Budget {
    fn charge(&mut self, value: &str) -> Result<(), String>;
}

impl Budget for ProcessingBudget {
    fn charge(&mut self, value: &str) -> Result<(), String> {
        self.remaining = match self.remaining.checked_sub(value.len()) {
            Some(remaining) => remaining,
            None => {
                self.exhausted = true;
                return Err("recipe: exceeds cumulative processing budget".to_string());
            }
        };
        Ok(())
    }
}

struct CombinedBudget<'a> {
    per_recipe: &'a mut ProcessingBudget,
    total: &'a mut ProcessingBudget,
}

impl Budget for CombinedBudget<'_> {
    fn charge(&mut self, value: &str) -> Result<(), String> {
        self.per_recipe.charge(value)?;
        self.total.charge(value)
    }
}

impl Operation {
    fn from_json(value: &Value) -> Result<Self, String> {
        let fields = value
            .as_object()
            .ok_or_else(|| "operation must be an object".to_string())?
            .clone();
        let kind = required_str(&fields, "kind")?.to_string();
        let operation = Self { kind, fields };
        operation.validate()?;
        Ok(operation)
    }

    fn validate(&self) -> Result<(), String> {
        for field in ["selector", "profile"] {
            if let Some(value) = self.fields.get(field).and_then(Value::as_str) {
                if value.chars().any(char::is_control) {
                    return Err(format!(
                        "{field} for {} contains control character",
                        self.kind
                    ));
                }
            }
        }
        let (required, optional): (&[&str], &[&str]) = match self.kind.as_str() {
            "identity"
            | "lowercase"
            | "invisible_strip"
            | "hex_decode"
            | "leetspeak"
            | "vowel_fold"
            | "query_unescape"
            | "invisible_space"
            | "hex_decode_liberal"
            | "html_entity_decode"
            | "whitespace_compact"
            | "url_noise_strip"
            | "ordered_query_concat"
            | "hostname_dot_remove"
            | "canary_canonicalize" => (&["kind"], &[]),
            "url_component" => (&["kind", "component"], &["selector", "occurrence"]),
            "percent_decode" => (&["kind", "passes"], &[]),
            "dlp_normalize" | "matching_normalize" => (&["kind", "profile"], &[]),
            "base32_decode" | "base64_decode" | "base32_decode_liberal" => {
                (&["kind"], &["decode_padding"])
            }
            "base64_decode_liberal" => (&["kind", "alphabet"], &["decode_padding"]),
            "encoded_token_normalize" => (&["kind", "alphabet"], &[]),
            "text_segment" => (&["kind"], &["occurrence"]),
            "query_subsequence" => (&["kind", "indices"], &[]),
            "encoded_run" => (&["kind", "minimum_length"], &["occurrence"]),
            _ => return Err(format!("unknown operation {:?}", self.kind)),
        };
        let allowed: BTreeSet<_> = required.iter().chain(optional).copied().collect();
        for key in self.fields.keys() {
            if !allowed.contains(key.as_str()) {
                return Err(format!("unsupported {key} for {}", self.kind));
            }
        }
        for key in required {
            if !self.fields.contains_key(*key) {
                return Err(format!("missing {key}"));
            }
        }
        match self.kind.as_str() {
            "url_component" => {
                let component = required_str(&self.fields, "component")?;
                if ![
                    "url",
                    "hostname",
                    "path",
                    "query_key",
                    "query_value",
                    "raw_query",
                ]
                .contains(&component)
                {
                    return Err(format!("unknown URL component {component:?}"));
                }
                if ["query_key", "query_value"].contains(&component) {
                    let selector = self
                        .fields
                        .get("selector")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "query component: missing selector".to_string())?;
                    if selector.is_empty() {
                        return Err("query component: missing selector".to_string());
                    }
                } else if self.fields.contains_key("selector") {
                    return Err(format!("unsupported selector for {}", self.kind));
                } else if self.fields.contains_key("occurrence") {
                    return Err(format!("unsupported occurrence for {}", self.kind));
                }
                optional_u32(&self.fields, "occurrence")?;
            }
            "percent_decode" => {
                let n = required_u32(&self.fields, "passes")?;
                if !(1..=4).contains(&n) {
                    return Err("percent decode passes must be 1..4".to_string());
                }
            }
            "dlp_normalize" if required_str(&self.fields, "profile")? != "pipelock-dlp-v1" => {
                return Err(format!(
                    "unknown DLP profile {:?}",
                    required_str(&self.fields, "profile")?
                ))
            }
            "matching_normalize"
                if required_str(&self.fields, "profile")? != "pipelock-matching-v1" =>
            {
                return Err(format!(
                    "unknown matching profile {:?}",
                    required_str(&self.fields, "profile")?
                ))
            }
            "base32_decode" | "base64_decode" | "base32_decode_liberal" => {
                optional_bool(&self.fields, "decode_padding")?;
            }
            "base64_decode_liberal" => {
                optional_bool(&self.fields, "decode_padding")?;
                if !["standard", "url"].contains(&required_str(&self.fields, "alphabet")?) {
                    return Err(format!(
                        "unknown base64 alphabet {:?}",
                        required_str(&self.fields, "alphabet")?
                    ));
                }
            }
            "encoded_token_normalize"
                if !["hex", "base32", "base64_standard", "base64_url"]
                    .contains(&required_str(&self.fields, "alphabet")?) =>
            {
                return Err(format!(
                    "unknown encoded-token alphabet {:?}",
                    required_str(&self.fields, "alphabet")?
                ));
            }
            "encoded_token_normalize" => {}
            "text_segment" => {
                optional_u32(&self.fields, "occurrence")?;
            }
            "encoded_run" => {
                optional_u32(&self.fields, "occurrence")?;
                if required_u32(&self.fields, "minimum_length")? == 0 {
                    return Err("encoded run minimum_length must be positive".to_string());
                }
            }
            "query_subsequence" => {
                let indices = self.fields["indices"]
                    .as_array()
                    .ok_or_else(|| "query subsequence indices must be an array".to_string())?;
                if !(2..=4).contains(&indices.len()) {
                    return Err("query subsequence indices must contain 2..4 entries".to_string());
                }
                let mut last = None;
                for item in indices {
                    let n = item.as_u64().filter(|n| *n < 20).ok_or_else(|| {
                        "query subsequence index exceeds scanner limit".to_string()
                    })? as u8;
                    if last.is_some_and(|p| n <= p) {
                        return Err(
                            "query subsequence indices must be strictly increasing".to_string()
                        );
                    }
                    last = Some(n);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn apply<B: Budget>(&self, value: &str, budget: &mut B) -> Result<String, String> {
        match self.kind.as_str() {
            "identity" => Ok(value.to_string()),
            "url_component" => url_component(
                value,
                required_str(&self.fields, "component")?,
                self.fields.get("selector").and_then(Value::as_str),
                optional_u32(&self.fields, "occurrence")?.unwrap_or(0),
                budget,
            ),
            "percent_decode" => {
                let mut v = value.to_string();
                for _ in 0..required_u32(&self.fields, "passes")? {
                    budget.charge(&v)?;
                    v = strict_percent_decode(&v, false)
                        .map_err(|e| format!("percent decode: {e}"))?;
                }
                Ok(v)
            }
            "dlp_normalize" => Ok(dlp_normalize(value)),
            // Go's strings.ToLower applies the Unicode simple one-rune mapping;
            // do not retain Rust's occasional multi-rune full-case expansion.
            "lowercase" => Ok(value
                .chars()
                .map(|c| c.to_lowercase().next().unwrap_or(c))
                .collect()),
            "invisible_strip" => Ok(map_invisible(value, None)),
            "hex_decode" => strict_hex(value, true, "hex decode"),
            "base32_decode" => base32_decode(
                value,
                optional_bool(&self.fields, "decode_padding")?.unwrap_or(false),
                true,
                "base32 decode",
            ),
            "base64_decode" => base64_decode(
                value,
                false,
                optional_bool(&self.fields, "decode_padding")?.unwrap_or(false),
                true,
                "base64 decode",
            ),
            "leetspeak" => Ok(value
                .chars()
                .map(|c| match c {
                    '0' => 'o',
                    '1' => 'i',
                    '3' => 'e',
                    '4' => 'a',
                    '5' => 's',
                    '7' => 't',
                    '@' => 'a',
                    '$' => 's',
                    x => x,
                })
                .collect()),
            "vowel_fold" => Ok(value
                .chars()
                .map(|c| match c {
                    'a' | 'e' | 'i' | 'o' | 'u' => 'a',
                    'A' | 'E' | 'I' | 'O' | 'U' => 'A',
                    x => x,
                })
                .collect()),
            "query_unescape" => query_unescape(value, budget),
            "invisible_space" => Ok(map_invisible(value, Some(' '))),
            "matching_normalize" => Ok(matching_normalize(value)),
            "hex_decode_liberal" => strict_hex(value, false, "liberal hex decode"),
            "base32_decode_liberal" => base32_decode(
                value,
                optional_bool(&self.fields, "decode_padding")?.unwrap_or(false),
                false,
                "liberal base32 decode",
            ),
            "base64_decode_liberal" => base64_decode(
                value,
                required_str(&self.fields, "alphabet")? == "url",
                optional_bool(&self.fields, "decode_padding")?.unwrap_or(false),
                false,
                "liberal base64 decode",
            ),
            "encoded_token_normalize" => Ok(encoded_token_normalize(
                value,
                required_str(&self.fields, "alphabet")?,
            )),
            "text_segment" => text_segment(
                value,
                optional_u32(&self.fields, "occurrence")?.unwrap_or(0),
            ),
            "html_entity_decode" => html_decode(value, budget),
            "whitespace_compact" => Ok(value.chars().filter(|c| !c.is_whitespace()).collect()),
            "url_noise_strip" => Ok(strip_chars(value, "./ \t\n\r+,;|")),
            "ordered_query_concat" => query_values(value)
                .into_iter()
                .map(|v| query_unescape(&v, budget))
                .collect(),
            "query_subsequence" => {
                let values = query_values(value)
                    .into_iter()
                    .take(20)
                    .map(|v| query_unescape(&v, budget))
                    .collect::<Result<Vec<_>, _>>()?;
                self.fields["indices"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| {
                        let i = v.as_u64().unwrap() as usize;
                        values
                            .get(i)
                            .cloned()
                            .ok_or_else(|| format!("query subsequence: index {i} unavailable"))
                    })
                    .collect()
            }
            "hostname_dot_remove" => Ok(value.replace('.', "")),
            "encoded_run" => encoded_run(
                value,
                optional_u32(&self.fields, "occurrence")?.unwrap_or(0),
                required_u32(&self.fields, "minimum_length")?,
            ),
            "canary_canonicalize" => Ok(strip_chars(value, "./\\?&= \t\n\r:;,-_@%+#")),
            _ => unreachable!(),
        }
    }
}

fn validate_digest(digest: &str) -> Result<(), String> {
    if digest.is_empty() {
        return Err("recipe: missing transform profile digest".to_string());
    }
    let valid_shape = digest.strip_prefix("sha256:").is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    });
    if !valid_shape {
        return Err("recipe: transform profile digest: invalid SHA-256 digest".to_string());
    }
    if digest != PROFILE_DIGEST {
        return Err("recipe: transform profile digest: unknown profile".to_string());
    }
    Ok(())
}
fn required_str<'a>(m: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    m.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))
}
fn required_u32(m: &Map<String, Value>, key: &str) -> Result<u32, String> {
    optional_u32(m, key)?.ok_or_else(|| format!("missing {key}"))
}
fn optional_u32(m: &Map<String, Value>, key: &str) -> Result<Option<u32>, String> {
    match m.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| format!("{key} must be a uint32")),
    }
}
fn optional_bool(m: &Map<String, Value>, key: &str) -> Result<Option<bool>, String> {
    match m.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("{key} must be a boolean")),
    }
}

fn strict_percent_decode(s: &str, plus: bool) -> Result<String, String> {
    let bytes = if plus {
        s.replace('+', " ")
    } else {
        s.to_string()
    };
    for (i, b) in bytes.as_bytes().iter().enumerate() {
        if *b == b'%'
            && (i + 2 >= bytes.len()
                || !bytes.as_bytes()[i + 1].is_ascii_hexdigit()
                || !bytes.as_bytes()[i + 2].is_ascii_hexdigit())
        {
            return Err("invalid URL escape".to_string());
        }
    }
    String::from_utf8(percent_decode_str(&bytes).collect())
        .map_err(|_| "output: invalid UTF-8".to_string())
}
fn query_unescape<B: Budget>(s: &str, budget: &mut B) -> Result<String, String> {
    let mut v = s.to_string();
    for _ in 0..500 {
        budget.charge(&v)?;
        match strict_percent_decode(&v, true) {
            Ok(next) if next != v => v = next,
            _ => break,
        }
    }
    Ok(v)
}
fn url_component(
    value: &str,
    component: &str,
    selector: Option<&str>,
    occurrence: u32,
    budget: &mut impl Budget,
) -> Result<String, String> {
    let u = Url::parse(value).map_err(|_| "URL parse: invalid absolute URL".to_string())?;
    if u.scheme().is_empty() || u.host_str().is_none() {
        return Err("URL parse: invalid absolute URL".to_string());
    }
    // A malformed absolute URL such as "https:api.vendor.example" carries a
    // scheme but no literal "://" authority. raw_hostname falls back to the
    // whole value in that case and yields a fabricated hostname, so a proof
    // would commit to a source view that does not exist. Go rejects this input;
    // match it before any component dispatch.
    if !value.contains("://") {
        return Err("URL parse: invalid absolute URL".to_string());
    }
    match component {
        "url" => Ok(value.to_string()),
        "hostname" => Ok(raw_hostname(value)),
        "path" => Ok(u.path().to_string()),
        "raw_query" => Ok(u.query().unwrap_or("").to_string()),
        "query_key" | "query_value" => {
            let key = selector.ok_or_else(|| "query component: missing selector".to_string())?;
            let pairs = strict_query(u.query().unwrap_or(""), budget)?;
            let values: Vec<_> = pairs
                .into_iter()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v)
                .collect();
            let v = values
                .get(occurrence as usize)
                .ok_or_else(|| format!("query component: occurrence {occurrence} unavailable"))?;
            if component == "query_key" {
                Ok(key.to_string())
            } else {
                Ok(v.clone())
            }
        }
        _ => unreachable!(),
    }
}
fn raw_hostname(value: &str) -> String {
    let rest = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    if let Some(bracketed) = host_port.strip_prefix('[') {
        return bracketed.split(']').next().unwrap_or("").to_string();
    }
    host_port
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(host_port)
        .to_string()
}
fn strict_query<B: Budget>(q: &str, budget: &mut B) -> Result<Vec<(String, String)>, String> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            budget.charge(k)?;
            budget.charge(v)?;
            Ok((
                strict_percent_decode(k, true).map_err(|e| format!("query parse: {e}"))?,
                strict_percent_decode(v, true).map_err(|e| format!("query parse: {e}"))?,
            ))
        })
        .collect()
}
fn strict_hex(s: &str, canonical: bool, label: &str) -> Result<String, String> {
    let b = hex::decode(s).map_err(|e| format!("{label}: {e}"))?;
    if canonical && hex::encode(&b) != s {
        return Err(format!("{label}: non-canonical encoding"));
    }
    String::from_utf8(b).map_err(|_| format!("{label} output: invalid UTF-8"))
}
fn base32_decode(s: &str, padded: bool, canonical: bool, label: &str) -> Result<String, String> {
    let data_len = s.trim_end_matches('=').len();
    let padding = s.len() - data_len;
    let expected_padding = match data_len % 8 {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        _ => return Err(format!("{label}: invalid padding")),
    };
    if (padded && padding != expected_padding) || (!padded && padding != 0) {
        return Err(format!("{label}: invalid padding"));
    }
    let b = liberal_base32_bytes(s).map_err(|e| format!("{label}: {e}"))?;
    let encoded = BASE32.encode(&b);
    let want = if padded {
        encoded
    } else {
        encoded.trim_end_matches('=').to_string()
    };
    if canonical && want != s {
        return Err(format!("{label}: non-canonical encoding"));
    }
    String::from_utf8(b).map_err(|_| format!("{label} output: invalid UTF-8"))
}

// Go's encoding/base32 decoder deliberately accepts non-zero unused trailing
// bits. The liberal profile operation pins that behavior; strict mode gets its
// canonicality from the re-encode comparison above.
fn liberal_base32_bytes(s: &str) -> Result<Vec<u8>, String> {
    let data = s.trim_end_matches('=');
    if s[data.len()..].chars().any(|c| c != '=') {
        return Err("invalid base32 padding".to_string());
    }
    let mut bits = 0_u32;
    let mut count = 0_u8;
    let mut out = Vec::new();
    for byte in data.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err("invalid base32 character".to_string()),
        } as u32;
        bits = (bits << 5) | value;
        count += 5;
        while count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Ok(out)
}
fn base64_decode(
    s: &str,
    url: bool,
    padded: bool,
    canonical: bool,
    label: &str,
) -> Result<String, String> {
    let config = (if padded {
        general_purpose::PAD
    } else {
        general_purpose::NO_PAD
    })
    .with_decode_allow_trailing_bits(!canonical);
    let e = general_purpose::GeneralPurpose::new(
        if url {
            &alphabet::URL_SAFE
        } else {
            &alphabet::STANDARD
        },
        config,
    );
    let b = e.decode(s).map_err(|x| format!("{label}: {x}"))?;
    if canonical && e.encode(&b) != s {
        return Err(format!("{label}: non-canonical encoding"));
    }
    String::from_utf8(b).map_err(|_| format!("{label} output: invalid UTF-8"))
}

fn invisible(c: char) -> bool {
    (c <= '\u{1f}' && c != '\t' && c != '\n' && c != '\r')
        || c == '\u{7f}'
        || ('\u{80}'..='\u{9f}').contains(&c)
        || matches!(c, '\u{ad}' | '\u{3164}' | '\u{feff}')
        || ('\u{115f}'..='\u{1160}').contains(&c)
        || ('\u{200b}'..='\u{200f}').contains(&c)
        || ('\u{202a}'..='\u{202e}').contains(&c)
        || ('\u{2060}'..='\u{2064}').contains(&c)
        || ('\u{2066}'..='\u{2069}').contains(&c)
        || ('\u{fe00}'..='\u{fe0f}').contains(&c)
        || ('\u{fff9}'..='\u{fffb}').contains(&c)
        || ('\u{e0000}'..='\u{e007f}').contains(&c)
        || ('\u{e0100}'..='\u{e01ef}').contains(&c)
}
fn map_invisible(s: &str, replacement: Option<char>) -> String {
    s.chars()
        .filter_map(|c| if invisible(c) { replacement } else { Some(c) })
        .collect()
}
fn exotic(c: char) -> bool {
    matches!(
        c,
        '\u{a0}'
            | '\u{1680}'
            | '\u{180e}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    ) || ('\u{2000}'..='\u{200a}').contains(&c)
}
fn confusable(c: char) -> char {
    let x = c as u32;
    if (0x1f170..=0x1f189).contains(&x) || (0x1f1e6..=0x1f1ff).contains(&x) {
        return char::from_u32('A' as u32 + x - if x >= 0x1f1e6 { 0x1f1e6 } else { 0x1f170 })
            .unwrap();
    }
    match c {
        'А' => 'A',
        'В' => 'B',
        'С' => 'C',
        'Е' => 'E',
        'Н' => 'H',
        'І' => 'I',
        'Ј' => 'J',
        'К' => 'K',
        'М' => 'M',
        'О' => 'O',
        'Р' => 'P',
        'Ѕ' => 'S',
        'Т' => 'T',
        'Х' => 'X',
        'а' => 'a',
        'в' => 'v',
        'е' => 'e',
        'н' => 'h',
        'і' => 'i',
        'к' => 'k',
        'м' => 'm',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'т' => 't',
        'у' => 'y',
        'х' => 'x',
        'ј' => 'j',
        'ѕ' => 's',
        'Α' => 'A',
        'Β' => 'B',
        'Ε' => 'E',
        'Ζ' => 'Z',
        'Η' => 'H',
        'Ι' => 'I',
        'Κ' => 'K',
        'Μ' => 'M',
        'Ν' => 'N',
        'Ο' => 'O',
        'Ρ' => 'P',
        'Τ' => 'T',
        'Υ' => 'Y',
        'Χ' => 'X',
        'α' => 'a',
        'ε' => 'e',
        'ι' => 'i',
        'κ' => 'k',
        'ν' => 'v',
        'ο' => 'o',
        'Օ' => 'O',
        'օ' => 'o',
        'Ս' => 'S',
        'ս' => 's',
        '\u{054c}' => 'L',
        'հ' => 'h',
        'ո' => 'n',
        'ռ' => 'n',
        'ա' => 'a',
        'Ꭺ' => 'A',
        'Ꭲ' => 'I',
        '\u{13d2}' => 'P',
        'Ꮪ' => 'S',
        'Ꭱ' => 'E',
        'Ꮃ' => 'W',
        'Ꮤ' => 'T',
        'Ø' => 'O',
        'ø' => 'o',
        'Đ' => 'D',
        'đ' => 'd',
        'Ł' => 'L',
        'ł' => 'l',
        'Ħ' => 'H',
        'ħ' => 'h',
        'Ŧ' => 'T',
        'ŧ' => 't',
        'ᴀ' => 'A',
        'ʙ' => 'B',
        'ᴄ' => 'C',
        'ᴅ' => 'D',
        'ᴇ' => 'E',
        'ꜰ' => 'F',
        'ɢ' => 'G',
        'ʜ' => 'H',
        'ɪ' => 'I',
        'ᴊ' => 'J',
        'ᴋ' => 'K',
        'ʟ' => 'L',
        'ᴍ' => 'M',
        'ɴ' => 'N',
        'ᴏ' => 'O',
        'ᴘ' => 'P',
        'ʀ' => 'R',
        'ꜱ' => 'S',
        'ᴛ' => 'T',
        'ᴜ' => 'U',
        'ᴠ' => 'V',
        'ᴡ' => 'W',
        'ʏ' => 'Y',
        'ᴢ' => 'Z',
        x => x,
    }
}
fn dlp_normalize(s: &str) -> String {
    s.chars()
        // DLP differs from matching: it removes all C0/C1 controls, including
        // TAB/LF/CR, before normalization.
        .filter(|c| !dlp_control_or_invisible(*c) && !exotic(*c))
        .collect::<String>()
        .nfkc()
        .map(confusable)
        .collect::<String>()
        .nfd()
        .filter(|c| !is_combining_mark(*c))
        .collect()
}
fn matching_normalize(s: &str) -> String {
    let x = map_invisible(s, None)
        .nfkc()
        .map(confusable)
        .collect::<String>()
        .nfd()
        .filter(|c| !is_combining_mark(*c))
        .collect::<String>();
    // ForMatching maps the explicit exotic set to spaces, but deliberately
    // preserves leading/trailing and repeated ordinary whitespace.
    x.chars().map(|c| if exotic(c) { ' ' } else { c }).collect()
}

fn dlp_control_or_invisible(c: char) -> bool {
    (c <= '\u{1f}' || c == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&c)) || invisible(c)
}
fn encoded_token_normalize(s: &str, a: &str) -> String {
    if s.len() < 4 {
        return String::new();
    }
    if a == "hex" {
        let v = s
            .replace("\\x", "")
            .replace("\\X", "")
            .replace("0x", "")
            .replace("0X", "")
            .chars()
            .filter(|c| !matches!(c, ':' | ' ' | '-' | ','))
            .collect::<String>();
        return if !v.is_empty() && v.len() % 2 == 0 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
            v
        } else {
            String::new()
        };
    }
    let mut changed = false;
    let mut out = String::new();
    for b in s.bytes() {
        let data = b.is_ascii_uppercase()
            || (a != "base32" && b.is_ascii_lowercase())
            || (b.is_ascii_digit() && (a != "base32" || (b'2'..=b'7').contains(&b)))
            || b == b'='
            || (a == "base64_standard" && matches!(b, b'+' | b'/'))
            || (a == "base64_url" && matches!(b, b'-' | b'_'));
        let sep = matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | 0x0b | b'.')
            || (a == "base64_standard" && matches!(b, b'-' | b'_'))
            || (a == "base64_url" && matches!(b, b'/' | b'+'))
            || (a == "base32" && matches!(b, b'-' | b'_' | b'/'));
        if data {
            out.push(b as char)
        } else if sep {
            changed = true
        } else {
            return String::new();
        }
    }
    if changed && out.len() >= 4 {
        out
    } else {
        String::new()
    }
}
fn text_segment(s: &str, n: u32) -> Result<String, String> {
    let d = |c: char| {
        matches!(
            c,
            '/' | '?'
                | '&'
                | '='
                | ' '
                | '\n'
                | '\r'
                | '\t'
                | '"'
                | '\''
                | '`'
                | '{'
                | '}'
                | '['
                | ']'
                | '('
                | ')'
                | '<'
                | '>'
                | ':'
                | ','
                | ';'
        )
    };
    s.split(d)
        .filter(|x| !x.is_empty())
        .nth(n as usize)
        .map(ToString::to_string)
        .ok_or_else(|| format!("text segment: occurrence {n} unavailable"))
}
fn html_decode<B: Budget>(s: &str, budget: &mut B) -> Result<String, String> {
    let mut v = s.to_string();
    for _ in 0..16 {
        budget.charge(&v)?;
        let n = html_escape::decode_html_entities(&v).into_owned();
        if n == v {
            break;
        }
        v = n
    }
    Ok(v)
}
fn strip_chars(s: &str, chars: &str) -> String {
    s.chars().filter(|c| !chars.contains(*c)).collect()
}
fn query_values(q: &str) -> Vec<String> {
    q.split('&')
        .filter_map(|p| p.split_once('=').map(|(_, v)| v.to_string()))
        .filter(|v| !v.is_empty())
        .collect()
}
fn encoded_run(s: &str, n: u32, min: u32) -> Result<String, String> {
    let mut runs = Vec::new();
    let b = s.as_bytes();
    let mut start = None;
    for i in 0..b.len() {
        if b[i].is_ascii_alphanumeric() || matches!(b[i], b'+' | b'/' | b'-' | b'_') {
            start.get_or_insert(i);
        } else if let Some(x) = start.take() {
            let mut e = i;
            while e < i + 2 && e < b.len() && b[e] == b'=' {
                e += 1
            }
            if e - x >= min as usize {
                runs.push(s[x..e].to_string())
            }
        }
    }
    if let Some(x) = start {
        if b.len() - x >= min as usize {
            runs.push(s[x..].to_string())
        }
    }
    runs.get(n as usize)
        .cloned()
        .ok_or_else(|| format!("encoded run: occurrence {n} unavailable"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn recipe_limits_reject_unbounded_verifier_work() {
        // Keep the normative boundary independent of MAX_OPERATIONS so
        // neutralizing the guard makes this test fail rather than move with it.
        let operations = Value::Array(vec![json!({"kind": "identity"}); 33]);
        let error = Recipe::from_json(PROFILE_DIGEST, &operations).unwrap_err();
        assert!(error.contains("exceeds 32 operations"), "{error}");

        let token = format!("%{}", "25".repeat(500));
        let recipe =
            Recipe::from_json(PROFILE_DIGEST, &json!([{"kind": "query_unescape"}])).unwrap();
        let error = recipe.apply(&token.repeat(1500)).unwrap_err();
        assert!(error.contains("cumulative processing budget"), "{error}");
    }

    #[test]
    fn liberal_base64_accepts_nonzero_trailing_bits() {
        let recipe = Recipe::from_json(
            PROFILE_DIGEST,
            &json!([{
                "kind": "base64_decode_liberal",
                "alphabet": "standard",
                "decode_padding": true
            }]),
        )
        .unwrap();
        assert_eq!(recipe.apply("Zh==").unwrap(), "f");
    }

    #[test]
    fn ordered_query_concat_is_not_truncated_to_subsequence_limit() {
        let input = (0..21)
            .map(|index| format!("k{index}=x"))
            .collect::<Vec<_>>()
            .join("&");
        let recipe =
            Recipe::from_json(PROFILE_DIGEST, &json!([{"kind": "ordered_query_concat"}])).unwrap();
        assert_eq!(recipe.apply(&input).unwrap(), "x".repeat(21));
    }
}
