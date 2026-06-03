// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//! AARP envelope model and strict decoding, ported from `internal/aarp`
//! (envelope.go, suite.go, numbers.go grammars, chain.go).
//!
//! Decoding rejects unknown fields in AARP-controlled objects (profile,
//! subject, assertion, chain, signature, signature.protected) so a producer
//! cannot smuggle unsigned-but-meaningful content past appraisal. `ext` is a
//! free map and is not modelled here (it is not part of the signed payload).

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::jcs::{canonicalize_tree, enforce_safe_numbers, parse_strict, JcsError, Json};

pub const PROFILE: &str = "aarp/v0.1";
pub const CANON_ID: &str = "jcs-rfc8785-nfc";
pub const CONTEXT_ASSERTION: &str = "pipelock-aarp-v0.1/assurance-assertion";
pub const GENESIS_PRIOR_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

const HEX_DIGEST_LEN: usize = 64;

/// FatalError is any condition that makes an envelope unappraisable: a schema
/// violation, profile/canon mismatch, unknown critical extension, unsafe number,
/// duplicate key, trailing tokens, unknown field, or bad grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatalError(pub String);

impl std::fmt::Display for FatalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for FatalError {}

impl From<JcsError> for FatalError {
    fn from(err: JcsError) -> Self {
        FatalError(err.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ProtectedHeader {
    pub profile: String,
    pub canon: String,
    pub alg: String,
    pub key_type: String,
    pub key_id: String,
    pub signer_role: String,
    pub crit: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub protected: ProtectedHeader,
    pub sig: String,
}

#[derive(Debug, Clone)]
pub struct Subject {
    pub action_record_sha256: String,
    pub receipt_envelope_sha256: String,
    pub receipt_signer_key: String,
    pub receipt_type: String,
}

#[derive(Debug, Clone)]
pub struct Assertion {
    pub claimed: Vec<String>,
    pub mediator_id: String,
    pub trust_domain: String,
}

#[derive(Debug, Clone)]
pub struct ChainLink {
    pub issuer_id: String,
    pub seq: String,
    pub prior_hash: String,
}

#[derive(Debug, Clone)]
pub struct Envelope {
    pub profile: String,
    pub subject: Subject,
    pub assertion: Assertion,
    pub chain: Option<ChainLink>,
    pub signatures: Vec<Signature>,
    pub crit_ext: Vec<String>,
    /// The strict-parse tree, retained so the signed payload can be rebuilt and
    /// canonicalized exactly (profile, subject, assertion, crit_ext?, chain?).
    tree: Json,
}

// ---- helpers over the strict-parse tree ----

fn obj<'a>(value: &'a Json, ctx: &str) -> Result<&'a BTreeMap<String, Json>, FatalError> {
    match value {
        Json::Object(map) => Ok(map),
        _ => Err(FatalError(format!("{ctx} must be an object"))),
    }
}

fn require_str(map: &BTreeMap<String, Json>, key: &str, ctx: &str) -> Result<String, FatalError> {
    match map.get(key) {
        Some(Json::String(s)) => Ok(s.clone()),
        Some(_) => Err(FatalError(format!("{ctx}.{key} must be a string"))),
        None => Err(FatalError(format!("{ctx}.{key} is required"))),
    }
}

fn opt_str(map: &BTreeMap<String, Json>, key: &str, ctx: &str) -> Result<String, FatalError> {
    match map.get(key) {
        Some(Json::String(s)) => Ok(s.clone()),
        Some(_) => Err(FatalError(format!("{ctx}.{key} must be a string"))),
        None => Ok(String::new()),
    }
}

fn require_bool(map: &BTreeMap<String, Json>, key: &str, ctx: &str) -> Result<bool, FatalError> {
    match map.get(key) {
        Some(Json::Bool(b)) => Ok(*b),
        Some(_) => Err(FatalError(format!("{ctx}.{key} must be a boolean"))),
        None => Err(FatalError(format!("{ctx}.{key} is required"))),
    }
}

fn str_array(
    map: &BTreeMap<String, Json>,
    key: &str,
    ctx: &str,
) -> Result<Vec<String>, FatalError> {
    match map.get(key) {
        Some(Json::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Json::String(s) => out.push(s.clone()),
                    _ => {
                        return Err(FatalError(format!(
                            "{ctx}.{key} must be an array of strings"
                        )))
                    }
                }
            }
            Ok(out)
        }
        Some(Json::Null) | None => Ok(Vec::new()),
        Some(_) => Err(FatalError(format!("{ctx}.{key} must be an array"))),
    }
}

/// reject_unknown_fields fails if the object carries a key outside `allowed`.
/// Mirrors Go's `DisallowUnknownFields` on AARP-controlled objects.
fn reject_unknown_fields(
    map: &BTreeMap<String, Json>,
    allowed: &[&str],
    ctx: &str,
) -> Result<(), FatalError> {
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(FatalError(format!(
                "unknown field {key:?} in AARP-controlled object {ctx}"
            )));
        }
    }
    Ok(())
}

// ---- grammar validators (numbers.go) ----

pub fn validate_hex256(s: &str, ctx: &str) -> Result<(), FatalError> {
    if s.len() != HEX_DIGEST_LEN {
        return Err(FatalError(format!(
            "{ctx}: digest length {}, want {HEX_DIGEST_LEN}",
            s.len()
        )));
    }
    for c in s.bytes() {
        let ok = c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
        if !ok {
            return Err(FatalError(format!(
                "{ctx}: digest contains non-lowercase-hex byte {:?}",
                c as char
            )));
        }
    }
    Ok(())
}

pub fn validate_uint64_string(s: &str, ctx: &str) -> Result<(), FatalError> {
    if s.is_empty() {
        return Err(FatalError(format!("{ctx}: empty unsigned counter")));
    }
    if s == "0" {
        return Ok(());
    }
    if s.starts_with('0') {
        return Err(FatalError(format!("{ctx}: leading zero in counter {s:?}")));
    }
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            return Err(FatalError(format!("{ctx}: non-digit in counter {s:?}")));
        }
    }
    // Range-check against u64.
    if s.parse::<u64>().is_err() {
        return Err(FatalError(format!("{ctx}: counter {s:?} exceeds uint64")));
    }
    Ok(())
}

/// validate_timestamp checks an RFC3339Nano timestamp with a mandatory zone,
/// matching Go's `time.Parse(time.RFC3339Nano, s)`.
pub fn validate_timestamp(s: &str, ctx: &str) -> Result<(), FatalError> {
    if s.is_empty() {
        return Err(FatalError(format!("{ctx}: empty timestamp")));
    }
    if rfc3339nano_valid(s) {
        Ok(())
    } else {
        Err(FatalError(format!(
            "{ctx}: timestamp {s:?} is not RFC3339Nano"
        )))
    }
}

/// rfc3339nano_valid implements the subset of RFC3339 that Go's RFC3339Nano
/// layout accepts: `YYYY-MM-DDTHH:MM:SS[.fraction]<zone>` where the date/time
/// separators are literal and the zone is `Z` or `±HH:MM`.
fn rfc3339nano_valid(s: &str) -> bool {
    let bytes = s.as_bytes();
    // Minimum: 2006-01-02T15:04:05Z = 20 chars.
    if bytes.len() < 20 {
        return false;
    }
    let digit = |b: u8| b.is_ascii_digit();
    // YYYY-MM-DD
    if !(digit(bytes[0])
        && digit(bytes[1])
        && digit(bytes[2])
        && digit(bytes[3])
        && bytes[4] == b'-'
        && digit(bytes[5])
        && digit(bytes[6])
        && bytes[7] == b'-'
        && digit(bytes[8])
        && digit(bytes[9])
        && bytes[10] == b'T')
    {
        return false;
    }
    // HH:MM:SS
    if !(digit(bytes[11])
        && digit(bytes[12])
        && bytes[13] == b':'
        && digit(bytes[14])
        && digit(bytes[15])
        && bytes[16] == b':'
        && digit(bytes[17])
        && digit(bytes[18]))
    {
        return false;
    }
    let mut idx = 19;
    // Optional fraction.
    if idx < bytes.len() && bytes[idx] == b'.' {
        idx += 1;
        let frac_start = idx;
        while idx < bytes.len() && digit(bytes[idx]) {
            idx += 1;
        }
        if idx == frac_start {
            return false; // dot with no digits
        }
    }
    // Zone: Z or ±HH:MM.
    if idx >= bytes.len() {
        return false;
    }
    match bytes[idx] {
        b'Z' => idx == bytes.len() - 1,
        b'+' | b'-' => {
            idx + 6 == bytes.len()
                && digit(bytes[idx + 1])
                && digit(bytes[idx + 2])
                && bytes[idx + 3] == b':'
                && digit(bytes[idx + 4])
                && digit(bytes[idx + 5])
        }
        _ => false,
    }
}

// ---- chain validation (chain.go) ----

impl ChainLink {
    pub fn validate(&self) -> Result<(), FatalError> {
        if self.issuer_id.is_empty() {
            return Err(FatalError("chain.issuer_id is required".to_string()));
        }
        validate_uint64_string(&self.seq, "chain.seq")?;
        validate_hex256(&self.prior_hash, "chain.prior_hash")?;
        if self.seq == "0" && self.prior_hash != GENESIS_PRIOR_HASH {
            return Err(FatalError(
                "genesis link (seq 0) must carry the zero prior hash".to_string(),
            ));
        }
        if self.seq != "0" && self.prior_hash == GENESIS_PRIOR_HASH {
            return Err(FatalError(format!(
                "non-genesis link (seq {}) must not carry the genesis prior hash",
                self.seq
            )));
        }
        Ok(())
    }
}

// ---- decode ----

impl Envelope {
    /// unmarshal parses and structurally validates an AARP envelope. It rejects
    /// duplicate keys (any depth), trailing tokens, unsafe numbers, unknown
    /// fields in AARP-controlled objects, and grammar violations. All failures
    /// are envelope-fatal.
    pub fn unmarshal(data: &str) -> Result<Envelope, FatalError> {
        let tree = parse_strict(data)?;
        enforce_safe_numbers(&tree)?;

        let root = obj(&tree, "envelope")?;
        reject_unknown_fields(
            root,
            &[
                "profile",
                "subject",
                "assertion",
                "chain",
                "signatures",
                "crit_ext",
                "ext",
            ],
            "envelope",
        )?;

        let profile = require_str(root, "profile", "envelope")?;

        let subject_map = obj(
            root.get("subject")
                .ok_or_else(|| FatalError("envelope.subject is required".to_string()))?,
            "subject",
        )?;
        reject_unknown_fields(
            subject_map,
            &[
                "action_record_sha256",
                "receipt_envelope_sha256",
                "receipt_signer_key",
                "receipt_type",
            ],
            "subject",
        )?;
        let subject = Subject {
            action_record_sha256: require_str(subject_map, "action_record_sha256", "subject")?,
            receipt_envelope_sha256: require_str(
                subject_map,
                "receipt_envelope_sha256",
                "subject",
            )?,
            receipt_signer_key: require_str(subject_map, "receipt_signer_key", "subject")?,
            receipt_type: require_str(subject_map, "receipt_type", "subject")?,
        };

        let assertion_map = obj(
            root.get("assertion")
                .ok_or_else(|| FatalError("envelope.assertion is required".to_string()))?,
            "assertion",
        )?;
        reject_unknown_fields(
            assertion_map,
            &[
                "claimed",
                "mediator_id",
                "trust_domain",
                "complete_mediation",
                "evidence_refs",
                "issued_at",
            ],
            "assertion",
        )?;
        // complete_mediation and issued_at are required by the Go struct shape
        // (non-pointer fields); enforce their presence/type.
        let _ = require_bool(assertion_map, "complete_mediation", "assertion")?;
        let issued_at = require_str(assertion_map, "issued_at", "assertion")?;
        let assertion = Assertion {
            claimed: str_array(assertion_map, "claimed", "assertion")?,
            mediator_id: require_str(assertion_map, "mediator_id", "assertion")?,
            trust_domain: opt_str(assertion_map, "trust_domain", "assertion")?,
        };

        let chain = match root.get("chain") {
            Some(value) => {
                let chain_map = obj(value, "chain")?;
                reject_unknown_fields(chain_map, &["issuer_id", "seq", "prior_hash"], "chain")?;
                Some(ChainLink {
                    issuer_id: require_str(chain_map, "issuer_id", "chain")?,
                    seq: require_str(chain_map, "seq", "chain")?,
                    prior_hash: require_str(chain_map, "prior_hash", "chain")?,
                })
            }
            None => None,
        };

        let crit_ext = str_array(root, "crit_ext", "envelope")?;

        let signatures = match root.get("signatures") {
            Some(Json::Array(items)) => {
                let mut sigs = Vec::with_capacity(items.len());
                for item in items {
                    sigs.push(parse_signature(item)?);
                }
                sigs
            }
            Some(_) => {
                return Err(FatalError(
                    "envelope.signatures must be an array".to_string(),
                ))
            }
            None => Vec::new(),
        };

        let env = Envelope {
            profile,
            subject,
            assertion,
            chain,
            signatures,
            crit_ext,
            tree,
        };

        // Validate grammars and structure now (all envelope-fatal).
        env.validate_structure(&issued_at)?;
        Ok(env)
    }

    fn validate_structure(&self, issued_at: &str) -> Result<(), FatalError> {
        if self.profile != PROFILE {
            return Err(FatalError(format!(
                "profile {:?}, want {PROFILE:?}",
                self.profile
            )));
        }
        validate_hex256(
            &self.subject.action_record_sha256,
            "subject.action_record_sha256",
        )?;
        validate_hex256(
            &self.subject.receipt_envelope_sha256,
            "subject.receipt_envelope_sha256",
        )?;
        validate_hex256(
            &self.subject.receipt_signer_key,
            "subject.receipt_signer_key",
        )?;
        if !matches!(
            self.subject.receipt_type.as_str(),
            "action_receipt_v1" | "evidence_receipt_v2"
        ) {
            return Err(FatalError(format!(
                "unknown subject.receipt_type {:?}",
                self.subject.receipt_type
            )));
        }
        if self.assertion.mediator_id.is_empty() {
            return Err(FatalError("assertion.mediator_id is required".to_string()));
        }
        validate_timestamp(issued_at, "assertion.issued_at")?;
        // trust_domain syntax (when set) is validated in the attestation layer;
        // core mirrors the non-empty/DNS-name guard via a light check here.
        if !self.assertion.trust_domain.is_empty() {
            validate_trust_domain(&self.assertion.trust_domain)?;
        }
        if let Some(chain) = &self.chain {
            chain.validate()?;
        }
        // The envelope-level crit_ext (the envelope's own critical-extension
        // list, part of the signed payload) STAYS envelope-fatal.
        check_critical_extensions(&self.crit_ext)?;

        if self.signatures.is_empty() {
            return Err(FatalError("envelope has no signatures".to_string()));
        }
        // Per-signature suite fields (a signature's protected profile, canon, and
        // its own critical-extension list) are deliberately NOT checked here:
        // they are per-signature outcomes appraised in `appraise_signature`. The
        // signatures array is not itself signed, so a man-in-the-middle can append
        // a junk signature; if a bad protected header were envelope-fatal, that
        // append would deny a legitimately-signed envelope. Per-signature handling
        // makes one unverifiable signature inert instead of fatal.
        Ok(())
    }

    /// canonical_payload returns the JCS-canonical bytes of the signed payload:
    /// `{profile, subject, assertion, crit_ext, chain?}` — never signatures,
    /// never ext. Built from the original strict-parse tree so the exact source
    /// representation (e.g. assertion's full field set) is preserved.
    ///
    /// `crit_ext` is ALWAYS emitted: a nil/absent envelope critical-extension
    /// list serializes as `"crit_ext":[]` (never omitted, never null), matching
    /// the Go `payload()` normalization (struct tag `json:"crit_ext"` with no
    /// omitempty). Without this, the computed payload digest would differ from
    /// Go and every signature would fail to verify. `chain` keeps `omitempty`
    /// (omitted when absent), matching the Go payload struct tag.
    pub fn canonical_payload(&self) -> Result<Vec<u8>, FatalError> {
        let root = obj(&self.tree, "envelope")?;
        let mut payload: BTreeMap<String, Json> = BTreeMap::new();
        for key in ["profile", "subject", "assertion", "chain"] {
            if let Some(value) = root.get(key) {
                // chain is omitempty: omitted when absent, matching the Go
                // payload struct tag.
                payload.insert(key.to_string(), value.clone());
            }
        }
        // crit_ext is never omitempty: a nil/absent or empty list normalizes to
        // an empty array so the signed canonical bytes match Go's payload().
        let crit_ext = match root.get("crit_ext") {
            Some(Json::Array(items)) => Json::Array(items.clone()),
            // Absent or null both normalize to [].
            _ => Json::Array(Vec::new()),
        };
        payload.insert("crit_ext".to_string(), crit_ext);
        canonicalize_tree(&Json::Object(payload)).map_err(FatalError::from)
    }

    pub fn payload_digest(&self) -> Result<String, FatalError> {
        let canonical = self.canonical_payload()?;
        Ok(hex::encode(Sha256::digest(&canonical)))
    }

    /// signing_input builds the canonical bytes one signature signs:
    /// `JCS({context, payload_sha256, protected})`.
    pub fn signing_input(
        payload_digest: &str,
        header: &ProtectedHeader,
    ) -> Result<Vec<u8>, FatalError> {
        let mut protected: BTreeMap<String, Json> = BTreeMap::new();
        protected.insert("profile".to_string(), Json::String(header.profile.clone()));
        protected.insert("canon".to_string(), Json::String(header.canon.clone()));
        protected.insert("alg".to_string(), Json::String(header.alg.clone()));
        protected.insert(
            "key_type".to_string(),
            Json::String(header.key_type.clone()),
        );
        protected.insert("key_id".to_string(), Json::String(header.key_id.clone()));
        protected.insert(
            "signer_role".to_string(),
            Json::String(header.signer_role.clone()),
        );
        // crit is omitempty: included only when non-empty (Go json `omitempty`).
        if !header.crit.is_empty() {
            protected.insert(
                "crit".to_string(),
                Json::Array(header.crit.iter().cloned().map(Json::String).collect()),
            );
        }

        let mut obj: BTreeMap<String, Json> = BTreeMap::new();
        obj.insert(
            "context".to_string(),
            Json::String(CONTEXT_ASSERTION.to_string()),
        );
        obj.insert(
            "payload_sha256".to_string(),
            Json::String(payload_digest.to_string()),
        );
        obj.insert("protected".to_string(), Json::Object(protected));

        canonicalize_tree(&Json::Object(obj)).map_err(FatalError::from)
    }
}

fn parse_signature(value: &Json) -> Result<Signature, FatalError> {
    let map = obj(value, "signature")?;
    reject_unknown_fields(map, &["protected", "sig"], "signature")?;
    let protected_map = obj(
        map.get("protected")
            .ok_or_else(|| FatalError("signature.protected is required".to_string()))?,
        "signature.protected",
    )?;
    reject_unknown_fields(
        protected_map,
        &[
            "profile",
            "canon",
            "alg",
            "key_type",
            "key_id",
            "signer_role",
            "crit",
        ],
        "signature.protected",
    )?;
    let protected = ProtectedHeader {
        profile: require_str(protected_map, "profile", "protected")?,
        canon: require_str(protected_map, "canon", "protected")?,
        alg: require_str(protected_map, "alg", "protected")?,
        key_type: require_str(protected_map, "key_type", "protected")?,
        key_id: require_str(protected_map, "key_id", "protected")?,
        signer_role: require_str(protected_map, "signer_role", "protected")?,
        crit: str_array(protected_map, "crit", "protected")?,
    };
    let sig = require_str(map, "sig", "signature")?;
    Ok(Signature { protected, sig })
}

/// CritError classifies a critical-extension list failure so callers can map a
/// malformed list and an unknown (but well-formed) name to different outcomes.
/// `Malformed` is an empty-string name or a duplicate; `Unknown` is a
/// well-formed name not in the (empty) v0.1 registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CritError {
    Malformed(String),
    Unknown(String),
}

impl CritError {
    pub fn message(&self) -> &str {
        match self {
            CritError::Malformed(msg) | CritError::Unknown(msg) => msg,
        }
    }
}

/// classify_critical_extensions checks a critical-extension list, returning the
/// classified failure (or Ok when the list is empty). The v0.1 registry is
/// empty, so any well-formed name is Unknown. Malformed names (empty string or
/// duplicate) are detected first, in list order, so the result is deterministic.
pub fn classify_critical_extensions(crit: &[String]) -> std::result::Result<(), CritError> {
    let mut seen = std::collections::HashSet::new();
    for name in crit {
        if name.is_empty() {
            return Err(CritError::Malformed(
                "empty critical extension name".to_string(),
            ));
        }
        if !seen.insert(name.clone()) {
            return Err(CritError::Malformed(format!(
                "duplicate critical extension {name:?}"
            )));
        }
    }
    // Registry is empty in v0.1: the first well-formed name is unknown.
    if let Some(name) = crit.first() {
        return Err(CritError::Unknown(format!(
            "unknown critical extension {name:?}"
        )));
    }
    Ok(())
}

/// check_critical_extensions rejects any critical extension name. The v0.1
/// registry is empty, so any name (and empty/duplicate names) is fatal. This is
/// the envelope-fatal path (envelope-level crit_ext); per-signature callers use
/// `classify_critical_extensions` to distinguish malformed from unknown.
pub fn check_critical_extensions(crit: &[String]) -> Result<(), FatalError> {
    classify_critical_extensions(crit).map_err(|err| FatalError(err.message().to_string()))
}

/// validate_trust_domain mirrors the core SPIFFE trust-domain syntax guard: a
/// non-empty DNS-name-like value, not an IP literal. The corpus does not set
/// trust_domain, so this is a structural guard for completeness.
fn validate_trust_domain(s: &str) -> Result<(), FatalError> {
    if s.is_empty() {
        return Err(FatalError("trust domain is empty".to_string()));
    }
    // Reject bare IP literals (SPIFFE requires a DNS name).
    if s.parse::<std::net::IpAddr>().is_ok() {
        return Err(FatalError(format!(
            "trust domain must be a DNS name, not an IP address: {s:?}"
        )));
    }
    // SPIFFE trust-domain names are lowercase letters, digits, and -._.
    let ok = s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | '_'));
    if !ok {
        return Err(FatalError(format!("invalid trust domain {s:?}")));
    }
    Ok(())
}
