// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//! AARP appraisal, ported from `internal/aarp` (verify.go, appraise.go,
//! suite.go, sign.go). Per-signature problems are reported per signature, never
//! as an envelope rejection, so one bad parallel signature can neither mask nor
//! poison a good one.

use std::collections::BTreeMap;

use base64::Engine;
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};

use super::envelope::{classify_critical_extensions, CritError, Envelope, CANON_ID, PROFILE};

// Axis names.
pub const AXIS_IDENTITY: &str = "identity";
pub const AXIS_INTEGRITY: &str = "integrity";
pub const AXIS_FRESHNESS: &str = "freshness";

// Verified-claim names.
pub const CLAIM_ASSERTION_SIGNATURE_VALID: &str = "assertion_signature_valid";
pub const CLAIM_MEDIATOR_KEY_PINNED: &str = "mediator_key_pinned";
pub const CLAIM_CHAIN_LINK_PRESENT: &str = "chain_link_present";

// Per-signature status enum values.
pub const SIG_VERIFIED: &str = "verified";
pub const SIG_FAILED: &str = "failed";
pub const SIG_UNKNOWN_KEY: &str = "unknown_key";
pub const SIG_UNIMPLEMENTED: &str = "unimplemented";
pub const SIG_UNKNOWN_SUITE: &str = "unknown_suite";
pub const SIG_MALFORMED: &str = "malformed";

const ALG_ED25519: &str = "ed25519";
const ALG_MLDSA65: &str = "ml-dsa-65";

const DOES_NOT_ASSERT: &[&str] = &[
    "efficacy",
    "absence_of_bypass",
    "complete_mediation",
    "policy_correctness",
    "action_safety",
];

const KNOWN_SIGNER_ROLES: &[&str] = &["mediator", "issuer", "countersig"];

/// key_type_for_alg returns the required key type for a recognized algorithm, or
/// None for an unrecognized one. Mirrors Go's keyTypeForAlg map.
fn key_type_for_alg(alg: &str) -> Option<&'static str> {
    match alg {
        ALG_ED25519 => Some("ed25519"),
        ALG_MLDSA65 => Some("ml-dsa"),
        _ => None,
    }
}

fn alg_implemented(alg: &str) -> bool {
    alg == ALG_ED25519
}

/// TrustEntry binds a signing key id to an authority namespace.
#[derive(Debug, Clone, Default)]
pub struct TrustEntry {
    pub mediator_id: String,
    pub role: String,
    pub trust_domain: String,
}

/// VerifyOptions carries the verifier's pinned trust.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// key id -> raw 32-byte Ed25519 public key.
    pub trusted_keys: BTreeMap<String, [u8; 32]>,
    /// key id -> authority-namespace binding.
    pub trust: BTreeMap<String, TrustEntry>,
}

/// SignatureResult is the appraisal of one parallel signature.
#[derive(Debug, Clone)]
pub struct SignatureResult {
    pub key_id: String,
    pub alg: String,
    pub role: String,
    pub status: String,
}

/// Appraisal is the AARP verifier result. It never carries a "trusted"/"safe"
/// boolean.
#[derive(Debug, Clone)]
pub struct Appraisal {
    pub profile: String,
    pub assertion_signed: bool,
    pub signatures: Vec<SignatureResult>,
    pub assurance_claimed: Vec<String>,
    pub verified_claims: Vec<String>,
    pub claimed_unverified: Vec<String>,
    pub axes: BTreeMap<String, Vec<String>>,
    pub does_not_assert: Vec<String>,
}

impl Appraisal {
    fn new() -> Self {
        Appraisal {
            profile: PROFILE.to_string(),
            assertion_signed: false,
            signatures: Vec::new(),
            assurance_claimed: Vec::new(),
            verified_claims: Vec::new(),
            claimed_unverified: Vec::new(),
            axes: BTreeMap::new(),
            does_not_assert: DOES_NOT_ASSERT.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn add_verified(&mut self, claim: &str, axis: &str) {
        self.verified_claims.push(claim.to_string());
        self.axes
            .entry(axis.to_string())
            .or_default()
            .push(claim.to_string());
    }
}

struct VerifiedSigner {
    key_id: String,
    role: String,
}

/// verify appraises an envelope. The envelope has already passed
/// `Envelope::unmarshal` (structural validation), so this only runs the
/// per-signature appraisal and claim classification — both non-fatal.
pub fn verify(env: &Envelope, opts: &VerifyOptions) -> Result<Appraisal, String> {
    let digest = env
        .payload_digest()
        .map_err(|err| format!("payload digest: {err}"))?;

    let mut ap = Appraisal::new();
    ap.assurance_claimed = env.assertion.claimed.clone();

    let mut verified: Vec<VerifiedSigner> = Vec::new();
    for sig in &env.signatures {
        let (result, ok) = appraise_signature(sig, &digest, opts)?;
        ap.signatures.push(result);
        if ok {
            verified.push(VerifiedSigner {
                key_id: sig.protected.key_id.clone(),
                role: sig.protected.signer_role.clone(),
            });
        }
    }

    if !verified.is_empty() {
        ap.assertion_signed = true;
        ap.add_verified(CLAIM_ASSERTION_SIGNATURE_VALID, AXIS_INTEGRITY);
        if mediator_key_pinned(env, &verified, &opts.trust) {
            ap.add_verified(CLAIM_MEDIATOR_KEY_PINNED, AXIS_IDENTITY);
        }
        if env.chain.is_some() {
            ap.add_verified(CLAIM_CHAIN_LINK_PRESENT, AXIS_INTEGRITY);
        }
    }

    classify_claims(&mut ap);
    Ok(ap)
}

/// appraise_signature verifies one parallel signature. It never falls back: an
/// unknown or unimplemented suite, an untrusted key, or an invalid signature all
/// yield ok=false.
fn appraise_signature(
    sig: &super::envelope::Signature,
    digest: &str,
    opts: &VerifyOptions,
) -> Result<(SignatureResult, bool), String> {
    let header = &sig.protected;
    let mut result = SignatureResult {
        key_id: header.key_id.clone(),
        alg: header.alg.clone(),
        role: header.signer_role.clone(),
        status: String::new(),
    };

    // Per-signature suite identity. A wrong profile/canon or a bad critical-
    // extension list in THIS signature's protected header makes only this
    // signature unverifiable — it never rejects the envelope, so an appended junk
    // signature cannot deny a verifiable sibling. (The signed top-level profile
    // and crit_ext are checked envelope-fatal in validate_structure.)
    if header.profile != PROFILE {
        result.status = SIG_UNKNOWN_SUITE.to_string();
        return Ok((result, false));
    }
    if header.canon != CANON_ID {
        result.status = SIG_UNKNOWN_SUITE.to_string();
        return Ok((result, false));
    }
    if let Err(err) = classify_critical_extensions(&header.crit) {
        result.status = match err {
            CritError::Unknown(_) => SIG_UNKNOWN_SUITE.to_string(),
            CritError::Malformed(_) => SIG_MALFORMED.to_string(),
        };
        return Ok((result, false));
    }

    if header.key_id.is_empty() {
        result.status = SIG_MALFORMED.to_string();
        return Ok((result, false));
    }
    if !KNOWN_SIGNER_ROLES.contains(&header.signer_role.as_str()) {
        result.status = SIG_MALFORMED.to_string();
        return Ok((result, false));
    }
    let Some(want_key_type) = key_type_for_alg(&header.alg) else {
        result.status = SIG_UNKNOWN_SUITE.to_string();
        return Ok((result, false));
    };
    if header.key_type != want_key_type {
        result.status = SIG_MALFORMED.to_string();
        return Ok((result, false));
    }
    if !alg_implemented(&header.alg) {
        result.status = SIG_UNIMPLEMENTED.to_string();
        return Ok((result, false));
    }

    // Implemented suite: Ed25519.
    let Some(pub_key) = opts.trusted_keys.get(&header.key_id) else {
        result.status = SIG_UNKNOWN_KEY.to_string();
        return Ok((result, false));
    };
    let input = match Envelope::signing_input(digest, header) {
        Ok(bytes) => bytes,
        Err(_) => {
            result.status = SIG_MALFORMED.to_string();
            return Ok((result, false));
        }
    };
    let raw = match decode_sig_wire(&header.alg, &sig.sig) {
        Ok(bytes) => bytes,
        Err(_) => {
            result.status = SIG_MALFORMED.to_string();
            return Ok((result, false));
        }
    };
    if !verify_ed25519(pub_key, &input, &raw) {
        result.status = SIG_FAILED.to_string();
        return Ok((result, false));
    }
    result.status = SIG_VERIFIED.to_string();
    Ok((result, true))
}

fn verify_ed25519(pub_key: &[u8; 32], message: &[u8], sig: &[u8]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(pub_key) else {
        return false;
    };
    let Ok(signature) = DalekSignature::from_slice(sig) else {
        return false;
    };
    verifying_key.verify_strict(message, &signature).is_ok()
}

/// decode_sig_wire splits "<alg>:<base64-std>" into raw bytes.
fn decode_sig_wire(alg: &str, wire: &str) -> Result<Vec<u8>, String> {
    let prefix = format!("{alg}:");
    let Some(body) = wire.strip_prefix(&prefix) else {
        return Err(format!("signature wire missing {prefix:?} prefix"));
    };
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|err| format!("signature base64: {err}"))
}

/// mediator_key_pinned reports whether any verifying signature is bound by a
/// trust entry to the asserted mediator identity (and role/domain when set).
fn mediator_key_pinned(
    env: &Envelope,
    verified: &[VerifiedSigner],
    trust: &BTreeMap<String, TrustEntry>,
) -> bool {
    for vs in verified {
        let Some(entry) = trust.get(&vs.key_id) else {
            continue;
        };
        if entry.mediator_id != env.assertion.mediator_id {
            continue;
        }
        if !entry.trust_domain.is_empty() && entry.trust_domain != env.assertion.trust_domain {
            continue;
        }
        if !entry.role.is_empty() && entry.role != vs.role {
            continue;
        }
        return true;
    }
    false
}

/// claim_required returns the verified-claim names a producer claim requires.
/// `Some(&[])` means a known claim that is structurally never verifiable in
/// v0.1; `None` means an unknown claim (reported claim-only).
fn claim_required(claim: &str) -> Option<&'static [&'static str]> {
    match claim {
        "mediated" => Some(&[CLAIM_MEDIATOR_KEY_PINNED]),
        "complete-mediation" | "complete_mediation" => Some(&[]),
        "transparency_inclusion" => Some(&[]),
        "workload_identity_verified" => Some(&["workload_identity_verified"]),
        "x509_svid_bound" => Some(&["x509_svid_bound"]),
        "svid_valid_at_action_time" => Some(&["svid_valid_at_action_time"]),
        _ => None,
    }
}

/// reclassify_claims recomputes claimed_unverified from scratch. The SVID
/// attestation layer adds verified claims AFTER the initial appraisal, so the
/// producer claim `workload_identity_verified` must be reclassified (it moves
/// from claimed_unverified to satisfied once the binding verifies). This mirrors
/// the Go `AppraiseWithSVID` order: addSVIDClaims, then classifyClaims once.
pub fn reclassify_claims(ap: &mut Appraisal) {
    ap.claimed_unverified.clear();
    classify_claims(ap);
}

/// classify_claims fills claimed_unverified from the producer claims the
/// verifier did not confirm, deduplicating producer claims.
fn classify_claims(ap: &mut Appraisal) {
    let verified: std::collections::HashSet<&str> =
        ap.verified_claims.iter().map(String::as_str).collect();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut unverified = Vec::new();
    for claimed in &ap.assurance_claimed {
        if !seen.insert(claimed.clone()) {
            continue;
        }
        match claim_required(claimed) {
            None => unverified.push(claimed.clone()),
            Some([]) => unverified.push(claimed.clone()),
            Some(required) => {
                if !required.iter().all(|r| verified.contains(r)) {
                    unverified.push(claimed.clone());
                }
            }
        }
    }
    ap.claimed_unverified = unverified;
}

// ---- comparable output (comparable.go) ----

/// comparable_appraisal returns the JCS-canonical bytes of the cross-language
/// comparison surface for an appraised envelope.
pub fn comparable_appraisal(ap: &Appraisal) -> Result<Vec<u8>, String> {
    use super::jcs::{canonicalize_value, Json};

    let sigs: Vec<Json> = ap
        .signatures
        .iter()
        .map(|s| {
            let mut map = BTreeMap::new();
            map.insert("alg".to_string(), Json::String(s.alg.clone()));
            map.insert("key_id".to_string(), Json::String(s.key_id.clone()));
            map.insert("signer_role".to_string(), Json::String(s.role.clone()));
            map.insert("status".to_string(), Json::String(s.status.clone()));
            Json::Object(map)
        })
        .collect();

    let mut axes: BTreeMap<String, Json> = BTreeMap::new();
    for (axis, claims) in &ap.axes {
        if claims.is_empty() {
            continue;
        }
        axes.insert(axis.clone(), sorted_unique(claims));
    }

    let mut obj: BTreeMap<String, Json> = BTreeMap::new();
    obj.insert("profile".to_string(), Json::String(ap.profile.clone()));
    obj.insert(
        "assertion_signed".to_string(),
        Json::Bool(ap.assertion_signed),
    );
    obj.insert("signatures".to_string(), Json::Array(sigs));
    obj.insert(
        "verified_claims".to_string(),
        sorted_unique(&ap.verified_claims),
    );
    obj.insert(
        "claimed_unverified".to_string(),
        sorted_unique(&ap.claimed_unverified),
    );
    obj.insert("axes".to_string(), Json::Object(axes));
    obj.insert(
        "does_not_assert".to_string(),
        sorted_unique(&ap.does_not_assert),
    );

    canonicalize_value(&Json::Object(obj)).map_err(|err| err.to_string())
}

fn sorted_unique(input: &[String]) -> super::jcs::Json {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for s in input {
        if seen.insert(s.clone()) {
            out.push(s.clone());
        }
    }
    out.sort();
    super::jcs::Json::Array(out.into_iter().map(super::jcs::Json::String).collect())
}
