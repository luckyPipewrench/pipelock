// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//! X.509-SVID attestation layer, ported from the Go reference in
//! `internal/svid/svid.go`, `internal/aarp/attest.go`, and
//! `cmd/pipelock-verifier/aarp_svid.go`.
//!
//! The layer is additive: it never changes the envelope appraisal, never makes
//! an envelope fatal, and never removes a core claim. When a `--svid` sidecar is
//! supplied AND the X.509-SVID proof-of-possession binding verifies against the
//! operator-pinned trust bundle on a signed assertion, it adds exactly three
//! verified claims (`workload_identity_verified`, `x509_svid_bound`,
//! `svid_valid_at_action_time`). Any failure withholds all three and never
//! errors the envelope.
//!
//! Two trust boundaries are kept strictly apart:
//!   - `evidence` is producer-supplied and attacker-controlled: every structural
//!     or cryptographic failure is appraised fail-closed (no claim, no error).
//!   - `verify` is the verifier's operator-pinned trust context: a malformed
//!     pinned bundle (bad DER, inverted/empty window, empty domain) is a config
//!     error (CLI exit 2), never a fixture verdict.
//!
//! Scope: the corpus is single-CA, leaf-directly-under-root (no intermediates),
//! and every pinned CA signs with Ed25519. Issuer-signature verification here
//! therefore supports an Ed25519 or ECDSA-P256 trust authority and a single
//! generation covering the action time; multi-intermediate chains are a
//! documented out-of-scope extension (matching AARP-CORPUS-CONTRACT.md).

use std::collections::BTreeMap;

use base64::Engine;
use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey as EdVerifyingKey};
use p256::ecdsa::{
    signature::hazmat::PrehashVerifier, Signature as P256Signature,
    VerifyingKey as P256VerifyingKey,
};
use p256::pkcs8::DecodePublicKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use super::envelope::{validate_timestamp, Envelope};
use super::jcs::{canonicalize_tree, Json};
use super::verify::{Appraisal, AXIS_FRESHNESS, AXIS_IDENTITY};

/// Domain separator for the SVID proof-of-possession binding. Mirrors
/// `aarp.ContextSVIDBinding`.
const CONTEXT_SVID_BINDING: &str = "pipelock-aarp-v0.1/svid-receipt-binding";

/// The AARP profile id, a signed field of the binding payload.
const PROFILE: &str = "aarp/v0.1";

/// Minimum SVID-binding nonce size: 128 bits. Mirrors `aarp.minNonceBytes`.
const MIN_NONCE_BYTES: usize = 16;

/// Binding algorithm identifiers. The binding signature follows the SVID leaf
/// key type, never the CA key type.
const BINDING_ALG_ECDSA_P256_SHA256: &str = "ecdsa-p256-sha256";
const BINDING_ALG_ED25519: &str = "ed25519";

/// The three SVID verified-claim names. Mirror the Go constants in appraise.go.
const CLAIM_WORKLOAD_IDENTITY_VERIFIED: &str = "workload_identity_verified";
const CLAIM_X509_SVID_BOUND: &str = "x509_svid_bound";
const CLAIM_SVID_VALID_AT_ACTION_TIME: &str = "svid_valid_at_action_time";

// ---- sidecar wire shape (cmd/pipelock-verifier/aarp_svid.go) ----

/// SvidFile is the `--svid` per-fixture sidecar: producer evidence plus the
/// verifier-pinned trust context. Unknown fields are rejected to match Go's
/// `DisallowUnknownFields`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvidFile {
    pub evidence: SvidEvidence,
    pub verify: SvidVerify,
}

/// SvidEvidence is the producer-supplied X.509-SVID proof-of-possession. It is
/// attacker-controlled; every field is appraised fail-closed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvidEvidence {
    #[serde(rename = "type")]
    pub typ: String,
    pub spiffe_id: String,
    pub leaf_der_b64: String,
    #[serde(default)]
    pub chain_der_b64: Vec<String>,
    pub nonce: String,
    pub issued_at: String,
    pub binding: SvidBinding,
}

/// SvidBinding is the proof-of-possession signature tying an SVID to a receipt.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvidBinding {
    pub alg: String,
    pub context: String,
    #[serde(default)]
    pub payload_sha256: String,
    pub signature_b64: String,
}

/// SvidVerify is the verifier-pinned trust context. Never producer-controlled.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvidVerify {
    pub trust_domain: String,
    pub action_time: String,
    #[serde(default)]
    pub allowed_spiffe_ids: Vec<String>,
    pub bundle: Vec<SvidBundleGen>,
}

/// SvidBundleGen is one pinned trust-bundle generation: a window and the CA
/// authorities authoritative during it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvidBundleGen {
    pub not_before: String,
    #[serde(default)]
    pub not_after: String,
    pub authorities_der_b64: Vec<String>,
}

// ---- pinned trust (operator-config; exit 2 on error) ----

/// Instant is a full-precision point in time: whole unix seconds plus a
/// fractional nanosecond component in `[0, 1_000_000_000)`. Go compares SVID
/// times at `time.Time` (nanosecond) precision via `time.Parse(time.RFC3339Nano)`
/// and `x509svid.WithTime`; truncating to whole seconds would wrongly accept a
/// binding whose `issued_at` is sub-second past a whole-second leaf expiry
/// (corpus fixture s19). `Instant` derives `Ord` so a tuple comparison reproduces
/// Go's `time.Before`/`time.After` exactly: `(secs, nanos)` lexicographic order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Instant {
    secs: i64,
    nanos: u32,
}

impl Instant {
    /// at_second builds a whole-second instant (X.509 GeneralizedTime/UTCTime
    /// carry no sub-second component, so a parsed cert window endpoint is exact
    /// at `nanos == 0`).
    fn at_second(secs: i64) -> Self {
        Instant { secs, nanos: 0 }
    }
}

/// PinnedGen is one validated generation: a window and the DER of each CA
/// authority. Built from the operator-pinned bundle; a structural problem here
/// is a config error.
struct PinnedGen {
    not_before: Instant,
    /// Upper bound; `None` means open-ended (current generation).
    not_after: Option<Instant>,
    authorities_der: Vec<Vec<u8>>,
}

/// PinnedTrust is the verifier's resolved SVID trust context.
pub struct PinnedTrust {
    pub trust_domain: String,
    action_time: Instant,
    pub allowed_spiffe_ids: Vec<String>,
    gens: Vec<PinnedGen>,
}

impl PinnedTrust {
    /// generation_at returns the DER of the authorities authoritative at the
    /// action time, or None if no pinned generation covers it (stale/forked).
    /// The window is half-open `[not_before, not_after)`, mirroring
    /// `svid.bundleAt`: `t >= not_before && (not_after.is_none() || t < not_after)`.
    fn authorities_at(&self, at: Instant) -> Option<&[Vec<u8>]> {
        for g in &self.gens {
            if at < g.not_before {
                continue;
            }
            match g.not_after {
                Some(end) if at >= end => continue,
                _ => return Some(&g.authorities_der),
            }
        }
        None
    }
}

/// load_svid_file reads a `--svid` sidecar into the producer evidence and the
/// verifier's pinned trust context. A structural problem in the operator-pinned
/// trust material (bad bundle DER, unparseable/inverted/empty window, empty
/// domain, divergent fork in the pinned history) is a config error (Err here →
/// CLI exit 2), never a fixture verdict.
pub fn load_svid_file(path: &str) -> std::result::Result<(SvidEvidence, PinnedTrust), String> {
    let data = std::fs::read_to_string(std::path::Path::new(path))
        .map_err(|err| format!("read svid file: {err}"))?;
    let sf: SvidFile =
        serde_json::from_str(&data).map_err(|err| format!("parse svid file: {err}"))?;

    if sf.verify.trust_domain.is_empty() {
        return Err("verify.trust_domain is empty".to_string());
    }
    // Mirror svid.parseTrustDomain: a trust domain must be a DNS name, not an IP
    // literal. (go-spiffe accepts IP literals; the Go reference rejects them.)
    if sf.verify.trust_domain.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!(
            "verify.trust_domain must be a DNS name, not an IP address: {:?}",
            sf.verify.trust_domain
        ));
    }

    let action_time = parse_rfc3339nano_instant(&sf.verify.action_time)
        .map_err(|err| format!("verify.action_time: {err}"))?;

    // Build the pinned generations, enforcing the append-only/non-overlap
    // invariant (mirror svid.appendGen). The window comparison uses
    // full-precision instants; the corpus bundle windows are whole-second.
    let mut gens: Vec<PinnedGen> = Vec::with_capacity(sf.verify.bundle.len());
    for (i, b) in sf.verify.bundle.iter().enumerate() {
        let not_before = parse_rfc3339nano_instant(&b.not_before)
            .map_err(|err| format!("bundle[{i}].not_before: {err}"))?;
        let not_after = if b.not_after.is_empty() {
            None
        } else {
            Some(
                parse_rfc3339nano_instant(&b.not_after)
                    .map_err(|err| format!("bundle[{i}].not_after: {err}"))?,
            )
        };
        if let Some(end) = not_after {
            if end <= not_before {
                return Err(format!(
                    "bundle[{i}]: generation notAfter must be after notBefore"
                ));
            }
        }
        if b.authorities_der_b64.is_empty() {
            return Err(format!("bundle[{i}]: generation has no trust authorities"));
        }
        let mut authorities_der = Vec::with_capacity(b.authorities_der_b64.len());
        for (j, der_b64) in b.authorities_der_b64.iter().enumerate() {
            let der = base64::engine::general_purpose::STANDARD
                .decode(der_b64)
                .map_err(|err| format!("bundle[{i}].authorities_der_b64[{j}]: {err}"))?;
            // Parse to confirm it is a well-formed CA certificate.
            let (_, cert) = X509Certificate::from_der(&der).map_err(|err| {
                format!("bundle[{i}].authorities_der_b64[{j}]: parse certificate: {err}")
            })?;
            if !cert.tbs_certificate.is_ca() {
                return Err(format!(
                    "bundle[{i}].authorities_der_b64[{j}]: trust authority certificate is not a CA"
                ));
            }
            // Mirror svid.validateAuthority: an authority that carries a KeyUsage
            // extension MUST assert keyCertSign. A non-empty KeyUsage that omits
            // cert-sign is a malformed pinned bundle (operator-config error, exit
            // 2), not a fixture verdict. An absent KeyUsage extension is permitted
            // (Go's `c.KeyUsage == 0` means "no usage bits", which crypto/x509
            // leaves zero when the extension is absent).
            if let Some(has_cert_sign) = authority_cert_sign_usage(&cert)? {
                if !has_cert_sign {
                    return Err(format!(
                        "bundle[{i}].authorities_der_b64[{j}]: trust authority certificate lacks cert-sign key usage"
                    ));
                }
            }
            authorities_der.push(der);
        }
        // Append-only / non-overlap invariant against the previous generation.
        if let Some(last) = gens.last_mut() {
            if not_before <= last.not_before {
                return Err(format!(
                    "bundle[{i}]: generation starts at or before the previous generation"
                ));
            }
            match last.not_after {
                None => last.not_after = Some(not_before),
                Some(end) if not_before < end => {
                    return Err(format!(
                        "bundle[{i}]: generation overlaps a closed generation"
                    ));
                }
                _ => {}
            }
        }
        gens.push(PinnedGen {
            not_before,
            not_after,
            authorities_der,
        });
    }
    if gens.is_empty() {
        return Err("trust bundle history needs at least one generation".to_string());
    }

    let trust = PinnedTrust {
        trust_domain: sf.verify.trust_domain.clone(),
        action_time,
        allowed_spiffe_ids: sf.verify.allowed_spiffe_ids.clone(),
        gens,
    };
    Ok((sf.evidence, trust))
}

// ---- claim attachment (attest.go addSVIDClaims) ----

/// add_svid_claims attaches the three SVID claims to the appraisal IFF the
/// assertion is signed AND the binding verifies. It never removes a claim,
/// never errors the envelope, and never inflates. A signed-but-failed binding,
/// or an unsigned assertion, attaches nothing.
pub fn add_svid_claims(ap: &mut Appraisal, env: &Envelope, ev: &SvidEvidence, trust: &PinnedTrust) {
    if !ap.assertion_signed {
        // Mirror Go: warning only; workload identity is claim-only.
        return;
    }
    if verify_svid_binding(env, ev, trust).is_err() {
        // Fail-closed: no claim, no envelope error.
        return;
    }
    ap.add_verified(CLAIM_WORKLOAD_IDENTITY_VERIFIED, AXIS_IDENTITY);
    ap.add_verified(CLAIM_X509_SVID_BOUND, AXIS_IDENTITY);
    ap.add_verified(CLAIM_SVID_VALID_AT_ACTION_TIME, AXIS_FRESHNESS);
}

// ---- the 9-step binding verification (attest.go VerifySVIDBinding) ----

/// A validated leaf, mirroring svid.Validated. Holds the SPIFFE ID and the leaf
/// validity window (full-precision instants) needed by later steps. X.509 cert
/// times are whole-second, so the endpoints have `nanos == 0`; carrying them as
/// `Instant` lets the step-8 `issued_at` bound compare at the same nanosecond
/// precision Go uses (corpus fixture s19).
struct ValidatedLeaf {
    spiffe_id: String,
    leaf_not_before: Instant,
    leaf_not_after: Instant,
    leaf_der: Vec<u8>,
}

/// verify_svid_binding runs the 9-step fail-closed validation, matching
/// `aarp.VerifySVIDBinding` step-for-step. On success it confirms (a) the SVID
/// validated offline at the action time against the pinned bundle, and (b) the
/// proof-of-possession signature verifies under the leaf key over the canonical
/// binding payload. Any failure returns Err (which the caller turns into "no
/// claim", never an envelope error).
fn verify_svid_binding(
    env: &Envelope,
    ev: &SvidEvidence,
    trust: &PinnedTrust,
) -> std::result::Result<String, String> {
    // 1. evidence.type must be x509.
    if ev.typ != "x509" {
        return Err(format!("evidence type {:?} (only x509 counts)", ev.typ));
    }
    // 2. issued_at must be a valid RFC3339Nano timestamp. Parse at full
    //    nanosecond precision; the step-8 window bound compares it against the
    //    leaf window exactly as Go's `time.Parse(time.RFC3339Nano)` does.
    validate_timestamp(&ev.issued_at, "evidence.issued_at").map_err(|e| e.to_string())?;
    let issued_at = parse_rfc3339nano_instant(&ev.issued_at)?;

    // 3. nonce: base64url no padding, decoding to >= 16 bytes.
    let nonce_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&ev.nonce)
        .map_err(|err| format!("nonce not base64url: {err}"))?;
    if nonce_bytes.len() < MIN_NONCE_BYTES {
        return Err(format!(
            "nonce {} bytes, want >= {MIN_NONCE_BYTES}",
            nonce_bytes.len()
        ));
    }

    // 4. binding.context must equal the SVID binding context.
    if ev.binding.context != CONTEXT_SVID_BINDING {
        return Err(format!("binding context {:?}", ev.binding.context));
    }

    // 5. Offline point-in-time chain validation at the action time.
    let validated = validate_svid(ev, trust)?;

    // 6. claimed spiffe_id must equal the validated leaf SAN, and be permitted.
    if ev.spiffe_id != validated.spiffe_id {
        return Err(format!(
            "evidence spiffe_id {:?} != validated {:?}",
            ev.spiffe_id, validated.spiffe_id
        ));
    }
    if !spiffe_id_permitted(&validated.spiffe_id, &trust.allowed_spiffe_ids) {
        return Err(format!("spiffe_id {:?} not permitted", validated.spiffe_id));
    }

    // 7. The signed assertion must declare the same trust domain (anti-confusion).
    if env.assertion.trust_domain.is_empty() {
        return Err("assertion.trust_domain is required with an SVID binding".to_string());
    }
    if env.assertion.trust_domain != trust.trust_domain {
        return Err(format!(
            "assertion trust_domain {:?} != validated SVID trust domain {:?}",
            env.assertion.trust_domain, trust.trust_domain
        ));
    }

    // 8. issued_at must fall within the leaf [NotBefore, NotAfter] (post-expiry
    //    key use is rejected even when the chain validates at action time). The
    //    comparison is full-precision: an issued_at one nanosecond past a
    //    whole-second leaf expiry is rejected (mirrors Go's time.Time bound).
    if issued_at < validated.leaf_not_before || issued_at > validated.leaf_not_after {
        return Err(format!(
            "binding issued_at {} outside the SVID leaf validity window",
            ev.issued_at
        ));
    }

    // 9. The proof-of-possession signature must verify under the LEAF key over
    //    the canonical binding payload.
    let canonical = binding_canonical(env, ev)?;
    if !ev.binding.payload_sha256.is_empty() {
        let want = hex::encode(Sha256::digest(&canonical));
        if ev.binding.payload_sha256 != want {
            return Err("binding payload_sha256 mismatch".to_string());
        }
    }
    let sig = base64::engine::general_purpose::STANDARD
        .decode(&ev.binding.signature_b64)
        .map_err(|err| format!("binding signature base64: {err}"))?;
    verify_leaf_signature(&validated.leaf_der, &ev.binding.alg, &canonical, &sig)?;

    Ok(validated.spiffe_id)
}

/// validate_svid mirrors `svid.ValidateSVID` for the single-CA,
/// leaf-directly-under-root corpus scope: it (a) parses the leaf, (b) extracts
/// exactly one well-formed SPIFFE URI SAN whose trust domain matches, (c) finds
/// the pinned generation authoritative at the action time, (d) verifies the
/// leaf is within its own validity window at the action time, and (e) verifies
/// the leaf's issuer signature against a pinned authority. Intermediates are
/// rejected (out of corpus scope) so a producer cannot smuggle a self-built
/// path past the single pinned root.
fn validate_svid(
    ev: &SvidEvidence,
    trust: &PinnedTrust,
) -> std::result::Result<ValidatedLeaf, String> {
    let leaf_der = base64::engine::general_purpose::STANDARD
        .decode(&ev.leaf_der_b64)
        .map_err(|err| format!("leaf_der_b64: {err}"))?;
    if leaf_der.is_empty() {
        return Err("empty leaf certificate DER".to_string());
    }
    // Intermediates are out of corpus scope (single-CA, leaf-under-root). A
    // non-empty chain is rejected rather than silently ignored so a producer
    // cannot present an attacker-built path.
    if !ev.chain_der_b64.is_empty() {
        return Err("intermediate certificates are out of scope (single-CA corpus)".to_string());
    }

    let (_, leaf) = X509Certificate::from_der(&leaf_der)
        .map_err(|err| format!("leaf is not a parseable X.509 certificate: {err}"))?;

    // Exactly one well-formed SPIFFE URI SAN, and its trust domain must match.
    let spiffe_id = leaf_spiffe_id(&leaf)?;
    let leaf_td = spiffe_trust_domain(&spiffe_id)?;
    if leaf_td != trust.trust_domain {
        return Err(format!(
            "SVID trust domain {:?}, expected {:?}",
            leaf_td, trust.trust_domain
        ));
    }

    // Pinned generation authoritative at the action time (stale/forked → reject).
    let authorities = trust
        .authorities_at(trust.action_time)
        .ok_or_else(|| "no pinned bundle authoritative at the action time".to_string())?;

    // Leaf within its own validity window at the action time (inclusive bounds,
    // matching crypto/x509 + go-spiffe WithTime semantics). X.509 cert times are
    // whole-second; the action time may be sub-second, so compare at full
    // precision via Instant.
    let leaf_not_before = Instant::at_second(leaf.validity().not_before.timestamp());
    let leaf_not_after = Instant::at_second(leaf.validity().not_after.timestamp());
    if trust.action_time < leaf_not_before || trust.action_time > leaf_not_after {
        return Err("SVID leaf not valid at the action time".to_string());
    }

    // Issuer signature: the leaf must be signed by one of the pinned authorities
    // (and that authority must itself be valid at the action time).
    let mut chained = false;
    for ca_der in authorities {
        let (_, ca) = match X509Certificate::from_der(ca_der) {
            Ok(parsed) => parsed,
            Err(_) => continue,
        };
        let ca_not_before = Instant::at_second(ca.validity().not_before.timestamp());
        let ca_not_after = Instant::at_second(ca.validity().not_after.timestamp());
        if trust.action_time < ca_not_before || trust.action_time > ca_not_after {
            continue;
        }
        if verify_issuer_signature(&leaf, &ca) {
            chained = true;
            break;
        }
    }
    if !chained {
        return Err("chain does not validate to a pinned bundle".to_string());
    }

    Ok(ValidatedLeaf {
        spiffe_id,
        leaf_not_before,
        leaf_not_after,
        leaf_der,
    })
}

/// leaf_spiffe_id extracts the single SPIFFE URI SAN from the leaf and validates
/// it against the SPIFFE-ID grammar. A certificate without exactly one
/// well-formed SPIFFE URI SAN is not an SVID (mirror go-spiffe's
/// `x509svid.IDFromCert` → `spiffeid.FromURI` → `spiffeid.FromString`). The
/// returned string is the validated, grammar-conformant SPIFFE ID.
fn leaf_spiffe_id(leaf: &X509Certificate) -> std::result::Result<String, String> {
    let san = leaf
        .subject_alternative_name()
        .map_err(|err| format!("leaf SAN extension invalid: {err}"))?
        .ok_or_else(|| "leaf is not an X.509-SVID: no SAN extension".to_string())?;
    let mut uris: Vec<&str> = Vec::new();
    for gn in &san.value.general_names {
        if let GeneralName::URI(uri) = gn {
            uris.push(uri);
        }
    }
    if uris.len() != 1 {
        return Err(format!(
            "leaf is not an X.509-SVID: want exactly one URI SAN, found {}",
            uris.len()
        ));
    }
    let id = uris[0];
    // Enforce the full SPIFFE-ID grammar, not just the scheme prefix. A loose
    // `starts_with("spiffe://")` accepts dot-segment paths and other malformed
    // SANs that go-spiffe's FromString rejects, which would inflate identity.
    validate_spiffe_id(id)?;
    Ok(id.to_string())
}

/// spiffe_trust_domain extracts the trust domain (authority) from an already
/// grammar-validated SPIFFE ID, and additionally rejects IP-literal authorities
/// (mirror svid.parseTrustDomain, which is stricter than go-spiffe). Callers MUST
/// pass an id that has already passed `validate_spiffe_id`.
fn spiffe_trust_domain(id: &str) -> std::result::Result<String, String> {
    let rest = id
        .strip_prefix(SPIFFE_SCHEME)
        .ok_or_else(|| format!("not a SPIFFE ID: {id:?}"))?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(format!("SPIFFE ID {id:?} has an empty trust domain"));
    }
    if authority.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!(
            "trust domain must be a DNS name, not an IP address: {authority:?}"
        ));
    }
    Ok(authority.to_string())
}

/// The SPIFFE URI scheme prefix, exactly as go-spiffe's `schemePrefix`.
const SPIFFE_SCHEME: &str = "spiffe://";

/// validate_spiffe_id enforces the SPIFFE-ID grammar byte-for-byte against
/// go-spiffe v2.6.0 `spiffeid.FromString` (default build, charset backcompat
/// OFF). Returning `Ok(())` means an id that go-spiffe would accept; any error
/// means an id it would reject (so no identity is inflated).
///
/// Grammar (verified empirically against go-spiffe v2.6.0):
///   - scheme MUST be exactly `spiffe://`;
///   - trust domain = authority up to the first `/`: non-empty, each byte in
///     `[a-z0-9._-]` (lowercase only — uppercase, `@`, `:`, and any other byte
///     are rejected as a bad trust-domain char; this also rejects userinfo and a
///     port, since `@`/`:` are not valid authority bytes);
///   - path = the remainder from the first `/`: MAY be empty; if present it MUST
///     start with `/`, each `/`-separated segment MUST be non-empty (no `//`),
///     MUST NOT be `.` or `..` (no dot-segments), each byte in `[A-Za-z0-9._-]`
///     (uppercase IS allowed in path segments, unlike the trust domain), and the
///     path MUST NOT end in `/`;
///   - no query (`?`) and no fragment (`#`) are representable (they are not in
///     the path charset, so they are rejected as bad path-segment chars).
fn validate_spiffe_id(id: &str) -> std::result::Result<(), String> {
    let rest = id
        .strip_prefix(SPIFFE_SCHEME)
        .ok_or_else(|| format!("leaf URI SAN {id:?} is not a SPIFFE ID (wrong scheme)"))?;
    let bytes = rest.as_bytes();
    // Trust-domain authority: read up to the first '/'.
    let mut idx = 0;
    while idx < bytes.len() && bytes[idx] != b'/' {
        if !is_valid_trust_domain_char(bytes[idx]) {
            return Err(format!(
                "SPIFFE ID {id:?} has an invalid trust domain character"
            ));
        }
        idx += 1;
    }
    if idx == 0 {
        return Err(format!("SPIFFE ID {id:?} has an empty trust domain"));
    }
    // Path = remainder from the first '/'. An empty path is valid.
    validate_spiffe_path(&rest[idx..]).map_err(|e| format!("SPIFFE ID {id:?}: {e}"))
}

/// validate_spiffe_path mirrors go-spiffe `spiffeid.ValidatePath`.
fn validate_spiffe_path(path: &str) -> std::result::Result<(), String> {
    if path.is_empty() {
        return Ok(());
    }
    let bytes = path.as_bytes();
    if bytes[0] != b'/' {
        return Err("path must have a leading slash".to_string());
    }
    let mut segment_start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'/' {
            match &path[segment_start..i] {
                "/" => return Err("path cannot contain empty segments".to_string()),
                "/." | "/.." => return Err("path cannot contain dot segments".to_string()),
                _ => {}
            }
            segment_start = i;
            i += 1;
            continue;
        }
        if !is_valid_path_segment_char(c) {
            return Err("path contains an invalid character".to_string());
        }
        i += 1;
    }
    match &path[segment_start..] {
        "/" => Err("path cannot have a trailing slash".to_string()),
        "/." | "/.." => Err("path cannot contain dot segments".to_string()),
        _ => Ok(()),
    }
}

/// is_valid_trust_domain_char mirrors go-spiffe `isValidTrustDomainChar` with the
/// default (charset-backcompat-disabled) build: lowercase letters, digits, `.`,
/// `-`, `_`. No uppercase.
fn is_valid_trust_domain_char(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'.' | b'_')
}

/// is_valid_path_segment_char mirrors go-spiffe `isValidPathSegmentChar` with the
/// default build: letters (any case), digits, `.`, `-`, `_`.
fn is_valid_path_segment_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_')
}

/// authority_cert_sign_usage returns `Ok(None)` when the certificate carries no
/// KeyUsage extension, and `Ok(Some(has_cert_sign))` when it does. Mirrors Go's
/// `c.KeyUsage != 0` gate around the `keyCertSign` bit in `svid.validateAuthority`:
/// crypto/x509 leaves `KeyUsage == 0` when the extension is absent, so an absent
/// extension is permitted and a present one MUST assert keyCertSign.
fn authority_cert_sign_usage(cert: &X509Certificate) -> std::result::Result<Option<bool>, String> {
    match cert
        .tbs_certificate
        .key_usage()
        .map_err(|err| format!("key usage extension invalid: {err}"))?
    {
        Some(ext) => Ok(Some(ext.value.key_cert_sign())),
        None => Ok(None),
    }
}

/// verify_issuer_signature verifies the leaf's signature against a candidate CA
/// public key. The corpus CAs all sign Ed25519, but an ECDSA-P256 CA is also
/// supported for completeness. The signed message is the leaf's raw TBS DER.
fn verify_issuer_signature(leaf: &X509Certificate, ca: &X509Certificate) -> bool {
    // Match Go's x509 path builder: issuer/subject linkage is part of chain
    // validation. A raw public-key signature check alone would accept a leaf
    // signed by the same key while naming a different issuer.
    if leaf.issuer() != ca.subject() {
        return false;
    }
    let tbs = leaf.tbs_certificate.as_ref();
    let sig = leaf.signature_value.as_ref();
    let ca_spki = ca.tbs_certificate.subject_pki.raw;
    // Try Ed25519 first (every corpus CA), then ECDSA-P256.
    if let Ok(vk) = ed25519_verifying_key_from_spki(ca) {
        if let Ok(signature) = EdSignature::from_slice(sig) {
            if vk.verify(tbs, &signature).is_ok() {
                return true;
            }
        }
        return false;
    }
    if let Ok(vk) = P256VerifyingKey::from_public_key_der(ca_spki) {
        if let Ok(signature) = P256Signature::from_der(sig) {
            let digest = Sha256::digest(tbs);
            return vk.verify_prehash(&digest, &signature).is_ok();
        }
    }
    false
}

/// ed25519_verifying_key_from_spki extracts a 32-byte Ed25519 public key from a
/// certificate's SPKI when the key type is Ed25519, else Err.
fn ed25519_verifying_key_from_spki(
    cert: &X509Certificate,
) -> std::result::Result<EdVerifyingKey, ()> {
    // Ed25519 SPKI algorithm OID is 1.3.101.112; the raw subjectPublicKey is the
    // 32-byte key.
    let alg_oid = cert
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_id_string();
    if alg_oid != "1.3.101.112" {
        return Err(());
    }
    let raw = &cert.tbs_certificate.subject_pki.subject_public_key.data;
    let bytes: [u8; 32] = raw.as_ref().try_into().map_err(|_| ())?;
    EdVerifyingKey::from_bytes(&bytes).map_err(|_| ())
}

/// verify_leaf_signature verifies a proof-of-possession signature under the SVID
/// leaf public key, dispatching on the declared algorithm and the actual leaf
/// key type. The curve is enforced by the type: parsing the leaf SPKI into a
/// p256 VerifyingKey only succeeds for P-256, so a P-384/P-521 leaf under the
/// `ecdsa-p256-sha256` alg id is rejected (the explicit curve check).
fn verify_leaf_signature(
    leaf_der: &[u8],
    alg: &str,
    msg: &[u8],
    sig: &[u8],
) -> std::result::Result<(), String> {
    let (_, leaf) =
        X509Certificate::from_der(leaf_der).map_err(|err| format!("leaf parse: {err}"))?;
    let spki = leaf.tbs_certificate.subject_pki.raw;
    let key_alg_oid = leaf
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_id_string();

    // Ed25519 leaf (OID 1.3.101.112).
    if key_alg_oid == "1.3.101.112" {
        if alg != BINDING_ALG_ED25519 {
            return Err(format!(
                "binding alg {alg:?} does not match Ed25519 leaf key"
            ));
        }
        let vk = ed25519_verifying_key_from_spki(&leaf)
            .map_err(|()| "Ed25519 leaf key is malformed".to_string())?;
        let signature = EdSignature::from_slice(sig)
            .map_err(|_| "Ed25519 proof-of-possession does not verify".to_string())?;
        return vk
            .verify(msg, &signature)
            .map_err(|_| "Ed25519 proof-of-possession does not verify".to_string());
    }

    // EC leaf (OID 1.2.840.10045.2.1). The alg id names P-256; the curve check
    // is the parse into a p256 VerifyingKey — a P-384/P-521 SPKI fails to parse.
    if key_alg_oid == "1.2.840.10045.2.1" {
        if alg != BINDING_ALG_ECDSA_P256_SHA256 {
            return Err(format!("binding alg {alg:?} does not match ECDSA leaf key"));
        }
        let vk = P256VerifyingKey::from_public_key_der(spki)
            .map_err(|_| "ECDSA leaf curve is not P-256, binding alg requires P-256".to_string())?;
        let signature = P256Signature::from_der(sig)
            .map_err(|_| "ECDSA proof-of-possession does not verify".to_string())?;
        let digest = Sha256::digest(msg);
        return vk
            .verify_prehash(&digest, &signature)
            .map_err(|_| "ECDSA proof-of-possession does not verify".to_string());
    }

    Err(format!(
        "unsupported SVID leaf key type (alg oid {key_alg_oid})"
    ))
}

/// binding_canonical returns the JCS-canonical bytes of the binding payload the
/// SVID leaf key signs (attest.go bindingCanonical). The 10 fields are all
/// string-valued; JCS sorts keys, so building a sorted map and canonicalizing it
/// reproduces the Go output byte-for-byte. `assurance_assertion_sha256` is the
/// SHA-256 of the JCS-canonical signed payload — the same digest signatures use.
fn binding_canonical(env: &Envelope, ev: &SvidEvidence) -> std::result::Result<Vec<u8>, String> {
    let assertion_digest = env.payload_digest().map_err(|e| e.to_string())?;
    let mut obj: BTreeMap<String, Json> = BTreeMap::new();
    obj.insert(
        "action_record_sha256".to_string(),
        Json::String(env.subject.action_record_sha256.clone()),
    );
    obj.insert(
        "assurance_assertion_sha256".to_string(),
        Json::String(assertion_digest),
    );
    obj.insert(
        "context".to_string(),
        Json::String(CONTEXT_SVID_BINDING.to_string()),
    );
    obj.insert("issued_at".to_string(), Json::String(ev.issued_at.clone()));
    obj.insert(
        "mediator_id".to_string(),
        Json::String(env.assertion.mediator_id.clone()),
    );
    obj.insert("nonce".to_string(), Json::String(ev.nonce.clone()));
    obj.insert("profile".to_string(), Json::String(PROFILE.to_string()));
    obj.insert(
        "receipt_envelope_sha256".to_string(),
        Json::String(env.subject.receipt_envelope_sha256.clone()),
    );
    obj.insert(
        "receipt_signer_key".to_string(),
        Json::String(env.subject.receipt_signer_key.clone()),
    );
    obj.insert("spiffe_id".to_string(), Json::String(ev.spiffe_id.clone()));
    canonicalize_tree(&Json::Object(obj)).map_err(|e| e.to_string())
}

/// spiffe_id_permitted reports whether id is in the allowed set. An empty set
/// permits any validated SPIFFE ID in the (already verified) trust domain.
fn spiffe_id_permitted(id: &str, allowed: &[String]) -> bool {
    allowed.is_empty() || allowed.iter().any(|a| a == id)
}

/// parse_rfc3339nano_instant parses an RFC3339Nano timestamp into a
/// full-precision `Instant` (whole unix seconds + nanoseconds). Go's
/// `time.Parse(time.RFC3339Nano, s)` is the reference; this enforces the same
/// grammar (via the shared envelope check) and rejects anything Go would reject,
/// then returns the nanosecond-precision instant used for window comparison.
fn parse_rfc3339nano_instant(s: &str) -> std::result::Result<Instant, String> {
    // Reuse the envelope grammar check (identical to Go's RFC3339Nano accept set).
    validate_timestamp(s, "timestamp").map_err(|e| e.to_string())?;
    rfc3339_to_instant(s).ok_or_else(|| format!("timestamp {s:?} is not RFC3339Nano"))
}

/// rfc3339_to_instant converts a grammar-valid RFC3339Nano string to a
/// full-precision `Instant`. The fractional-seconds component is carried as
/// nanoseconds (truncated to nanosecond precision, matching Go's `time.Time`),
/// so a `.000000001Z` suffix yields `nanos == 1` and a `T+1ns` instant sorts
/// strictly after the whole second `T` — the precision the s19 fixture needs.
fn rfc3339_to_instant(s: &str) -> Option<Instant> {
    let b = s.as_bytes();
    let n = |start: usize, len: usize| -> Option<i64> {
        std::str::from_utf8(&b[start..start + len])
            .ok()?
            .parse::<i64>()
            .ok()
    };
    let year = n(0, 4)?;
    let month = n(5, 2)?;
    let day = n(8, 2)?;
    let hour = n(11, 2)?;
    let minute = n(14, 2)?;
    let second = n(17, 2)?;

    // Days from civil date (Howard Hinnant's algorithm), giving days since the
    // unix epoch (1970-01-01).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146097 + doe - 719468;

    let mut secs = days * 86400 + hour * 3600 + minute * 60 + second;

    // Optional fractional seconds → nanoseconds. The grammar guarantees a dot
    // followed by >= 1 digit when present. Take up to 9 fractional digits
    // (nanosecond resolution); pad short fractions on the right and truncate any
    // beyond 9 digits, exactly as Go's time.Time keeps at most nanosecond
    // precision.
    let mut idx = 19;
    let mut nanos: u32 = 0;
    if idx < b.len() && b[idx] == b'.' {
        idx += 1;
        let frac_start = idx;
        while idx < b.len() && b[idx].is_ascii_digit() {
            idx += 1;
        }
        // First 9 fractional digits, right-padded to exactly 9.
        let mut buf = [b'0'; 9];
        for (k, &d) in b[frac_start..idx].iter().take(9).enumerate() {
            buf[k] = d;
        }
        nanos = std::str::from_utf8(&buf).ok()?.parse::<u32>().ok()?;
    }

    // Apply the zone offset. Grammar guarantees Z or ±HH:MM at the current index.
    if idx < b.len() && (b[idx] == b'+' || b[idx] == b'-') {
        let sign = if b[idx] == b'+' { 1 } else { -1 };
        let oh = n(idx + 1, 2)?;
        let om = n(idx + 4, 2)?;
        // A timestamp at +02:00 is two hours ahead of UTC, so subtract the offset.
        secs -= sign * (oh * 3600 + om * 60);
    }
    Some(Instant { secs, nanos })
}
