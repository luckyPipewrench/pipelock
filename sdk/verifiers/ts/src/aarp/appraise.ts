// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Appraisal vocabulary, claim classification, signature verification, and the
// comparable output projection. Ported from internal/aarp/appraise.go,
// verify.go, and comparable.go.

import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { canonicalize } from "./canonical.js";
import {
  Assertion,
  Envelope,
  Signature,
  payloadDigest,
  signingInput,
  validateStructure,
} from "./envelope.js";
import {
  ALG_ED25519,
  CANON_ID,
  MalformedCritError,
  PROFILE,
  UnknownCritError,
  checkCriticalExtensions,
  implementedAlgs,
  keyTypeForAlg,
  knownSignerRoles,
} from "./suite.js";

// Axis names group verified claims by the kind of proof they rest on.
export const AXIS_IDENTITY = "identity";
export const AXIS_INTEGRITY = "integrity";

// Verified-claim names.
export const CLAIM_ASSERTION_SIGNATURE_VALID = "assertion_signature_valid";
export const CLAIM_MEDIATOR_KEY_PINNED = "mediator_key_pinned";
// A signed, well-formed Rung-1 chain link is present on the envelope (its
// position is authenticated by the verified signature). Mirrors Go's
// ClaimChainLinkPresent = "chain_link_present". This is the single-envelope
// appraisal claim; the cross-envelope stream linkage ("chain_linked") is a
// separate concept reported by verifyChain/comparableChain.
export const CLAIM_CHAIN_LINK_PRESENT = "chain_link_present";

// docsNotAsserted is the fixed set of properties an AARP appraisal never asserts.
const docsNotAsserted = [
  "efficacy",
  "absence_of_bypass",
  "complete_mediation",
  "policy_correctness",
  "action_safety",
];

// SignatureStatus is the per-signature appraisal outcome.
export type SignatureStatus =
  | "verified"
  | "failed"
  | "unknown_key"
  | "unimplemented"
  | "unknown_suite"
  | "malformed";

export interface SignatureResult {
  key_id: string;
  alg: string;
  signer_role: string;
  status: SignatureStatus;
  reason?: string;
}

export interface Appraisal {
  profile: string;
  assertion_signed: boolean;
  signatures: SignatureResult[];
  assurance_claimed: string[];
  verified_claims: string[];
  claimed_unverified: string[];
  axes: Record<string, string[]>;
  does_not_assert: string[];
  warnings: string[];
}

export interface TrustEntry {
  mediator_id: string;
  role?: string;
  trust_domain?: string;
}

export interface VerifyOptions {
  // trustedKeys maps a key id to its raw 32-byte Ed25519 public key.
  trustedKeys: Map<string, Uint8Array>;
  // trust maps a key id to its authority-namespace binding.
  trust: Map<string, TrustEntry>;
}

// claimVerifiedBy maps each producer claim to the verified claims required for it
// to count as confirmed. An empty list means structurally claim-only.
const claimVerifiedBy: Record<string, string[]> = {
  mediated: [CLAIM_MEDIATOR_KEY_PINNED],
  "complete-mediation": [],
  complete_mediation: [],
  transparency_inclusion: [],
};

interface VerifiedSigner {
  keyID: string;
  role: string;
}

// ed25519 SPKI DER prefix for a raw 32-byte public key.
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function ed25519PublicKey(raw: Uint8Array) {
  const der = Buffer.concat([SPKI_PREFIX, Buffer.from(raw)]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

function decodeSigWire(alg: string, wire: string): Buffer | null {
  const prefix = `${alg}:`;
  if (!wire.startsWith(prefix)) return null;
  const b64 = wire.slice(prefix.length);
  // Strict standard-base64 round-trip check: Node's base64 decoder is lenient,
  // so re-encode and compare to reject malformed input the way Go does.
  const raw = Buffer.from(b64, "base64");
  if (raw.toString("base64") !== b64) return null;
  return raw;
}

// appraiseSignature verifies one parallel signature. It never falls back.
function appraiseSignature(
  s: Signature,
  digest: string,
  opts: VerifyOptions,
): { result: SignatureResult; ok: boolean } {
  const res: SignatureResult = {
    key_id: s.protected.key_id,
    alg: s.protected.alg,
    signer_role: s.protected.signer_role,
    status: "malformed",
  };

  // Per-signature suite identity. A wrong profile/canon or an unknown critical
  // extension in THIS signature's protected header makes only this signature
  // unverifiable - it never rejects the envelope, so an appended junk signature
  // cannot deny a verifiable sibling. (The signed top-level profile and
  // envelope-level crit_ext are checked envelope-fatal in validateStructure.)
  if (s.protected.profile !== PROFILE) {
    res.status = "unknown_suite";
    res.reason = `profile ${JSON.stringify(s.protected.profile)} != ${JSON.stringify(PROFILE)}`;
    return { result: res, ok: false };
  }
  if (s.protected.canon !== CANON_ID) {
    res.status = "unknown_suite";
    res.reason = `canon ${JSON.stringify(s.protected.canon)} != ${JSON.stringify(CANON_ID)}`;
    return { result: res, ok: false };
  }
  try {
    checkCriticalExtensions(s.protected.crit);
  } catch (err) {
    if (err instanceof UnknownCritError) {
      res.status = "unknown_suite";
      res.reason = err.message;
    } else if (err instanceof MalformedCritError) {
      res.status = "malformed";
      res.reason = err.message;
    } else {
      throw err;
    }
    return { result: res, ok: false };
  }

  if (s.protected.key_id === "") {
    res.status = "malformed";
    res.reason = "empty key_id";
    return { result: res, ok: false };
  }
  if (!knownSignerRoles[s.protected.signer_role]) {
    res.status = "malformed";
    res.reason = "unknown signer_role";
    return { result: res, ok: false };
  }
  const wantKeyType = keyTypeForAlg[s.protected.alg];
  if (wantKeyType === undefined) {
    res.status = "unknown_suite";
    res.reason = "unrecognized algorithm; no fallback";
    return { result: res, ok: false };
  }
  if (s.protected.key_type !== wantKeyType) {
    res.status = "malformed";
    res.reason = `key_type ${JSON.stringify(s.protected.key_type)} != ${JSON.stringify(wantKeyType)} required by alg`;
    return { result: res, ok: false };
  }
  if (!implementedAlgs[s.protected.alg]) {
    res.status = "unimplemented";
    res.reason = "recognized suite, verifier not yet built";
    return { result: res, ok: false };
  }

  // Implemented suite: Ed25519.
  const pub = opts.trustedKeys.get(s.protected.key_id);
  if (pub === undefined) {
    res.status = "unknown_key";
    res.reason = "key_id not in trusted set";
    return { result: res, ok: false };
  }
  if (pub.length !== 32) {
    res.status = "malformed";
    res.reason = "trusted key has wrong size";
    return { result: res, ok: false };
  }
  const raw = decodeSigWire(s.protected.alg, s.sig);
  if (raw === null) {
    res.status = "malformed";
    res.reason = "signature wire malformed";
    return { result: res, ok: false };
  }
  if (raw.length !== 64) {
    res.status = "failed";
    res.reason = "signature does not verify over canonical bytes";
    return { result: res, ok: false };
  }
  const input = signingInput(digest, s.protected);
  let valid = false;
  try {
    valid = cryptoVerify(null, input, ed25519PublicKey(pub), raw);
  } catch {
    valid = false;
  }
  if (!valid) {
    res.status = "failed";
    res.reason = "signature does not verify over canonical bytes";
    return { result: res, ok: false };
  }
  res.status = "verified";
  return { result: res, ok: true };
}

// mediatorKeyPinned reports whether any verifying signature is bound by a trust
// entry to the asserted mediator identity (role/domain-scoped).
function mediatorKeyPinned(
  a: Assertion,
  verified: VerifiedSigner[],
  trust: Map<string, TrustEntry>,
): boolean {
  for (const vs of verified) {
    const entry = trust.get(vs.keyID);
    if (entry === undefined) continue;
    if (entry.mediator_id !== a.mediator_id) continue;
    if (
      entry.trust_domain !== undefined &&
      entry.trust_domain !== "" &&
      entry.trust_domain !== (a.trust_domain ?? "")
    ) {
      continue;
    }
    if (entry.role !== undefined && entry.role !== "" && entry.role !== vs.role) continue;
    return true;
  }
  return false;
}

function newAppraisal(): Appraisal {
  return {
    profile: "aarp/v0.1",
    assertion_signed: false,
    signatures: [],
    assurance_claimed: [],
    verified_claims: [],
    claimed_unverified: [],
    axes: {},
    does_not_assert: [...docsNotAsserted],
    warnings: [],
  };
}

function addVerified(ap: Appraisal, claim: string, axis: string): void {
  ap.verified_claims.push(claim);
  if (ap.axes[axis] === undefined) ap.axes[axis] = [];
  (ap.axes[axis] as string[]).push(claim);
}

function classifyClaims(ap: Appraisal): void {
  const verified = new Set(ap.verified_claims);
  const seenClaim = new Set<string>();
  for (const claimed of ap.assurance_claimed) {
    if (seenClaim.has(claimed)) continue;
    seenClaim.add(claimed);
    const required = claimVerifiedBy[claimed];
    if (required === undefined) {
      ap.claimed_unverified.push(claimed);
      ap.warnings.push(`unknown assurance claim reported claim-only: ${claimed}`);
      continue;
    }
    if (required.length === 0) {
      ap.claimed_unverified.push(claimed);
      continue;
    }
    if (required.every((r) => verified.has(r))) continue;
    ap.claimed_unverified.push(claimed);
  }
}

// verify appraises an AARP envelope. It throws an EnvelopeFatal-class error only
// for envelope-fatal conditions; per-signature problems are reported in the
// appraisal, never as a hard rejection.
export function verify(e: Envelope, opts: VerifyOptions): Appraisal {
  validateStructure(e);
  const digest = payloadDigest(e);

  const ap = newAppraisal();
  ap.profile = e.profile;
  ap.assurance_claimed = [...e.assertion.claimed];

  const verified: VerifiedSigner[] = [];
  for (const s of e.signatures) {
    const { result, ok } = appraiseSignature(s, digest, opts);
    ap.signatures.push(result);
    if (ok) {
      verified.push({ keyID: s.protected.key_id, role: s.protected.signer_role });
    }
  }

  if (verified.length > 0) {
    ap.assertion_signed = true;
    addVerified(ap, CLAIM_ASSERTION_SIGNATURE_VALID, AXIS_INTEGRITY);
    if (mediatorKeyPinned(e.assertion, verified, opts.trust)) {
      addVerified(ap, CLAIM_MEDIATOR_KEY_PINNED, AXIS_IDENTITY);
    }
    if (e.chain !== undefined) {
      addVerified(ap, CLAIM_CHAIN_LINK_PRESENT, AXIS_INTEGRITY);
    }
  } else {
    ap.warnings.push(
      "no signature verified under a trusted key; all assurance claims are untrusted input",
    );
  }

  classifyClaims(ap);
  return ap;
}

// sortedUnique returns a sorted, de-duplicated copy of in.
function sortedUnique(input: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const s of input) {
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  out.sort();
  return out;
}

// comparableAppraisal projects an appraisal onto the cross-language comparison
// surface and returns its JCS-canonical bytes. Excludes warnings, per-signature
// reason, and assurance_claimed.
export function comparableAppraisal(ap: Appraisal): string {
  const sigs = ap.signatures.map((s) => ({
    alg: s.alg,
    key_id: s.key_id,
    signer_role: s.signer_role,
    status: s.status,
  }));

  const axes: Record<string, unknown> = {};
  for (const [axis, claims] of Object.entries(ap.axes)) {
    if (claims.length === 0) continue;
    axes[axis] = sortedUnique(claims);
  }

  const obj = {
    profile: ap.profile,
    assertion_signed: ap.assertion_signed,
    signatures: sigs,
    verified_claims: sortedUnique(ap.verified_claims),
    claimed_unverified: sortedUnique(ap.claimed_unverified),
    axes,
    does_not_assert: sortedUnique(ap.does_not_assert),
  };
  return canonicalize(obj);
}
