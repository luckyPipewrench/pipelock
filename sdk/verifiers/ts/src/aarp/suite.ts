// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Protected signature suite, ported from internal/aarp/suite.go. The suite is
// authenticated agility: profile, canon, alg, key type, key id, role, and
// critical extensions all live inside the signed protected header.

export const PROFILE = "aarp/v0.1";
export const CANON_ID = "jcs-rfc8785-nfc";

export const ALG_ED25519 = "ed25519";
export const ALG_MLDSA65 = "ml-dsa-65";

// keyTypeForAlg maps each recognized algorithm to its required key type.
export const keyTypeForAlg: Record<string, string> = {
  [ALG_ED25519]: "ed25519",
  [ALG_MLDSA65]: "ml-dsa",
};

// implementedAlgs is the set of algorithms whose verification is built.
export const implementedAlgs: Record<string, boolean> = {
  [ALG_ED25519]: true,
};

// knownSignerRoles is the closed set of signer roles a protected header may use.
export const knownSignerRoles: Record<string, boolean> = {
  mediator: true,
  issuer: true,
  countersig: true,
};

// knownCriticalExtensions is empty in v0.1: any name flagged critical fails the
// envelope closed.
export const knownCriticalExtensions: Record<string, boolean> = {};

// ProtectedHeader is the per-signature suite descriptor.
export interface ProtectedHeader {
  profile: string;
  canon: string;
  alg: string;
  key_type: string;
  key_id: string;
  signer_role: string;
  crit?: string[];
}

// Suite-failure classes. When checkCriticalExtensions runs over the
// ENVELOPE-LEVEL crit_ext list these mark envelope-fatal conditions; when it
// runs over a per-signature protected.crit list the appraiser catches them and
// maps the class to a per-signature status (never an envelope rejection).
// Per-signature alg/key problems are handled inline in the appraiser, never
// thrown.
//
// MalformedCritError mirrors Go's ErrMalformedSuite path (empty-string name or
// duplicate) and UnknownCritError mirrors Go's ErrUnknownCriticalExtension path
// (a critical extension name not in the known registry). The appraiser maps the
// former to status "malformed" and the latter to status "unknown_suite".
export class MalformedCritError extends Error {
  readonly code = 1;
}

export class UnknownCritError extends Error {
  readonly code = 1;
}

// checkCriticalExtensions rejects any critical-extension name that is empty,
// duplicated, or not in the known registry. Empty/duplicate throw
// MalformedCritError; an unknown name throws UnknownCritError. When applied to
// the envelope-level crit_ext list either is envelope-fatal; when applied to a
// signature's protected.crit list the appraiser turns them into a per-signature
// status.
export function checkCriticalExtensions(crit: string[] | undefined): void {
  if (crit === undefined) return;
  const seen = new Set<string>();
  for (const name of crit) {
    if (name === "") {
      throw new MalformedCritError("empty critical extension name");
    }
    if (seen.has(name)) {
      throw new MalformedCritError(`duplicate critical extension ${JSON.stringify(name)}`);
    }
    seen.add(name);
  }
  for (const name of seen) {
    if (!knownCriticalExtensions[name]) {
      throw new UnknownCritError(`unknown critical extension ${JSON.stringify(name)}`);
    }
  }
}
