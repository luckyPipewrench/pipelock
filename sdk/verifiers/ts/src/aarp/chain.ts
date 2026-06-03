// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Rung-1 chain linkage, ported from internal/aarp/chain.go. VerifyChain checks
// that a slice of envelopes forms a contiguous, hash-linked, single-issuer
// stream; it never checks signatures. comparableChain projects the outcome.

import { canonicalize } from "./canonical.js";
import { Envelope, payloadDigest } from "./envelope.js";

// verifyChain returns true when envs form a contiguous, single-issuer,
// hash-linked stream: every envelope carries a chain link, all links share one
// issuer, the sequence increments by exactly 1, and each prior_hash equals the
// previous envelope's payload digest. Returns false on any break.
export function verifyChain(envs: Envelope[]): boolean {
  if (envs.length === 0) return false;
  let issuer = "";
  let prevSeq = 0n;
  let prevHash = "";
  for (let i = 0; i < envs.length; i++) {
    const e = envs[i] as Envelope;
    if (e.chain === undefined) return false;
    // Chain-link grammar was validated during decode (validateChainLink runs in
    // validateStructure via decode path); here we re-derive the numeric seq.
    let seq: bigint;
    try {
      seq = BigInt(e.chain.seq);
    } catch {
      return false;
    }
    if (i === 0) {
      issuer = e.chain.issuer_id;
    } else {
      if (e.chain.issuer_id !== issuer) return false;
      if (seq !== prevSeq + 1n) return false;
      if (e.chain.prior_hash !== prevHash) return false;
    }
    prevSeq = seq;
    prevHash = payloadDigest(e);
  }
  return true;
}

// comparableChain projects a verifyChain outcome onto the cross-language
// comparison surface and returns its JCS-canonical bytes.
export function comparableChain(envs: Envelope[]): string {
  return canonicalize({
    chain_linked: verifyChain(envs),
    length: envs.length,
  });
}
