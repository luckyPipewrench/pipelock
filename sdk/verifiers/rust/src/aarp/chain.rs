// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//! Rung-1 chain linkage verification, ported from `internal/aarp/chain.go`.
//! VerifyChain checks only the linkage that makes backdating, insertion, and
//! reordering within a single issuer's stream detectable. It does NOT verify
//! signatures.

use std::collections::BTreeMap;

use super::envelope::Envelope;
use super::jcs::{canonicalize_value, Json};

/// verify_chain checks that envs form a contiguous, hash-linked stream from a
/// single issuer. Returns Ok(()) when linked, Err(msg) otherwise.
pub fn verify_chain(envs: &[Envelope]) -> Result<(), String> {
    if envs.is_empty() {
        return Err("empty chain".to_string());
    }
    let mut issuer = String::new();
    let mut prev_seq: u64 = 0;
    let mut prev_hash = String::new();
    for (index, env) in envs.iter().enumerate() {
        let Some(chain) = &env.chain else {
            return Err(format!("envelope[{index}] has no chain link"));
        };
        chain.validate().map_err(|err| err.to_string())?;
        let seq = parse_seq(&chain.seq)?;
        if index == 0 {
            issuer = chain.issuer_id.clone();
        } else {
            if chain.issuer_id != issuer {
                return Err(format!(
                    "envelope[{index}] issuer {:?} != stream issuer {issuer:?}",
                    chain.issuer_id
                ));
            }
            if seq != prev_seq + 1 {
                return Err(format!(
                    "envelope[{index}] seq {seq}, expected {}",
                    prev_seq + 1
                ));
            }
            if chain.prior_hash != prev_hash {
                return Err(format!(
                    "envelope[{index}] prior_hash does not match previous payload digest"
                ));
            }
        }
        let digest = env
            .payload_digest()
            .map_err(|err| format!("envelope[{index}]: {err}"))?;
        prev_seq = seq;
        prev_hash = digest;
    }
    Ok(())
}

fn parse_seq(s: &str) -> Result<u64, String> {
    super::envelope::validate_uint64_string(s, "chain.seq").map_err(|err| err.to_string())?;
    s.parse::<u64>().map_err(|err| format!("seq: {err}"))
}

/// comparable_chain returns the JCS-canonical bytes of the chain comparison
/// surface: `{chain_linked, length}`.
pub fn comparable_chain(envs: &[Envelope]) -> Result<Vec<u8>, String> {
    let linked = verify_chain(envs).is_ok();
    let mut obj: BTreeMap<String, Json> = BTreeMap::new();
    obj.insert("chain_linked".to_string(), Json::Bool(linked));
    obj.insert("length".to_string(), Json::Number(envs.len().to_string()));
    canonicalize_value(&Json::Object(obj)).map_err(|err| err.to_string())
}
