// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//! AARP v0.1 assurance-envelope verifier, ported from the Go reference in
//! `internal/aarp` and `cmd/pipelock-verifier/aarp.go`.
//!
//! CLI: `pipelock-verifier-rs aarp <PATH> --trust <TRUST_JSON> [--chain] [--json]`
//!
//! Exit codes: 0 appraised (single) / linked (chain); 1 envelope-fatal or chain
//! not linked; 2 I/O or trust-file error; 64 usage error. With `--json` a fatal
//! envelope prints `{"envelope_fatal":true,...}` and exits non-zero.

pub mod chain;
pub mod envelope;
pub mod jcs;
pub mod svid;
pub mod verify;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use envelope::Envelope;
use jcs::Json;
use verify::{TrustEntry, VerifyOptions};

use crate::util::{Result, VerifierError};

/// Outcome holds the bytes to print on stdout and the process exit code.
struct Outcome {
    stdout: String,
    code: i32,
}

#[derive(Default)]
struct AarpArgs {
    target: Option<String>,
    trust_path: String,
    svid_path: String,
    json: bool,
    chain: bool,
}

/// run_aarp is the `aarp` subcommand entry. It returns the process exit code.
/// Usage and trust/IO errors are surfaced as VerifierError (exit 64/2); all
/// envelope/chain outcomes are printed and return their own code.
pub fn run_aarp(args: &[String]) -> Result<i32> {
    let parsed = parse_aarp_args(args)?;
    let Some(target) = parsed.target.as_deref() else {
        return Err(VerifierError::Usage(aarp_usage()));
    };

    // --svid is single-envelope only; it cannot be combined with --chain.
    if parsed.chain && !parsed.svid_path.is_empty() {
        return Err(VerifierError::Usage(format!(
            "--svid is single-envelope only and cannot be combined with --chain\n{}",
            aarp_usage()
        )));
    }

    let opts = load_trust_file(&parsed.trust_path)
        .map_err(|err| VerifierError::Runtime(format!("load trust: {err}")))?;

    // Load the SVID sidecar (if any) before reading the envelope, so a malformed
    // operator-pinned bundle is reported as a config error (exit 2) rather than
    // entangled with envelope appraisal.
    let svid_input = if parsed.svid_path.is_empty() {
        None
    } else {
        Some(
            svid::load_svid_file(&parsed.svid_path)
                .map_err(|err| VerifierError::Runtime(format!("load svid: {err}")))?,
        )
    };

    let data = fs::read_to_string(Path::new(target))
        .map_err(|err| VerifierError::Runtime(format!("read envelope: {err}")))?;

    let outcome = if parsed.chain {
        run_chain(&data, parsed.json)
    } else {
        run_single(&data, &opts, svid_input.as_ref(), parsed.json)
    };

    print!("{}", outcome.stdout);
    Ok(outcome.code)
}

fn run_single(
    data: &str,
    opts: &VerifyOptions,
    svid_input: Option<&(svid::SvidEvidence, svid::PinnedTrust)>,
    json_mode: bool,
) -> Outcome {
    let env = match Envelope::unmarshal(data) {
        Ok(env) => env,
        Err(err) => return fatal(json_mode, &err.to_string()),
    };
    let mut appraisal = match verify::verify(&env, opts) {
        Ok(ap) => ap,
        Err(err) => return fatal(json_mode, &err),
    };
    // With --svid, appraise the X.509-SVID binding on top of the envelope
    // appraisal. The SVID claims attach only on a signed assertion whose binding
    // verifies against the pinned bundle; otherwise nothing is added and the
    // envelope appraisal is byte-identical. The producer claim
    // workload_identity_verified moves from claimed_unverified to verified only
    // when the binding verifies, so re-run the claim classification afterward.
    if let Some((ev, trust)) = svid_input {
        svid::add_svid_claims(&mut appraisal, &env, ev, trust);
        verify::reclassify_claims(&mut appraisal);
    }
    let comparable = match verify::comparable_appraisal(&appraisal) {
        Ok(bytes) => bytes,
        Err(err) => return fatal(json_mode, &format!("render appraisal: {err}")),
    };
    if json_mode {
        let mut stdout = String::from_utf8_lossy(&comparable).into_owned();
        stdout.push('\n');
        Outcome { stdout, code: 0 }
    } else {
        Outcome {
            stdout: human_appraisal(&appraisal),
            code: 0,
        }
    }
}

fn run_chain(data: &str, json_mode: bool) -> Outcome {
    let mut envs = Vec::new();
    for (index, line) in data.trim().split('\n').enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match Envelope::unmarshal(line) {
            Ok(env) => envs.push(env),
            Err(err) => return fatal(json_mode, &format!("chain line {index}: {err}")),
        }
    }

    let comparable = match chain::comparable_chain(&envs) {
        Ok(bytes) => bytes,
        Err(err) => return fatal(json_mode, &format!("render chain: {err}")),
    };

    let linked = chain::verify_chain(&envs).is_ok();
    let code = if linked { 0 } else { 1 };

    if json_mode {
        let mut stdout = String::from_utf8_lossy(&comparable).into_owned();
        stdout.push('\n');
        Outcome { stdout, code }
    } else {
        Outcome {
            stdout: format!("AARP chain: {} envelopes\n", envs.len()),
            code,
        }
    }
}

/// fatal builds the envelope-fatal outcome: the `{"envelope_fatal":true,...}`
/// marker in JSON mode (exit 1), or a human message in non-JSON mode.
fn fatal(json_mode: bool, cause: &str) -> Outcome {
    if json_mode {
        let mut obj: BTreeMap<String, Json> = BTreeMap::new();
        obj.insert("envelope_fatal".to_string(), Json::Bool(true));
        obj.insert("error".to_string(), Json::String(cause.to_string()));
        let bytes = jcs::canonicalize_value(&Json::Object(obj))
            .unwrap_or_else(|_| br#"{"envelope_fatal":true}"#.to_vec());
        let mut stdout = String::from_utf8_lossy(&bytes).into_owned();
        stdout.push('\n');
        Outcome { stdout, code: 1 }
    } else {
        Outcome {
            stdout: format!("ENVELOPE FATAL: {cause}\n"),
            code: 1,
        }
    }
}

fn human_appraisal(ap: &verify::Appraisal) -> String {
    let mut out = String::new();
    out.push_str(&format!("AARP appraisal ({})\n", ap.profile));
    out.push_str(&format!("  assertion_signed:   {}\n", ap.assertion_signed));
    out.push_str(&format!("  verified_claims:    {:?}\n", ap.verified_claims));
    out.push_str(&format!(
        "  claimed_unverified: {:?}\n",
        ap.claimed_unverified
    ));
    for s in &ap.signatures {
        out.push_str(&format!(
            "  signature {}/{}: {}\n",
            s.key_id, s.alg, s.status
        ));
    }
    out.push_str(&format!("  does_not_assert:    {:?}\n", ap.does_not_assert));
    out
}

fn parse_aarp_args(args: &[String]) -> Result<AarpArgs> {
    let mut parsed = AarpArgs::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--json" => parsed.json = true,
            "--chain" => parsed.chain = true,
            "--trust" => {
                index += 1;
                parsed.trust_path = args
                    .get(index)
                    .ok_or_else(|| {
                        VerifierError::Usage(format!("--trust requires a value\n{}", aarp_usage()))
                    })?
                    .clone();
            }
            _ if arg.starts_with("--trust=") => {
                parsed.trust_path = arg["--trust=".len()..].to_string();
            }
            "--svid" => {
                index += 1;
                parsed.svid_path = args
                    .get(index)
                    .ok_or_else(|| {
                        VerifierError::Usage(format!("--svid requires a value\n{}", aarp_usage()))
                    })?
                    .clone();
            }
            _ if arg.starts_with("--svid=") => {
                parsed.svid_path = arg["--svid=".len()..].to_string();
            }
            _ if arg.starts_with("--") => {
                return Err(VerifierError::Usage(format!(
                    "unknown option {arg}\n{}",
                    aarp_usage()
                )));
            }
            _ => {
                if parsed.target.is_some() {
                    return Err(VerifierError::Usage(format!(
                        "accepts 1 positional arg\n{}",
                        aarp_usage()
                    )));
                }
                parsed.target = Some(arg.clone());
            }
        }
        index += 1;
    }
    Ok(parsed)
}

fn aarp_usage() -> String {
    "Usage: pipelock-verifier-rs aarp PATH --trust TRUST_JSON [--svid SVID_JSON] [--chain] [--json]"
        .to_string()
}

// ---- trust file ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    #[serde(default)]
    trusted_keys: BTreeMap<String, String>,
    #[serde(default)]
    trust_entries: BTreeMap<String, TrustEntryFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustEntryFile {
    mediator_id: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    trust_domain: String,
}

/// load_trust_file reads the pinned trust JSON. A missing path yields empty
/// trust (every signature reported unknown_key) so the verifier still runs.
fn load_trust_file(path: &str) -> std::result::Result<VerifyOptions, String> {
    let mut opts = VerifyOptions::default();
    if path.is_empty() {
        return Ok(opts);
    }
    let data =
        fs::read_to_string(Path::new(path)).map_err(|err| format!("read trust file: {err}"))?;
    let tf: TrustFile =
        serde_json::from_str(&data).map_err(|err| format!("parse trust file: {err}"))?;
    for (key_id, key_hex) in tf.trusted_keys {
        let raw = hex::decode(&key_hex)
            .map_err(|err| format!("trusted_keys[{key_id:?}]: not hex: {err}"))?;
        let arr: [u8; 32] = raw.try_into().map_err(|raw: Vec<u8>| {
            format!("trusted_keys[{key_id:?}]: {} bytes, want 32", raw.len())
        })?;
        opts.trusted_keys.insert(key_id, arr);
    }
    for (key_id, entry) in tf.trust_entries {
        opts.trust.insert(
            key_id,
            TrustEntry {
                mediator_id: entry.mediator_id,
                role: entry.role,
                trust_domain: entry.trust_domain,
            },
        );
    }
    Ok(opts)
}
