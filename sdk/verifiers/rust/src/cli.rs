// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use crate::audit_packet::{verify_audit_packet, AuditPacketOptions};
use crate::chain::verify_chain_with_options;
use crate::chain_set::{
    chain_scoped_trust, read_session_receipts, resolve_base_sessions, run_session_base,
    verify_base, BaseVerifyOptions,
};
use crate::lifecycle::analyze_lifecycle;
use crate::output::{emit_audit_packet, emit_chain, emit_chain_set, emit_receipt};
use crate::provenance_proof::run_provenance;
use crate::receipt::run_receipt;
use crate::recorder::{
    extract_typed_receipts, extract_typed_receipts_from_session_dir, ExtractedReceipts,
};
use crate::rotation::{
    load_rotation_endorsement_file, verify_chain_with_endorsements, RotationEndorsement,
};
use crate::types::{
    ChainCommandReport, ChainSetContinuity, ChainSetEntry, ChainSetLink, ChainSetReport, Receipt,
};
use crate::util::{resolve_signer_key, Result, VerifierError};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Default)]
struct ParsedArgs {
    positionals: Vec<String>,
    json: bool,
    key: String,
    offline: bool,
    allow_self_consistent_only: bool,
    allow_unpinned: bool,
    allow_incomplete: bool,
    no_trust_required: bool,
    expect_sha256: String,
    dir: bool,
    session_id: String,
    session_explicit: bool,
    rotation_endorsements: Vec<String>,
}

pub fn run(args: &[String]) -> Result<i32> {
    let Some((command, rest)) = args.split_first() else {
        return Err(VerifierError::Usage(usage(None)));
    };
    match command.as_str() {
        "aarp" => crate::aarp::run_aarp(rest),
        "audit-packet" => run_audit_packet_command(rest),
        "chain" => run_chain_command(rest),
        "receipt" => run_receipt_command(rest),
        "provenance" => run_provenance_command(rest),
        _ => Err(VerifierError::Usage(format!(
            "unknown command {command}\n{}",
            usage(None)
        ))),
    }
}

fn run_provenance_command(args: &[String]) -> Result<i32> {
    let parsed = parse_args(args, "provenance")?;
    let target = require_one_arg(&parsed.positionals, "provenance")?;
    let report = run_provenance(&PathBuf::from(target))?;
    // This is intentionally compact and has a fixed key order: it is a
    // fixture-only differential surface, not the human receipt report.
    println!(
        "{}",
        serde_json::to_string(&report)
            .map_err(|err| VerifierError::Runtime(format!("encode provenance report: {err}")))?
    );
    Ok(
        if report.overall == "invalid"
            || (report.overall == "incomplete" && !parsed.allow_incomplete)
        {
            1
        } else {
            0
        },
    )
}

fn run_audit_packet_command(args: &[String]) -> Result<i32> {
    let parsed = parse_args(args, "audit-packet")?;
    let target = require_one_arg(&parsed.positionals, "audit-packet")?;
    let report = verify_audit_packet(
        target,
        &AuditPacketOptions {
            signer_key: parsed.key,
            offline: parsed.offline,
            allow_self_consistent_only: parsed.allow_self_consistent_only,
            no_trust_required: parsed.no_trust_required,
            expect_sha256: parsed.expect_sha256,
        },
    )?;
    emit_audit_packet(&report, parsed.json)?;
    Ok(if report.valid { 0 } else { 1 })
}

fn chain_report_for(
    label: String,
    receipts: &[Receipt],
    key_hex: &str,
    allow_unpinned: bool,
    endorsements: &[RotationEndorsement],
    session_id: &str,
) -> ChainCommandReport {
    if receipts.is_empty() {
        return ChainCommandReport {
            path: label,
            valid: false,
            unpinned: None,
            receipt_count: 0,
            final_seq: 0,
            root_hash: None,
            error: Some("no receipts in chain".to_string()),
            broken_at_seq: None,
        };
    }
    let result = if endorsements.is_empty() {
        verify_chain_with_options(receipts, key_hex, allow_unpinned)
    } else {
        verify_chain_with_endorsements(receipts, session_id, endorsements, key_hex)
    };
    let lifecycle = analyze_lifecycle(receipts, &result);
    let lifecycle_broken = lifecycle.status == "BROKEN";
    ChainCommandReport {
        path: label,
        valid: result.valid && !lifecycle_broken,
        unpinned: (key_hex.is_empty()
            && (result.error.as_deref().unwrap_or("").contains("UNPINNED")
                || (result.valid && !lifecycle_broken)))
            .then_some(true),
        receipt_count: result.receipt_count,
        final_seq: result.final_seq,
        root_hash: (!result.root_hash.is_empty()).then_some(result.root_hash),
        // Preserve the verifier's concrete cryptographic, hash, trust, or
        // sequence failure. Lifecycle is a supplemental gate only when the
        // chain itself verified successfully.
        error: if lifecycle_broken && result.valid {
            Some(format!("lifecycle: {}", lifecycle.reason))
        } else {
            result.error
        },
        broken_at_seq: result.broken_at_seq,
    }
}

/// Picks the key an EvidenceReceipt v2 chain is verified against. A v2 chain
/// has one signer and is verified against one key. Given a trusted set
/// (directory mode passes each run its scoped trust, which includes an
/// endorsed successor key), it is the trusted key equal to the chain's
/// declared `signer_key_id`. The declared id only selects: every receipt is
/// still verified against that key, and a signer outside the set gets the
/// first trusted key, which then fails. A single key is returned unchanged.
fn evidence_chain_key(key_hex: &str, receipts: &[Receipt]) -> String {
    let keys: Vec<String> = key_hex
        .split(',')
        .map(|key| key.trim().to_ascii_lowercase())
        .filter(|key| !key.is_empty())
        .collect();
    if keys.len() <= 1 {
        return key_hex.to_string();
    }
    let declared = receipts
        .first()
        .and_then(|r| r.get("signature"))
        .and_then(|sig| sig.get("signer_key_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    keys.iter()
        .find(|key| **key == declared)
        .unwrap_or(&keys[0])
        .clone()
}

/// Verifies every receipt chain one session or file holds. A current run
/// writes an ActionReceipt v1 chain and an EvidenceReceipt v2 chain into the
/// same files, each signed on its own, so a forged receipt in one leaves the
/// other intact: verifying only the chain `select_chain` picks reported a
/// session valid while its v2 chain was forged. Both chains must verify. The
/// action report stays the primary one, so a session whose chains both pass
/// prints exactly what it did before, and a failure names the chain it came
/// from.
fn typed_chain_report(
    label: String,
    typed: ExtractedReceipts,
    key_hex: &str,
    allow_unpinned: bool,
    endorsements: &[RotationEndorsement],
    session_id: &str,
) -> ChainCommandReport {
    if typed.action.is_empty() {
        let key = evidence_chain_key(key_hex, &typed.evidence);
        return chain_report_for(
            label,
            &typed.evidence,
            &key,
            allow_unpinned,
            endorsements,
            session_id,
        );
    }
    let primary = chain_report_for(
        label.clone(),
        &typed.action,
        key_hex,
        allow_unpinned,
        endorsements,
        session_id,
    );
    if typed.evidence.is_empty() {
        return primary;
    }
    let evidence = chain_report_for(
        label,
        &typed.evidence,
        &evidence_chain_key(key_hex, &typed.evidence),
        allow_unpinned,
        endorsements,
        session_id,
    );
    if primary.valid && evidence.valid {
        return primary;
    }
    // Without a key and without --allow-unpinned both chains fail only for
    // being unpinned; the action report already says so.
    if primary.unpinned == Some(true) && evidence.unpinned == Some(true) {
        return primary;
    }
    let mut reasons = Vec::new();
    if !primary.valid {
        reasons.push(format!(
            "action receipt chain: {}",
            primary.error.as_deref().unwrap_or("")
        ));
    }
    if !evidence.valid {
        reasons.push(format!(
            "evidence receipt chain: {}",
            evidence.error.as_deref().unwrap_or("")
        ));
    }
    ChainCommandReport {
        valid: false,
        unpinned: None,
        error: Some(reasons.join("; ")),
        broken_at_seq: if primary.valid {
            evidence.broken_at_seq
        } else {
            primary.broken_at_seq
        },
        ..primary
    }
}

fn load_endorsements(paths: &[String], allow_unpinned: bool) -> Result<Vec<RotationEndorsement>> {
    if !paths.is_empty() && allow_unpinned {
        return Err(VerifierError::Usage(
            "--rotation-endorsement cannot be combined with --allow-unpinned".to_string(),
        ));
    }
    paths
        .iter()
        .map(|path| load_rotation_endorsement_file(&PathBuf::from(path)))
        .collect()
}

/// Verifies every chain of `base` in `dir` and the base's restart
/// continuity, matching the Go reference `verify-receipt --chain`.
fn run_chain_set_command(
    dir: &Path,
    base: &str,
    key_hex: &str,
    parsed: &ParsedArgs,
) -> Result<i32> {
    let endorsements = load_endorsements(&parsed.rotation_endorsements, parsed.allow_unpinned)?;
    let trusted_keys: Vec<String> = key_hex
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_string)
        .collect();
    let (sessions, base_report) = resolve_base_sessions(dir, base)
        .and_then(|sessions| {
            let opts = BaseVerifyOptions {
                trusted_keys: trusted_keys.clone(),
                endorsements: endorsements.clone(),
            };
            verify_base(dir, base, &opts).map(|report| (sessions, report))
        })
        .map_err(|err| {
            VerifierError::Runtime(format!("restart continuity check incomplete: {err}"))
        })?;
    let mut chains = Vec::new();
    for session in &sessions {
        let label = format!("{} (session {session})", dir.display());
        let (keys, own) = chain_scoped_trust(&base_report, session, &trusted_keys, &endorsements);
        let chain = match read_session_receipts(dir, session) {
            Ok((action, evidence)) => typed_chain_report(
                label,
                ExtractedReceipts { action, evidence },
                &keys.join(","),
                parsed.allow_unpinned,
                &own,
                session,
            ),
            Err(err) => ChainCommandReport {
                path: label,
                valid: false,
                unpinned: None,
                receipt_count: 0,
                final_seq: 0,
                root_hash: None,
                error: Some(format!("extract receipts: {err}")),
                broken_at_seq: None,
            },
        };
        chains.push(ChainSetEntry {
            session: session.clone(),
            report: chain,
        });
    }
    let healthy = base_report.healthy();
    let report = ChainSetReport {
        path: dir.display().to_string(),
        base: base.to_string(),
        valid: healthy && chains.iter().all(|c| c.report.valid),
        chains,
        continuity: ChainSetContinuity {
            healthy,
            linked: base_report
                .chains
                .iter()
                .filter_map(|c| {
                    c.link.as_ref().map(|link| ChainSetLink {
                        session: c.session.clone(),
                        predecessor_session: link.predecessor_session.clone(),
                        predecessor_tail_seq: link.predecessor_tail_seq,
                        trust: if c.link_trust.is_empty() {
                            "untrusted".to_string()
                        } else {
                            c.link_trust.clone()
                        },
                    })
                })
                .collect(),
            unlinked: base_report.unlinked(),
            findings: base_report.findings.clone(),
        },
    };
    emit_chain_set(&report, parsed.json)?;
    Ok(if report.valid { 0 } else { 1 })
}

fn run_chain_command(args: &[String]) -> Result<i32> {
    let parsed = parse_args(args, "chain")?;
    let target = require_one_arg(&parsed.positionals, "chain")?;
    let key_hex = resolve_signer_key(&parsed.key)?;
    let clean = PathBuf::from(target);
    // Without an explicit --session-id, a directory whose base has per-run
    // chains is verified as a whole: every run and the links between them.
    // An explicit --session-id keeps single-session verification.
    if parsed.dir && !parsed.session_explicit {
        let has_runs = resolve_base_sessions(&clean, &parsed.session_id)
            .map_err(|err| VerifierError::Runtime(format!("extract receipts: {err}")))?
            .iter()
            .any(|s| run_session_base(s).is_some());
        if has_runs {
            return run_chain_set_command(&clean, &parsed.session_id, &key_hex, &parsed);
        }
    }
    let (typed, label) = if parsed.dir {
        (
            extract_typed_receipts_from_session_dir(&clean, &parsed.session_id)
                .map_err(|err| VerifierError::Runtime(format!("extract receipts: {err}")))?,
            format!("{} (session {})", clean.display(), parsed.session_id),
        )
    } else {
        if fs::metadata(&clean)
            .map_err(|err| VerifierError::Runtime(format!("stat {}: {err}", clean.display())))?
            .is_dir()
        {
            return Err(VerifierError::Runtime(format!(
                "{target} is a directory; pass --dir to verify a session directory"
            )));
        }
        (
            extract_typed_receipts(&clean)
                .map_err(|err| VerifierError::Runtime(format!("extract receipts: {err}")))?,
            clean.display().to_string(),
        )
    };

    if typed.action.is_empty() && typed.evidence.is_empty() {
        let report = chain_report_for(label, &[], &key_hex, false, &[], &parsed.session_id);
        emit_chain(&report, parsed.json)?;
        return Ok(1);
    }

    let endorsements = load_endorsements(&parsed.rotation_endorsements, parsed.allow_unpinned)?;
    let report = typed_chain_report(
        label,
        typed,
        &key_hex,
        parsed.allow_unpinned,
        &endorsements,
        &parsed.session_id,
    );
    emit_chain(&report, parsed.json)?;
    Ok(if report.valid { 0 } else { 1 })
}

fn run_receipt_command(args: &[String]) -> Result<i32> {
    let parsed = parse_args(args, "receipt")?;
    let target = require_one_arg(&parsed.positionals, "receipt")?;
    let report = run_receipt(target, &parsed.key, parsed.allow_unpinned)?;
    emit_receipt(&report, parsed.json)?;
    Ok(if report.valid { 0 } else { 1 })
}

fn parse_args(args: &[String], command: &str) -> Result<ParsedArgs> {
    let mut parsed = ParsedArgs {
        session_id: "proxy".to_string(),
        ..ParsedArgs::default()
    };
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if !arg.starts_with("--") {
            parsed.positionals.push(arg.clone());
            index += 1;
            continue;
        }
        let (flag, inline_value) = split_flag_value(arg);
        match arg.as_str() {
            "--json" => parsed.json = true,
            "--offline" if command == "audit-packet" => parsed.offline = true,
            "--allow-self-consistent-only" if command == "audit-packet" => {
                parsed.allow_self_consistent_only = true;
            }
            "--allow-unpinned" if command == "chain" || command == "receipt" => {
                parsed.allow_unpinned = true;
            }
            "--allow-incomplete" if command == "provenance" => parsed.allow_incomplete = true,
            "--no-trust-required" if command == "audit-packet" => parsed.no_trust_required = true,
            "--dir" if command == "chain" => parsed.dir = true,
            "--key" => {
                index += 1;
                parsed.key = args
                    .get(index)
                    .ok_or_else(|| {
                        VerifierError::Usage(format!(
                            "--key requires a value\n{}",
                            usage(Some(command))
                        ))
                    })?
                    .clone();
            }
            "--expect-sha256" if command == "audit-packet" => {
                index += 1;
                parsed.expect_sha256 = args
                    .get(index)
                    .ok_or_else(|| {
                        VerifierError::Usage(format!(
                            "--expect-sha256 requires a value\n{}",
                            usage(Some(command))
                        ))
                    })?
                    .clone();
            }
            "--session-id" if command == "chain" => {
                index += 1;
                parsed.session_explicit = true;
                parsed.session_id = args
                    .get(index)
                    .ok_or_else(|| {
                        VerifierError::Usage(format!(
                            "--session-id requires a value\n{}",
                            usage(Some(command))
                        ))
                    })?
                    .clone();
            }
            "--rotation-endorsement" if command == "chain" => {
                index += 1;
                parsed.rotation_endorsements.push(
                    args.get(index)
                        .ok_or_else(|| {
                            VerifierError::Usage(format!(
                                "--rotation-endorsement requires a value\n{}",
                                usage(Some(command))
                            ))
                        })?
                        .clone(),
                );
            }
            _ => {
                if flag == "--key" {
                    parsed.key = inline_value.expect("split flag produced value").to_string();
                } else if flag == "--expect-sha256" && command == "audit-packet" {
                    parsed.expect_sha256 =
                        inline_value.expect("split flag produced value").to_string();
                } else if flag == "--session-id" && command == "chain" {
                    parsed.session_explicit = true;
                    parsed.session_id =
                        inline_value.expect("split flag produced value").to_string();
                } else if flag == "--rotation-endorsement" && command == "chain" {
                    parsed
                        .rotation_endorsements
                        .push(inline_value.expect("split flag produced value").to_string());
                } else {
                    return Err(VerifierError::Usage(format!(
                        "Unknown option {arg}\n{}",
                        usage(Some(command))
                    )));
                }
            }
        }
        index += 1;
    }
    Ok(parsed)
}

fn split_flag_value(arg: &str) -> (&str, Option<&str>) {
    if let Some((flag, value)) = arg.split_once('=') {
        (flag, Some(value))
    } else {
        (arg, None)
    }
}

fn require_one_arg<'a>(positionals: &'a [String], command: &str) -> Result<&'a str> {
    if positionals.len() != 1 {
        return Err(VerifierError::Usage(format!(
            "{}\naccepts 1 arg, received {}",
            usage(Some(command)),
            positionals.len()
        )));
    }
    Ok(&positionals[0])
}

fn usage(command: Option<&str>) -> String {
    match command {
        Some("audit-packet") => "Usage: pipelock-verifier-rs audit-packet PATH [--json] [--key HEX_OR_FILE] [--offline] [--allow-self-consistent-only] [--no-trust-required] [--expect-sha256 HEX]".to_string(),
        Some("chain") => "Usage: pipelock-verifier-rs chain PATH [--json] [--key HEX_OR_FILE] [--rotation-endorsement FILE]... [--allow-unpinned] [--dir] [--session-id ID]".to_string(),
        Some("receipt") => "Usage: pipelock-verifier-rs receipt PATH [--json] [--key HEX_OR_FILE] [--allow-unpinned]".to_string(),
        Some("provenance") => {
            "Usage: pipelock-verifier-rs provenance PATH [--allow-incomplete]".to_string()
        }
        _ => "Usage: pipelock-verifier-rs {aarp|audit-packet|chain|provenance|receipt} PATH [flags]"
            .to_string(),
    }
}
