// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use crate::audit_packet::{verify_audit_packet, AuditPacketOptions};
use crate::chain::{evidence_chain_key, verify_chain_with_options};
use crate::chain_set::{
    chain_scoped_trust, check_file_entry_sessions, read_session_evidence, read_session_receipts,
    refuse_symlink_in_evidence_root_path, resolve_base_sessions, run_session_base, verify_base,
    with_pinned_evidence_directory, BaseVerifyOptions, SessionReadError,
    FINDING_OUTER_CHAIN_BROKEN,
};
use crate::lifecycle::analyze_lifecycle;
use crate::output::{emit_audit_packet, emit_chain, emit_chain_set, emit_receipt, report_failure};
use crate::provenance_proof::run_provenance;
use crate::receipt::run_receipt;
use crate::recorder::{extract_typed_from_lines, read_entry_lines, ExtractedReceipts};
use crate::recorder_chain::verify_recorder_chain;
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
    keys: Vec<String>,
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
            signer_key: String::new(),
            signer_keys: parsed.keys,
            offline: parsed.offline,
            allow_self_consistent_only: parsed.allow_self_consistent_only,
            no_trust_required: parsed.no_trust_required,
            expect_sha256: parsed.expect_sha256,
        },
    )?;
    emit_audit_packet(&report, parsed.json)?;
    if !report.valid {
        report_failure(&format!(
            "audit packet {}: {}",
            report.path,
            report
                .errors
                .as_ref()
                .and_then(|errors| errors.first())
                .map_or("not valid", String::as_str)
        ));
    }
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
            ..ChainCommandReport::default()
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
        ..ChainCommandReport::default()
    }
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
    let (action, evidence) = (typed.action.len(), typed.evidence.len());
    ChainCommandReport {
        action_receipts: Some(action),
        evidence_receipts: Some(evidence),
        ..both_chains_report(
            label,
            typed,
            key_hex,
            allow_unpinned,
            endorsements,
            session_id,
        )
    }
}

fn both_chains_report(
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
            &[],
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
        &[],
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

fn load_endorsements(
    paths: &[String],
    allow_unpinned: bool,
    key_hex: &str,
) -> Result<Vec<RotationEndorsement>> {
    check_endorsement_usage(paths, allow_unpinned, key_hex)?;
    paths
        .iter()
        .map(|path| load_rotation_endorsement_file(&PathBuf::from(path)))
        .collect()
}

/// Usage errors outrank path resolution, so a bad flag combination reports
/// the same exit status whether or not the endorsement file exists.
fn check_endorsement_usage(paths: &[String], allow_unpinned: bool, key_hex: &str) -> Result<()> {
    if !paths.is_empty() && allow_unpinned {
        return Err(VerifierError::Usage(
            "--rotation-endorsement cannot be combined with --allow-unpinned".to_string(),
        ));
    }
    if !paths.is_empty() && key_hex.trim().is_empty() {
        return Err(VerifierError::Usage(
            "--rotation-endorsement requires --key: an endorsement is authority only under a trusted root key".to_string(),
        ));
    }
    Ok(())
}

/// Verifies chains of `base` in `dir` and the base's restart continuity,
/// matching the Go reference `verify-receipt --chain`. Without `targets` every
/// chain of the base is verified. With `targets` (a named run) only those
/// chains are verified, and the whole base is still checked: a named run fails
/// on any finding in its base, and the finding names the run it concerns,
/// because a run's standing depends on facts only the base shows (its
/// predecessor's tail, a second successor, a replayed copy of it).
fn run_chain_set_command(
    dir: &Path,
    display_dir: &Path,
    base: &str,
    key_hex: &str,
    parsed: &ParsedArgs,
    targets: Option<Vec<String>>,
) -> Result<i32> {
    let endorsements = load_endorsements(
        &parsed.rotation_endorsements,
        parsed.allow_unpinned,
        key_hex,
    )?;
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
    for session in targets.as_ref().unwrap_or(&sessions) {
        let label = format!("{} (session {session})", display_dir.display());
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
                error: Some(format!("extract receipts: {err}")),
                ..ChainCommandReport::default()
            },
        };
        chains.push(ChainSetEntry {
            session: session.clone(),
            report: chain,
        });
    }
    let healthy = base_report.healthy();
    let report = ChainSetReport {
        path: display_dir.display().to_string(),
        base: base.to_string(),
        valid: healthy && chains.iter().all(|c| c.report.valid),
        chains,
        continuity: ChainSetContinuity {
            healthy,
            chain_count: base_report.chains.len(),
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
            discontinuities: base_report
                .chains
                .iter()
                .filter_map(|c| {
                    c.recovery_seal
                        .as_ref()
                        .map(|seal| crate::types::ChainSetDiscontinuity {
                            session: c.session.clone(),
                            predecessor_session: seal.predecessor_session.clone(),
                            shard: seal.shard.clone(),
                            damage_offset: seal.damage_offset,
                        })
                })
                .collect(),
            unlinked: base_report.unlinked(),
            findings: base_report.findings.clone(),
        },
    };
    emit_chain_set(&report, parsed.json)?;
    if !report.valid {
        let mut reasons = Vec::new();
        let failed: Vec<&str> = report
            .chains
            .iter()
            .filter(|c| !c.report.valid)
            .map(|c| c.session.as_str())
            .collect();
        if !failed.is_empty() {
            reasons.push(format!(
                "chain verification failed for {} of {} chain(s): {}",
                failed.len(),
                report.chains.len(),
                failed.join(", ")
            ));
        }
        if !healthy {
            reasons.push(format!(
                "restart continuity: {} finding(s): {}",
                base_report.findings.len(),
                base_report
                    .findings
                    .iter()
                    .map(|f| format!("{} ({})", f.kind, f.session))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        report_failure(&format!(
            "{}: {}",
            display_dir.display(),
            reasons.join("; ")
        ));
    }
    Ok(if report.valid { 0 } else { 1 })
}

/// Folds the recorder entry hash chain into a chain report: a report whose
/// receipts verify is still broken when the entries around them were edited
/// without recomputing the recorder hashes.
fn with_recorder_chain(report: ChainCommandReport, outer: Option<String>) -> ChainCommandReport {
    let Some(outer) = outer else {
        return report;
    };
    let reason = format!("{FINDING_OUTER_CHAIN_BROKEN}: recorder entry hash chain: {outer}");
    let error = match (&report.error, report.valid) {
        (Some(err), false) => format!("{reason}; {err}"),
        _ => reason,
    };
    ChainCommandReport {
        valid: false,
        unpinned: None,
        error: Some(error),
        ..report
    }
}

fn emit_chain_result(report: &ChainCommandReport, json: bool) -> Result<i32> {
    emit_chain(report, json)?;
    if report.valid {
        return Ok(0);
    }
    report_failure(&format!(
        "{}: {}: {}",
        report.path,
        if report.unpinned == Some(true) {
            "chain unpinned"
        } else {
            "chain broken"
        },
        report.error.as_deref().unwrap_or("no receipts in chain")
    ));
    Ok(1)
}

/// Resolves every `--key` value and joins the trusted set.
fn resolve_signer_keys(values: &[String]) -> Result<String> {
    Ok(values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .map(|value| resolve_signer_key(value))
        .collect::<Result<Vec<_>>>()?
        .join(","))
}

fn run_chain_command(args: &[String]) -> Result<i32> {
    let mut parsed = parse_args(args, "chain")?;
    let target = require_one_arg(&parsed.positionals, "chain")?;
    let key_hex = resolve_signer_keys(&parsed.keys)?;
    let clean = PathBuf::from(target);
    if parsed.dir {
        match refuse_symlink_in_evidence_root_path(&clean) {
            Ok(()) => {}
            Err(err) if err.refused => {
                let report = ChainCommandReport {
                    path: target.to_string(),
                    error: Some(err.message),
                    ..ChainCommandReport::default()
                };
                return emit_chain_result(&report, parsed.json);
            }
            Err(err) => {
                return Err(VerifierError::Runtime(format!(
                    "resolve evidence location: {}",
                    err.message
                )))
            }
        }
        // Endorsements are read after the working directory is pinned, so
        // resolve them against the operator's directory first.
        check_endorsement_usage(
            &parsed.rotation_endorsements,
            parsed.allow_unpinned,
            &key_hex,
        )?;
        parsed.rotation_endorsements = parsed
            .rotation_endorsements
            .iter()
            .map(|p| {
                fs::canonicalize(p)
                    .map(|path| path.to_string_lossy().into_owned())
                    .map_err(|err| {
                        VerifierError::Runtime(format!("resolve rotation endorsement {p}: {err}"))
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        return with_pinned_evidence_directory(&clean, || {
            run_chain_at(Path::new("."), &clean, target, &parsed, &key_hex)
        });
    }
    run_chain_at(&clean, &clean, target, &parsed, &key_hex)
}

fn run_chain_at(
    clean: &Path,
    display: &Path,
    target: &str,
    parsed: &ParsedArgs,
    key_hex: &str,
) -> Result<i32> {
    // A directory whose base has per-run chains is verified as a base, as the
    // Go reference does: the base of a run session is its prefix, and any
    // other session is its own base. Without --session-id every chain of the
    // base is verified; with it only that chain, plus the whole-base checks.
    if parsed.dir {
        let base = run_session_base(&parsed.session_id).unwrap_or(&parsed.session_id);
        let has_runs = resolve_base_sessions(clean, base)
            .map_err(|err| VerifierError::Runtime(format!("extract receipts: {err}")))?
            .iter()
            .any(|s| run_session_base(s).is_some());
        if has_runs {
            let targets = parsed
                .session_explicit
                .then(|| vec![parsed.session_id.clone()]);
            return run_chain_set_command(clean, display, base, key_hex, parsed, targets);
        }
    }
    let label = if parsed.dir {
        format!("{} (session {})", display.display(), parsed.session_id)
    } else {
        clean.display().to_string()
    };
    let read = if parsed.dir {
        read_session_evidence(clean, &parsed.session_id)
    } else {
        if fs::metadata(clean)
            .map_err(|err| VerifierError::Runtime(format!("stat {}: {err}", clean.display())))?
            .is_dir()
        {
            return Err(VerifierError::Runtime(format!(
                "{target} is a directory; pass --dir to verify a session directory"
            )));
        }
        // A file named on the command line is read as given, even through a
        // symlink: the operator chose it.
        read_file_evidence(clean)
    };
    let (outer, typed) = match read {
        Ok(read) => read,
        Err(err) if err.refused => {
            let report = ChainCommandReport {
                path: label,
                error: Some(err.message),
                ..ChainCommandReport::default()
            };
            return emit_chain_result(&report, parsed.json);
        }
        Err(err) => {
            return Err(VerifierError::Runtime(format!(
                "extract receipts: {}",
                err.message
            )))
        }
    };

    if typed.action.is_empty() && typed.evidence.is_empty() {
        let report = chain_report_for(label, &[], key_hex, false, &[], &parsed.session_id);
        return emit_chain_result(&with_recorder_chain(report, outer), parsed.json);
    }

    let endorsements = load_endorsements(
        &parsed.rotation_endorsements,
        parsed.allow_unpinned,
        key_hex,
    )?;
    let report = typed_chain_report(
        label,
        typed,
        key_hex,
        parsed.allow_unpinned,
        &endorsements,
        &parsed.session_id,
    );
    emit_chain_result(&with_recorder_chain(report, outer), parsed.json)
}

/// Reads one recorder file: its hash chain verdict and its two receipt chains.
fn read_file_evidence(
    path: &Path,
) -> std::result::Result<(Option<String>, ExtractedReceipts), SessionReadError> {
    let lines = read_entry_lines(path).map_err(|err| SessionReadError {
        refused: false,
        message: err.to_string(),
    })?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    check_file_entry_sessions(&name, &lines)?;
    let outer = verify_recorder_chain(&lines.iter().map(|l| l.line.as_str()).collect::<Vec<_>>());
    let typed = extract_typed_from_lines(lines).map_err(|err| SessionReadError {
        refused: false,
        message: err.to_string(),
    })?;
    Ok((outer, typed))
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
                parsed.keys.push(parsed.key.clone());
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
                    parsed.keys.push(parsed.key.clone());
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
        Some("audit-packet") => "Usage: pipelock-verifier-rs audit-packet PATH [--json] [--key HEX_OR_FILE]... [--offline] [--allow-self-consistent-only] [--no-trust-required] [--expect-sha256 HEX]".to_string(),
        Some("chain") => "Usage: pipelock-verifier-rs chain PATH [--json] [--key HEX_OR_FILE]... [--rotation-endorsement FILE]... [--allow-unpinned] [--dir] [--session-id ID]".to_string(),
        Some("receipt") => "Usage: pipelock-verifier-rs receipt PATH [--json] [--key HEX_OR_FILE] [--allow-unpinned]".to_string(),
        Some("provenance") => {
            "Usage: pipelock-verifier-rs provenance PATH [--allow-incomplete]".to_string()
        }
        _ => "Usage: pipelock-verifier-rs {aarp|audit-packet|chain|provenance|receipt} PATH [flags]"
            .to_string(),
    }
}
