// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use crate::chain::{compute_totals, evidence_chain_key, verify_chain_with_options};
use crate::lifecycle::analyze_lifecycle;
use crate::recorder::extract_typed_receipts;
use crate::schema::validate_audit_packet;
use crate::types::{
    AuditPacket, AuditPacketReport, ChainResult, Receipt, ReportPosture, ReportRun, ReportSummary,
    Totals,
};
use crate::util::{
    bool_at, parse_json_text, reject_duplicate_keys, resolve_artifact_path, resolve_packet_path,
    resolve_signer_key, sha256_hex, string_at, string_vec_at, u64_at, Result,
};

#[derive(Debug, Clone, Default)]
pub struct AuditPacketOptions {
    pub signer_key: String,
    /// The trusted key set (each a hex key or key file), used instead of
    /// `signer_key` when non-empty, as repeated `--key` flags give it.
    pub signer_keys: Vec<String>,
    pub offline: bool,
    pub allow_self_consistent_only: bool,
    pub no_trust_required: bool,
    pub expect_sha256: String,
}

/// Keeps a failed verification from repeating the packet's own trust claim.
/// The report starts with the packet's verdict and trusted fields, so any
/// failure after that point would otherwise report "verdict: valid, trusted:
/// true" beside an INVALID result. A report that is not valid never claims
/// trust, and a success verdict becomes invalid. A successful report and the
/// offline report are unchanged.
fn without_claimed_trust(mut report: AuditPacketReport) -> AuditPacketReport {
    if report.valid {
        return report;
    }
    report.trusted = false;
    if report.verdict == "valid" || report.verdict == "self_consistent_only" {
        report.verdict = "invalid".to_string();
    }
    report
}

pub fn verify_audit_packet(target: &str, opts: &AuditPacketOptions) -> Result<AuditPacketReport> {
    verify_audit_packet_report(target, opts).map(without_claimed_trust)
}

fn verify_audit_packet_report(
    target: &str,
    opts: &AuditPacketOptions,
) -> Result<AuditPacketReport> {
    let (packet_path, base_dir) = resolve_packet_path(target)?;
    let raw_packet = crate::util::read_verifier_bytes(&packet_path)?;
    let packet_path_string = packet_path.display().to_string();
    let mut report = report_from_packet(&packet_path_string, None);

    if !opts.expect_sha256.is_empty() {
        let got = sha256_hex(&raw_packet);
        let want = opts.expect_sha256.trim().to_ascii_lowercase();
        if got != want {
            push_error(
                &mut report,
                format!("packet sha256 mismatch: got {got}, want {want}"),
            );
            return Ok(report);
        }
    }

    let packet_text = match String::from_utf8(raw_packet) {
        Ok(text) => text,
        Err(err) => {
            push_error(&mut report, format!("packet json: invalid UTF-8: {err}"));
            return Ok(report);
        }
    };
    // Reject duplicate object keys before parsing, matching the Go verifier and
    // the receipt path. Last-wins parsing would otherwise let this verifier
    // accept a packet the Go verifier rejects, resolving the duplicate to the
    // attacker's second value.
    if let Err(err) = reject_duplicate_keys(&packet_text) {
        push_error(&mut report, format!("packet json: {err}"));
        return Ok(report);
    }
    let packet = match parse_json_text(&packet_text, "malformed JSON") {
        Ok(packet) => packet,
        Err(err) => {
            push_error(&mut report, format!("packet json: {err}"));
            return Ok(report);
        }
    };
    report = report_from_packet(&packet_path_string, Some(&packet));
    if opts.offline {
        report.verdict.clear();
        report.trusted = false;
    }

    let schema_errors = validate_audit_packet(&packet);
    if !schema_errors.is_empty() {
        report.schema_check = "fail".to_string();
        for err in schema_errors {
            push_error(&mut report, format!("schema: {err}"));
        }
        return Ok(report);
    }
    report.schema_check = "pass".to_string();

    if opts.offline {
        report.lifecycle_assessment_reason =
            Some("offline mode skips chain re-verification".to_string());
        report.verdict = "schema_checked_trust_unverified".to_string();
        report.trusted = false;
        report.valid = false;
        push_error(
            &mut report,
            "schema checked, trust unverified: chain and signer were not verified".to_string(),
        );
        return Ok(report);
    }

    let evidence_path = match resolve_artifact_path(
        &base_dir,
        string_at(&packet, &["artifacts", "evidence"]).unwrap_or(""),
    ) {
        Ok(path) => path,
        Err(err) => {
            report.chain_check = "fail".to_string();
            push_error(&mut report, format!("chain: {err}"));
            return Ok(report);
        }
    };
    let typed = match extract_typed_receipts(&evidence_path) {
        Ok(typed) => typed,
        Err(err) => {
            report.chain_check = "fail".to_string();
            push_error(&mut report, format!("chain: {err}"));
            return Ok(report);
        }
    };
    let packet_key = string_at(&packet, &["verifier", "signer_key"]).unwrap_or("");
    let packet_key_allowed = !opts.expect_sha256.trim().is_empty()
        || opts.no_trust_required
        || (string_at(&packet, &["verifier", "verdict"]) == Some("self_consistent_only")
            && opts.allow_self_consistent_only);
    let listed: Vec<&String> = opts
        .signer_keys
        .iter()
        .filter(|key| !key.trim().is_empty())
        .collect();
    let key_input = if !listed.is_empty() {
        ""
    } else if !opts.signer_key.trim().is_empty() {
        opts.signer_key.as_str()
    } else if packet_key_allowed {
        packet_key
    } else {
        report.chain_check = "fail".to_string();
        push_error(
            &mut report,
            "chain: trusted Audit Packet verification requires --key or --expect-sha256"
                .to_string(),
        );
        return Ok(report);
    };
    let resolved = if listed.is_empty() {
        resolve_signer_key(key_input)
    } else {
        listed
            .iter()
            .map(|key| resolve_signer_key(key))
            .collect::<Result<Vec<_>>>()
            .map(|keys| keys.join(","))
    };
    let key_hex = match resolved {
        Ok(key) => key,
        Err(err) => {
            report.chain_check = "fail".to_string();
            push_error(&mut report, format!("chain: {err}"));
            return Ok(report);
        }
    };
    let has_both = !typed.action.is_empty() && !typed.evidence.is_empty();
    let evidence_only = typed.action.is_empty();
    let evidence_receipts = typed.evidence.clone();
    let receipts = typed.select_chain();
    let primary_key = if evidence_only {
        evidence_chain_key(&key_hex, &receipts)
    } else {
        key_hex.clone()
    };
    let mut chain =
        verify_chain_with_options(&receipts, &primary_key, opts.allow_self_consistent_only);
    // The evidence file of a current run holds an ActionReceipt v1 chain and
    // an EvidenceReceipt v2 chain, each signed on its own. The packet's counts
    // and root describe the first; the second must verify too, or a forged
    // decision record in it would sit behind a trusted verdict.
    if has_both {
        let other = verify_chain_with_options(
            &evidence_receipts,
            &evidence_chain_key(&key_hex, &evidence_receipts),
            opts.allow_self_consistent_only,
        );
        if !other.valid {
            chain.valid = false;
            chain.error = Some(format!(
                "evidence receipt chain: {}",
                other.error.as_deref().unwrap_or("verification failed")
            ));
        }
    }
    report.chain_check = if chain.valid { "pass" } else { "fail" }.to_string();
    let lifecycle = analyze_lifecycle(&receipts, &chain);
    let lifecycle_broken = lifecycle.status == "BROKEN";
    let lifecycle_reason = lifecycle.reason.clone();
    report.lifecycle_status = Some(lifecycle.status);
    report.lifecycle_reason = Some(lifecycle.reason);
    report.lifecycle_assessment = "assessed".to_string();
    report.lifecycle_assessment_reason = None;
    if !chain.valid {
        push_error(
            &mut report,
            format!(
                "chain: {}",
                chain.error.as_deref().unwrap_or("verification failed")
            ),
        );
    }
    let cross_errors = cross_check(&packet, &chain, &receipts);
    if !cross_errors.is_empty() {
        report.cross_check = "fail".to_string();
        for err in cross_errors {
            push_error(&mut report, format!("cross-check: {err}"));
        }
        return Ok(report);
    }
    report.cross_check = "pass".to_string();
    report.valid = chain.valid && !lifecycle_broken && trust_verdict(&packet, opts);
    if lifecycle_broken {
        push_error(&mut report, format!("lifecycle: {lifecycle_reason}"));
    }
    if !report.valid {
        push_error(&mut report, "packet not trusted".to_string());
    }
    Ok(report)
}

pub fn report_from_packet(path: &str, packet: Option<&AuditPacket>) -> AuditPacketReport {
    AuditPacketReport {
        path: path.to_string(),
        verdict: packet
            .and_then(|packet| string_at(packet, &["verifier", "verdict"]))
            .unwrap_or("")
            .to_string(),
        trusted: packet
            .and_then(|packet| bool_at(packet, &["verifier", "trusted"]))
            .unwrap_or(false),
        valid: false,
        summary: ReportSummary {
            receipt_count: packet
                .and_then(|packet| u64_at(packet, &["summary", "receipt_count"]))
                .unwrap_or(0),
            totals: totals_from_packet(packet),
        },
        posture: ReportPosture {
            enforcement_mode: packet
                .and_then(|packet| string_at(packet, &["posture", "enforcement_mode"]))
                .unwrap_or("")
                .to_string(),
            unsupported_paths: packet
                .map(|packet| string_vec_at(packet, &["posture", "unsupported_paths"]))
                .unwrap_or_default(),
        },
        run: ReportRun {
            provider: packet
                .and_then(|packet| string_at(packet, &["run", "provider"]))
                .unwrap_or("")
                .to_string(),
            repository: packet
                .and_then(|packet| string_at(packet, &["run", "repository"]))
                .map(str::to_string),
            sha: packet
                .and_then(|packet| string_at(packet, &["run", "sha"]))
                .map(str::to_string),
            agent_identity: packet
                .and_then(|packet| string_at(packet, &["run", "agent_identity"]))
                .unwrap_or("")
                .to_string(),
        },
        errors: None,
        warnings: None,
        schema_check: "skipped".to_string(),
        chain_check: "skipped".to_string(),
        cross_check: "skipped".to_string(),
        lifecycle_status: None,
        lifecycle_reason: None,
        lifecycle_assessment: "not_assessed".to_string(),
        lifecycle_assessment_reason: Some("chain re-verification did not complete".to_string()),
    }
}

fn push_error(report: &mut AuditPacketReport, message: String) {
    report.errors.get_or_insert_with(Vec::new).push(message);
}

fn trust_verdict(packet: &AuditPacket, opts: &AuditPacketOptions) -> bool {
    if opts.no_trust_required {
        return true;
    }
    match string_at(packet, &["verifier", "verdict"]) {
        Some("valid") => bool_at(packet, &["verifier", "trusted"]) == Some(true),
        Some("self_consistent_only") => opts.allow_self_consistent_only,
        _ => false,
    }
}

fn cross_check(packet: &AuditPacket, chain: &ChainResult, receipts: &[Receipt]) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(receipt_count) = u64_at(packet, &["summary", "receipt_count"]) {
        if chain.receipt_count as u64 != receipt_count {
            errors.push(format!(
                "chain receipt_count {} != packet.summary.receipt_count {receipt_count}",
                chain.receipt_count
            ));
        }
    }
    let expected_totals = compute_totals(receipts);
    let got_totals = totals_from_packet(Some(packet));
    for key in Totals::keys() {
        if expected_totals.get(key) != got_totals.get(key) {
            errors.push(format!(
                "totals[{key}]: chain={} packet={}",
                expected_totals.get(key),
                got_totals.get(key)
            ));
        }
    }
    if let Some(root_hash) = string_at(packet, &["verifier", "root_hash"]) {
        if !root_hash.is_empty() && root_hash != chain.root_hash {
            errors.push(format!(
                "root_hash mismatch: chain={} packet={root_hash}",
                chain.root_hash
            ));
        }
    }
    if let Some(final_seq) = u64_at(packet, &["verifier", "final_seq"]) {
        if final_seq != chain.final_seq {
            errors.push(format!(
                "final_seq mismatch: chain={} packet={final_seq}",
                chain.final_seq
            ));
        }
    }
    match string_at(packet, &["verifier", "verdict"]) {
        Some("valid" | "self_consistent_only") if !chain.valid => errors.push(format!(
            "verdict={} but chain rejected: {}",
            string_at(packet, &["verifier", "verdict"]).unwrap_or(""),
            chain.error.as_deref().unwrap_or("")
        )),
        Some("invalid") if chain.valid => {
            errors.push("verdict=invalid but chain re-verified successfully".to_string());
        }
        _ => {}
    }
    errors
}

fn totals_from_packet(packet: Option<&AuditPacket>) -> Totals {
    let mut totals = Totals::zero();
    let Some(totals_value) = packet
        .and_then(|packet| packet.get("summary"))
        .and_then(|summary| summary.get("totals"))
    else {
        return totals;
    };
    totals.allow = totals_value
        .get("allow")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    totals.block = totals_value
        .get("block")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    totals.warn = totals_value
        .get("warn")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    totals.ask = totals_value
        .get("ask")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    totals.strip = totals_value
        .get("strip")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    totals.forward = totals_value
        .get("forward")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    totals.redirect = totals_value
        .get("redirect")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    totals.other = totals_value
        .get("other")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    totals
}
