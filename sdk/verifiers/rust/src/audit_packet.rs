use crate::chain::{compute_totals, verify_chain};
use crate::recorder::extract_receipts;
use crate::schema::validate_audit_packet;
use crate::types::{
    AuditPacket, AuditPacketReport, ChainResult, Receipt, ReportPosture, ReportRun, ReportSummary,
    Totals,
};
use crate::util::{
    bool_at, parse_json_file, resolve_artifact_path, resolve_packet_path, resolve_signer_key,
    sha256_hex, string_at, string_vec_at, u64_at, Result,
};
use std::fs;

#[derive(Debug, Clone)]
pub struct AuditPacketOptions {
    pub signer_key: String,
    pub offline: bool,
    pub allow_self_consistent_only: bool,
    pub no_trust_required: bool,
    pub expect_sha256: String,
}

pub fn verify_audit_packet(target: &str, opts: &AuditPacketOptions) -> Result<AuditPacketReport> {
    let (packet_path, base_dir) = resolve_packet_path(target)?;
    let raw_packet = fs::read(&packet_path).map_err(|err| {
        crate::util::VerifierError::Runtime(format!("read {}: {err}", packet_path.display()))
    })?;
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

    let packet = match parse_json_file(&packet_path) {
        Ok(packet) => packet,
        Err(err) => {
            push_error(&mut report, format!("packet json: {err}"));
            return Ok(report);
        }
    };
    report = report_from_packet(&packet_path_string, Some(&packet));

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
        report.valid = trust_verdict(&packet, opts);
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
    let receipts = match extract_receipts(&evidence_path) {
        Ok(receipts) => receipts,
        Err(err) => {
            report.chain_check = "fail".to_string();
            push_error(&mut report, format!("chain: {err}"));
            return Ok(report);
        }
    };
    let key_input = if opts.signer_key.trim().is_empty() {
        string_at(&packet, &["verifier", "signer_key"]).unwrap_or("")
    } else {
        opts.signer_key.as_str()
    };
    let key_hex = match resolve_signer_key(key_input) {
        Ok(key) => key,
        Err(err) => {
            report.chain_check = "fail".to_string();
            push_error(&mut report, format!("chain: {err}"));
            return Ok(report);
        }
    };
    let chain = verify_chain(&receipts, &key_hex);
    report.chain_check = if chain.valid { "pass" } else { "fail" }.to_string();
    if !chain.valid {
        push_error(
            &mut report,
            format!(
                "chain: {}",
                chain.error.as_deref().unwrap_or("verification failed")
            ),
        );
        return Ok(report);
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
    report.valid = chain.valid && trust_verdict(&packet, opts);
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
    let Some(totals_value) = packet.and_then(|packet| packet.get("summary")).and_then(|summary| summary.get("totals")) else {
        return totals;
    };
    totals.allow = totals_value.get("allow").and_then(serde_json::Value::as_u64).unwrap_or(0);
    totals.block = totals_value.get("block").and_then(serde_json::Value::as_u64).unwrap_or(0);
    totals.warn = totals_value.get("warn").and_then(serde_json::Value::as_u64).unwrap_or(0);
    totals.ask = totals_value.get("ask").and_then(serde_json::Value::as_u64).unwrap_or(0);
    totals.strip = totals_value.get("strip").and_then(serde_json::Value::as_u64).unwrap_or(0);
    totals.forward = totals_value
        .get("forward")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    totals.redirect = totals_value
        .get("redirect")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    totals.other = totals_value.get("other").and_then(serde_json::Value::as_u64).unwrap_or(0);
    totals
}
