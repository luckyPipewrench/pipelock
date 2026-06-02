use crate::audit_packet::{verify_audit_packet, AuditPacketOptions};
use crate::chain::verify_chain;
use crate::output::{emit_audit_packet, emit_chain, emit_receipt};
use crate::receipt::run_receipt;
use crate::recorder::{extract_receipts, extract_receipts_from_session_dir};
use crate::types::ChainCommandReport;
use crate::util::{resolve_signer_key, Result, VerifierError};
use std::fs;
use std::path::PathBuf;

#[derive(Default)]
struct ParsedArgs {
    positionals: Vec<String>,
    json: bool,
    key: String,
    offline: bool,
    allow_self_consistent_only: bool,
    no_trust_required: bool,
    expect_sha256: String,
    dir: bool,
    session_id: String,
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
        _ => Err(VerifierError::Usage(format!(
            "unknown command {command}\n{}",
            usage(None)
        ))),
    }
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

fn run_chain_command(args: &[String]) -> Result<i32> {
    let parsed = parse_args(args, "chain")?;
    let target = require_one_arg(&parsed.positionals, "chain")?;
    let key_hex = resolve_signer_key(&parsed.key)?;
    let clean = PathBuf::from(target);
    let (receipts, label) = if parsed.dir {
        (
            extract_receipts_from_session_dir(&clean, &parsed.session_id)
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
            extract_receipts(&clean)
                .map_err(|err| VerifierError::Runtime(format!("extract receipts: {err}")))?,
            clean.display().to_string(),
        )
    };

    if receipts.is_empty() {
        let report = ChainCommandReport {
            path: label,
            valid: false,
            receipt_count: 0,
            final_seq: 0,
            root_hash: None,
            error: Some("no receipts in chain".to_string()),
            broken_at_seq: None,
        };
        emit_chain(&report, parsed.json)?;
        return Ok(1);
    }

    let result = verify_chain(&receipts, &key_hex);
    let report = ChainCommandReport {
        path: label,
        valid: result.valid,
        receipt_count: result.receipt_count,
        final_seq: result.final_seq,
        root_hash: (!result.root_hash.is_empty()).then_some(result.root_hash),
        error: result.error,
        broken_at_seq: result.broken_at_seq,
    };
    emit_chain(&report, parsed.json)?;
    Ok(if report.valid { 0 } else { 1 })
}

fn run_receipt_command(args: &[String]) -> Result<i32> {
    let parsed = parse_args(args, "receipt")?;
    let target = require_one_arg(&parsed.positionals, "receipt")?;
    let report = run_receipt(target, &parsed.key)?;
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
            _ => {
                if flag == "--key" {
                    parsed.key = inline_value.expect("split flag produced value").to_string();
                } else if flag == "--expect-sha256" && command == "audit-packet" {
                    parsed.expect_sha256 =
                        inline_value.expect("split flag produced value").to_string();
                } else if flag == "--session-id" && command == "chain" {
                    parsed.session_id =
                        inline_value.expect("split flag produced value").to_string();
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
        Some("chain") => "Usage: pipelock-verifier-rs chain PATH [--json] [--key HEX_OR_FILE] [--dir] [--session-id ID]".to_string(),
        Some("receipt") => "Usage: pipelock-verifier-rs receipt PATH [--json] [--key HEX_OR_FILE]".to_string(),
        _ => "Usage: pipelock-verifier-rs {aarp|audit-packet|chain|receipt} PATH [flags]"
            .to_string(),
    }
}
