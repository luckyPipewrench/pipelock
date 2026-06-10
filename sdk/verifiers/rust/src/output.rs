use crate::types::{AuditPacketReport, ChainCommandReport, ReceiptReport};
use crate::util::{Result, VerifierError};

pub fn write_json<T: serde::Serialize>(value: &T) -> Result<()> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|err| VerifierError::Runtime(format!("encode json: {err}")))?;
    println!("{text}");
    Ok(())
}

pub fn emit_audit_packet(report: &AuditPacketReport, json: bool) -> Result<()> {
    if json {
        return write_json(report);
    }
    let verdict = if report.verdict.is_empty() {
        "(unset)"
    } else {
        report.verdict.as_str()
    };
    println!("Audit Packet:   {}", report.path);
    println!("  schema:       {}", report.schema_check);
    println!("  chain:        {}", report.chain_check);
    println!("  cross-check:  {}", report.cross_check);
    println!("  verdict:      {verdict}");
    println!("  trusted:      {}", report.trusted);
    println!("  receipts:     {}", report.summary.receipt_count);
    if !report.run.provider.is_empty() {
        println!("  provider:     {}", report.run.provider);
    }
    if let Some(repository) = &report.run.repository {
        println!("  repository:   {repository}");
    }
    if let Some(sha) = &report.run.sha {
        println!("  sha:          {sha}");
    }
    if !report.run.agent_identity.is_empty() {
        println!("  agent:        {}", report.run.agent_identity);
    }
    if !report.posture.enforcement_mode.is_empty() {
        println!("  enforcement:  {}", report.posture.enforcement_mode);
    }
    if !report.posture.unsupported_paths.is_empty() {
        println!(
            "  unsupported:  {}",
            report.posture.unsupported_paths.join(", ")
        );
    }
    if let Some(errors) = &report.errors {
        for err in errors {
            eprintln!("ERROR: {err}");
        }
    }
    if let Some(warnings) = &report.warnings {
        for warning in warnings {
            eprintln!("WARN:  {warning}");
        }
    }
    println!(
        "  result:       {}",
        if report.valid { "VALID" } else { "INVALID" }
    );
    Ok(())
}

pub fn emit_receipt(report: &ReceiptReport, json: bool) -> Result<()> {
    if json {
        return write_json(report);
    }
    if report.valid {
        if report.unpinned == Some(true) {
            println!("RECEIPT UNPINNED: {}", report.path);
            if let Some(error) = &report.error {
                println!("  warning:      {error}");
            }
        } else {
            println!("RECEIPT VALID: {}", report.path);
        }
        println!(
            "  action_id:    {}",
            report.action_id.as_deref().unwrap_or("")
        );
        println!(
            "  verdict:      {}",
            report.verdict.as_deref().unwrap_or("")
        );
        println!(
            "  transport:    {}",
            report.transport.as_deref().unwrap_or("")
        );
        println!(
            "  signer:       {}",
            report.signer_key.as_deref().unwrap_or("")
        );
        println!(
            "  policy_hash:  {}",
            report.policy_hash.as_deref().unwrap_or("")
        );
        println!("  chain_seq:    {}", report.chain_seq.unwrap_or(0));
        return Ok(());
    }
    if report.unpinned == Some(true) {
        eprintln!("RECEIPT UNPINNED: {}", report.path);
        if let Some(error) = &report.error {
            eprintln!("  warning: {error}");
        }
        return Ok(());
    }
    eprintln!("RECEIPT INVALID: {}", report.path);
    if let Some(error) = &report.error {
        eprintln!("  error: {error}");
    }
    Ok(())
}

pub fn emit_chain(report: &ChainCommandReport, json: bool) -> Result<()> {
    if json {
        return write_json(report);
    }
    if report.valid {
        if report.unpinned == Some(true) {
            println!("CHAIN UNPINNED: {}", report.path);
            if let Some(error) = &report.error {
                println!("  warning:    {error}");
            }
        } else {
            println!("CHAIN VALID: {}", report.path);
        }
        println!("  receipts:   {}", report.receipt_count);
        println!("  final seq:  {}", report.final_seq);
        println!(
            "  root hash:  {}",
            report.root_hash.as_deref().unwrap_or("")
        );
        return Ok(());
    }
    if report.unpinned == Some(true) {
        eprintln!("CHAIN UNPINNED: {}", report.path);
        if let Some(error) = &report.error {
            eprintln!("  warning:    {error}");
        }
        return Ok(());
    }
    eprintln!("CHAIN BROKEN: {}", report.path);
    if let Some(error) = &report.error {
        eprintln!("  error:      {error}");
    }
    if let Some(seq) = report.broken_at_seq {
        eprintln!("  broken at:  seq {seq}");
    } else if report.error.is_some() {
        eprintln!("  broken at:  seq unknown");
    }
    Ok(())
}
