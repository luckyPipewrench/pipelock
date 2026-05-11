use serde::Serialize;
use serde_json::Value;

pub type Receipt = Value;
pub type AuditPacket = Value;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Totals {
    pub allow: u64,
    pub block: u64,
    pub warn: u64,
    pub ask: u64,
    pub strip: u64,
    pub forward: u64,
    pub redirect: u64,
    pub other: u64,
}

impl Totals {
    pub fn zero() -> Self {
        Self {
            allow: 0,
            block: 0,
            warn: 0,
            ask: 0,
            strip: 0,
            forward: 0,
            redirect: 0,
            other: 0,
        }
    }

    pub fn keys() -> [&'static str; 8] {
        [
            "allow", "block", "warn", "ask", "strip", "forward", "redirect", "other",
        ]
    }

    pub fn get(&self, key: &str) -> u64 {
        match key {
            "allow" => self.allow,
            "block" => self.block,
            "warn" => self.warn,
            "ask" => self.ask,
            "strip" => self.strip,
            "forward" => self.forward,
            "redirect" => self.redirect,
            "other" => self.other,
            _ => 0,
        }
    }

    pub fn add_verdict(&mut self, verdict: &str) {
        match verdict.trim().to_ascii_lowercase().as_str() {
            "allow" => self.allow += 1,
            "block" => self.block += 1,
            "warn" => self.warn += 1,
            "ask" => self.ask += 1,
            "strip" => self.strip += 1,
            "forward" => self.forward += 1,
            "redirect" => self.redirect += 1,
            _ => self.other += 1,
        }
    }

    pub fn sum(&self) -> u64 {
        self.allow
            + self.block
            + self.warn
            + self.ask
            + self.strip
            + self.forward
            + self.redirect
            + self.other
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainResult {
    pub valid: bool,
    pub receipt_count: usize,
    pub final_seq: u64,
    pub root_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at_seq: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditPacketReport {
    pub path: String,
    pub verdict: String,
    pub trusted: bool,
    pub valid: bool,
    pub summary: ReportSummary,
    pub posture: ReportPosture,
    pub run: ReportRun,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
    pub schema_check: String,
    pub chain_check: String,
    pub cross_check: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSummary {
    pub receipt_count: u64,
    pub totals: Totals,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportPosture {
    pub enforcement_mode: String,
    pub unsupported_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportRun {
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
    pub agent_identity: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptReport {
    pub path: String,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainCommandReport {
    pub path: String,
    pub valid: bool,
    pub receipt_count: usize,
    pub final_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at_seq: Option<u64>,
}
