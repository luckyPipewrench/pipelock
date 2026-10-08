// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! Restart continuity across the receipt chains of one base, ported from the
//! Go reference `internal/receipt/chain_set.go` and `chain_link.go`. Every
//! Pipelock process run writes its own chain, `<base>.run.<32hex>`, and a
//! restart may publish a signed link file `chain-link-<predecessor>.json`
//! naming the exact tail it continues. [`verify_base`] verifies every chain of
//! a base and every link file that names one, with the same findings Go
//! reports.
//!
//! Each chain is read the way Go's session reader reads it: a symlinked
//! evidence file inside the directory is refused, and every entry must carry
//! the session its file name claims. The recorder's own entry hash chain is
//! checked (finding `outer_chain_broken`), and two chains whose signed action
//! records carry the same `run_nonce` are reported (finding
//! `duplicate_run_nonce`), because a process run writes exactly one chain.

use crate::chain::{evidence_chain_key, receipt_hash, verify_chain_with_options};
use crate::line_space::is_go_space;
use crate::recorder::{
    extract_typed_from_lines, read_entry_lines, read_entry_lines_text, ExtractedReceipts,
    RecorderLine,
};
use crate::recorder_chain::verify_recorder_chain;
pub use crate::recorder_chain::FINDING_OUTER_CHAIN_BROKEN;
use crate::rotation::{
    canonical_utc_timestamp, verify_chain_with_endorsements, verify_rotation_endorsement,
    RotationEndorsement,
};
use crate::types::{ChainResult, Receipt};
use crate::util::{
    read_verifier_bytes, reject_duplicate_keys, same_open_file, set_pinned_evidence_directory,
    sha256_hex, string_at, u64_at, Result as VerifierResult, VerifierError,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const FINDING_CORRUPT_CHAIN: &str = "corrupt_chain";
pub const FINDING_INVALID_LINK: &str = "invalid_link";
pub const FINDING_LINK_NAME_MISMATCH: &str = "link_name_mismatch";
pub const FINDING_DANGLING_LINK: &str = "dangling_link";
pub const FINDING_PREDECESSOR_UNVERIFIED: &str = "predecessor_unverified";
pub const FINDING_LINK_TAIL_MISMATCH: &str = "link_tail_mismatch";
pub const FINDING_APPENDED_AFTER_LINK: &str = "appended_after_link";
pub const FINDING_DOUBLE_SUCCESSOR: &str = "double_successor";
pub const FINDING_UNTRUSTED_SUCCESSOR_KEY: &str = "untrusted_successor_key";
pub const FINDING_DUPLICATE_RUN_NONCE: &str = "duplicate_run_nonce";
pub const FINDING_INVALID_RECOVERY_SEAL: &str = "invalid_recovery_seal";
pub const FINDING_ATTESTED_DISCONTINUITY: &str = "attested_discontinuity";

pub const LINK_TRUST_SAME_KEY: &str = "same_key";
pub const LINK_TRUST_TRUSTED_KEY: &str = "trusted_key";
pub const LINK_TRUST_ENDORSED: &str = "endorsed";

const RUN_INFIX: &str = ".run.";
const EVIDENCE_PREFIX: &str = "evidence-";
const EVIDENCE_SUFFIX: &str = ".jsonl";
const CHAIN_LINK_FILE_PREFIX: &str = "chain-link-";
const CHAIN_LINK_FILE_SUFFIX: &str = ".json";
const CHAIN_LINK_VERSION: i64 = 1;
const CHAIN_LINK_DOMAIN: &str = "pipelock-chain-link-v1\0";
const RECOVERY_SEAL_DOMAIN: &str = "pipelock-recovery-seal-v1\0";
const SIGNATURE_PREFIX: &str = "ed25519:";
const MAX_CHAIN_LINK_FILE_BYTES: u64 = 64 << 10;
const MAX_RECORDER_ENTRY_LINE_BYTES: usize = 1 << 20;
const APPENDED_AFTER_LINK: &str = "entries were appended to the predecessor after the linked tail";

const CHAIN_LINK_FIELDS: [&str; 9] = [
    "version",
    "predecessor_session",
    "predecessor_tail_seq",
    "predecessor_tail_hash",
    "predecessor_signer_key",
    "successor_session",
    "successor_signer_key",
    "linked_at",
    "signature",
];
const RECOVERY_SEAL_FIELDS: [&str; 17] = [
    "kind",
    "version",
    "predecessor_session",
    "shard",
    "shard_size",
    "shard_sha256",
    "damage_offset",
    "last_good_seq",
    "last_good_hash",
    "predecessor_tail_seq",
    "predecessor_tail_hash",
    "predecessor_signer_key",
    "successor_session",
    "successor_signer_key",
    "successor_open_hash",
    "observed_at",
    "signature",
];

/// A run session's signed statement that it continues exactly one earlier
/// chain of the same base. Mirrors Go's `ChainLink`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ChainLink {
    pub version: i64,
    pub predecessor_session: String,
    pub predecessor_tail_seq: u64,
    pub predecessor_tail_hash: String,
    pub predecessor_signer_key: String,
    pub successor_session: String,
    pub successor_signer_key: String,
    pub linked_at: String,
    pub signature: String,
}

/// Signed observation that a successor follows a damaged final shard. The
/// seal binds the exact raw shard and complete prefix heads; it does not prove
/// the damage was accidental or that an operator-controlled signer is honest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoverySeal {
    pub kind: String,
    pub version: i64,
    pub predecessor_session: String,
    pub shard: String,
    pub shard_size: u64,
    pub shard_sha256: String,
    pub damage_offset: u64,
    pub last_good_seq: u64,
    pub last_good_hash: String,
    pub predecessor_tail_seq: u64,
    pub predecessor_tail_hash: String,
    pub predecessor_signer_key: String,
    pub successor_session: String,
    pub successor_signer_key: String,
    pub successor_open_hash: String,
    pub observed_at: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct BaseChain {
    pub session: String,
    pub legacy: bool,
    pub receipts: usize,
    pub final_seq: u64,
    pub tail_hash: String,
    pub signer_key: String,
    pub link: Option<ChainLink>,
    pub recovery_seal: Option<RecoverySeal>,
    pub link_file: Option<String>,
    pub link_trust: String,
    pub valid: bool,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BaseFinding {
    pub kind: String,
    pub session: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct BaseReport {
    pub base: String,
    pub chains: Vec<BaseChain>,
    pub findings: Vec<BaseFinding>,
}

impl BaseReport {
    /// True when every chain verified and every link file held. It says
    /// nothing about unlinked runs; see [`BaseReport::unlinked`].
    pub fn healthy(&self) -> bool {
        self.findings.is_empty()
    }

    /// Every chain no verified predecessor claim continues into. An unlinked chain is
    /// reported, never a finding: first runs, concurrent runs, and runs by
    /// older binaries are honestly unlinked, and so is a run whose claim file
    /// was deleted. A healthy report is therefore not proof of continuity.
    pub fn unlinked(&self) -> Vec<String> {
        self.chains
            .iter()
            .filter(|c| c.link.is_none() && c.recovery_seal.is_none())
            .map(|c| c.session.clone())
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct BaseVerifyOptions {
    pub trusted_keys: Vec<String>,
    pub endorsements: Vec<RotationEndorsement>,
}

pub fn run_session_base(session: &str) -> Option<&str> {
    match session.find(RUN_INFIX) {
        Some(idx) if idx > 0 => Some(&session[..idx]),
        _ => None,
    }
}

fn is_base_chain(session: &str, base: &str) -> bool {
    session == base || run_session_base(session) == Some(base)
}

/// Mirrors Go `evidencename.Parse`: the session is everything between
/// `evidence-` and the LAST dash, and a sequence that is not a u64 parses
/// as 0.
pub fn parse_evidence_filename(name: &str) -> Option<(String, u64)> {
    let rest = name
        .strip_prefix(EVIDENCE_PREFIX)?
        .strip_suffix(EVIDENCE_SUFFIX)?;
    let last_dash = rest.rfind('-')?;
    let digits = &rest[last_dash + 1..];
    let seq = if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        digits.parse::<u64>().unwrap_or(0)
    } else {
        0
    };
    Some((rest[..last_dash].to_string(), seq))
}

#[cfg(test)]
mod filename_vector_tests {
    use super::parse_evidence_filename;
    use serde_json::Value;

    #[test]
    fn shared_filename_vectors() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../filename-vectors.json")).unwrap();
        for item in vectors["parse"].as_array().unwrap() {
            let name = item["name"].as_str().unwrap();
            let want = item["session"]
                .as_str()
                .map(|session| (session.to_owned(), item["seq"].as_u64().unwrap()));
            assert_eq!(parse_evidence_filename(name), want, "{name}");
        }
        let names = vectors["duplicate"].as_array().unwrap();
        let first = parse_evidence_filename(names[0].as_str().unwrap());
        let second = parse_evidence_filename(names[1].as_str().unwrap());
        assert!(first.is_some());
        assert_eq!(first, second, "the vector names must parse to one start");

        // The index, not the parser, must refuse the pair: drive it through a
        // real directory holding both files.
        let dir = std::env::temp_dir().join(format!(
            "pipelock-rust-duplicate-start-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for name in names {
            std::fs::write(dir.join(name.as_str().unwrap()), b"").unwrap();
        }
        let err = super::indexed_session_files(&dir).unwrap_err();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            err.contains("ambiguous evidence shard sequence start"),
            "duplicate sequence must be rejected by the index: {err}"
        );
    }
}

/// Each session's shard files in order. A symlinked evidence file is kept
/// apart: it names its session, so that session is listed and then refused,
/// rather than silently read or silently dropped.
struct EvidenceIndex {
    files: BTreeMap<String, Vec<PathBuf>>,
    symlinks: BTreeMap<String, Vec<String>>,
}

fn index_recorder_files(dir: &Path) -> Result<EvidenceIndex, String> {
    let mut shards: BTreeMap<String, Vec<(u64, String, PathBuf)>> = BTreeMap::new();
    let mut symlinks: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let entries = fs::read_dir(dir).map_err(|err| format!("reading evidence directory: {err}"))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("reading evidence directory: {err}"))?;
        let file_type = entry
            .file_type()
            .map_err(|err| format!("reading evidence directory: {err}"))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(EVIDENCE_SUFFIX) {
            continue;
        }
        let Some((session, seq)) = parse_evidence_filename(&name) else {
            continue;
        };
        if file_type.is_symlink() {
            let list = symlinks.entry(session.clone()).or_default();
            list.push(name);
            list.sort();
            shards.entry(session).or_default();
            continue;
        }
        shards
            .entry(session)
            .or_default()
            .push((seq, name, entry.path()));
    }
    let files = shards
        .into_iter()
        .map(|(session, mut list)| {
            list.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
            (session, list.into_iter().map(|(_, _, path)| path).collect())
        })
        .collect();
    Ok(EvidenceIndex { files, symlinks })
}

/// Ordered files for every session, including the duplicate-start and symlink
/// checks used by the standalone chain verifier.
pub(crate) fn indexed_session_files(dir: &Path) -> Result<BTreeMap<String, Vec<PathBuf>>, String> {
    let index = index_recorder_files(dir)?;
    index
        .files
        .keys()
        .map(|session| {
            index_files(&index, session)
                .map(|files| (session.clone(), files.to_vec()))
                .map_err(|err| err.message)
        })
        .collect()
}

/// Evidence the verifier will not read as the session it claims to be: a
/// symlinked file in the evidence directory, or an entry whose `session_id`
/// differs from the session its file name claims. It is a verification
/// failure, never a usage error.
#[derive(Debug, Clone)]
pub struct SessionReadError {
    pub refused: bool,
    pub message: String,
}

impl std::fmt::Display for SessionReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<String> for SessionReadError {
    fn from(message: String) -> Self {
        Self {
            refused: false,
            message,
        }
    }
}

/// Applies Go's no-symlink evidence-root rule
/// (`recorder.refuseSymlinkInWalkedRootPath`) along the path the operating
/// system walks, so a symlink component is refused even when a later `..`
/// would lexically cancel it.
pub fn refuse_symlink_in_evidence_root_path(root: &Path) -> Result<(), SessionReadError> {
    use std::path::Component;
    let mut current = if root.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().map_err(|err| SessionReadError {
            message: format!("resolve evidence root: {err}"),
            refused: false,
        })?
    };
    for component in root.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            // Every component walked so far is not a symlink, so the lexical
            // parent is the physical parent. The operating system climbs out
            // of a directory only: "file/.." fails with ENOTDIR, so it fails
            // here too, with the same message as the Go and TypeScript walks.
            Component::ParentDir => {
                let meta = fs::symlink_metadata(&current).map_err(|err| SessionReadError {
                    message: format!(
                        "stat evidence root component \"{}\": {err}",
                        current.display()
                    ),
                    refused: false,
                })?;
                if !meta.is_dir() {
                    return Err(SessionReadError {
                        message: format!(
                            "evidence root component \"{}\" is not a directory",
                            current.display()
                        ),
                        refused: false,
                    });
                }
                current.pop();
            }
            Component::Normal(name) => {
                current.push(name);
                let meta = fs::symlink_metadata(&current).map_err(|err| SessionReadError {
                    message: format!(
                        "stat evidence root component \"{}\": {err}",
                        current.display()
                    ),
                    refused: false,
                })?;
                if meta.file_type().is_symlink() {
                    return Err(refused(format!(
                        "refuse symlink in evidence root path: \"{}\"",
                        current.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Pins each directory component as the process working directory. The CLI
/// uses one process per command; all later directory reads use "." and child
/// base names. A rename of the original path then cannot redirect a read.
pub(crate) fn with_pinned_evidence_directory<T>(
    root: &Path,
    read: impl FnOnce() -> VerifierResult<T>,
) -> VerifierResult<T> {
    let original =
        std::env::current_dir().map_err(|err| VerifierError::Runtime(err.to_string()))?;
    let result = (|| {
        use std::path::Component;
        let anchor: PathBuf = root
            .components()
            .take_while(|part| matches!(part, Component::Prefix(_) | Component::RootDir))
            .collect();
        if !anchor.as_os_str().is_empty() {
            std::env::set_current_dir(&anchor)
                .map_err(|err| VerifierError::Runtime(format!("enter evidence root: {err}")))?;
        }
        // Retain each opened parent. A child can be renamed into another
        // directory while we are inside it; `..` must return to the parent
        // selected before that rename, not the child's new parent.
        let mut parents = vec![open_pinned_directory(Path::new("."))?];
        for part in root.components() {
            match part {
                Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
                Component::ParentDir => {
                    // An initial relative `..` has no descended parent yet;
                    // open it before changing cwd and compare after entering.
                    let initial_parent = if parents.len() == 1 {
                        Some(open_pinned_directory(Path::new(".."))?)
                    } else {
                        None
                    };
                    let expected = match initial_parent.as_ref() {
                        Some(parent) => parent,
                        None => &parents[parents.len() - 2],
                    };
                    let entered = enter_pinned_parent(expected)?;
                    if parents.len() > 1 {
                        parents.pop();
                    } else {
                        parents[0] = entered;
                    }
                }
                Component::Normal(name) => {
                    let name = Path::new(name);
                    let before = fs::symlink_metadata(name).map_err(|err| {
                        VerifierError::Runtime(format!("stat evidence root component: {err}"))
                    })?;
                    if before.file_type().is_symlink() {
                        return Err(VerifierError::Invalid(
                            "refuse symlink in evidence root path".to_string(),
                        ));
                    }
                    if !before.is_dir() {
                        return Err(VerifierError::Runtime(
                            "evidence root component is not a directory".to_string(),
                        ));
                    }
                    // open_pinned_directory refuses a non-directory itself.
                    let opened = open_pinned_directory(name)?;
                    std::env::set_current_dir(name).map_err(|err| {
                        VerifierError::Runtime(format!("enter evidence root component: {err}"))
                    })?;
                    let entered = open_pinned_directory(Path::new("."))?;
                    if !same_open_file(&opened, &entered)? {
                        return Err(VerifierError::Invalid(
                            "evidence root component changed while entering".to_string(),
                        ));
                    }
                    parents.push(opened);
                }
            }
        }
        set_pinned_evidence_directory(true);
        read()
    })();
    set_pinned_evidence_directory(false);
    let _ = std::env::set_current_dir(original);
    result
}

fn enter_pinned_parent(expected: &fs::File) -> VerifierResult<fs::File> {
    std::env::set_current_dir("..")
        .map_err(|err| VerifierError::Runtime(format!("enter evidence parent: {err}")))?;
    let entered = open_pinned_directory(Path::new("."))?;
    if !same_open_file(expected, &entered)? {
        return Err(VerifierError::Invalid(
            "evidence root parent changed while entering".to_string(),
        ));
    }
    Ok(entered)
}

fn open_pinned_directory(path: &Path) -> VerifierResult<fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);
    // These handles establish directory identity; only the final cwd needs
    // read permission for indexing. Ancestors may grant search only.
    #[cfg(target_os = "linux")]
    options.custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    #[cfg(target_os = "macos")]
    options.custom_flags(libc::O_SEARCH | libc::O_NOFOLLOW);
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    #[cfg(windows)]
    {
        // Access mode 0 permits metadata queries without directory listing.
        options
            .access_mode(0)
            .custom_flags(0x0200_0000 | 0x0020_0000); // BACKUP_SEMANTICS | OPEN_REPARSE_POINT
    }
    let file = options
        .open(path)
        .map_err(|err| VerifierError::Runtime(format!("open evidence directory: {err}")))?;
    let kind = file
        .metadata()
        .map_err(|err| VerifierError::Runtime(format!("stat opened evidence directory: {err}")))?;
    if !kind.is_dir() || kind.file_type().is_symlink() {
        return Err(VerifierError::Invalid(
            "opened evidence path is not a directory".to_string(),
        ));
    }
    Ok(file)
}

#[cfg(all(test, unix))]
mod pinned_directory_tests {
    use super::{enter_pinned_parent, open_pinned_directory, with_pinned_evidence_directory};
    use crate::util::{read_verifier_bytes, same_open_file};
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn directory_rename_does_not_redirect_read() {
        // The helper changes process cwd, so run the proof in a dedicated
        // test process instead of changing the cwd of parallel unit tests.
        if std::env::var_os("PIPELOCK_PINNED_DIR_CHILD").is_none() {
            let output = Command::new(std::env::current_exe().expect("test executable"))
                .arg("--exact")
                .arg("chain_set::pinned_directory_tests::directory_rename_does_not_redirect_read")
                .env("PIPELOCK_PINNED_DIR_CHILD", "1")
                .output()
                .expect("start isolated test");
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let base = fs::canonicalize(std::env::temp_dir())
            .expect("canonical temp dir")
            .join(format!("pipelock-pinned-dir-{}", std::process::id()));
        fs::create_dir(&base).expect("create test base");
        let root = base.join("root");
        let moved = base.join("moved");
        let outside = base.join("outside");
        fs::create_dir(&root).expect("create root");
        fs::create_dir(&outside).expect("create outside");
        fs::write(root.join("evidence.jsonl"), b"inside").expect("write inside");
        fs::write(outside.join("evidence.jsonl"), b"outside").expect("write outside");
        with_pinned_evidence_directory(&root, || {
            fs::rename(&root, &moved).expect("move selected directory");
            symlink(&outside, &root).expect("replace selected path");
            assert_eq!(
                fs::read(root.join("evidence.jsonl")).expect("outside control"),
                b"outside"
            );
            assert_eq!(read_verifier_bytes(Path::new("evidence.jsonl"))?, b"inside");
            Ok(())
        })
        .expect("pinned read");
        with_pinned_evidence_directory(&base.join("outside").join("..").join("moved"), || {
            assert_eq!(read_verifier_bytes(Path::new("evidence.jsonl"))?, b"inside");
            Ok(())
        })
        .expect("ordinary parent path");
        fs::remove_dir_all(&base).expect("remove test base");
    }

    #[test]
    fn parent_step_refuses_a_relocated_child() {
        if std::env::var_os("PIPELOCK_PINNED_PARENT_CHILD").is_none() {
            let output = Command::new(std::env::current_exe().expect("test executable"))
                .arg("--exact")
                .arg("chain_set::pinned_directory_tests::parent_step_refuses_a_relocated_child")
                .env("PIPELOCK_PINNED_PARENT_CHILD", "1")
                .output()
                .expect("start isolated test");
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let base = fs::canonicalize(std::env::temp_dir())
            .expect("canonical temp dir")
            .join(format!("pipelock-pinned-parent-{}", std::process::id()));
        let selected_parent = base.join("selected");
        let child = selected_parent.join("child");
        let alternate_parent = base.join("alternate");
        fs::create_dir_all(&child).expect("create selected child");
        fs::create_dir(&alternate_parent).expect("create alternate parent");
        let expected = open_pinned_directory(&selected_parent).expect("open selected parent");

        std::env::set_current_dir(&child).expect("enter child");
        let entered = enter_pinned_parent(&expected).expect("ordinary parent step");
        assert!(same_open_file(&expected, &entered).expect("compare parent"));

        std::env::set_current_dir(&child).expect("reenter child");
        fs::rename(&child, alternate_parent.join("child")).expect("relocate child");
        let err = enter_pinned_parent(&expected).expect_err("relocated parent must be refused");
        assert!(
            err.to_string().contains("parent changed while entering"),
            "{err}"
        );
        std::env::set_current_dir(&base).expect("leave alternate parent");
        fs::remove_dir_all(&base).expect("remove test base");
    }

    #[test]
    fn traverse_only_ancestor_allows_evidence_read() {
        if std::env::var_os("PIPELOCK_TRAVERSE_ONLY_CHILD").is_none() {
            let output = Command::new(std::env::current_exe().expect("test executable"))
                .arg("--exact")
                .arg("chain_set::pinned_directory_tests::traverse_only_ancestor_allows_evidence_read")
                .env("PIPELOCK_TRAVERSE_ONLY_CHILD", "1")
                .output()
                .expect("start isolated test");
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let base = fs::canonicalize(std::env::temp_dir())
            .expect("canonical temp dir")
            .join(format!("pipelock-traverse-only-{}", std::process::id()));
        let ancestor = base.join("search-only");
        let root = ancestor.join("evidence");
        fs::create_dir_all(&root).expect("create evidence root");
        fs::write(root.join("evidence.jsonl"), b"inside").expect("write evidence");
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o100))
            .expect("remove ancestor read permission");
        let result = with_pinned_evidence_directory(&root, || {
            assert_eq!(read_verifier_bytes(Path::new("evidence.jsonl"))?, b"inside");
            Ok(())
        });
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))
            .expect("restore ancestor permissions");
        fs::remove_dir_all(&base).expect("remove test base");
        result.expect("traverse-only ancestor");
    }
}

fn refused(message: String) -> SessionReadError {
    SessionReadError {
        refused: true,
        message,
    }
}

/// Refuses a symlinked evidence file of the session, as Go's evidence reader
/// does, and two distinct shard names that start the session at the same
/// sequence, as Go's `evidencename.CheckNoDuplicateSeqStart` does.
fn index_files<'a>(
    ix: &'a EvidenceIndex,
    session: &str,
) -> Result<&'a [PathBuf], SessionReadError> {
    if let Some(name) = ix.symlinks.get(session).and_then(|l| l.first()) {
        return Err(refused(format!(
            "refuse symlink in evidence directory: \"{name}\""
        )));
    }
    let files = ix.files.get(session).map_or(&[][..], Vec::as_slice);
    for pair in files.windows(2) {
        let prev = pair[0].file_name().map(|n| n.to_string_lossy().to_string());
        let cur = pair[1].file_name().map(|n| n.to_string_lossy().to_string());
        if let (Some(prev), Some(cur)) = (prev, cur) {
            if let (Some(p), Some(c)) = (
                parse_evidence_filename(&prev),
                parse_evidence_filename(&cur),
            ) {
                if p == c {
                    return Err(SessionReadError::from(format!(
                        "ambiguous evidence shard sequence start: {prev} and {cur} both start session \"{}\" at sequence {}",
                        c.0, c.1
                    )));
                }
            }
        }
    }
    Ok(files)
}

/// Lists the legacy base session and every run session of `base` in `dir`,
/// sorted.
pub fn resolve_base_sessions(dir: &Path, base: &str) -> Result<Vec<String>, String> {
    Ok(index_recorder_files(dir)?
        .files
        .into_keys()
        .filter(|s| is_base_chain(s, base))
        .collect())
}

/// Reads every recorder entry of one session in shard order. Like Go's
/// session reader (`internal/recorder/query.go`), it refuses an entry whose
/// `session_id` is not the session its file name claims: a file named for run
/// X that holds run Y's entries is not run X's evidence.
fn read_session_lines(
    ix: &EvidenceIndex,
    session: &str,
) -> Result<Vec<RecorderLine>, SessionReadError> {
    let mut out = Vec::new();
    for file in index_files(ix, session)? {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        for line in read_entry_lines(file).map_err(|err| SessionReadError::from(err.to_string()))? {
            let got = line.entry.get("session_id");
            if got.and_then(Value::as_str) != Some(session) {
                return Err(refused(format!(
                    "reading {name}: entry seq {} session_id {} does not match requested session {}",
                    line.entry
                        .get("seq")
                        .map_or_else(|| "null".to_string(), Value::to_string),
                    got.map_or_else(|| "null".to_string(), Value::to_string),
                    Value::String(session.to_string())
                )));
            }
            out.push(line);
        }
    }
    Ok(out)
}

/// Applies the session rule to one evidence file read on its own, as Go's
/// `receipt.CheckRecorderFile` does: when the file name claims a session, every
/// entry must carry it, and a file whose name claims none must hold one
/// session. A file named for run X that holds run Y's entries is not run X's
/// evidence, read alone or in its directory.
pub(crate) fn check_file_entry_sessions(
    name: &str,
    lines: &[RecorderLine],
) -> Result<(), SessionReadError> {
    let session_of = |line: &RecorderLine| line.entry.get("session_id").cloned();
    let show = |v: Option<Value>| v.map_or_else(|| "null".to_string(), |v| v.to_string());
    if let Some((claimed, _)) = parse_evidence_filename(name) {
        for line in lines {
            let got = line.entry.get("session_id");
            if got.and_then(Value::as_str) != Some(claimed.as_str()) {
                return Err(refused(format!(
                    "reading {name}: entry seq {} session_id {} does not match requested session {}",
                    line.entry
                        .get("seq")
                        .map_or_else(|| "null".to_string(), Value::to_string),
                    show(got.cloned()),
                    Value::String(claimed.clone())
                )));
            }
        }
        return Ok(());
    }
    let Some(first) = lines.first() else {
        return Ok(());
    };
    let first_session = session_of(first);
    for line in &lines[1..] {
        let got = session_of(line);
        if got != first_session {
            return Err(refused(format!(
                "evidence file mixes recorder sessions {} and {}",
                show(first_session),
                show(got)
            )));
        }
    }
    Ok(())
}

/// Reads one session of `dir` with the refusals above, returning the recorder
/// hash chain verdict (`None` when it holds) and the two receipt chains.
pub(crate) fn read_session_evidence(
    dir: &Path,
    session: &str,
) -> Result<(Option<String>, ExtractedReceipts), SessionReadError> {
    let lines = read_session_lines(&index_recorder_files(dir)?, session)?;
    let outer = verify_recorder_chain(&lines.iter().map(|l| l.line.as_str()).collect::<Vec<_>>());
    let typed =
        extract_typed_from_lines(lines).map_err(|err| SessionReadError::from(err.to_string()))?;
    Ok((outer, typed))
}

/// Returns one session's receipts in shard order, as the action-receipt and
/// evidence-receipt subsequences.
pub fn read_session_receipts(
    dir: &Path,
    session: &str,
) -> Result<(Vec<Receipt>, Vec<Receipt>), String> {
    let (_, typed) = read_session_evidence(dir, session).map_err(|err| err.message)?;
    Ok((typed.action, typed.evidence))
}

fn chain_link_file_predecessor(name: &str) -> Option<&str> {
    let pred = name
        .strip_prefix(CHAIN_LINK_FILE_PREFIX)?
        .strip_suffix(CHAIN_LINK_FILE_SUFFIX)?;
    (!pred.is_empty()).then_some(pred)
}

/// Encodes a string exactly as Go's `encoding/json` does: HTML-sensitive
/// characters and U+2028/U+2029 are escaped, `\b \f \n \r \t` use their
/// short escapes (Go 1.22 and later), and other control characters use
/// `\u00XX`.
fn go_json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || matches!(c, '<' | '>' | '&' | '\u{2028}' | '\u{2029}') => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn chain_link_digest(l: &ChainLink) -> Vec<u8> {
    let canonical = format!(
        "{{\"version\":{},\"predecessor_session\":{},\"predecessor_tail_seq\":{},\"predecessor_tail_hash\":{},\"predecessor_signer_key\":{},\"successor_session\":{},\"successor_signer_key\":{},\"linked_at\":{}}}",
        l.version,
        go_json_string(&l.predecessor_session),
        l.predecessor_tail_seq,
        go_json_string(&l.predecessor_tail_hash),
        go_json_string(&l.predecessor_signer_key),
        go_json_string(&l.successor_session),
        go_json_string(&l.successor_signer_key),
        go_json_string(&l.linked_at),
    );
    let mut out = CHAIN_LINK_DOMAIN.as_bytes().to_vec();
    out.extend_from_slice(canonical.as_bytes());
    out
}

fn valid_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Go folds these all-ASCII field names case-insensitively: ASCII letters
/// fold, and so do the two non-ASCII letters that fold to ASCII.
fn go_fold_key(key: &str) -> String {
    key.chars()
        .map(|ch| match ch {
            '\u{17f}' => 's',
            '\u{212a}' => 'k',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// Applies the decoding rules of Go's `UnmarshalChainLink`: duplicate keys,
/// case-folded aliases, unknown fields, and trailing tokens are rejected; a
/// JSON null leaves the zero value; numbers must fit their Go type.
fn decode_chain_link(text: &str) -> Result<ChainLink, String> {
    reject_duplicate_keys(text).map_err(|err| format!("unmarshal chain link: {err}"))?;
    let value: Value =
        serde_json::from_str(text).map_err(|err| format!("unmarshal chain link: {err}"))?;
    let empty = serde_json::Map::new();
    let obj = match &value {
        Value::Null => &empty,
        Value::Object(obj) => obj,
        _ => return Err("unmarshal chain link: not a JSON object".to_string()),
    };
    for key in obj.keys() {
        if CHAIN_LINK_FIELDS.contains(&key.as_str()) {
            continue;
        }
        if let Some(name) = CHAIN_LINK_FIELDS
            .iter()
            .find(|name| go_fold_key(key) == **name)
        {
            return Err(format!(
                "unmarshal chain link: case-folded key: \"{key}\" aliases \"{name}\""
            ));
        }
        return Err(format!(
            "unmarshal chain link: json: unknown field \"{key}\""
        ));
    }
    let string = |field: &str| -> Result<String, String> {
        match obj.get(field) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(s)) => Ok(s.clone()),
            Some(_) => Err(format!("unmarshal chain link: {field} must be a string")),
        }
    };
    let tail_seq = match obj.get("predecessor_tail_seq") {
        None | Some(Value::Null) => 0,
        Some(Value::Number(n)) if n.is_u64() => n.as_u64().unwrap_or(0),
        Some(_) => {
            return Err(
                "unmarshal chain link: predecessor_tail_seq must be an unsigned integer"
                    .to_string(),
            )
        }
    };
    let version = match obj.get("version") {
        None | Some(Value::Null) => 0,
        Some(Value::Number(n)) if n.is_i64() || n.is_u64() => n.as_i64().unwrap_or(-1),
        Some(_) => return Err("unmarshal chain link: version must be an integer".to_string()),
    };
    Ok(ChainLink {
        version,
        predecessor_session: string("predecessor_session")?,
        predecessor_tail_seq: tail_seq,
        predecessor_tail_hash: string("predecessor_tail_hash")?,
        predecessor_signer_key: string("predecessor_signer_key")?,
        successor_session: string("successor_session")?,
        successor_signer_key: string("successor_signer_key")?,
        linked_at: string("linked_at")?,
        signature: string("signature")?,
    })
}

/// Strictly decodes the v1 recovery-seal envelope. The fixed field order is
/// used for signature bytes; aliases, duplicate keys, unknown fields, missing
/// fields, and trailing JSON are rejected before any binding is considered.
pub fn decode_recovery_seal(text: &str) -> Result<RecoverySeal, String> {
    reject_duplicate_keys(text).map_err(|err| format!("unmarshal recovery seal: {err}"))?;
    let value: Value =
        serde_json::from_str(text).map_err(|err| format!("unmarshal recovery seal: {err}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "unmarshal recovery seal: not a JSON object".to_string())?;
    for key in obj.keys() {
        if RECOVERY_SEAL_FIELDS.contains(&key.as_str()) {
            continue;
        }
        if let Some(name) = RECOVERY_SEAL_FIELDS
            .iter()
            .find(|name| go_fold_key(key) == **name)
        {
            return Err(format!(
                "unmarshal recovery seal: case-folded key: \"{key}\" aliases \"{name}\""
            ));
        }
        return Err(format!(
            "unmarshal recovery seal: json: unknown field \"{key}\""
        ));
    }
    let string = |field: &str| -> Result<String, String> {
        match obj.get(field) {
            Some(Value::String(value)) => Ok(value.clone()),
            _ => Err(format!("unmarshal recovery seal: {field} must be a string")),
        }
    };
    let number = |field: &str| -> Result<u64, String> {
        match obj.get(field).and_then(Value::as_u64) {
            Some(value) if value <= 9_007_199_254_740_991 => Ok(value),
            _ => Err(format!(
                "unmarshal recovery seal: {field} must be an unsigned integer <= 2^53-1"
            )),
        }
    };
    let version = match obj.get("version").and_then(Value::as_i64) {
        Some(value) => value,
        None => return Err("unmarshal recovery seal: version must be an integer".to_string()),
    };
    let seal = RecoverySeal {
        kind: string("kind")?,
        version,
        predecessor_session: string("predecessor_session")?,
        shard: string("shard")?,
        shard_size: number("shard_size")?,
        shard_sha256: string("shard_sha256")?,
        damage_offset: number("damage_offset")?,
        last_good_seq: number("last_good_seq")?,
        last_good_hash: string("last_good_hash")?,
        predecessor_tail_seq: number("predecessor_tail_seq")?,
        predecessor_tail_hash: string("predecessor_tail_hash")?,
        predecessor_signer_key: string("predecessor_signer_key")?,
        successor_session: string("successor_session")?,
        successor_signer_key: string("successor_signer_key")?,
        successor_open_hash: string("successor_open_hash")?,
        observed_at: string("observed_at")?,
        signature: string("signature")?,
    };
    verify_recovery_seal(&seal)?;
    Ok(seal)
}

fn recovery_seal_digest(seal: &RecoverySeal) -> Vec<u8> {
    let canonical = format!(
        "{{\"kind\":{},\"version\":{},\"predecessor_session\":{},\"shard\":{},\"shard_size\":{},\"shard_sha256\":{},\"damage_offset\":{},\"last_good_seq\":{},\"last_good_hash\":{},\"predecessor_tail_seq\":{},\"predecessor_tail_hash\":{},\"predecessor_signer_key\":{},\"successor_session\":{},\"successor_signer_key\":{},\"successor_open_hash\":{},\"observed_at\":{}}}",
        go_json_string(&seal.kind), seal.version,
        go_json_string(&seal.predecessor_session), go_json_string(&seal.shard),
        seal.shard_size, go_json_string(&seal.shard_sha256), seal.damage_offset,
        seal.last_good_seq, go_json_string(&seal.last_good_hash),
        seal.predecessor_tail_seq, go_json_string(&seal.predecessor_tail_hash),
        go_json_string(&seal.predecessor_signer_key), go_json_string(&seal.successor_session),
        go_json_string(&seal.successor_signer_key), go_json_string(&seal.successor_open_hash),
        go_json_string(&seal.observed_at),
    );
    let mut out = RECOVERY_SEAL_DOMAIN.as_bytes().to_vec();
    out.extend_from_slice(canonical.as_bytes());
    out
}

/// Verifies the seal's own canonical signature and format constraints.
pub fn verify_recovery_seal(seal: &RecoverySeal) -> Result<(), String> {
    if seal.kind != "recovery_seal" || seal.version != 1 {
        return Err("unsupported recovery seal kind or version".to_string());
    }
    if seal.predecessor_session.chars().all(is_go_space)
        || seal.successor_session.chars().all(is_go_space)
        || seal.predecessor_session.contains(['/', '\\'])
        || seal.successor_session.contains(['/', '\\'])
        || seal.predecessor_session == seal.successor_session
    {
        return Err("recovery seal sessions must be non-empty and distinct".to_string());
    }
    let base = run_session_base(&seal.successor_session)
        .ok_or_else(|| "recovery seal successor must be a run session".to_string())?;
    if !is_base_chain(&seal.predecessor_session, base) {
        return Err("recovery seal sessions must belong to one base".to_string());
    }
    if parse_evidence_filename(&seal.shard)
        .as_ref()
        .map(|(s, _)| s)
        != Some(&seal.predecessor_session)
        || seal.shard.contains('/')
        || seal.shard.contains('\\')
        || seal.shard == "."
        || seal.shard == ".."
    {
        return Err("recovery seal shard is not a predecessor evidence basename".to_string());
    }
    for (field, value) in [
        ("shard_sha256", seal.shard_sha256.as_str()),
        ("successor_open_hash", seal.successor_open_hash.as_str()),
    ] {
        if !valid_lower_hex(value, 32) {
            return Err(format!("recovery seal {field} is invalid"));
        }
    }
    for (field, value) in [
        ("last_good_hash", seal.last_good_hash.as_str()),
        ("predecessor_tail_hash", seal.predecessor_tail_hash.as_str()),
    ] {
        if value != "genesis" && !valid_lower_hex(value, 32) {
            return Err(format!("recovery seal {field} is invalid"));
        }
    }
    if !valid_lower_hex(&seal.predecessor_signer_key, 32)
        || !valid_lower_hex(&seal.successor_signer_key, 32)
    {
        return Err("recovery seal signer key is invalid".to_string());
    }
    if seal.shard_size == 0 || seal.damage_offset >= seal.shard_size {
        return Err("recovery seal damage_offset must precede non-empty shard end".to_string());
    }
    if !canonical_utc_timestamp(&seal.observed_at) || seal.observed_at == "0001-01-01T00:00:00Z" {
        return Err("recovery seal observed_at must be canonical UTC RFC3339Nano".to_string());
    }
    let sig_hex = seal
        .signature
        .strip_prefix(SIGNATURE_PREFIX)
        .ok_or_else(|| {
            format!("invalid recovery seal signature format: missing {SIGNATURE_PREFIX} prefix")
        })?;
    if sig_hex.len() != 128
        || !sig_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid recovery seal signature".to_string());
    }
    let sig = hex::decode(sig_hex).map_err(|_| "invalid recovery seal signature".to_string())?;
    let key: [u8; 32] = hex::decode(&seal.successor_signer_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("invalid recovery seal successor signer key")?;
    let key = VerifyingKey::from_bytes(&key)
        .map_err(|_| "invalid recovery seal successor signer key".to_string())?;
    let signature =
        Signature::from_slice(&sig).map_err(|_| "invalid recovery seal signature".to_string())?;
    key.verify_strict(&recovery_seal_digest(seal), &signature)
        .map_err(|_| "recovery seal signature verification failed".to_string())
}

/// Mirrors Go's `VerifyChainLink`: structure, then the successor-key
/// signature over the domain-separated canonical fields.
pub fn verify_chain_link(l: &ChainLink) -> Result<(), String> {
    if l.version != CHAIN_LINK_VERSION {
        return Err(format!("unsupported chain link version {}", l.version));
    }
    if l.predecessor_session.chars().all(is_go_space)
        || l.successor_session.chars().all(is_go_space)
    {
        return Err("chain link sessions must be non-empty".to_string());
    }
    if l.predecessor_session == l.successor_session {
        return Err("chain link must not name its own session as predecessor".to_string());
    }
    if !valid_lower_hex(&l.predecessor_signer_key, 32) {
        return Err("chain link predecessor_signer_key is invalid".to_string());
    }
    if !valid_lower_hex(&l.successor_signer_key, 32) {
        return Err("chain link successor_signer_key is invalid".to_string());
    }
    if !valid_lower_hex(&l.predecessor_tail_hash, 32) {
        return Err("chain link predecessor_tail_hash is invalid".to_string());
    }
    if !canonical_utc_timestamp(&l.linked_at) || l.linked_at == "0001-01-01T00:00:00Z" {
        return Err("chain link linked_at must be canonical UTC RFC3339Nano".to_string());
    }
    if l.signature.is_empty() {
        return Err("chain link signature is empty".to_string());
    }
    let sig_hex = l.signature.strip_prefix(SIGNATURE_PREFIX).ok_or_else(|| {
        format!("invalid chain link signature format: missing {SIGNATURE_PREFIX} prefix")
    })?;
    let sig = hex::decode(sig_hex)
        .ok()
        .filter(|b| b.len() == 64)
        .ok_or("invalid chain link signature")?;
    let key: [u8; 32] = hex::decode(&l.successor_signer_key)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("invalid successor_signer_key")?;
    let verifying_key =
        VerifyingKey::from_bytes(&key).map_err(|_| "invalid successor_signer_key".to_string())?;
    let signature =
        Signature::from_slice(&sig).map_err(|_| "invalid chain link signature".to_string())?;
    verifying_key
        .verify_strict(&chain_link_digest(l), &signature)
        .map_err(|_| "chain link signature verification failed".to_string())
}

fn read_chain_claim_file(path: &Path) -> ChainClaim {
    let result = (|| -> Result<ChainClaim, String> {
        let info =
            fs::symlink_metadata(path).map_err(|err| format!("stat chain link file: {err}"))?;
        if !info.file_type().is_file() {
            return Err("chain link file is not a regular file".to_string());
        }
        if info.len() > MAX_CHAIN_LINK_FILE_BYTES {
            return Err(format!(
                "chain link file exceeds {MAX_CHAIN_LINK_FILE_BYTES} bytes"
            ));
        }
        let bytes =
            read_verifier_bytes(path).map_err(|err| format!("read chain link file: {err}"))?;
        if bytes.len() as u64 > MAX_CHAIN_LINK_FILE_BYTES {
            return Err(format!(
                "chain link file exceeds {MAX_CHAIN_LINK_FILE_BYTES} bytes"
            ));
        }
        let text = String::from_utf8(bytes)
            .map_err(|err| format!("read chain link file as UTF-8: {err}"))?;
        let value: Value = serde_json::from_str(&text).map_err(|err| err.to_string())?;
        if value.get("kind").and_then(Value::as_str) == Some("recovery_seal") {
            return Ok(decode_recovery_seal(&text)
                .map(ChainClaim::RecoverySeal)
                .unwrap_or_else(ChainClaim::InvalidRecoverySeal));
        }
        let link = decode_chain_link(&text)?;
        verify_chain_link(&link)?;
        Ok(ChainClaim::Link(link))
    })();
    result.unwrap_or_else(ChainClaim::InvalidLink)
}

struct ChainLinkRecord {
    name: String,
    name_pred: String,
    claim: ChainClaim,
}

#[derive(Debug, Clone)]
enum ChainClaim {
    Link(ChainLink),
    RecoverySeal(RecoverySeal),
    InvalidRecoverySeal(String),
    InvalidLink(String),
}

fn read_chain_link_files(dir: &Path) -> Result<Vec<ChainLinkRecord>, String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).map_err(|err| format!("listing chain link files: {err}"))? {
        let entry = entry.map_err(|err| format!("listing chain link files: {err}"))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if chain_link_file_predecessor(&name).is_some() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names
        .into_iter()
        .map(|name| ChainLinkRecord {
            name_pred: chain_link_file_predecessor(&name)
                .unwrap_or_default()
                .to_string(),
            claim: read_chain_claim_file(&dir.join(&name)),
            name,
        })
        .collect())
}

fn chain_seq(receipt: &Receipt) -> u64 {
    u64_at(receipt, &["action_record", "chain_seq"]).unwrap_or(0)
}

fn signer_key(receipt: &Receipt) -> &str {
    string_at(receipt, &["signer_key"]).unwrap_or("")
}

/// Mirrors Go's `VerifyCrossChainEndorsement`: the endorsement must verify,
/// be signed by the link's predecessor key, name the successor key, and bind
/// the predecessor session and its exact linked tail.
pub fn verify_cross_chain_endorsement(e: &RotationEndorsement, link: &ChainLink) -> bool {
    verify_rotation_endorsement(e).is_ok()
        && e.session_id == link.predecessor_session
        && e.prior_signer_key == link.predecessor_signer_key
        && e.new_signer_key == link.successor_signer_key
        && e.prior_final_seq == link.predecessor_tail_seq
        && e.prior_tail_hash == link.predecessor_tail_hash
}

/// Returns `Ok` when `link` names the exact tail of `receipts`, or the
/// reason it does not (`APPENDED_AFTER_LINK` when it names an earlier
/// receipt).
fn check_linked_tail(receipts: &[Receipt], link: &ChainLink) -> Result<(), String> {
    let last = &receipts[receipts.len() - 1];
    let last_hash = receipt_hash(last);
    if chain_seq(last) == link.predecessor_tail_seq && last_hash == link.predecessor_tail_hash {
        if signer_key(last) != link.predecessor_signer_key {
            return Err("link predecessor key does not sign the linked tail".to_string());
        }
        return Ok(());
    }
    for r in receipts[..receipts.len() - 1].iter().rev() {
        if receipt_hash(r) == link.predecessor_tail_hash
            && chain_seq(r) == link.predecessor_tail_seq
        {
            return Err(APPENDED_AFTER_LINK.to_string());
        }
    }
    Err(format!(
        "link names tail seq {} hash {}, predecessor tail is seq {} hash {}",
        link.predecessor_tail_seq,
        link.predecessor_tail_hash,
        chain_seq(last),
        last_hash
    ))
}

/// Verifies a recovery seal against the predecessor bytes and both receipt
/// chains, then binds it to the successor's signed genesis session_open.
/// Nothing is attached to a report until every check succeeds.
fn verify_recovery_recorder_sequence(lines: &[RecorderLine]) -> Result<(), String> {
    for (index, line) in lines.iter().enumerate() {
        let expected = u64::try_from(index)
            .map_err(|_| "recovery recorder sequence exceeds u64".to_string())?;
        let actual = u64_at(&line.entry, &["seq"]).ok_or_else(|| {
            format!("recovery recorder sequence is not an unsigned integer at entry {index}")
        })?;
        if actual != expected {
            return Err(format!(
                "recovery recorder sequence mismatch: entry {index} has seq {actual}, expected {expected}"
            ));
        }
    }
    Ok(())
}

fn verify_recovery_binding(
    ix: &EvidenceIndex,
    data: &HashMap<String, BaseChainData>,
    seal: &RecoverySeal,
    opts: &BaseVerifyOptions,
) -> Result<(), String> {
    verify_recovery_seal(seal)?;
    let files = index_files(ix, &seal.predecessor_session).map_err(|err| err.message)?;
    let final_file = files
        .last()
        .ok_or_else(|| "predecessor has no evidence shards".to_string())?;
    let final_name = final_file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "predecessor shard name is not UTF-8".to_string())?;
    if final_name != seal.shard {
        return Err("recovery seal does not name the predecessor's final shard".to_string());
    }
    let raw = read_verifier_bytes(final_file).map_err(|err| err.to_string())?;
    if raw.len() as u64 != seal.shard_size || sha256_hex(&raw) != seal.shard_sha256 {
        return Err("recovery seal shard size or SHA-256 does not match".to_string());
    }
    let offset = usize::try_from(seal.damage_offset)
        .map_err(|_| "recovery seal damage_offset is not addressable".to_string())?;
    if offset > raw.len() || (offset > 0 && raw[offset - 1] != b'\n') {
        return Err(
            "recovery seal damage_offset is not the end of an LF-terminated prefix".to_string(),
        );
    }
    let suffix = &raw[offset..];
    if suffix.is_empty() {
        return Err("recovery seal suffix is not a recognized torn final record".to_string());
    }
    // Go's tail inspector trims only trailing NUL bytes before classifying a
    // torn record. Keep the full raw suffix covered by the signed size/hash,
    // but apply the same rule here so a partial record followed by torn-write
    // padding is accepted while embedded NULs remain invalid.
    let effective_end = suffix
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    let torn_suffix = &suffix[..effective_end];
    let trailing_nuls = torn_suffix.is_empty();
    if torn_suffix.contains(&b'\n') {
        return Err("recovery seal suffix is not a recognized torn final record".to_string());
    }
    if torn_suffix.contains(&0) {
        return Err("recovery seal suffix contains an embedded NUL".to_string());
    }
    if torn_suffix.len() > MAX_RECORDER_ENTRY_LINE_BYTES {
        return Err(format!(
            "recovery seal torn suffix exceeds {MAX_RECORDER_ENTRY_LINE_BYTES}-byte recorder entry limit"
        ));
    }

    let mut all_lines = Vec::new();
    for file in &files[..files.len() - 1] {
        all_lines.extend(read_entry_lines(file).map_err(|err| err.to_string())?);
    }
    let prefix = std::str::from_utf8(&raw[..offset])
        .map_err(|err| format!("recovery seal prefix is not UTF-8: {err}"))?;
    all_lines.extend(read_entry_lines_text(prefix).map_err(|err| err.to_string())?);

    // The seal heads cover only complete LF-terminated entries. A complete
    // JSON record without its final newline is still authenticated below.
    let mut observed_lines = all_lines.clone();
    if !trailing_nuls {
        match std::str::from_utf8(torn_suffix) {
            Ok(tail) if serde_json::from_str::<Value>(tail).is_ok() => {
                observed_lines.extend(read_entry_lines_text(tail).map_err(|err| err.to_string())?);
            }
            Err(_) => {
                // Go's json.Valid recognizes invalid UTF-8 inside an otherwise
                // complete JSON string, then its evidence decoder rejects the
                // record instead of treating it as a torn fragment. Lossy
                // decoding is only a syntax probe; never use its value as
                // evidence or as input to the signed-chain verifier.
                let lossy = String::from_utf8_lossy(torn_suffix);
                if serde_json::from_str::<Value>(&lossy).is_ok() {
                    return Err(
                        "recovery seal final JSON record contains invalid UTF-8".to_string()
                    );
                }
            }
            _ => {}
        }
    }
    for line in &observed_lines {
        if line.entry.get("session_id").and_then(Value::as_str)
            != Some(seal.predecessor_session.as_str())
        {
            return Err(
                "recovery seal predecessor shard contains a different session_id".to_string(),
            );
        }
    }
    let raw_complete: Vec<&str> = all_lines.iter().map(|line| line.line.as_str()).collect();
    if let Some(err) = verify_recorder_chain(&raw_complete) {
        return Err(format!(
            "recovery seal predecessor complete outer chain is invalid: {err}"
        ));
    }
    let (outer_seq, outer_hash) = all_lines.last().map_or((0, "genesis".to_string()), |line| {
        (
            u64_at(&line.entry, &["seq"]).unwrap_or(0),
            string_at(&line.entry, &["hash"])
                .unwrap_or("genesis")
                .to_string(),
        )
    });
    if outer_seq != seal.last_good_seq || outer_hash != seal.last_good_hash {
        return Err("recovery seal last-good outer recorder head does not match".to_string());
    }

    if observed_lines.len() != all_lines.len() {
        let raw_observed: Vec<&str> = observed_lines
            .iter()
            .map(|line| line.line.as_str())
            .collect();
        if let Some(err) = verify_recorder_chain(&raw_observed) {
            return Err(format!(
                "recovery seal observed predecessor outer chain is invalid: {err}"
            ));
        }
    }
    verify_recovery_recorder_sequence(&observed_lines)?;
    let extracted = extract_typed_from_lines(observed_lines).map_err(|err| err.to_string())?;
    for receipt in &extracted.action {
        let control = receipt
            .get("action_record")
            .and_then(|record| record.get("session_control"));
        if control
            .and_then(|control| control.get("kind"))
            .and_then(Value::as_str)
            == Some("session_open")
        {
            let recorder_session = control
                .and_then(|control| control.get("open"))
                .and_then(|open| open.get("recorder_session"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if recorder_session != seal.predecessor_session {
                return Err(
                    "recovery seal predecessor session_open binding does not match".to_string(),
                );
            }
        }
    }
    let trusted = opts.trusted_keys.join(",");
    if !extracted.action.is_empty() {
        let result = crate::chain::verify_chain_with_options(
            &extracted.action,
            &trusted,
            opts.trusted_keys.is_empty(),
        );
        if !chain_acceptable(&result) {
            return Err(format!(
                "recovery seal predecessor ActionReceipt chain is invalid: {}",
                result
                    .error
                    .unwrap_or_else(|| "chain verification failed".to_string())
            ));
        }
    }
    if !extracted.evidence.is_empty() {
        let key = evidence_chain_key(&trusted, &extracted.evidence);
        let result = crate::chain::verify_chain_with_options(
            &extracted.evidence,
            &key,
            opts.trusted_keys.is_empty(),
        );
        if !result.valid {
            return Err(format!(
                "recovery seal predecessor EvidenceReceipt chain is invalid: {}",
                result
                    .error
                    .unwrap_or_else(|| "chain verification failed".to_string())
            ));
        }
    }
    let complete_extracted = extract_typed_from_lines(all_lines).map_err(|err| err.to_string())?;
    let last_action = complete_extracted.action.last();
    let (tail_seq, tail_hash, predecessor_key) = match last_action {
        Some(receipt) => (
            chain_seq(receipt),
            receipt_hash(receipt),
            signer_key(receipt).to_string(),
        ),
        None => (0, "genesis".to_string(), seal.successor_signer_key.clone()),
    };
    if tail_seq != seal.predecessor_tail_seq
        || tail_hash != seal.predecessor_tail_hash
        || predecessor_key != seal.predecessor_signer_key
    {
        return Err("recovery seal predecessor ActionReceipt head does not match".to_string());
    }

    if seal.successor_signer_key != seal.predecessor_signer_key
        && !opts.trusted_keys.contains(&seal.successor_signer_key)
    {
        return Err(
            "recovery seal successor key differs and is not explicitly trusted".to_string(),
        );
    }
    let successor = data
        .get(&seal.successor_session)
        .ok_or_else(|| "recovery seal successor chain not found".to_string())?;
    if !successor.chain.valid || successor.receipts.is_empty() {
        return Err("recovery seal successor chain did not verify".to_string());
    }
    let first = &successor.receipts[0];
    let control = first
        .get("action_record")
        .and_then(|record| record.get("session_control"));
    let open = control
        .filter(|control| control.get("kind").and_then(Value::as_str) == Some("session_open"))
        .and_then(|control| control.get("open"))
        .filter(|open| open.is_object())
        .ok_or_else(|| "recovery seal successor does not begin with session_open".to_string())?;
    if chain_seq(first) != 0
        || signer_key(first) != seal.successor_signer_key
        || receipt_hash(first) != seal.successor_open_hash
        || open.get("recorder_session").and_then(Value::as_str)
            != Some(seal.successor_session.as_str())
    {
        return Err("recovery seal successor session_open binding does not match".to_string());
    }
    Ok(())
}

struct BaseChainData {
    chain: BaseChain,
    receipts: Vec<Receipt>,
    /// The run's EvidenceReceipt v2 chain, verified beside its ActionReceipt
    /// v1 chain: a forged v2 receipt leaves the v1 chain intact.
    evidence: Vec<Receipt>,
}

fn chain_acceptable(res: &ChainResult) -> bool {
    res.valid
        || (res.failure_kind.as_deref() == Some("lifecycle_missing_open") && res.integrity_verified)
}

/// Verifies every chain of `base` in `dir` and every link file that names a
/// chain of `base`, mirroring Go's `VerifyBase` (non links-only mode). An
/// error means the directory could not be enumerated; a caller must treat
/// that as incomplete, never as healthy.
pub fn verify_base(dir: &Path, base: &str, opts: &BaseVerifyOptions) -> Result<BaseReport, String> {
    let ix = index_recorder_files(dir)?;
    let sessions: Vec<String> = ix
        .files
        .keys()
        .filter(|s| is_base_chain(s, base))
        .cloned()
        .collect();
    let links = read_chain_link_files(dir)?;
    let mut findings: Vec<BaseFinding> = Vec::new();
    let mut add = |kind: &str, session: &str, detail: String| {
        findings.push(BaseFinding {
            kind: kind.to_string(),
            session: session.to_string(),
            detail,
        });
    };

    let scoped: Vec<&ChainLinkRecord> = links
        .iter()
        .filter(|lf| {
            is_base_chain(&lf.name_pred, base)
                || match &lf.claim {
                    ChainClaim::Link(link) => {
                        is_base_chain(&link.predecessor_session, base)
                            || is_base_chain(&link.successor_session, base)
                    }
                    ChainClaim::RecoverySeal(seal) => {
                        is_base_chain(&seal.predecessor_session, base)
                            || is_base_chain(&seal.successor_session, base)
                    }
                    _ => false,
                }
        })
        .collect();

    let mut data: HashMap<String, BaseChainData> = HashMap::new();
    for s in &sessions {
        let mut d = BaseChainData {
            chain: BaseChain {
                session: s.clone(),
                legacy: s == base,
                receipts: 0,
                final_seq: 0,
                tail_hash: String::new(),
                signer_key: String::new(),
                link: None,
                recovery_seal: None,
                link_file: None,
                link_trust: String::new(),
                valid: false,
                error: String::new(),
            },
            receipts: Vec::new(),
            evidence: Vec::new(),
        };
        load_base_chain(&ix, &mut d, &mut add);
        data.insert(s.clone(), d);
    }

    let mut successors: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut recovery_claims: Vec<(&ChainLinkRecord, RecoverySeal)> = Vec::new();
    for lf in scoped {
        let link = match &lf.claim {
            ChainClaim::InvalidLink(err) => {
                add(
                    FINDING_INVALID_LINK,
                    &lf.name_pred,
                    format!("link file {}: {err}", lf.name),
                );
                continue;
            }
            ChainClaim::InvalidRecoverySeal(err) => {
                add(
                    FINDING_INVALID_RECOVERY_SEAL,
                    &lf.name_pred,
                    format!("recovery seal file {}: {err}", lf.name),
                );
                continue;
            }
            ChainClaim::RecoverySeal(seal) => {
                if seal.predecessor_session != lf.name_pred {
                    add(
                        FINDING_INVALID_RECOVERY_SEAL,
                        &lf.name_pred,
                        format!(
                            "recovery seal file {} names a different predecessor",
                            lf.name
                        ),
                    );
                    continue;
                }
                if !is_base_chain(&seal.predecessor_session, base)
                    || run_session_base(&seal.successor_session) != Some(base)
                {
                    add(
                        FINDING_INVALID_RECOVERY_SEAL,
                        &seal.successor_session,
                        format!("recovery seal file {} is outside base {base:?}", lf.name),
                    );
                    continue;
                }
                successors
                    .entry(seal.predecessor_session.clone())
                    .or_default()
                    .push(seal.successor_session.clone());
                recovery_claims.push((lf, seal.clone()));
                continue;
            }
            ChainClaim::Link(link) => link,
        };
        if link.predecessor_session != lf.name_pred {
            add(
                FINDING_LINK_NAME_MISMATCH,
                &lf.name_pred,
                format!(
                    "link file {} names predecessor \"{}\"",
                    lf.name, link.predecessor_session
                ),
            );
        }
        successors
            .entry(link.predecessor_session.clone())
            .or_default()
            .push(link.successor_session.clone());
        if !is_base_chain(&link.predecessor_session, base) {
            add(
                FINDING_INVALID_LINK,
                &link.successor_session,
                format!(
                    "link file {}: predecessor \"{}\" is not a chain of \"{base}\"",
                    lf.name, link.predecessor_session
                ),
            );
            continue;
        }
        if run_session_base(&link.successor_session) != Some(base) {
            add(
                FINDING_INVALID_LINK,
                &link.successor_session,
                format!(
                    "link file {}: successor is not a run chain of \"{base}\"",
                    lf.name
                ),
            );
            continue;
        }
        let Some(sd) = data.get_mut(&link.successor_session) else {
            add(
                FINDING_DANGLING_LINK,
                &link.successor_session,
                format!(
                    "link file {}: successor \"{}\" not found",
                    lf.name, link.successor_session
                ),
            );
            continue;
        };
        if let Some(existing) = &sd.chain.link {
            add(
                FINDING_INVALID_LINK,
                &link.successor_session,
                format!(
                    "link file {}: successor already continues \"{}\"",
                    lf.name, existing.predecessor_session
                ),
            );
            continue;
        }
        sd.chain.link = Some(link.clone());
        sd.chain.link_file = Some(lf.name.clone());
    }

    // An endorsement vouches for a successor key only once the chain holding
    // the endorsing key has itself verified, so chains resolve in dependency
    // order; a cycle never reaches a verified root and stays unendorsed.
    let mut endorsed: HashSet<String> = HashSet::new();
    let mut endorsable: HashSet<String> = HashSet::new();
    let mut cross_used: HashSet<usize> = HashSet::new();
    for s in &sessions {
        let Some(link) = &data[s].chain.link else {
            continue;
        };
        if link.successor_signer_key == link.predecessor_signer_key {
            continue;
        }
        if let Some(i) = opts
            .endorsements
            .iter()
            .position(|e| verify_cross_chain_endorsement(e, link))
        {
            endorsable.insert(s.clone());
            cross_used.insert(i);
        }
    }
    let verify = |s: &str,
                  is_endorsed: bool,
                  data: &mut HashMap<String, BaseChainData>,
                  add: &mut dyn FnMut(&str, &str, String)| {
        let d = data.get_mut(s).expect("session loaded");
        let own: Vec<RotationEndorsement> = opts
            .endorsements
            .iter()
            .enumerate()
            .filter(|(i, e)| {
                e.session_id == s && !cross_used.contains(i) && !binds_final_receipt(e, &d.chain)
            })
            .map(|(_, e)| e.clone())
            .collect();
        verify_base_chain(d, &opts.trusted_keys, &own, is_endorsed, add);
    };
    let mut resolved: HashSet<String> = HashSet::new();
    let mut pending: Vec<String> = sessions.clone();
    let mut progress = true;
    while progress && !pending.is_empty() {
        progress = false;
        let mut waiting = Vec::new();
        for s in &pending {
            if endorsable.contains(s) {
                let link = data[s]
                    .chain
                    .link
                    .clone()
                    .expect("endorsable chain is linked");
                let pred_session = &link.predecessor_session;
                if data.contains_key(pred_session) && !resolved.contains(pred_session) {
                    waiting.push(s.clone());
                    continue;
                }
                let ok = data.get(pred_session).is_some_and(|pred| {
                    pred.chain.valid
                        && !pred.receipts.is_empty()
                        && check_linked_tail(&pred.receipts, &link).is_ok()
                });
                if ok {
                    endorsed.insert(s.clone());
                }
            }
            verify(s, endorsed.contains(s), &mut data, &mut add);
            resolved.insert(s.clone());
            progress = true;
        }
        pending = waiting;
    }
    for s in &pending {
        verify(s, endorsed.contains(s), &mut data, &mut add);
    }

    for (lf, seal) in recovery_claims {
        match verify_recovery_binding(&ix, &data, &seal, opts) {
            Ok(()) => {
                if let Some(successor) = data.get_mut(&seal.successor_session) {
                    if successor.chain.link.is_some() || successor.chain.recovery_seal.is_some() {
                        add(
                            FINDING_INVALID_RECOVERY_SEAL,
                            &seal.successor_session,
                            "successor already has a predecessor claim".to_string(),
                        );
                    } else {
                        successor.chain.recovery_seal = Some(seal.clone());
                        successor.chain.link_file = Some(lf.name.clone());
                        add(
                            FINDING_ATTESTED_DISCONTINUITY,
                            &seal.successor_session,
                            format!(
                                "linked across attested discontinuity from {} at {} byte {}",
                                seal.predecessor_session, seal.shard, seal.damage_offset
                            ),
                        );
                    }
                } else {
                    add(
                        FINDING_INVALID_RECOVERY_SEAL,
                        &seal.successor_session,
                        "recovery seal successor chain not found".to_string(),
                    );
                }
            }
            Err(err) => add(
                FINDING_INVALID_RECOVERY_SEAL,
                &seal.successor_session,
                format!("recovery seal file {}: {err}", lf.name),
            ),
        }
    }

    for s in &sessions {
        check_base_link(&mut data, s, opts, endorsed.contains(s), &mut add);
    }
    for (p, succ) in &successors {
        if succ.len() > 1 {
            add(
                FINDING_DOUBLE_SUCCESSOR,
                p,
                format!(
                    "continued by {} link files: [{}]",
                    succ.len(),
                    succ.join(" ")
                ),
            );
        }
    }
    check_run_nonces(&sessions, &data, &mut add);
    let chains = sessions
        .iter()
        .map(|s| data.remove(s).expect("session loaded").chain)
        .collect();
    Ok(BaseReport {
        base: base.to_string(),
        chains,
        findings,
    })
}

/// Reports two chains of the base that carry the same `run_nonce`. Every
/// action record a process run signs carries that run's nonce, and a run
/// writes exactly one chain, so a nonce in two chains means one run's evidence
/// appears twice: a replayed or copied run under a second session name. The
/// `session_id` and file name are unsigned; the nonce is signed. Only chains
/// that verified are compared, so the nonce is one their signatures cover; a
/// chain with no action records has no nonce and is not compared. Each chain
/// sharing the nonce is named, because nothing signed says which one is the
/// original.
fn check_run_nonces(
    sessions: &[String],
    data: &HashMap<String, BaseChainData>,
    add: &mut dyn FnMut(&str, &str, String),
) {
    let mut holders: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for s in sessions {
        let d = &data[s];
        if !d.chain.valid || d.receipts.is_empty() {
            continue;
        }
        let nonces: std::collections::BTreeSet<&str> = d
            .receipts
            .iter()
            .filter_map(|r| string_at(r, &["action_record", "run_nonce"]))
            .filter(|n| !n.is_empty())
            .collect();
        for nonce in nonces {
            holders
                .entry(nonce.to_string())
                .or_default()
                .push(s.clone());
        }
    }
    for (nonce, chains) in &holders {
        if chains.len() < 2 {
            continue;
        }
        for s in chains {
            let others: Vec<&str> = chains
                .iter()
                .filter(|c| *c != s)
                .map(String::as_str)
                .collect();
            add(
                FINDING_DUPLICATE_RUN_NONCE,
                s,
                format!(
                    "run_nonce {nonce} is also carried by {}: one run's signed records appear in more than one chain",
                    others.join(", ")
                ),
            );
        }
    }
}

fn load_base_chain(
    ix: &EvidenceIndex,
    d: &mut BaseChainData,
    add: &mut dyn FnMut(&str, &str, String),
) {
    let s = d.chain.session.clone();
    let lines = match read_session_lines(ix, &s) {
        Ok(lines) => lines,
        Err(err) => {
            d.chain.error = err.message.clone();
            add(FINDING_CORRUPT_CHAIN, &s, err.message);
            return;
        }
    };
    if let Some(outer) =
        verify_recorder_chain(&lines.iter().map(|l| l.line.as_str()).collect::<Vec<_>>())
    {
        add(FINDING_OUTER_CHAIN_BROKEN, &s, outer);
    }
    let loaded = extract_typed_from_lines(lines).map_err(|err| err.to_string());
    match loaded {
        Err(err) => {
            d.chain.error = err.clone();
            add(FINDING_CORRUPT_CHAIN, &s, err);
        }
        Ok(typed) => {
            d.receipts = typed.action;
            d.evidence = typed.evidence;
            let Some(last) = d.receipts.last() else {
                // A chain holding only EvidenceReceipt v2 entries is decided
                // by verify_base_chain, never passed with nothing verified.
                d.chain.valid = d.evidence.is_empty();
                return;
            };
            d.chain.receipts = d.receipts.len();
            d.chain.signer_key = signer_key(&d.receipts[0]).to_string();
            d.chain.final_seq = chain_seq(last);
            d.chain.tail_hash = receipt_hash(last);
        }
    }
}

fn verify_base_chain(
    d: &mut BaseChainData,
    trusted: &[String],
    own: &[RotationEndorsement],
    is_endorsed: bool,
    add: &mut dyn FnMut(&str, &str, String),
) {
    if !d.chain.error.is_empty() || (d.receipts.is_empty() && d.evidence.is_empty()) {
        return;
    }
    let mut keys = trusted.to_vec();
    if is_endorsed && !trusted.is_empty() {
        if let Some(link) = &d.chain.link {
            keys.push(link.successor_signer_key.clone());
        }
    }
    let joined = keys.join(",");
    if !d.receipts.is_empty() {
        let res = if own.is_empty() {
            verify_chain_with_options(&d.receipts, &joined, keys.is_empty())
        } else {
            verify_chain_with_endorsements(&d.receipts, &d.chain.session, own, &joined)
        };
        if !chain_acceptable(&res) {
            d.chain.valid = false;
            d.chain.error = res
                .error
                .unwrap_or_else(|| "chain verification failed".to_string());
            add(
                FINDING_CORRUPT_CHAIN,
                &d.chain.session,
                d.chain.error.clone(),
            );
            return;
        }
    }
    if !d.evidence.is_empty() {
        let key = evidence_chain_key(&joined, &d.evidence);
        let res = verify_chain_with_options(&d.evidence, &key, keys.is_empty());
        if !res.valid {
            d.chain.valid = false;
            d.chain.error = format!(
                "evidence receipt chain: {}",
                res.error
                    .unwrap_or_else(|| "chain verification failed".to_string())
            );
            add(
                FINDING_CORRUPT_CHAIN,
                &d.chain.session,
                d.chain.error.clone(),
            );
            return;
        }
    }
    d.chain.valid = true;
}

fn check_base_link(
    data: &mut HashMap<String, BaseChainData>,
    s: &str,
    opts: &BaseVerifyOptions,
    is_endorsed: bool,
    add: &mut dyn FnMut(&str, &str, String),
) {
    let Some(link) = data[s].chain.link.clone() else {
        return;
    };
    if let Some(first) = data[s].receipts.first() {
        if signer_key(first) != link.successor_signer_key {
            add(
                FINDING_INVALID_LINK,
                s,
                "link successor key does not sign the chain".to_string(),
            );
        }
    }
    let Some(pred) = data.get(&link.predecessor_session) else {
        add(
            FINDING_DANGLING_LINK,
            s,
            format!("predecessor \"{}\" not found", link.predecessor_session),
        );
        return;
    };
    if !pred.chain.valid || pred.receipts.is_empty() {
        add(
            FINDING_PREDECESSOR_UNVERIFIED,
            s,
            format!(
                "predecessor \"{}\" did not verify",
                link.predecessor_session
            ),
        );
        return;
    }
    if let Err(err) = check_linked_tail(&pred.receipts, &link) {
        let kind = if err == APPENDED_AFTER_LINK {
            FINDING_APPENDED_AFTER_LINK
        } else {
            FINDING_LINK_TAIL_MISMATCH
        };
        add(
            kind,
            &link.predecessor_session,
            format!("linked by {s}: {err}"),
        );
    }
    let trust = if link.successor_signer_key == link.predecessor_signer_key {
        LINK_TRUST_SAME_KEY
    } else if opts.trusted_keys.contains(&link.successor_signer_key) {
        LINK_TRUST_TRUSTED_KEY
    } else if is_endorsed {
        LINK_TRUST_ENDORSED
    } else {
        add(
            FINDING_UNTRUSTED_SUCCESSOR_KEY,
            s,
            "successor key differs from predecessor key and is neither trusted nor endorsed"
                .to_string(),
        );
        ""
    };
    if let Some(d) = data.get_mut(s) {
        d.chain.link_trust = trust.to_string();
    }
}

/// True when `e` hands off from `c`'s last receipt, which only a
/// cross-chain endorsement does.
fn binds_final_receipt(e: &RotationEndorsement, c: &BaseChain) -> bool {
    !c.tail_hash.is_empty() && e.prior_final_seq == c.final_seq && e.prior_tail_hash == c.tail_hash
}

/// Narrows the operator's endorsements and keys to one chain, as Go's
/// verify-receipt does: an endorsement that authorizes a key change across a
/// link is placed by the link check, never handed to either chain.
pub fn chain_scoped_trust(
    report: &BaseReport,
    session: &str,
    trusted_keys: &[String],
    endorsements: &[RotationEndorsement],
) -> (Vec<String>, Vec<RotationEndorsement>) {
    let own = endorsements
        .iter()
        .filter(|e| {
            e.session_id == session
                && !report.chains.iter().any(|c| {
                    c.link
                        .as_ref()
                        .is_some_and(|l| verify_cross_chain_endorsement(e, l))
                        || (c.session == session && binds_final_receipt(e, c))
                })
        })
        .cloned()
        .collect();
    let mut keys = trusted_keys.to_vec();
    for c in &report.chains {
        if c.session == session && c.link_trust == LINK_TRUST_ENDORSED {
            if let Some(link) = &c.link {
                keys = trusted_keys.to_vec();
                keys.push(link.successor_signer_key.clone());
            }
        }
    }
    (keys, own)
}

#[cfg(test)]
mod go_json_escape_tests {
    use super::{
        decode_chain_link, decode_recovery_seal, go_json_string, recovery_seal_digest, verify_base,
        verify_chain_link, verify_recovery_seal, BaseVerifyOptions, RecoverySeal,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    #[test]
    fn recovery_sequence_requires_an_explicit_unsigned_integer() {
        let line = |entry| super::RecorderLine {
            entry,
            ext: None,
            line: String::new(),
        };
        assert!(super::verify_recovery_recorder_sequence(&[
            line(serde_json::json!({"seq": 0})),
            line(serde_json::json!({"seq": 1})),
        ])
        .is_ok());
        for entry in [
            serde_json::json!({}),
            serde_json::json!({"seq": null}),
            serde_json::json!({"seq": "0"}),
            serde_json::json!({"seq": -1}),
            serde_json::json!({"seq": 0.5}),
        ] {
            assert!(super::verify_recovery_recorder_sequence(&[line(entry)]).is_err());
        }
    }

    // Written by the Go conformance test from encoding/json itself, so this
    // holds the link encoder to Go's bytes rather than to a recollection.
    fn fixture(name: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/testdata/go-json-escapes")
            .join(name);
        std::fs::read_to_string(path).expect("read fixture")
    }

    #[test]
    fn rotated_recovery_fixture_requires_every_prefix_key_pinned() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/testdata/recovery-seals/rotated");
        let keys: Vec<String> = std::fs::read_to_string(fixture.join("signer.pub"))
            .expect("read fixture keys")
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let seal = decode_recovery_seal(
            &std::fs::read_to_string(fixture.join("seal.json")).expect("read fixture seal"),
        )
        .expect("decode fixture seal");
        for (pins, expected) in [
            (keys.clone(), true),
            (Vec::new(), false),
            (keys[..1].to_vec(), false),
            (keys[1..].to_vec(), false),
        ] {
            let report = verify_base(
                &fixture.join("evidence"),
                "proxy",
                &BaseVerifyOptions {
                    trusted_keys: pins,
                    endorsements: Vec::new(),
                },
            )
            .expect("verify rotated fixture");
            assert_eq!(
                report
                    .chains
                    .iter()
                    .any(|chain| chain.session == seal.successor_session
                        && chain.recovery_seal.is_some()),
                expected
            );
            assert!(!report.healthy());
        }
    }

    #[test]
    fn link_encoder_writes_every_ascii_character_and_line_separators_as_go_does() {
        let table: serde_json::Value = serde_json::from_str(&fixture("table.json")).expect("parse");
        let entries = table["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), 130);
        for entry in entries {
            let cp = entry["codepoint"].as_str().expect("codepoint");
            let ch = char::from_u32(u32::from_str_radix(cp, 16).expect("hex")).expect("char");
            let got = hex::encode(go_json_string(&ch.to_string()));
            assert_eq!(got, entry["go_json_hex"].as_str().expect("hex"), "U+{cp}");
        }
    }

    #[test]
    fn a_go_signed_chain_link_whose_sessions_need_every_escape_verifies() {
        let raw = fixture("chain-link.json");
        verify_chain_link(&decode_chain_link(&raw).expect("decode")).expect("verify");
        let changed = raw.replacen(r"proxy.run.b\b\f", r"proxy.run.b\b", 1);
        assert_ne!(changed, raw, "fixture shape changed");
        let edited = decode_chain_link(&changed).expect("decode edited");
        assert!(verify_chain_link(&edited).is_err());
    }

    fn signed_seal_json() -> String {
        let key = SigningKey::from_bytes(&[7; 32]);
        let verifying_key = hex::encode(key.verifying_key().to_bytes());
        let mut seal = RecoverySeal {
            kind: "recovery_seal".to_string(),
            version: 1,
            predecessor_session: "proxy.run.old".to_string(),
            shard: "evidence-proxy.run.old-0.jsonl".to_string(),
            shard_size: 42,
            shard_sha256: "a".repeat(64),
            damage_offset: 38,
            last_good_seq: 3,
            last_good_hash: "b".repeat(64),
            predecessor_tail_seq: 1,
            predecessor_tail_hash: "c".repeat(64),
            predecessor_signer_key: verifying_key.clone(),
            successor_session: "proxy.run.new".to_string(),
            successor_signer_key: verifying_key,
            successor_open_hash: "d".repeat(64),
            observed_at: "2026-10-01T12:34:56Z".to_string(),
            signature: String::new(),
        };
        seal.signature = format!(
            "ed25519:{}",
            hex::encode(key.sign(&recovery_seal_digest(&seal)).to_bytes())
        );
        recovery_seal_json(&seal)
    }

    fn recovery_seal_json(seal: &RecoverySeal) -> String {
        format!(
            "{{\"kind\":{},\"version\":{},\"predecessor_session\":{},\"shard\":{},\"shard_size\":{},\"shard_sha256\":{},\"damage_offset\":{},\"last_good_seq\":{},\"last_good_hash\":{},\"predecessor_tail_seq\":{},\"predecessor_tail_hash\":{},\"predecessor_signer_key\":{},\"successor_session\":{},\"successor_signer_key\":{},\"successor_open_hash\":{},\"observed_at\":{},\"signature\":{}}}",
            go_json_string(&seal.kind), seal.version,
            go_json_string(&seal.predecessor_session), go_json_string(&seal.shard),
            seal.shard_size, go_json_string(&seal.shard_sha256), seal.damage_offset,
            seal.last_good_seq, go_json_string(&seal.last_good_hash),
            seal.predecessor_tail_seq, go_json_string(&seal.predecessor_tail_hash),
            go_json_string(&seal.predecessor_signer_key),
            go_json_string(&seal.successor_session),
            go_json_string(&seal.successor_signer_key),
            go_json_string(&seal.successor_open_hash),
            go_json_string(&seal.observed_at), go_json_string(&seal.signature),
        )
    }

    #[test]
    fn recovery_seal_v1_signature_and_strict_envelope_verify() {
        let raw = signed_seal_json();
        let seal = decode_recovery_seal(&raw).expect("strict decode");
        verify_recovery_seal(&seal).expect("signature verifies");
        assert!(decode_recovery_seal(&raw.replacen(
            "\"version\":1",
            "\"version\":1,\"version\":1",
            1
        ))
        .is_err());
        assert!(decode_recovery_seal(&raw.replacen("\"version\":1", "\"version\":2", 1)).is_err());
        assert!(decode_recovery_seal(&raw.replacen(
            "\"version\":1",
            "\"Version\":1,\"version\":1",
            1
        ))
        .is_err());
        assert!(decode_recovery_seal(&format!("{raw} {{}}")).is_err());
        assert!(decode_recovery_seal(
            &raw.replace("\"signature\":", "\"unknown\":true,\"signature\":")
        )
        .is_err());
        // Ordinary-link decoders reject the discriminator as an unknown field.
        assert!(decode_chain_link(&raw)
            .unwrap_err()
            .contains("unknown field \"kind\""));
        let edited = raw.replace(&"a".repeat(64), &"e".repeat(64));
        assert!(decode_recovery_seal(&edited).is_err());
    }

    #[test]
    fn empty_complete_prefix_still_checks_a_valid_json_receipt_without_newline() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/testdata/recovery-seals/valid");
        let source = fixture.join("evidence");
        let original = decode_recovery_seal(
            &std::fs::read_to_string(fixture.join("seal.json")).expect("read seal fixture"),
        )
        .expect("decode Go seal");
        let seed: [u8; 32] = Sha256::digest(b"pipelock-recovery-seal-conformance-v1").into();
        let signing_key = SigningKey::from_bytes(&seed);
        let pinned = hex::encode(signing_key.verifying_key().to_bytes());
        assert_eq!(
            std::fs::read_to_string(fixture.join("signer.pub"))
                .expect("read signer pub")
                .trim(),
            pinned
        );

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let run_dir = std::env::temp_dir().join(format!(
            "pipelock-rust-no-newline-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&run_dir).expect("create test evidence dir");
        for entry in std::fs::read_dir(&source).expect("list fixture evidence") {
            let entry = entry.expect("fixture entry");
            std::fs::copy(entry.path(), run_dir.join(entry.file_name())).expect("copy fixture");
        }
        let shard_path = run_dir.join(&original.shard);
        let original_bytes = std::fs::read(&shard_path).expect("read predecessor shard");
        let durable = &original_bytes[..original.damage_offset as usize];
        let records: Vec<&[u8]> = durable.split_inclusive(|byte| *byte == b'\n').collect();
        assert!(!records.is_empty(), "fixture needs a predecessor receipt");
        let no_newline = records[0]
            .strip_suffix(b"\n")
            .unwrap_or(records[0])
            .to_vec();
        let mut seal = original.clone();
        seal.shard_size = no_newline.len() as u64;
        seal.shard_sha256 = super::sha256_hex(&no_newline);
        seal.damage_offset = 0;
        seal.last_good_seq = 0;
        seal.last_good_hash = "genesis".to_string();
        seal.predecessor_tail_seq = 0;
        seal.predecessor_tail_hash = "genesis".to_string();
        seal.predecessor_signer_key = seal.successor_signer_key.clone();
        seal.signature.clear();
        seal.signature = format!(
            "ed25519:{}",
            hex::encode(signing_key.sign(&recovery_seal_digest(&seal)).to_bytes())
        );
        std::fs::write(&shard_path, no_newline).expect("write missing-newline evidence");
        std::fs::write(
            run_dir.join(format!("chain-link-{}.json", seal.predecessor_session)),
            recovery_seal_json(&seal),
        )
        .expect("write re-signed seal");

        let report = verify_base(
            &run_dir,
            "proxy",
            &BaseVerifyOptions {
                trusted_keys: vec![pinned],
                endorsements: Vec::new(),
            },
        )
        .expect("verify missing-newline recovery");
        assert!(report
            .findings
            .iter()
            .any(|finding| { finding.kind == super::FINDING_ATTESTED_DISCONTINUITY }));
        assert!(report
            .chains
            .iter()
            .any(|chain| chain.recovery_seal.is_some()));
        std::fs::remove_dir_all(run_dir).expect("cleanup test evidence dir");
    }

    #[test]
    fn malformed_and_truncated_utf8_final_records_match_go_tail_classification() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/testdata/recovery-seals/valid");
        let original = decode_recovery_seal(
            &std::fs::read_to_string(fixture.join("seal.json")).expect("read seal fixture"),
        )
        .expect("decode Go seal");
        let seed: [u8; 32] = Sha256::digest(b"pipelock-recovery-seal-conformance-v1").into();
        let signing_key = SigningKey::from_bytes(&seed);
        let pinned = hex::encode(signing_key.verifying_key().to_bytes());
        for (case, torn) in [
            ("malformed-json", &b"{\"partial\":!invalid"[..]),
            ("truncated-utf8", &b"{\"partial\":\"\xe2\x82"[..]),
        ] {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos();
            let run_dir = std::env::temp_dir().join(format!(
                "pipelock-rust-torn-{case}-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&run_dir).expect("create test evidence dir");
            let source = fixture.join("evidence");
            for entry in std::fs::read_dir(&source).expect("list fixture evidence") {
                let entry = entry.expect("fixture entry");
                std::fs::copy(entry.path(), run_dir.join(entry.file_name())).expect("copy fixture");
            }

            let shard_path = run_dir.join(&original.shard);
            let mut bytes = std::fs::read(&shard_path).expect("read predecessor shard");
            bytes.truncate(original.damage_offset as usize);
            bytes.extend_from_slice(torn);
            bytes.extend_from_slice(&[0, 0]);
            let mut seal = original.clone();
            seal.shard_size = bytes.len() as u64;
            seal.shard_sha256 = super::sha256_hex(&bytes);
            seal.signature.clear();
            seal.signature = format!(
                "ed25519:{}",
                hex::encode(signing_key.sign(&recovery_seal_digest(&seal)).to_bytes())
            );
            std::fs::write(&shard_path, bytes).expect("write padded torn evidence");
            std::fs::write(
                run_dir.join(format!("chain-link-{}.json", seal.predecessor_session)),
                recovery_seal_json(&seal),
            )
            .expect("write re-signed seal");

            let report = verify_base(
                &run_dir,
                "proxy",
                &BaseVerifyOptions {
                    trusted_keys: vec![pinned.clone()],
                    endorsements: Vec::new(),
                },
            )
            .unwrap_or_else(|err| panic!("{case}: verify padded torn recovery: {err}"));
            assert!(
                report
                    .chains
                    .iter()
                    .any(|chain| chain.recovery_seal.is_some()),
                "{case}: valid seal should attach"
            );
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.kind == super::FINDING_ATTESTED_DISCONTINUITY),
                "{case}: valid seal should report discontinuity"
            );
            std::fs::remove_dir_all(run_dir).expect("cleanup test evidence dir");
        }
    }

    #[test]
    fn invalid_record_boundaries_and_complete_invalid_utf8_json_are_rejected() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/testdata/recovery-seals/valid");
        let original = decode_recovery_seal(
            &std::fs::read_to_string(fixture.join("seal.json")).expect("read seal fixture"),
        )
        .expect("decode Go seal");
        let seed: [u8; 32] = Sha256::digest(b"pipelock-recovery-seal-conformance-v1").into();
        let signing_key = SigningKey::from_bytes(&seed);
        let pinned = hex::encode(signing_key.verifying_key().to_bytes());
        let invalid_utf8_complete_json = [b"{\"partial\":\"".as_slice(), &[0xff], b"\"}"].concat();
        for (case, torn) in [
            ("line-feed", &b"partial\n"[..]),
            ("embedded-nul", &b"partial\0record"[..]),
            (
                "complete-invalid-utf8-json",
                invalid_utf8_complete_json.as_slice(),
            ),
        ] {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos();
            let run_dir = std::env::temp_dir().join(format!(
                "pipelock-rust-rejected-torn-{case}-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&run_dir).expect("create test evidence dir");
            let source = fixture.join("evidence");
            for entry in std::fs::read_dir(&source).expect("list fixture evidence") {
                let entry = entry.expect("fixture entry");
                std::fs::copy(entry.path(), run_dir.join(entry.file_name())).expect("copy fixture");
            }

            let shard_path = run_dir.join(&original.shard);
            let mut bytes = std::fs::read(&shard_path).expect("read predecessor shard");
            bytes.truncate(original.damage_offset as usize);
            bytes.extend_from_slice(torn);
            let mut seal = original.clone();
            seal.shard_size = bytes.len() as u64;
            seal.shard_sha256 = super::sha256_hex(&bytes);
            seal.signature = format!(
                "ed25519:{}",
                hex::encode(signing_key.sign(&recovery_seal_digest(&seal)).to_bytes())
            );
            std::fs::write(&shard_path, bytes).expect("write rejected torn evidence");
            std::fs::write(
                run_dir.join(format!("chain-link-{}.json", seal.predecessor_session)),
                recovery_seal_json(&seal),
            )
            .expect("write re-signed seal");

            let report = verify_base(
                &run_dir,
                "proxy",
                &BaseVerifyOptions {
                    trusted_keys: vec![pinned.clone()],
                    endorsements: Vec::new(),
                },
            )
            .unwrap_or_else(|err| panic!("{case}: verify rejected torn suffix: {err}"));
            assert!(report
                .chains
                .iter()
                .all(|chain| chain.recovery_seal.is_none()));
            assert!(report.findings.iter().any(|finding| {
                finding.kind == super::FINDING_INVALID_RECOVERY_SEAL
                    && finding.session == original.successor_session
            }));
            std::fs::remove_dir_all(run_dir).expect("cleanup test evidence dir");
        }
    }

    #[test]
    fn rehashed_resequenced_recovery_prefix_is_rejected() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/testdata/recovery-seals/valid");
        let mut seal = decode_recovery_seal(
            &std::fs::read_to_string(fixture.join("seal.json")).expect("read seal fixture"),
        )
        .expect("decode Go seal");
        let seed: [u8; 32] = Sha256::digest(b"pipelock-recovery-seal-conformance-v1").into();
        let signing_key = SigningKey::from_bytes(&seed);
        let pinned = hex::encode(signing_key.verifying_key().to_bytes());
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let run_dir = std::env::temp_dir().join(format!(
            "pipelock-rust-resequenced-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&run_dir).expect("create test evidence dir");
        let source = fixture.join("evidence");
        for entry in std::fs::read_dir(&source).expect("list fixture evidence") {
            let entry = entry.expect("fixture entry");
            std::fs::copy(entry.path(), run_dir.join(entry.file_name())).expect("copy fixture");
        }

        let shard_path = run_dir.join(&seal.shard);
        let raw = std::fs::read(&shard_path).expect("read predecessor shard");
        let prefix = &raw[..seal.damage_offset as usize];
        let suffix = &raw[seal.damage_offset as usize..];
        let mut resequenced = Vec::new();
        let mut previous_hash = "genesis".to_string();
        let mut count = 0u64;
        for line in prefix.split_inclusive(|byte| *byte == b'\n') {
            let mut entry: Value = serde_json::from_slice(line).expect("parse complete entry");
            entry["seq"] = serde_json::json!(count + 1);
            entry["prev_hash"] = serde_json::json!(previous_hash);
            let encoded = serde_json::to_string(&entry).expect("encode resequenced entry");
            let hash = crate::recorder_chain::recorder_entry_hash(&encoded)
                .expect("hash resequenced entry");
            entry["hash"] = serde_json::json!(hash);
            previous_hash = hash;
            let encoded = serde_json::to_string(&entry).expect("encode hashed entry");
            resequenced.extend_from_slice(encoded.as_bytes());
            resequenced.push(b'\n');
            count += 1;
        }
        assert!(count > 0, "fixture needs a complete predecessor prefix");
        seal.last_good_seq = count;
        seal.last_good_hash = previous_hash;
        seal.damage_offset = resequenced.len() as u64;
        resequenced.extend_from_slice(suffix);
        seal.shard_size = resequenced.len() as u64;
        seal.shard_sha256 = super::sha256_hex(&resequenced);
        seal.signature = format!(
            "ed25519:{}",
            hex::encode(signing_key.sign(&recovery_seal_digest(&seal)).to_bytes())
        );
        std::fs::write(&shard_path, resequenced).expect("write resequenced shard");
        std::fs::write(
            run_dir.join(format!("chain-link-{}.json", seal.predecessor_session)),
            recovery_seal_json(&seal),
        )
        .expect("write re-signed seal");

        let report = verify_base(
            &run_dir,
            "proxy",
            &BaseVerifyOptions {
                trusted_keys: vec![pinned],
                endorsements: Vec::new(),
            },
        )
        .expect("verify rehashed resequenced recovery");
        assert!(report
            .chains
            .iter()
            .all(|chain| chain.recovery_seal.is_none()));
        assert!(report.findings.iter().any(|finding| {
            finding.kind == super::FINDING_INVALID_RECOVERY_SEAL
                && finding.detail.contains("sequence mismatch")
        }));
        std::fs::remove_dir_all(run_dir).expect("cleanup test evidence dir");
    }

    #[test]
    fn valid_json_final_record_without_newline_is_checked_for_sequence_gap() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/testdata/recovery-seals/valid");
        let mut seal = decode_recovery_seal(
            &std::fs::read_to_string(fixture.join("seal.json")).expect("read seal fixture"),
        )
        .expect("decode Go seal");
        let seed: [u8; 32] = Sha256::digest(b"pipelock-recovery-seal-conformance-v1").into();
        let signing_key = SigningKey::from_bytes(&seed);
        let pinned = hex::encode(signing_key.verifying_key().to_bytes());
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let run_dir = std::env::temp_dir().join(format!(
            "pipelock-rust-no-newline-sequence-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&run_dir).expect("create test evidence dir");
        let source = fixture.join("evidence");
        for entry in std::fs::read_dir(&source).expect("list fixture evidence") {
            let entry = entry.expect("fixture entry");
            std::fs::copy(entry.path(), run_dir.join(entry.file_name())).expect("copy fixture");
        }

        let shard_path = run_dir.join(&seal.shard);
        let raw = std::fs::read(&shard_path).expect("read predecessor shard");
        let complete: Vec<&[u8]> = raw[..seal.damage_offset as usize]
            .split_inclusive(|byte| *byte == b'\n')
            .collect();
        assert!(
            complete.len() >= 2,
            "fixture needs a complete receipt prefix"
        );
        let durable_count = complete.len() - 1;
        let mut prefix = complete[..durable_count].concat();
        let last_complete: Value = serde_json::from_slice(complete[durable_count - 1])
            .expect("parse final durable receipt");
        let prefix_hash = last_complete["hash"]
            .as_str()
            .expect("durable recorder hash")
            .to_string();
        let mut final_record: Value =
            serde_json::from_slice(complete[durable_count]).expect("parse final complete record");
        final_record["seq"] = serde_json::json!(durable_count as u64 + 7);
        final_record["prev_hash"] = serde_json::json!(prefix_hash);
        let encoded = serde_json::to_string(&final_record).expect("encode final record");
        let final_hash =
            crate::recorder_chain::recorder_entry_hash(&encoded).expect("hash final record");
        final_record["hash"] = serde_json::json!(final_hash);
        let encoded = serde_json::to_string(&final_record).expect("encode hashed final record");
        let damage_offset = prefix.len() as u64;
        prefix.extend_from_slice(encoded.as_bytes());
        let suffix = &raw[seal.damage_offset as usize..];
        prefix.extend_from_slice(suffix);

        seal.last_good_seq = durable_count as u64 - 1;
        seal.last_good_hash = prefix_hash;
        seal.damage_offset = damage_offset;
        seal.shard_size = prefix.len() as u64;
        seal.shard_sha256 = super::sha256_hex(&prefix);
        seal.signature = format!(
            "ed25519:{}",
            hex::encode(signing_key.sign(&recovery_seal_digest(&seal)).to_bytes())
        );
        std::fs::write(&shard_path, prefix).expect("write gapped final record");
        std::fs::write(
            run_dir.join(format!("chain-link-{}.json", seal.predecessor_session)),
            recovery_seal_json(&seal),
        )
        .expect("write re-signed seal");

        let report = verify_base(
            &run_dir,
            "proxy",
            &BaseVerifyOptions {
                trusted_keys: vec![pinned],
                endorsements: Vec::new(),
            },
        )
        .expect("verify gapped final record");
        assert!(report
            .chains
            .iter()
            .all(|chain| chain.recovery_seal.is_none()));
        assert!(report.findings.iter().any(|finding| {
            finding.kind == super::FINDING_INVALID_RECOVERY_SEAL
                && finding.detail.contains("sequence mismatch")
        }));
        std::fs::remove_dir_all(run_dir).expect("cleanup test evidence dir");
    }
}
