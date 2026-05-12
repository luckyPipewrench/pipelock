use pipelock_verifier_rs::util::resolve_artifact_path;
use std::fs;

#[cfg(unix)]
#[test]
fn artifact_path_rejects_symlinked_parent_for_missing_leaf() {
    let id = std::process::id();
    let base = std::env::temp_dir().join(format!("pipelock-rust-verifier-base-{id}"));
    let outside = std::env::temp_dir().join(format!("pipelock-rust-verifier-outside-{id}"));
    let _ = fs::remove_dir_all(&base);
    let _ = fs::remove_dir_all(&outside);
    fs::create_dir(&base).unwrap();
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, base.join("linked")).unwrap();

    let err = resolve_artifact_path(&base, "linked/new.json").unwrap_err();
    assert!(err.to_string().contains("via symlink"), "{err}");
}
