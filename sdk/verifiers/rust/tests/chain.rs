mod common;

use pipelock_verifier_rs::chain::verify_chain;
use pipelock_verifier_rs::recorder::extract_receipts;

#[test]
fn valid_go_generated_chain_verifies() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/valid-chain.jsonl")).unwrap();
    let result = verify_chain(&receipts, "");
    assert!(result.valid, "{:?}", result.error);
    assert_eq!(result.receipt_count, 5);
    assert_eq!(result.final_seq, 4);
    assert_eq!(
        result.root_hash,
        "be904bd5ca82adc26c2969872c23925f22ff24e33faf44a1185b9ffc0e2c2b5a"
    );
}

#[test]
fn broken_chain_prev_hash_is_rejected() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/broken-chain.jsonl")).unwrap();
    let result = verify_chain(&receipts, "");
    assert!(!result.valid);
    assert_eq!(result.broken_at_seq, Some(3));
    assert!(result.error.unwrap_or_default().contains("chain_prev_hash mismatch"));
}
