// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// recorderEntryType mirrors the production flight-recorder entry type for
// action receipts. Matching by string keeps this test decoupled from the
// internal/receipt package constant.
const recorderEntryType = "action_receipt"

// recorderSessionID is the session identifier stamped on every conformance
// entry. Fixed so the golden JSONL files remain byte-deterministic.
const recorderSessionID = "conformance-session"

// update regenerates the golden files in testdata/ when passed.
// Run: go test ./sdk/conformance/ -run TestGenerateGoldenFiles -update.
var update = flag.Bool("update", false, "regenerate golden conformance files")

const (
	// testSeedPhrase seeds the deterministic test keypair. It is obviously
	// a test key; it MUST NEVER be used for production signing. The seed
	// itself is sha256(testSeedPhrase).
	testSeedPhrase = "pipelock-conformance-test-key-v1"

	testdataDir = "testdata"

	goldenValidSingle      = "valid-single.json"
	goldenValidChain       = "valid-chain.jsonl"
	goldenG1ValidChain     = "g1-valid-chain.jsonl"
	goldenG1RestartChain   = "g1-restart-chain.jsonl"
	goldenG1BrokenGenesis  = "g1-broken-genesis.jsonl"
	goldenG1LegacyOpen     = "g1-legacy-open-genesis.jsonl"
	goldenG1Vectors        = "g1-genesis-vectors.json"
	goldenInvalidSignature = "invalid-signature.json"
	goldenBrokenChain      = "broken-chain.jsonl"
	goldenTestKey          = "test-key.json"

	chainLen      = 5
	brokenAtIndex = 3
	brokenPrev    = "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	g1RunNonce         = "0123456789abcdef0123456789abcdef"
	g1OpenNonce        = "open-nonce-g1"
	g1RestartRunNonce  = "abcdef0123456789abcdef0123456789"
	g1RestartOpenNonce = "open-nonce-g1-restart"
)

// baseTime fixes the timestamp floor for golden receipts. Each successive
// receipt in a chain is one second later than the previous.
var baseTime = time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)

// testSeed returns the deterministic 32-byte Ed25519 seed for the test key.
func testSeed() [32]byte {
	return sha256.Sum256([]byte(testSeedPhrase))
}

// testKeyPair returns the deterministic test Ed25519 keypair.
func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := testSeed()
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("unexpected public key type %T", priv.Public())
	}
	return pub, priv
}

// fixedActionRecord builds a deterministic action record for the golden
// fixtures. Chain state (seq, prev_hash) is supplied by the caller.
func fixedActionRecord(seq uint64, prevHash string) receipt.ActionRecord {
	// Offsets are bounded by chainLen (small constant), so the uint64 -> int64
	// conversion cannot overflow. Cast via time.Duration(int64(seq)) explicitly
	// to document intent and silence gosec G115.
	offset := time.Duration(int64(seq)) * time.Second //nolint:gosec // seq bounded by chainLen
	return receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        fmt.Sprintf("conformance-%05d", seq),
		ActionType:      receipt.ActionWrite,
		Timestamp:       baseTime.Add(offset),
		Principal:       "org:conformance-test",
		Actor:           "agent:conformance-runner",
		DelegationChain: []string{"test-policy-v1", "test-grant"},
		Target:          "https://api.example.com/conformance",
		SideEffectClass: receipt.SideEffectExternalWrite,
		Reversibility:   receipt.ReversibilityCompensatable,
		PolicyHash:      "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Verdict:         "allow",
		Transport:       "https",
		Method:          "POST",
		ChainPrevHash:   prevHash,
		ChainSeq:        seq,
	}
}

// buildValidChain signs chainLen receipts in a valid hash chain.
func buildValidChain(t *testing.T, priv ed25519.PrivateKey) []receipt.Receipt {
	t.Helper()
	chain := make([]receipt.Receipt, 0, chainLen)
	prevHash := receipt.GenesisHash
	for i := range chainLen {
		ar := fixedActionRecord(uint64(i), prevHash)
		r, err := receipt.Sign(ar, priv)
		if err != nil {
			t.Fatalf("Sign chain[%d]: %v", i, err)
		}
		h, err := receipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash chain[%d]: %v", i, err)
		}
		chain = append(chain, r)
		prevHash = h
	}
	return chain
}

func buildG1ValidChain(t *testing.T, priv ed25519.PrivateKey) []receipt.Receipt {
	t.Helper()
	policyHash := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	open := receipt.SessionOpen{
		RunNonce:             g1RunNonce,
		OpenNonce:            g1OpenNonce,
		RecorderSession:      recorderSessionID,
		PolicyHash:           policyHash,
		SignerKeyEpoch:       "epoch-2026-04",
		HeartbeatSeconds:     30,
		ChainOpenSeq:         0,
		GenesisAnchorHead:    "anchor-head-0001",
		GenesisAnchorLog:     "anchor-log-0001",
		PostureCapsuleSHA256: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		PostureSignerKeyID:   "posture-key-1",
		ContainmentNonce:     "containment-nonce-0001",
		ContainedUID:         "966",
	}
	genesis := receipt.ComputeSessionOpenGenesis(open)
	open.GenesisHash = genesis

	chain := make([]receipt.Receipt, 0, chainLen)
	openAR := fixedActionRecord(0, genesis)
	openAR.ActionID = "g1-session-open"
	openAR.ActionType = receipt.ActionUnclassified
	openAR.Target = "receipt-session:open"
	openAR.PolicyHash = policyHash
	openAR.Transport = "receipt_session"
	openAR.Method = ""
	openAR.Layer = "session_control"
	openAR.RunNonce = g1RunNonce
	openAR.SessionControl = &receipt.SessionControl{
		Kind: receipt.SessionControlOpen,
		Open: &open,
	}
	openReceipt, err := receipt.Sign(openAR, priv)
	if err != nil {
		t.Fatalf("Sign g1 open: %v", err)
	}
	chain = append(chain, openReceipt)
	prevHash := mustReceiptHash(t, openReceipt)

	intentAR := fixedActionRecord(1, prevHash)
	intentAR.ActionID = "g1-decision-intent"
	intentAR.Intent = "write_customer_record"
	intentAR.DecisionPhase = receipt.DecisionPhaseIntent
	intentAR.RunNonce = g1RunNonce
	intentReceipt, err := receipt.Sign(intentAR, priv)
	if err != nil {
		t.Fatalf("Sign g1 intent: %v", err)
	}
	chain = append(chain, intentReceipt)
	prevHash = mustReceiptHash(t, intentReceipt)

	outcomeAR := fixedActionRecord(2, prevHash)
	outcomeAR.ActionID = "g1-decision-outcome"
	outcomeAR.Intent = "write_customer_record"
	outcomeAR.DecisionPhase = receipt.DecisionPhaseOutcome
	outcomeAR.RunNonce = g1RunNonce
	outcomeReceipt, err := receipt.Sign(outcomeAR, priv)
	if err != nil {
		t.Fatalf("Sign g1 outcome: %v", err)
	}
	chain = append(chain, outcomeReceipt)
	prevHash = mustReceiptHash(t, outcomeReceipt)

	heartbeatAR := fixedActionRecord(3, prevHash)
	heartbeatAR.ActionID = "g1-session-heartbeat"
	heartbeatAR.ActionType = receipt.ActionUnclassified
	heartbeatAR.Target = "receipt-session:heartbeat"
	heartbeatAR.Transport = "receipt_session"
	heartbeatAR.Method = ""
	heartbeatAR.Layer = "session_control"
	heartbeatAR.RunNonce = g1RunNonce
	heartbeatAR.SessionControl = &receipt.SessionControl{
		Kind: receipt.SessionControlHeartbeat,
		Heartbeat: &receipt.SessionHeartbeat{
			RunNonce:         g1RunNonce,
			OpenNonce:        g1OpenNonce,
			Beat:             1,
			ChainHead:        prevHash,
			ChainSeqHead:     2,
			HeartbeatTime:    baseTime.Add(3 * time.Second).Format(time.RFC3339),
			FsyncErrorsGated: 2,
			DurabilityBlocks: 3,
		},
	}
	heartbeatReceipt, err := receipt.Sign(heartbeatAR, priv)
	if err != nil {
		t.Fatalf("Sign g1 heartbeat: %v", err)
	}
	chain = append(chain, heartbeatReceipt)
	prevHash = mustReceiptHash(t, heartbeatReceipt)

	closeAR := fixedActionRecord(4, prevHash)
	closeAR.ActionID = "g1-session-close"
	closeAR.ActionType = receipt.ActionUnclassified
	closeAR.Target = "receipt-session:close"
	closeAR.Transport = "receipt_session"
	closeAR.Method = ""
	closeAR.Layer = "session_control"
	closeAR.RunNonce = g1RunNonce
	closeAR.SessionControl = &receipt.SessionControl{
		Kind: receipt.SessionControlClose,
		Close: &receipt.SessionClose{
			RunNonce:         g1RunNonce,
			OpenNonce:        g1OpenNonce,
			FinalSeq:         4,
			RootHash:         prevHash,
			ReceiptCount:     5,
			CloseReason:      "normal",
			FsyncErrorsGated: 3,
			DurabilityBlocks: 4,
		},
	}
	closeReceipt, err := receipt.Sign(closeAR, priv)
	if err != nil {
		t.Fatalf("Sign g1 close: %v", err)
	}
	chain = append(chain, closeReceipt)
	return chain
}

func buildG1RestartChain(t *testing.T, priv ed25519.PrivateKey) []receipt.Receipt {
	t.Helper()
	policyHash := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	chain := buildG1ValidChain(t, priv)[:2]
	prevHash := mustReceiptHash(t, chain[len(chain)-1])
	priorSeq := chain[len(chain)-1].ActionRecord.ChainSeq

	restartOpen := receipt.SessionOpen{
		RunNonce:             g1RestartRunNonce,
		OpenNonce:            g1RestartOpenNonce,
		RecorderSession:      recorderSessionID,
		PolicyHash:           policyHash,
		SignerKeyEpoch:       "epoch-2026-04-restart",
		HeartbeatSeconds:     45,
		ChainOpenSeq:         2,
		PriorChainHead:       prevHash,
		PriorChainSeq:        priorSeq,
		GenesisAnchorHead:    "restart-anchor-head-0002",
		GenesisAnchorLog:     "restart-anchor-log-0002",
		PostureCapsuleSHA256: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		PostureSignerKeyID:   "posture-key-restart",
		ContainmentNonce:     "containment-nonce-0002",
		ContainedUID:         "967",
	}
	restartAR := fixedActionRecord(2, prevHash)
	restartAR.ActionID = "g1-session-open-restart"
	restartAR.ActionType = receipt.ActionUnclassified
	restartAR.Target = "receipt-session:open"
	restartAR.PolicyHash = policyHash
	restartAR.Transport = "receipt_session"
	restartAR.Method = ""
	restartAR.Layer = "session_control"
	restartAR.RunNonce = g1RestartRunNonce
	restartAR.SessionControl = &receipt.SessionControl{
		Kind: receipt.SessionControlOpen,
		Open: &restartOpen,
	}
	restartReceipt, err := receipt.Sign(restartAR, priv)
	if err != nil {
		t.Fatalf("Sign g1 restart open: %v", err)
	}
	chain = append(chain, restartReceipt)
	prevHash = mustReceiptHash(t, restartReceipt)

	heartbeatAR := fixedActionRecord(3, prevHash)
	heartbeatAR.ActionID = "g1-session-heartbeat-restart"
	heartbeatAR.ActionType = receipt.ActionUnclassified
	heartbeatAR.Target = "receipt-session:heartbeat"
	heartbeatAR.Transport = "receipt_session"
	heartbeatAR.Method = ""
	heartbeatAR.Layer = "session_control"
	heartbeatAR.RunNonce = g1RestartRunNonce
	heartbeatAR.SessionControl = &receipt.SessionControl{
		Kind: receipt.SessionControlHeartbeat,
		Heartbeat: &receipt.SessionHeartbeat{
			RunNonce:         g1RestartRunNonce,
			OpenNonce:        g1RestartOpenNonce,
			Beat:             7,
			ChainHead:        prevHash,
			ChainSeqHead:     2,
			HeartbeatTime:    baseTime.Add(3 * time.Second).Format(time.RFC3339),
			FsyncErrorsGated: 4,
			DurabilityBlocks: 8,
		},
	}
	heartbeatReceipt, err := receipt.Sign(heartbeatAR, priv)
	if err != nil {
		t.Fatalf("Sign g1 restart heartbeat: %v", err)
	}
	chain = append(chain, heartbeatReceipt)
	prevHash = mustReceiptHash(t, heartbeatReceipt)

	closeAR := fixedActionRecord(4, prevHash)
	closeAR.ActionID = "g1-session-close-restart"
	closeAR.ActionType = receipt.ActionUnclassified
	closeAR.Target = "receipt-session:close"
	closeAR.Transport = "receipt_session"
	closeAR.Method = ""
	closeAR.Layer = "session_control"
	closeAR.RunNonce = g1RestartRunNonce
	closeAR.SessionControl = &receipt.SessionControl{
		Kind: receipt.SessionControlClose,
		Close: &receipt.SessionClose{
			RunNonce:         g1RestartRunNonce,
			OpenNonce:        g1RestartOpenNonce,
			FinalSeq:         4,
			RootHash:         prevHash,
			ReceiptCount:     5,
			CloseReason:      "restart-normal",
			FsyncErrorsGated: 5,
			DurabilityBlocks: 9,
		},
	}
	closeReceipt, err := receipt.Sign(closeAR, priv)
	if err != nil {
		t.Fatalf("Sign g1 restart close: %v", err)
	}
	chain = append(chain, closeReceipt)
	return chain
}

func buildG1BrokenGenesisChain(t *testing.T, priv ed25519.PrivateKey) []receipt.Receipt {
	t.Helper()
	chain := buildG1ValidChain(t, priv)
	open := *chain[0].ActionRecord.SessionControl.Open
	open.OpenNonce += "-tampered"
	chain[0].ActionRecord.SessionControl.Open = &open
	brokenOpen, err := receipt.Sign(chain[0].ActionRecord, priv)
	if err != nil {
		t.Fatalf("Sign tampered g1 open: %v", err)
	}
	chain[0] = brokenOpen
	return chain
}

func buildG1LegacyOpenOnGenesisChain(t *testing.T, priv ed25519.PrivateKey) []receipt.Receipt {
	t.Helper()
	chain := buildG1ValidChain(t, priv)
	ar := chain[0].ActionRecord
	ar.ChainPrevHash = receipt.GenesisHash
	if ar.SessionControl != nil && ar.SessionControl.Open != nil {
		open := *ar.SessionControl.Open
		open.GenesisHash = ""
		ar.SessionControl.Open = &open
	}
	legacyOpen, err := receipt.Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign legacy genesis session_open: %v", err)
	}
	chain[0] = legacyOpen
	return chain[:1]
}

type g1Vector struct {
	Name     string              `json:"name"`
	Open     receipt.SessionOpen `json:"open"`
	Expected string              `json:"expected"`
}

func g1GenesisVectors() []g1Vector {
	fixtureOpen := receipt.SessionOpen{
		RunNonce:             g1RunNonce,
		OpenNonce:            g1OpenNonce,
		RecorderSession:      recorderSessionID,
		PolicyHash:           "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		SignerKeyEpoch:       "epoch-2026-04",
		HeartbeatSeconds:     30,
		ChainOpenSeq:         0,
		GenesisAnchorHead:    "anchor-head-0001",
		GenesisAnchorLog:     "anchor-log-0001",
		PostureCapsuleSHA256: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		PostureSignerKeyID:   "posture-key-1",
		ContainmentNonce:     "containment-nonce-0001",
		ContainedUID:         "966",
	}
	negativeHeartbeat := receipt.SessionOpen{
		RunNonce:         "rn",
		OpenNonce:        "on",
		RecorderSession:  "rs",
		PolicyHash:       "ph",
		SignerKeyEpoch:   "sk",
		HeartbeatSeconds: -7,
	}
	allOptionals := receipt.SessionOpen{
		RunNonce:             "feedface01234567cafebeef89abcdef",
		OpenNonce:            "open-nonce-all-optionals",
		RecorderSession:      "session-all-optionals",
		PolicyHash:           "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		SignerKeyEpoch:       "epoch-all-optionals",
		HeartbeatSeconds:     60,
		ChainOpenSeq:         11,
		PriorChainHead:       "prior-tail-hash",
		PriorChainSeq:        10,
		GenesisHash:          "g1:ignored-by-genesis-vector",
		GenesisAnchorHead:    "anchor-head-all",
		GenesisAnchorLog:     "anchor-log-all",
		PostureCapsuleSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PostureSignerKeyID:   "posture-key-ignored-by-genesis",
		ContainmentNonce:     "containment-nonce-all",
		ContainedUID:         "967",
	}
	utf8Framing := receipt.SessionOpen{
		RunNonce:             "00112233445566778899aabbccddeeff",
		OpenNonce:            "a",
		RecorderSession:      "bc",
		PolicyHash:           "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		SignerKeyEpoch:       "epoch-\u00e9-\U0001f512",
		HeartbeatSeconds:     1,
		GenesisAnchorHead:    "anchor-\u03c0",
		GenesisAnchorLog:     "log-\u65e5",
		PostureCapsuleSHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ContainmentNonce:     "nonce-\u00e9",
		ContainedUID:         "uid-\u2603",
	}
	inputs := []g1Vector{
		{Name: "empty", Open: receipt.SessionOpen{}},
		{Name: "fixture", Open: fixtureOpen},
		{Name: "negative-heartbeat-clamped", Open: negativeHeartbeat},
		{Name: "all-optionals", Open: allOptionals},
		{Name: "utf8-framing", Open: utf8Framing},
	}
	for i := range inputs {
		inputs[i].Expected = receipt.ComputeSessionOpenGenesis(inputs[i].Open)
	}
	return inputs
}

// TestGenerateGoldenFiles regenerates the golden files in testdata/ when
// run with -update. Normal test runs skip this.
func TestGenerateGoldenFiles(t *testing.T) {
	if !*update {
		t.Skip("pass -update to regenerate golden files")
	}

	if err := os.MkdirAll(testdataDir, 0o750); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}

	pub, priv := testKeyPair(t)
	seed := testSeed()

	// 1. Write the test key material so external verifiers can reproduce.
	keyInfo := map[string]string{
		"seed_phrase":    testSeedPhrase,
		"seed_hex":       hex.EncodeToString(seed[:]),
		"public_key_hex": hex.EncodeToString(pub),
		"note":           "TEST KEY ONLY. Derived from sha256(seed_phrase). Never use for production signing.",
	}
	writeJSONPretty(t, filepath.Join(testdataDir, goldenTestKey), keyInfo)

	// 2. valid-single.json - a single well-formed receipt at seq 0.
	singleAR := fixedActionRecord(0, receipt.GenesisHash)
	single, err := receipt.Sign(singleAR, priv)
	if err != nil {
		t.Fatalf("Sign single: %v", err)
	}
	writeJSONPretty(t, filepath.Join(testdataDir, goldenValidSingle), single)

	// 3. valid-chain.jsonl - five-receipt hash chain wrapped in production
	// flight-recorder entries. This is the format the Pipelock binary
	// actually writes. The ``pipelock verify-receipt`` CLI parses it
	// directly, and the Python verifier extracts receipts from the entry
	// ``detail`` field before checking the receipt chain.
	chain := buildValidChain(t, priv)
	chainEntries := wrapInFlightRecorderEntries(t, chain)
	writeEntryJSONL(t, filepath.Join(testdataDir, goldenValidChain), chainEntries)

	g1Chain := buildG1ValidChain(t, priv)
	writeEntryJSONL(t, filepath.Join(testdataDir, goldenG1ValidChain), wrapInFlightRecorderEntries(t, g1Chain))
	g1Restart := buildG1RestartChain(t, priv)
	writeEntryJSONL(t, filepath.Join(testdataDir, goldenG1RestartChain), wrapInFlightRecorderEntries(t, g1Restart))
	writeJSONPretty(t, filepath.Join(testdataDir, goldenG1Vectors), g1GenesisVectors())
	g1Broken := buildG1BrokenGenesisChain(t, priv)
	writeEntryJSONL(t, filepath.Join(testdataDir, goldenG1BrokenGenesis), wrapInFlightRecorderEntries(t, g1Broken))
	g1LegacyOpen := buildG1LegacyOpenOnGenesisChain(t, priv)
	writeEntryJSONL(t, filepath.Join(testdataDir, goldenG1LegacyOpen), wrapInFlightRecorderEntries(t, g1LegacyOpen))

	// 4. invalid-signature.json - tamper a signature byte. Individual verify
	// MUST fail. Chain verification also fails on this receipt.
	tampered := single
	sigHex := strings.TrimPrefix(tampered.Signature, "ed25519:")
	tampered.Signature = "ed25519:" + flipFirstHexNibble(sigHex)
	writeJSONPretty(t, filepath.Join(testdataDir, goldenInvalidSignature), tampered)

	// 5. broken-chain.jsonl - valid individual signatures, but the
	// prev_hash of receipt[brokenAtIndex] is wrong. Chain verification
	// MUST report a break at seq brokenAtIndex.
	broken := buildValidChain(t, priv)
	brokenAR := fixedActionRecord(uint64(brokenAtIndex), brokenPrev)
	brokenR, err := receipt.Sign(brokenAR, priv)
	if err != nil {
		t.Fatalf("Sign broken: %v", err)
	}
	broken[brokenAtIndex] = brokenR
	brokenEntries := wrapInFlightRecorderEntries(t, broken)
	writeEntryJSONL(t, filepath.Join(testdataDir, goldenBrokenChain), brokenEntries)

	t.Logf("regenerated golden files in %s", testdataDir)
}

// TestConformance_ValidSingle verifies the single-receipt golden file.
func TestConformance_ValidSingle(t *testing.T) {
	t.Parallel()

	r := readReceipt(t, filepath.Join(testdataDir, goldenValidSingle))

	pub, _ := testKeyPair(t)
	if err := receipt.VerifyWithKey(r, hex.EncodeToString(pub)); err != nil {
		t.Fatalf("VerifyWithKey: %v", err)
	}

	if got, want := r.ActionRecord.ActionID, "conformance-00000"; got != want {
		t.Errorf("action_id = %q, want %q", got, want)
	}
	if got := r.ActionRecord.ChainSeq; got != 0 {
		t.Errorf("chain_seq = %d, want 0", got)
	}
	if got, want := r.ActionRecord.ChainPrevHash, receipt.GenesisHash; got != want {
		t.Errorf("chain_prev_hash = %q, want %q", got, want)
	}
}

// TestConformance_ValidChain verifies the full five-receipt chain.
func TestConformance_ValidChain(t *testing.T) {
	t.Parallel()

	receipts := readReceiptsJSONL(t, filepath.Join(testdataDir, goldenValidChain))
	if len(receipts) != chainLen {
		t.Fatalf("receipt count = %d, want %d", len(receipts), chainLen)
	}

	pub, _ := testKeyPair(t)
	result := receipt.VerifyChain(receipts, hex.EncodeToString(pub))
	if !result.Valid {
		t.Fatalf("VerifyChain: %s", result.Error)
	}
	if result.ReceiptCount != chainLen {
		t.Errorf("receipt_count = %d, want %d", result.ReceiptCount, chainLen)
	}
	if result.FinalSeq != chainLen-1 {
		t.Errorf("final_seq = %d, want %d", result.FinalSeq, chainLen-1)
	}
	if result.RootHash == "" {
		t.Error("root_hash should not be empty")
	}
}

func TestConformance_G1ValidChain(t *testing.T) {
	t.Parallel()

	receipts := readReceiptsJSONL(t, filepath.Join(testdataDir, goldenG1ValidChain))
	if len(receipts) != chainLen {
		t.Fatalf("receipt count = %d, want %d", len(receipts), chainLen)
	}

	pub, _ := testKeyPair(t)
	result := receipt.VerifyChain(receipts, hex.EncodeToString(pub))
	if !result.Valid {
		t.Fatalf("VerifyChain: %s", result.Error)
	}
	if got := receipts[0].ActionRecord.ChainPrevHash; !strings.HasPrefix(got, "g1:") {
		t.Fatalf("genesis prev hash = %q, want g1 prefix", got)
	}
	if got := receipts[1].ActionRecord.DecisionPhase; got != receipt.DecisionPhaseIntent {
		t.Fatalf("receipt[1] decision_phase = %q, want %q", got, receipt.DecisionPhaseIntent)
	}
	if got := receipts[2].ActionRecord.DecisionPhase; got != receipt.DecisionPhaseOutcome {
		t.Fatalf("receipt[2] decision_phase = %q, want %q", got, receipt.DecisionPhaseOutcome)
	}
}

func TestConformance_G1GenesisVectors(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Clean(filepath.Join(testdataDir, goldenG1Vectors)))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var vectors []g1Vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(vectors) < 5 {
		t.Fatalf("vector count = %d, want at least 5", len(vectors))
	}
	for _, vector := range vectors {
		if got := receipt.ComputeSessionOpenGenesis(vector.Open); got != vector.Expected {
			t.Fatalf("%s: ComputeSessionOpenGenesis = %q, want %q", vector.Name, got, vector.Expected)
		}
	}
}

func TestConformance_G1RestartChain(t *testing.T) {
	t.Parallel()

	receipts := readReceiptsJSONL(t, filepath.Join(testdataDir, goldenG1RestartChain))
	if len(receipts) != chainLen {
		t.Fatalf("receipt count = %d, want %d", len(receipts), chainLen)
	}

	pub, _ := testKeyPair(t)
	result := receipt.VerifyChain(receipts, hex.EncodeToString(pub))
	if !result.Valid {
		t.Fatalf("VerifyChain: %s", result.Error)
	}
	open := receipts[2].ActionRecord.SessionControl.Open
	if open == nil {
		t.Fatal("restart receipt missing session_control.open")
	}
	if open.PriorChainHead == "" {
		t.Fatal("restart open prior_chain_head should be populated")
	}
	if open.PriorChainSeq != receipts[1].ActionRecord.ChainSeq {
		t.Fatalf("prior_chain_seq = %d, want %d", open.PriorChainSeq, receipts[1].ActionRecord.ChainSeq)
	}
}

func TestConformance_G1BrokenGenesisRejected(t *testing.T) {
	t.Parallel()

	receipts := readReceiptsJSONL(t, filepath.Join(testdataDir, goldenG1BrokenGenesis))
	pub, _ := testKeyPair(t)
	result := receipt.VerifyChain(receipts, hex.EncodeToString(pub))
	if result.Valid {
		t.Fatal("VerifyChain unexpectedly accepted broken g1 genesis")
	}
	if result.BrokenAtSeq != 0 {
		t.Errorf("broken_at_seq = %d, want 0", result.BrokenAtSeq)
	}
	if !strings.Contains(result.Error, "session_open genesis hash mismatch") {
		t.Errorf("error = %q, want substring 'session_open genesis hash mismatch'", result.Error)
	}
}

func TestConformance_G1LegacyOpenOnGenesisRejected(t *testing.T) {
	t.Parallel()

	receipts := readReceiptsJSONL(t, filepath.Join(testdataDir, goldenG1LegacyOpen))
	pub, _ := testKeyPair(t)
	result := receipt.VerifyChain(receipts, hex.EncodeToString(pub))
	if result.Valid {
		t.Fatal("VerifyChain unexpectedly accepted session_open on legacy genesis")
	}
	if result.BrokenAtSeq != 0 {
		t.Errorf("broken_at_seq = %d, want 0", result.BrokenAtSeq)
	}
	if !strings.Contains(result.Error, "session_open on legacy genesis") {
		t.Errorf("error = %q, want substring 'session_open on legacy genesis'", result.Error)
	}
}

func TestConformance_G1SignedFieldTamperingRejected(t *testing.T) {
	t.Parallel()

	pub, _ := testKeyPair(t)
	keyHex := hex.EncodeToString(pub)
	tests := []struct {
		name   string
		mutate func([]receipt.Receipt)
	}{
		{
			name: "session_open_posture_signer_key_id",
			mutate: func(receipts []receipt.Receipt) {
				receipts[0].ActionRecord.SessionControl.Open.PostureSignerKeyID = "posture-key-tampered"
			},
		},
		{
			name: "decision_phase",
			mutate: func(receipts []receipt.Receipt) {
				receipts[1].ActionRecord.DecisionPhase = receipt.DecisionPhaseOutcome
			},
		},
		{
			name: "heartbeat_beat",
			mutate: func(receipts []receipt.Receipt) {
				receipts[3].ActionRecord.SessionControl.Heartbeat.Beat++
			},
		},
		{
			name: "heartbeat_fsync_errors_gated",
			mutate: func(receipts []receipt.Receipt) {
				receipts[3].ActionRecord.SessionControl.Heartbeat.FsyncErrorsGated++
			},
		},
		{
			name: "close_root_hash",
			mutate: func(receipts []receipt.Receipt) {
				receipts[4].ActionRecord.SessionControl.Close.RootHash = "tampered-root"
			},
		},
		{
			name: "close_durability_blocks",
			mutate: func(receipts []receipt.Receipt) {
				receipts[4].ActionRecord.SessionControl.Close.DurabilityBlocks++
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receipts := readReceiptsJSONL(t, filepath.Join(testdataDir, goldenG1ValidChain))
			tt.mutate(receipts)
			result := receipt.VerifyChain(receipts, keyHex)
			if result.Valid {
				t.Fatal("VerifyChain unexpectedly accepted tampered signed field")
			}
			if !strings.Contains(result.Error, "signature") {
				t.Fatalf("error = %q, want signature failure", result.Error)
			}
		})
	}
}

// TestConformance_InvalidSignature verifies the tampered signature fixture fails.
func TestConformance_InvalidSignature(t *testing.T) {
	t.Parallel()

	r := readReceipt(t, filepath.Join(testdataDir, goldenInvalidSignature))

	err := receipt.VerifyInternalConsistencyOnly(r)
	if err == nil {
		t.Fatal("Verify() unexpectedly succeeded on tampered signature")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("error = %q, want substring 'signature verification failed'", err)
	}
}

// TestConformance_BrokenChain verifies the broken chain fixture: individual
// signatures all valid, chain verification reports break at the expected seq.
func TestConformance_BrokenChain(t *testing.T) {
	t.Parallel()

	receipts := readReceiptsJSONL(t, filepath.Join(testdataDir, goldenBrokenChain))
	if len(receipts) != chainLen {
		t.Fatalf("receipt count = %d, want %d", len(receipts), chainLen)
	}

	pub, _ := testKeyPair(t)
	keyHex := hex.EncodeToString(pub)

	// Every individual receipt must still verify against the test key.
	for i, r := range receipts {
		if err := receipt.VerifyWithKey(r, keyHex); err != nil {
			t.Errorf("receipt[%d] individual sig invalid: %v", i, err)
		}
	}

	result := receipt.VerifyChain(receipts, keyHex)
	if result.Valid {
		t.Fatal("VerifyChain unexpectedly succeeded on broken chain")
	}
	if result.BrokenAtSeq != brokenAtIndex {
		t.Errorf("broken_at_seq = %d, want %d", result.BrokenAtSeq, brokenAtIndex)
	}
	if !strings.Contains(result.Error, "chain_prev_hash mismatch") {
		t.Errorf("error = %q, want substring 'chain_prev_hash mismatch'", result.Error)
	}
}

// TestConformance_TestKeyMatches verifies the committed public key matches
// the deterministic seed. Guards against accidental key drift.
func TestConformance_TestKeyMatches(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Clean(filepath.Join(testdataDir, goldenTestKey)))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var info map[string]string
	if err := json.Unmarshal(data, &info); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	pub, _ := testKeyPair(t)
	wantPubHex := hex.EncodeToString(pub)
	if got := info["public_key_hex"]; got != wantPubHex {
		t.Errorf("public_key_hex = %q, want %q", got, wantPubHex)
	}

	seed := testSeed()
	if got, want := info["seed_hex"], hex.EncodeToString(seed[:]); got != want {
		t.Errorf("seed_hex = %q, want %q", got, want)
	}
	if got := info["seed_phrase"]; got != testSeedPhrase {
		t.Errorf("seed_phrase = %q, want %q", got, testSeedPhrase)
	}
}

// ---- helpers ----

func readReceipt(t *testing.T, path string) receipt.Receipt {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	r, err := receipt.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal %s: %v", path, err)
	}
	return r
}

// readReceiptsJSONL reads a flight-recorder JSONL file and extracts the
// receipts carried in each entry's Detail field. Matches the production
// read path used by “pipelock verify-receipt“.
func readReceiptsJSONL(t *testing.T, path string) []receipt.Receipt {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	var receipts []receipt.Receipt
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var entry recorder.Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("Unmarshal entry %d of %s: %v", i, path, err)
		}
		if entry.Type != recorderEntryType {
			continue
		}
		detailJSON, err := json.Marshal(entry.Detail)
		if err != nil {
			t.Fatalf("Marshal detail %d of %s: %v", i, path, err)
		}
		r, err := receipt.Unmarshal(detailJSON)
		if err != nil {
			t.Fatalf("Unmarshal receipt from entry %d of %s: %v", i, path, err)
		}
		receipts = append(receipts, r)
	}
	return receipts
}

// wrapInFlightRecorderEntries wraps each receipt in a flight-recorder entry
// with a valid entry-level hash chain. The entry chain (prev_hash/hash) is
// separate from the receipt chain inside the entries' Detail fields.
//
// Timestamps are taken from the receipts so the entries are fully
// deterministic. ComputeHash is the exact function pipelock uses in
// production, so these entries are byte-identical to what the emitter
// writes for the same inputs.
func wrapInFlightRecorderEntries(t *testing.T, receipts []receipt.Receipt) []recorder.Entry {
	t.Helper()
	entries := make([]recorder.Entry, 0, len(receipts))
	prevHash := recorder.GenesisHash
	for i, r := range receipts {
		receiptJSON, err := receipt.Marshal(r)
		if err != nil {
			t.Fatalf("marshal receipt %d: %v", i, err)
		}
		e := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  uint64(i),
			Timestamp: r.ActionRecord.Timestamp,
			SessionID: recorderSessionID,
			Type:      recorderEntryType,
			Transport: r.ActionRecord.Transport,
			Summary: fmt.Sprintf(
				"receipt: %s %s %s",
				r.ActionRecord.Verdict,
				r.ActionRecord.ActionType,
				r.ActionRecord.Transport,
			),
			Detail:   json.RawMessage(receiptJSON),
			PrevHash: prevHash,
		}
		e.Hash = recorder.ComputeHash(e)
		entries = append(entries, e)
		prevHash = e.Hash
	}
	return entries
}

func writeJSONPretty(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

// writeEntryJSONL writes flight-recorder entries as one compact JSON
// object per line. Matches the format written by the production recorder.
func writeEntryJSONL(t *testing.T, path string, entries []recorder.Entry) {
	t.Helper()
	var buf strings.Builder
	for i, e := range entries {
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("json.Marshal entry[%d]: %v", i, err)
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

func mustReceiptHash(t *testing.T, r receipt.Receipt) string {
	t.Helper()
	h, err := receipt.ReceiptHash(r)
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}
	return h
}

// flipFirstHexNibble flips the first hex character to produce a different
// but still well-formed hex string (so parsing succeeds, signature fails).
func flipFirstHexNibble(h string) string {
	if len(h) == 0 {
		return h
	}
	b := []byte(h)
	if b[0] == 'f' {
		b[0] = '0'
	} else {
		b[0] = 'f'
	}
	return string(b)
}
