// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	legacyreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func supportsCompactExchangeTest() bool { return runtime.GOOS == "linux" }

func TestRunCompactSignedMultiShardExchange(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("atomic evidence directory exchange is unsupported")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	originalBytes := make([]byte, 0)
	receiptPrev := contractreceipt.GenesisHash
	recorderPrev := recorder.GenesisHash
	sourceShards := recorder.MaxEvidenceReadDirectoryEntries + 1
	for i := range sourceShards {
		r := compactSignedReceipt(t, priv, uint64(i), receiptPrev)
		receiptPrev, err = contractreceipt.ReceiptHash(r)
		if err != nil {
			t.Fatal(err)
		}
		e := recorder.Entry{
			Version: recorder.CurrentWriteEntryVersion, Sequence: uint64(i),
			Timestamp: time.Unix(int64(i+1), 0).UTC(), SessionID: "proxy",
			Type: contractreceipt.EvidenceEntryType, EventKind: "proxy_decision",
			Transport: "fetch", Summary: strings.Repeat("x", 40_000), Detail: r, PrevHash: recorderPrev,
		}
		e.Hash = recorder.ComputeHash(e)
		recorderPrev = e.Hash
		line, marshalErr := json.Marshal(e)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		line = append(line, '\n')
		originalBytes = append(originalBytes, line...)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("evidence-proxy-%d.jsonl", i)), line, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cmd := compactCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--receipt-dir", dir, "--session", "proxy", "--key", hex.EncodeToString(pub)})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("compact command: %v", err)
	}
	active, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 {
		t.Fatalf("active entries = %d, want 2 compacted shards", len(active))
	}
	sort.Slice(active, func(i, j int) bool {
		_, a, _ := recorder.ParseEvidenceFilename(active[i].Name())
		_, b, _ := recorder.ParseEvidenceFilename(active[j].Name())
		return a < b
	})
	var compacted []byte
	for _, entry := range active {
		// #nosec G304 -- entry comes from the freshly compacted test directory.
		part, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		compacted = append(compacted, part...)
	}
	if !bytes.Equal(compacted, originalBytes) {
		t.Fatal("active compaction changed original JSONL line bytes")
	}
	archives, err := filepath.Glob(filepath.Join(parent, ".pipelock-evidence-archive-*"))
	if err != nil || len(archives) != 1 {
		t.Fatalf("archives = %v, err = %v", archives, err)
	}
	var manifest compactManifest
	manifestBytes, err := os.ReadFile(filepath.Join(archives[0], "compaction-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Original) != sourceShards || len(manifest.Replacement) != 2 || len(manifest.Mappings) != sourceShards {
		t.Fatalf("manifest counts = original %d replacement %d mappings %d", len(manifest.Original), len(manifest.Replacement), len(manifest.Mappings))
	}
	for i := range sourceShards {
		archived, readErr := os.ReadFile(filepath.Join(archives[0], fmt.Sprintf("evidence-proxy-%d.jsonl", i)))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if got := hex.EncodeToString(sha256Bytes(archived)); got != manifest.Original[i].SHA256 {
			t.Fatalf("archive digest %d = %s, manifest %s", i, got, manifest.Original[i].SHA256)
		}
	}
	if !strings.Contains(out.String(), "original preserved at") {
		t.Fatalf("command output = %q", out.String())
	}
}

// TestRunCompactFrozenV1ActionReceiptFixture is the compatibility proof for
// the immutable recorder format that the live migration must accept. The
// fixture predates the v2 evidence receipt and preserves deliberately compact
// v1 JSON spelling, so a decode/re-marshal verifier would not be an adequate
// substitute for this test.
func TestRunCompactFrozenV1ActionReceiptFixture(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("atomic evidence directory exchange is unsupported")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "frozen", "v1", "action-receipt-v1-chain.jsonl")
	// #nosec G304 -- fixed repository conformance fixture.
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read frozen v1 fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-conformance-session-0.jsonl"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	const fixtureKey = "4655a7e605c12ebb00a46037881c33c5bca5eb74b45a02e8e7261a7ff5a21678"
	if err := runCompact(compactCmd(), compactOptions{receiptDir: dir, sessionID: "conformance-session", publicKey: fixtureKey}); err != nil {
		t.Fatalf("compact frozen v1 action receipt chain: %v", err)
	}
	// #nosec G304 -- test-created compacted shard.
	active, err := os.ReadFile(filepath.Join(dir, "evidence-conformance-session-0.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(active, data) {
		t.Fatal("compaction changed immutable frozen v1 JSONL bytes")
	}
}

func TestStreamCompactFilesVerifiesSignedOuterCheckpoint(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1, SignCheckpoints: true}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	r := compactSignedReceipt(t, priv, 0, contractreceipt.GenesisHash)
	if err := rec.Record(recorder.Entry{SessionID: "proxy", Type: contractreceipt.EvidenceEntryType, EventKind: "proxy_decision", Transport: "fetch", Summary: "signed", Detail: r}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	location := recorder.EvidenceLocation{Root: dir, Dir: dir}
	names, err := compactStreamNames(location, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := streamCompactFiles(location, names, "proxy", pub, func(compactStreamFile, []byte, recorder.Entry) error { return nil }); err != nil {
		t.Fatalf("valid signed checkpoint stream: %v", err)
	}

	path := filepath.Join(dir, names[0])
	entries, err := recorder.ReadEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range entries {
		if entries[i].Type != "checkpoint" {
			continue
		}
		detail := entries[i].Detail.(map[string]any)
		detail["signature"] = strings.Repeat("00", ed25519.SignatureSize)
		entries[i].Detail = detail
		break
	}
	for i := range entries {
		entries[i].RawDetail = nil
		if i > 0 {
			entries[i].PrevHash = entries[i-1].Hash
		}
		entries[i].Hash = recorder.ComputeHash(entries[i])
	}
	var rewritten bytes.Buffer
	for _, entry := range entries {
		line, marshalErr := json.Marshal(entry)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		rewritten.Write(line)
		rewritten.WriteByte('\n')
	}
	if err := os.WriteFile(path, rewritten.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := streamCompactFiles(location, names, "proxy", pub, func(compactStreamFile, []byte, recorder.Entry) error { return nil }); err == nil || err.Error() != "entry seq 1: checkpoint signature verification failed" {
		t.Fatalf("tampered signed checkpoint error = %v, want exact checkpoint signature verification failure", err)
	}
}

func TestCompactOuterVerifierBoundsUnsignedCheckpointMetadata(t *testing.T) {
	detail := recorder.CheckpointDetail{EntryCount: 1, FirstSeq: 0, LastSeq: 0}
	rawDetail, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	entry := recorder.Entry{
		Version: recorder.CurrentWriteEntryVersion, Sequence: 0,
		Timestamp: time.Unix(1, 0).UTC(), SessionID: "proxy",
		Type: "checkpoint", EventKind: "checkpoint", Detail: detail,
		RawDetail: rawDetail, PrevHash: recorder.GenesisHash,
	}
	entry.Hash = recorder.ComputeHash(entry)

	allowed := compactOuterVerifier{unsignedCheckpoints: make([]compactUnsignedCheckpoint, maxCompactUnsignedCheckpoints-1)}
	if err := allowed.add(entry, "proxy", "evidence-proxy-0.jsonl"); err != nil {
		t.Fatalf("checkpoint at metadata limit: %v", err)
	}
	if got := len(allowed.unsignedCheckpoints); got != maxCompactUnsignedCheckpoints {
		t.Fatalf("unsigned checkpoint count = %d, want %d", got, maxCompactUnsignedCheckpoints)
	}

	refused := compactOuterVerifier{unsignedCheckpoints: make([]compactUnsignedCheckpoint, maxCompactUnsignedCheckpoints)}
	err = refused.add(entry, "proxy", "evidence-proxy-0.jsonl")
	if err == nil || !strings.Contains(err.Error(), "unsigned checkpoint count exceeds compaction limit 10000") {
		t.Fatalf("over-limit unsigned checkpoint error = %v", err)
	}
}

func TestRunCompactAcknowledgesUnsignedCheckpointSealedBySignedCheckpoint(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("atomic evidence directory exchange is unsupported")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receipt := compactSignedReceipt(t, priv, 0, contractreceipt.GenesisHash)
	items := []struct {
		typ    string
		detail any
	}{
		{contractreceipt.EvidenceEntryType, receipt},
		{"checkpoint", recorder.CheckpointDetail{EntryCount: 1, FirstSeq: 0, LastSeq: 0}},
		{"checkpoint", recorder.CheckpointDetail{EntryCount: 1, FirstSeq: 1, LastSeq: 1}},
	}
	var source bytes.Buffer
	previous := recorder.GenesisHash
	for i, item := range items {
		if item.typ == "checkpoint" && i == 2 {
			detail := item.detail.(recorder.CheckpointDetail)
			detail.Signature = hex.EncodeToString(ed25519.Sign(priv, []byte(previous)))
			item.detail = detail
		}
		entry := recorder.Entry{Version: recorder.CurrentWriteEntryVersion, Sequence: uint64(i), Timestamp: time.Unix(int64(i+1), 0).UTC(), SessionID: "proxy", Type: item.typ, EventKind: "proxy_decision", Transport: "fetch", Summary: item.typ, Detail: item.detail, PrevHash: previous}
		entry.Hash = recorder.ComputeHash(entry)
		previous = entry.Hash
		line, marshalErr := json.Marshal(entry)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		source.Write(line)
		source.WriteByte('\n')
	}
	path := filepath.Join(dir, "evidence-proxy-0.jsonl")
	if err := os.WriteFile(path, source.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := compactOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub)}
	if err := runCompact(compactCmd(), opts); err == nil || !strings.Contains(err.Error(), "--allow-unsigned-checkpoints=1") {
		t.Fatalf("missing acknowledgement error = %v", err)
	}
	if active, readErr := os.ReadFile(filepath.Clean(path)); readErr != nil || !bytes.Equal(active, source.Bytes()) {
		t.Fatalf("refusal changed source: err=%v", readErr)
	}
	opts.allowUnsignedCheckpoints = 2
	if err := runCompact(compactCmd(), opts); err == nil || !strings.Contains(err.Error(), "contains 1 historical unsigned") {
		t.Fatalf("wrong acknowledgement error = %v", err)
	}
	opts.allowUnsignedCheckpoints = 1
	cmd := compactCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runCompact(cmd, opts); err != nil {
		t.Fatalf("compact acknowledged history: %v", err)
	}
	if !strings.Contains(out.String(), "checkpoint proof: DEGRADED") {
		t.Fatalf("output = %q", out.String())
	}
	archives, err := filepath.Glob(filepath.Join(parent, ".pipelock-evidence-archive-*"))
	if err != nil || len(archives) != 1 {
		t.Fatalf("archives=%v err=%v", archives, err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(archives[0], "compaction-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest compactManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.CheckpointVerification.Status != "degraded" || len(manifest.CheckpointVerification.Unsigned) != 1 || !manifest.CheckpointVerification.Unsigned[0].LaterSignedCovered || manifest.CheckpointVerification.Unsigned[0].CoveredByRecorderSeq != 2 {
		t.Fatalf("checkpoint manifest = %+v", manifest.CheckpointVerification)
	}
	active, err := os.ReadFile(filepath.Clean(path))
	if err != nil || !bytes.Equal(active, source.Bytes()) {
		t.Fatalf("compaction changed source bytes: err=%v", err)
	}
	if err := runCompact(compactCmd(), opts); err != nil {
		t.Fatalf("rerun acknowledged compaction: %v", err)
	}
}

func TestRunCompactRefusesUnsignedCheckpointAtTail(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receipt := compactSignedReceipt(t, priv, 0, contractreceipt.GenesisHash)
	first := recorder.Entry{Version: recorder.CurrentWriteEntryVersion, Sequence: 0, Timestamp: time.Unix(1, 0).UTC(), SessionID: "proxy", Type: contractreceipt.EvidenceEntryType, EventKind: "proxy_decision", Transport: "fetch", Detail: receipt, PrevHash: recorder.GenesisHash}
	first.Hash = recorder.ComputeHash(first)
	tail := recorder.Entry{Version: recorder.CurrentWriteEntryVersion, Sequence: 1, Timestamp: time.Unix(2, 0).UTC(), SessionID: "proxy", Type: "checkpoint", EventKind: "checkpoint", Detail: recorder.CheckpointDetail{EntryCount: 1, FirstSeq: 0, LastSeq: 0}, PrevHash: first.Hash}
	tail.Hash = recorder.ComputeHash(tail)
	var source bytes.Buffer
	for _, entry := range []recorder.Entry{first, tail} {
		line, marshalErr := json.Marshal(entry)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		source.Write(line)
		source.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), source.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	err = runCompact(compactCmd(), compactOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), allowUnsignedCheckpoints: 1})
	if err == nil || !strings.Contains(err.Error(), "not sealed by a later signed checkpoint") {
		t.Fatalf("tail unsigned checkpoint error = %v", err)
	}
}

func TestStreamCompactFilesAcceptsRealRecorderUnsignedToSignedResume(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstReceipt := compactSignedReceipt(t, priv, 0, contractreceipt.GenesisHash)
	firstHead, err := contractreceipt.ReceiptHash(firstReceipt)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := unsigned.Record(recorder.Entry{SessionID: "proxy", Type: contractreceipt.EvidenceEntryType, EventKind: "proxy_decision", Transport: "fetch", Detail: firstReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := unsigned.Close(); err != nil {
		t.Fatal(err)
	}

	signed, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1, SignCheckpoints: true}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	secondReceipt := compactSignedReceipt(t, priv, 1, firstHead)
	if err := signed.Record(recorder.Entry{SessionID: "proxy", Type: contractreceipt.EvidenceEntryType, EventKind: "proxy_decision", Transport: "fetch", Detail: secondReceipt}); err != nil {
		t.Fatal(err)
	}
	if err := signed.Close(); err != nil {
		t.Fatal(err)
	}

	location := recorder.EvidenceLocation{Root: dir, Dir: dir}
	names, err := compactStreamNames(location, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := streamCompactFiles(location, names, "proxy", pub, func(compactStreamFile, []byte, recorder.Entry) error { return nil })
	if err != nil {
		t.Fatalf("real recorder unsigned-to-signed history: %v", err)
	}
	if len(proof.unsignedCheckpoints) != 1 || proof.unsignedCheckpoints[0].RecorderSeq != 1 || proof.unsignedCheckpoints[0].CoveredByRecorderSeq != 3 {
		t.Fatalf("unsigned checkpoint proof = %+v", proof.unsignedCheckpoints)
	}
}

func TestRunCompactRefusesHistoricalV1Epochs(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("atomic evidence directory exchange is unsupported")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var source bytes.Buffer
	for epoch := range 15 {
		receipt := receiptForCompactV1(t, priv, 0, legacyreceipt.GenesisHash, fmt.Sprintf("epoch-%d", epoch))
		entry := recorder.Entry{Version: 1, Sequence: 0, Timestamp: time.Unix(int64(epoch+1), 0).UTC(), SessionID: "proxy", Type: "action_receipt", EventKind: "proxy_decision", Transport: "fetch", Summary: "legacy epoch", Detail: receipt, PrevHash: recorder.GenesisHash}
		entry.Hash = recorder.ComputeHash(entry)
		line, marshalErr := json.Marshal(entry)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		source.Write(line)
		source.WriteByte('\n')
	}
	path := filepath.Join(dir, "evidence-proxy-0.jsonl")
	if err := os.WriteFile(path, source.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := compactOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub)}
	err = runCompact(compactCmd(), opts)
	if err == nil || !strings.Contains(err.Error(), "ordinary compaction cannot publish unlinked epochs") || !strings.Contains(err.Error(), "inspect-epochs") {
		t.Fatalf("legacy epoch refusal error = %v", err)
	}
	archives, err := filepath.Glob(filepath.Join(parent, ".pipelock-evidence-archive-*"))
	if err != nil || len(archives) != 0 {
		t.Fatalf("archives=%v err=%v", archives, err)
	}
	// #nosec G304 -- path is the test's own temporary evidence fixture.
	active, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(active, source.Bytes()) {
		t.Fatalf("refusal changed historical epoch bytes: err=%v", err)
	}
}

func TestCompactOuterVerifierRefusesV2RestartAndUncoveredEpochCheckpoint(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("v2 restart", func(t *testing.T) {
		firstReceipt := compactSignedReceipt(t, priv, 0, contractreceipt.GenesisHash)
		first := recorder.Entry{Version: 2, Sequence: 0, Timestamp: time.Unix(1, 0).UTC(), SessionID: "proxy", Type: contractreceipt.EvidenceEntryType, EventKind: "proxy_decision", Transport: "fetch", Summary: "v2", Detail: firstReceipt, PrevHash: recorder.GenesisHash}
		first.Hash = recorder.ComputeHash(first)
		second := first
		second.Timestamp = time.Unix(2, 0).UTC()
		second.Detail = compactSignedReceipt(t, priv, 1, contractreceipt.GenesisHash)
		second.Hash = recorder.ComputeHash(second)
		v := compactOuterVerifier{key: pub}
		if err := v.add(first, "proxy"); err != nil {
			t.Fatal(err)
		}
		if err := v.add(second, "proxy"); err == nil || !strings.Contains(err.Error(), "sequence or hash chain break") {
			t.Fatalf("v2 restart error = %v", err)
		}
	})
	t.Run("uncovered epoch checkpoint", func(t *testing.T) {
		legacy := recorder.Entry{Version: 1, Sequence: 0, Timestamp: time.Unix(1, 0).UTC(), SessionID: "proxy", Type: "decision", EventKind: "proxy_decision", Transport: "fetch", Summary: "legacy", Detail: map[string]string{"verdict": "block"}, PrevHash: recorder.GenesisHash}
		legacy.Hash = recorder.ComputeHash(legacy)
		checkpointDetail := recorder.CheckpointDetail{EntryCount: 1, FirstSeq: 0, LastSeq: 0}
		rawCheckpoint, marshalErr := json.Marshal(checkpointDetail)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		checkpoint := recorder.Entry{Version: 1, Sequence: 1, Timestamp: time.Unix(2, 0).UTC(), SessionID: "proxy", Type: "checkpoint", EventKind: "checkpoint", Detail: checkpointDetail, RawDetail: rawCheckpoint, PrevHash: legacy.Hash}
		checkpoint.Hash = recorder.ComputeHash(checkpoint)
		restart := legacy
		restart.Timestamp = time.Unix(3, 0).UTC()
		restart.Hash = recorder.ComputeHash(restart)
		v := compactOuterVerifier{key: pub}
		if err := v.add(legacy, "proxy"); err != nil {
			t.Fatal(err)
		}
		if err := v.add(checkpoint, "proxy"); err != nil {
			t.Fatal(err)
		}
		if err := v.add(restart, "proxy"); err == nil || !strings.Contains(err.Error(), "is not sealed before recorder restart") {
			t.Fatalf("cross-epoch unsigned checkpoint error = %v", err)
		}
	})
}

func TestCompactOuterVerifierBoundsLegacyEpochCompatibility(t *testing.T) {
	makeEntry := func(version int, ts int64) recorder.Entry {
		e := recorder.Entry{Version: version, Sequence: 0, Timestamp: time.Unix(ts, 0).UTC(), SessionID: "proxy", Type: "decision", EventKind: "proxy_decision", Transport: "fetch", Summary: "epoch", Detail: map[string]string{"verdict": "block"}, PrevHash: recorder.GenesisHash}
		e.Hash = recorder.ComputeHash(e)
		return e
	}
	t.Run("timestamp must advance", func(t *testing.T) {
		v := compactOuterVerifier{}
		if err := v.add(makeEntry(1, 2), "proxy"); err != nil {
			t.Fatal(err)
		}
		if err := v.add(makeEntry(1, 2), "proxy"); err == nil || !strings.Contains(err.Error(), "timestamp does not advance") {
			t.Fatalf("timestamp error = %v", err)
		}
	})
	t.Run("modern epoch cannot restart as legacy", func(t *testing.T) {
		v := compactOuterVerifier{}
		if err := v.add(makeEntry(2, 1), "proxy"); err != nil {
			t.Fatal(err)
		}
		if err := v.add(makeEntry(1, 2), "proxy"); err == nil || !strings.Contains(err.Error(), "v1-only epochs") {
			t.Fatalf("mixed-version error = %v", err)
		}
	})
	t.Run("epoch count is bounded", func(t *testing.T) {
		v := compactOuterVerifier{epoch: maxCompactLegacyEpochs - 1}
		if err := v.add(makeEntry(1, 1), "proxy"); err != nil {
			t.Fatal(err)
		}
		if err := v.add(makeEntry(1, 2), "proxy"); err == nil || !strings.Contains(err.Error(), "epoch count exceeds") {
			t.Fatalf("epoch limit error = %v", err)
		}
	})
}

func TestCompactOuterVerifierDoesNotSealPriorEpochCheckpoint(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	genesis := recorder.Entry{Version: 1, Sequence: 0, Timestamp: time.Unix(1, 0).UTC(), SessionID: "proxy", Type: "decision", EventKind: "proxy_decision", Transport: "fetch", Summary: "epoch", Detail: map[string]string{"verdict": "block"}, PrevHash: recorder.GenesisHash}
	genesis.Hash = recorder.ComputeHash(genesis)
	restart := genesis
	restart.Timestamp = time.Unix(2, 0).UTC()
	restart.Hash = recorder.ComputeHash(restart)
	v := compactOuterVerifier{key: pub}
	if err := v.add(genesis, "proxy"); err != nil {
		t.Fatal(err)
	}
	if err := v.add(restart, "proxy"); err != nil {
		t.Fatal(err)
	}
	v.unsignedCheckpoints = append(v.unsignedCheckpoints, compactUnsignedCheckpoint{Epoch: 0, RecorderSeq: 7})
	detail := recorder.CheckpointDetail{EntryCount: 1, FirstSeq: 0, LastSeq: 0, Signature: hex.EncodeToString(ed25519.Sign(priv, []byte(restart.Hash)))}
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := recorder.Entry{Version: 1, Sequence: 1, Timestamp: time.Unix(3, 0).UTC(), SessionID: "proxy", Type: "checkpoint", EventKind: "checkpoint", Detail: detail, RawDetail: raw, PrevHash: restart.Hash}
	checkpoint.Hash = recorder.ComputeHash(checkpoint)
	if err := v.add(checkpoint, "proxy"); err != nil {
		t.Fatal(err)
	}
	if v.unsignedCheckpoints[0].LaterSignedCovered {
		t.Fatal("signed checkpoint crossed a recorder epoch boundary")
	}
}

func TestStreamCompactFilesReportsCheckpointCoverageAfterGap(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1, SignCheckpoints: true}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Record(recorder.Entry{SessionID: "proxy", Type: "action_receipt", EventKind: "proxy_decision", Transport: "fetch", Summary: "signed", Detail: receiptForCompactV1(t, priv, 0, legacyreceipt.GenesisHash, "before-gap")}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Record(recorder.Entry{SessionID: "proxy", Type: "action_receipt", EventKind: "proxy_decision", Transport: "fetch", Summary: "gap", Detail: map[string]any{"redacted": true, "detected_patterns": []string{"[REDACTED:test pattern]"}, "original_size": 42}}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	location := recorder.EvidenceLocation{Root: dir, Dir: dir}
	names, err := compactStreamNames(location, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := streamCompactFiles(location, names, "proxy", pub, func(compactStreamFile, []byte, recorder.Entry) error { return nil })
	if err != nil {
		t.Fatalf("stream checkpoint-covered gap: %v", err)
	}
	if len(proof.degradations) != 1 || !proof.degradations[0].CheckpointCovered {
		t.Fatalf("degradations=%+v, want one checkpoint-covered gap", proof.degradations)
	}
}

func TestRunCompactSupportsOversizeLegacyShardAndResumeAppend(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("atomic evidence directory exchange is unsupported")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var source bytes.Buffer
	prevOuter, prevReceipt := recorder.GenesisHash, contractreceipt.GenesisHash
	for i := range 12 {
		r := compactSignedReceipt(t, priv, uint64(i), prevReceipt)
		prevReceipt, err = contractreceipt.ReceiptHash(r)
		if err != nil {
			t.Fatal(err)
		}
		e := recorder.Entry{Version: recorder.CurrentWriteEntryVersion, Sequence: uint64(i), Timestamp: time.Unix(int64(i+1), 0).UTC(), SessionID: "proxy", Type: contractreceipt.EvidenceEntryType, EventKind: "proxy_decision", Transport: "fetch", Summary: strings.Repeat("x", 700<<10), Detail: r, PrevHash: prevOuter}
		e.Hash = recorder.ComputeHash(e)
		prevOuter = e.Hash
		line, marshalErr := json.Marshal(e)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		source.Write(line)
		source.WriteByte('\n')
	}
	if source.Len() <= int(recorder.MaxEvidenceReadFileBytes) {
		t.Fatalf("fixture size = %d, want more than normal evidence shard limit %d", source.Len(), recorder.MaxEvidenceReadFileBytes)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), source.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runCompact(compactCmd(), compactOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub)}); err != nil {
		t.Fatalf("compact oversize shard: %v", err)
	}
	active, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	var compacted bytes.Buffer
	for _, shard := range active {
		info, statErr := shard.Info()
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Size() > recorder.MaxEvidenceReadFileBytes {
			t.Fatalf("compacted shard %q is %d bytes, exceeds %d", shard.Name(), info.Size(), recorder.MaxEvidenceReadFileBytes)
		}
		data, readErr := root.ReadFile(shard.Name())
		if readErr != nil {
			t.Fatal(readErr)
		}
		compacted.Write(data)
	}
	if !bytes.Equal(compacted.Bytes(), source.Bytes()) {
		t.Fatal("compaction changed bytes from oversized legacy shard")
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatalf("resume compacted recorder: %v", err)
	}
	if err := rec.Record(recorder.Entry{SessionID: "proxy", Type: "decision", EventKind: "proxy_decision", Transport: "fetch", Summary: "after compaction"}); err != nil {
		_ = rec.Close()
		t.Fatalf("append after compaction: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRunCompactSuccessfulRerunPreservesVerifiability(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("atomic evidence directory exchange is unsupported")
	}
	opts := newCompactFixture(t)
	for run := 0; run < 2; run++ {
		if err := runCompact(compactCmd(), opts); err != nil {
			t.Fatalf("successful compaction run %d: %v", run+1, err)
		}
	}
	archives, err := filepath.Glob(filepath.Join(filepath.Dir(opts.receiptDir), ".pipelock-evidence-archive-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(archives) != 2 {
		t.Fatalf("archives after successful rerun = %d, want 2", len(archives))
	}
}

func TestCompactStreamNamesRejectsDuplicateShardStarts(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"evidence-proxy-0.jsonl", "evidence-proxy-00.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := compactStreamNames(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("duplicate shard starts error = %v", err)
	}
}

func TestCompactStreamNamesFailsClosedOnUnsafeDirectoryShapes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  string
	}{
		{name: "missing directory", setup: func(t *testing.T, dir string) { _ = os.Remove(dir) }, want: "list evidence directory"},
		{name: "nested directory", setup: func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "nested"), 0o750); err != nil {
				t.Fatal(err)
			}
		}, want: "refuse nested directory"},
		{name: "escrow sidecar", setup: func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.raw.enc"), []byte("sealed"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "sidecar-preserving"},
		{name: "other session shard", setup: func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "evidence-other-0.jsonl"), []byte("line\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "refuse non-selected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			_, err := compactStreamNames(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("compactStreamNames error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestCompactStreamNamesRejectsDirectoryEntryOverflow(t *testing.T) {
	dir := t.TempDir()
	for i := range maxCompactInputShards + 1 {
		name := fmt.Sprintf("evidence-proxy-%d.jsonl", i)
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := compactStreamNames(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
	if err == nil || !strings.Contains(err.Error(), "input limit") {
		t.Fatalf("compactStreamNames error=%v", err)
	}
}

func TestCompactStreamNamesRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "evidence-proxy-0.jsonl")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := compactStreamNames(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
	if err == nil || !strings.Contains(err.Error(), "refuse symlink") {
		t.Fatalf("compactStreamNames error=%v", err)
	}
}

func TestCompactStreamWriterPreservesMappingsAndFailsClosed(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "evidence-proxy-0.jsonl")
	if err := os.WriteFile(sourcePath, []byte("source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	source := compactStreamFile{name: filepath.Base(sourcePath), path: sourcePath, info: info}

	t.Run("writes contiguous mapping and output digest", func(t *testing.T) {
		stage := t.TempDir()
		w := &compactStreamWriter{dir: stage, session: "proxy", sourceOffsets: make(map[string]int64)}
		entry := recorder.Entry{Sequence: 7}
		if err := w.add(source, []byte("one\n"), entry); err != nil {
			t.Fatal(err)
		}
		if err := w.add(source, []byte("two\n"), entry); err != nil {
			t.Fatal(err)
		}
		if err := w.close(); err != nil {
			t.Fatal(err)
		}
		if len(w.files) != 1 || len(w.mappings) != 1 || w.mappings[0].Bytes != int64(len("one\ntwo\n")) {
			t.Fatalf("files=%d mappings=%#v", len(w.files), w.mappings)
		}
		expected := []byte("one\ntwo\n")
		sum := sha256.Sum256(expected)
		if w.files[0].bytes != int64(len(expected)) || w.files[0].sum != hex.EncodeToString(sum[:]) {
			t.Fatalf("staged file metadata=%+v", w.files[0])
		}
	})

	t.Run("avoids repeated seq-zero epoch output-name collisions", func(t *testing.T) {
		stage := t.TempDir()
		w := &compactStreamWriter{dir: stage, session: "proxy", sourceOffsets: make(map[string]int64)}
		if err := w.add(source, []byte("epoch-a\n"), recorder.Entry{Sequence: 0}); err != nil {
			t.Fatal(err)
		}
		w.currentBytes = recorder.MaxEvidenceReadFileBytes
		if err := w.add(source, []byte("epoch-b\n"), recorder.Entry{Sequence: 0}); err != nil {
			t.Fatal(err)
		}
		if err := w.close(); err != nil {
			t.Fatal(err)
		}
		if len(w.files) != 2 || w.files[0].name == w.files[1].name {
			t.Fatalf("output files = %#v, want two unique names", w.files)
		}
	})

	t.Run("rejects oversized line before writing", func(t *testing.T) {
		w := &compactStreamWriter{dir: t.TempDir(), session: "proxy", sourceOffsets: make(map[string]int64)}
		if err := w.add(source, make([]byte, recorder.MaxEvidenceReadFileBytes+1), recorder.Entry{}); err == nil || !strings.Contains(err.Error(), "single JSONL line") {
			t.Fatalf("add error=%v", err)
		}
	})

	t.Run("refuses an unavailable stage before reading source", func(t *testing.T) {
		w := &compactStreamWriter{dir: filepath.Join(t.TempDir(), "missing"), session: "proxy", sourceOffsets: make(map[string]int64)}
		if err := w.add(source, []byte("line\n"), recorder.Entry{}); err == nil {
			t.Fatal("add accepted missing stage")
		}
	})

	t.Run("refuses mixed source modes without rotation", func(t *testing.T) {
		other := filepath.Join(t.TempDir(), "evidence-proxy-1.jsonl")
		if err := os.WriteFile(other, []byte("other\n"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(other, 0o400); err != nil {
			t.Fatal(err)
		}
		otherInfo, err := os.Stat(other)
		if err != nil {
			t.Fatal(err)
		}
		w := &compactStreamWriter{dir: t.TempDir(), session: "proxy", sourceOffsets: make(map[string]int64)}
		if err := w.add(source, []byte("first\n"), recorder.Entry{}); err != nil {
			t.Fatal(err)
		}
		if err := w.add(compactStreamFile{name: filepath.Base(other), path: other, info: otherInfo}, []byte("line\n"), recorder.Entry{}); err == nil || !strings.Contains(err.Error(), "mode differs") {
			t.Fatalf("add error=%v", err)
		}
	})

	t.Run("rejects output shard overflow during rotation", func(t *testing.T) {
		stage := t.TempDir()
		f, err := os.CreateTemp(stage, "evidence-proxy-")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("full\n"); err != nil {
			t.Fatal(err)
		}
		files := make([]compactStreamFile, recorder.MaxEvidenceReadDirectoryEntries-1)
		for i := range files {
			files[i].info = info
		}
		w := &compactStreamWriter{
			dir: stage, session: "proxy", current: f, currentName: filepath.Base(f.Name()),
			currentBytes: recorder.MaxEvidenceReadFileBytes, currentSource: source,
			files: files, sourceOffsets: make(map[string]int64),
		}
		err = w.add(source, []byte("next\n"), recorder.Entry{Sequence: 1})
		want := fmt.Sprintf("compaction produced %d shards, exceeds %d", recorder.MaxEvidenceReadDirectoryEntries+1, recorder.MaxEvidenceReadDirectoryEntries)
		if err == nil || err.Error() != want {
			t.Fatalf("rotation overflow error=%v, want %q", err, want)
		}
	})

	t.Run("does not publish when source metadata disappears", func(t *testing.T) {
		stage := t.TempDir()
		f, err := os.CreateTemp(stage, "evidence-proxy-0")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("line\n"); err != nil {
			t.Fatal(err)
		}
		w := &compactStreamWriter{dir: stage, current: f, currentName: filepath.Base(f.Name()), currentSource: compactStreamFile{path: filepath.Join(t.TempDir(), "gone"), info: info}}
		if err := w.close(); err == nil {
			t.Fatal("close accepted missing source metadata")
		}
	})

	t.Run("reports sync failure from a closed output", func(t *testing.T) {
		stage := t.TempDir()
		f, err := os.CreateTemp(stage, "evidence-proxy-0")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		w := &compactStreamWriter{dir: stage, current: f, currentName: filepath.Base(f.Name()), currentSource: source}
		if err := w.close(); err == nil {
			t.Fatal("close accepted already-closed output")
		}
	})

	t.Run("does not rotate after finalizing current shard fails", func(t *testing.T) {
		restoreCompactStreamFileHooks(t)
		stage := t.TempDir()
		f, err := os.CreateTemp(stage, "evidence-proxy-0")
		if err != nil {
			t.Fatal(err)
		}
		compactStreamSync = func(*os.File) error { return errors.New("rotate sync") }
		w := &compactStreamWriter{dir: stage, session: "proxy", current: f, currentName: filepath.Base(f.Name()), currentBytes: recorder.MaxEvidenceReadFileBytes, currentSource: source, sourceOffsets: make(map[string]int64)}
		if err := w.add(source, []byte("next\n"), recorder.Entry{Sequence: 1}); err == nil || !strings.Contains(err.Error(), "rotate sync") {
			t.Fatalf("rotate error=%v", err)
		}
	})

	t.Run("rejects staging filename sequence overflow", func(t *testing.T) {
		w := &compactStreamWriter{dir: t.TempDir(), session: "proxy", lastStart: ^uint64(0), hasLastStart: true, sourceOffsets: make(map[string]int64)}
		if err := w.add(source, []byte("line\n"), recorder.Entry{Sequence: 0}); err == nil || !strings.Contains(err.Error(), "sequence overflows") {
			t.Fatalf("overflow error = %v", err)
		}
	})

	for _, tc := range []struct {
		name   string
		inject func()
		call   func(*compactStreamWriter) error
	}{
		{name: "write", inject: func() {
			compactStreamWrite = func(*os.File, []byte) (int, error) { return 0, errors.New("injected write") }
		}, call: func(w *compactStreamWriter) error { return w.add(source, []byte("line\n"), recorder.Entry{}) }},
		{name: "sync", inject: func() { compactStreamSync = func(*os.File) error { return errors.New("injected sync") } }, call: func(w *compactStreamWriter) error {
			if err := w.add(source, []byte("line\n"), recorder.Entry{}); err != nil {
				return err
			}
			return w.close()
		}},
		{name: "close", inject: func() { compactStreamClose = func(*os.File) error { return errors.New("injected close") } }, call: func(w *compactStreamWriter) error {
			if err := w.add(source, []byte("line\n"), recorder.Entry{}); err != nil {
				return err
			}
			return w.close()
		}},
		{name: "read", inject: func() { compactStreamRead = func(string) ([]byte, error) { return nil, errors.New("injected read") } }, call: func(w *compactStreamWriter) error {
			if err := w.add(source, []byte("line\n"), recorder.Entry{}); err != nil {
				return err
			}
			return w.close()
		}},
	} {
		t.Run("propagates "+tc.name+" failure", func(t *testing.T) {
			restoreCompactStreamFileHooks(t)
			tc.inject()
			w := &compactStreamWriter{dir: t.TempDir(), session: "proxy", sourceOffsets: make(map[string]int64)}
			if err := tc.call(w); err == nil || !strings.Contains(err.Error(), "injected "+tc.name) {
				t.Fatalf("error=%v", err)
			}
		})
	}

	t.Run("rejects short write", func(t *testing.T) {
		restoreCompactStreamFileHooks(t)
		compactStreamWrite = func(*os.File, []byte) (int, error) { return 1, nil }
		w := &compactStreamWriter{dir: t.TempDir(), session: "proxy", sourceOffsets: make(map[string]int64)}
		if err := w.add(source, []byte("line\n"), recorder.Entry{}); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("error=%v, want io.ErrShortWrite", err)
		}
	})
}

func restoreCompactStreamFileHooks(t *testing.T) {
	t.Helper()
	compactStreamSync = func(f *os.File) error { return f.Sync() }
	compactStreamClose = func(f *os.File) error { return f.Close() }
	compactStreamWrite = func(f *os.File, line []byte) (int, error) { return f.Write(line) }
	compactStreamRead = os.ReadFile
	t.Cleanup(func() {
		compactStreamSync = func(f *os.File) error { return f.Sync() }
		compactStreamClose = func(f *os.File) error { return f.Close() }
		compactStreamWrite = func(f *os.File, line []byte) (int, error) { return f.Write(line) }
		compactStreamRead = os.ReadFile
	})
}

func TestCompactStreamHelpersCompareWholeProofs(t *testing.T) {
	base := compactStreamProof{bytes: 1, sum: "sum", v1Count: 2, v1Head: "v1", v2Count: 3, v2Head: "v2"}
	if !sameCompactProof(base, base) {
		t.Fatal("same proof did not compare equal")
	}
	for _, changed := range []compactStreamProof{{bytes: 2}, {sum: "other"}, {v1Count: 4}, {v1Head: "other"}, {v1Degraded: true}, {v1FirstGap: true}, {v1TailGap: true}, {degradations: []compactReceiptDegradation{{RecorderSeq: 9}}}, {v1Suffixes: []compactReceiptSuffix{{OriginSeq: 9}}}, {v2Count: 4}, {v2Head: "other"}, {unsignedCheckpoints: []compactUnsignedCheckpoint{{RecorderSeq: 9}}}} {
		candidate := base
		if changed.bytes != 0 {
			candidate.bytes = changed.bytes
		}
		if changed.sum != "" {
			candidate.sum = changed.sum
		}
		if changed.v1Count != 0 {
			candidate.v1Count = changed.v1Count
		}
		if changed.v1Head != "" {
			candidate.v1Head = changed.v1Head
		}
		if changed.v1Degraded {
			candidate.v1Degraded = true
		}
		if changed.v1FirstGap {
			candidate.v1FirstGap = true
		}
		if changed.v1TailGap {
			candidate.v1TailGap = true
		}
		if changed.degradations != nil {
			candidate.degradations = changed.degradations
		}
		if changed.v1Suffixes != nil {
			candidate.v1Suffixes = changed.v1Suffixes
		}
		if changed.v2Count != 0 {
			candidate.v2Count = changed.v2Count
		}
		if changed.v2Head != "" {
			candidate.v2Head = changed.v2Head
		}
		if changed.unsignedCheckpoints != nil {
			candidate.unsignedCheckpoints = changed.unsignedCheckpoints
		}
		if sameCompactProof(base, candidate) {
			t.Fatalf("different proof compared equal: %#v", candidate)
		}
	}
	withDetails := base
	withDetails.degradations = []compactReceiptDegradation{{RecorderSeq: 1}}
	withDetails.v1Suffixes = []compactReceiptSuffix{{OriginSeq: 2}}
	withDetails.unsignedCheckpoints = []compactUnsignedCheckpoint{{RecorderSeq: 3, CoveredByRecorderSeq: 4}}
	differentDegradation := withDetails
	differentDegradation.degradations = []compactReceiptDegradation{{RecorderSeq: 9}}
	if sameCompactProof(withDetails, differentDegradation) {
		t.Fatal("different degradation content compared equal")
	}
	differentSuffix := withDetails
	differentSuffix.v1Suffixes = []compactReceiptSuffix{{OriginSeq: 7}}
	if sameCompactProof(withDetails, differentSuffix) {
		t.Fatal("different suffix content compared equal")
	}
	differentCheckpoint := withDetails
	differentCheckpoint.unsignedCheckpoints = []compactUnsignedCheckpoint{{RecorderSeq: 3, CoveredByRecorderSeq: 5}}
	if sameCompactProof(withDetails, differentCheckpoint) {
		t.Fatal("different unsigned checkpoint content compared equal")
	}
	epochProof := base
	epochProof.v1Epochs = []compactEpochProof{{Epoch: 0, Version: 1, StartHash: "start", EndHash: "end", V1Count: 1, Degradations: []compactReceiptDegradation{{RecorderSeq: 4}}, V1Suffixes: []compactReceiptSuffix{{OriginSeq: 5}}}}
	cloneEpochProof := func() compactStreamProof {
		clone := epochProof
		clone.v1Epochs = append([]compactEpochProof(nil), epochProof.v1Epochs...)
		return clone
	}
	mutations := []struct {
		name   string
		mutate func(*compactStreamProof)
	}{
		{name: "epoch", mutate: func(p *compactStreamProof) { p.v1Epochs[0].Epoch++ }},
		{name: "version", mutate: func(p *compactStreamProof) { p.v1Epochs[0].Version++ }},
		{name: "start sequence", mutate: func(p *compactStreamProof) { p.v1Epochs[0].StartSeq++ }},
		{name: "end sequence", mutate: func(p *compactStreamProof) { p.v1Epochs[0].EndSeq++ }},
		{name: "entry count", mutate: func(p *compactStreamProof) { p.v1Epochs[0].EntryCount++ }},
		{name: "start hash", mutate: func(p *compactStreamProof) { p.v1Epochs[0].StartHash = "other" }},
		{name: "end hash", mutate: func(p *compactStreamProof) { p.v1Epochs[0].EndHash = "other" }},
		{name: "v1 count", mutate: func(p *compactStreamProof) { p.v1Epochs[0].V1Count++ }},
		{name: "v1 head", mutate: func(p *compactStreamProof) { p.v1Epochs[0].V1Head = "other" }},
		{name: "v1 degraded", mutate: func(p *compactStreamProof) { p.v1Epochs[0].V1Degraded = true }},
		{name: "v1 first gap", mutate: func(p *compactStreamProof) { p.v1Epochs[0].V1FirstGap = true }},
		{name: "v1 tail gap", mutate: func(p *compactStreamProof) { p.v1Epochs[0].V1TailGap = true }},
		{name: "no degradations", mutate: func(p *compactStreamProof) { p.v1Epochs[0].Degradations = nil }},
		{name: "different degradation", mutate: func(p *compactStreamProof) {
			p.v1Epochs[0].Degradations = []compactReceiptDegradation{{RecorderSeq: 8}}
		}},
		{name: "no v1 suffixes", mutate: func(p *compactStreamProof) { p.v1Epochs[0].V1Suffixes = nil }},
		{name: "different v1 suffix", mutate: func(p *compactStreamProof) { p.v1Epochs[0].V1Suffixes = []compactReceiptSuffix{{OriginSeq: 9}} }},
		{name: "additional epoch", mutate: func(p *compactStreamProof) { p.v1Epochs = append(p.v1Epochs, compactEpochProof{Epoch: 1}) }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := cloneEpochProof()
			mutation.mutate(&candidate)
			if sameCompactProof(epochProof, candidate) {
				t.Fatalf("different epoch proof compared equal: %+v", candidate.v1Epochs)
			}
		})
	}
	if sameCompactNameSet([]string{"a"}, []string{"a", "b"}) || sameCompactNameSet([]string{"a"}, []string{"b"}) || !sameCompactNameSet([]string{"a", "b"}, []string{"a", "b"}) {
		t.Fatal("unexpected compact name-set comparison")
	}
}

func TestNewCompactV1EpochStateRejectsMalformedKey(t *testing.T) {
	if _, err := newCompactV1EpochState(""); err == nil || !strings.Contains(err.Error(), "initialize v1 receipt verifier") {
		t.Fatalf("malformed key error = %v", err)
	}
	if _, err := streamCompactFiles(recorder.EvidenceLocation{}, nil, "proxy", nil, func(compactStreamFile, []byte, recorder.Entry) error { return nil }); err == nil || !strings.Contains(err.Error(), "initialize v1 receipt verifier") {
		t.Fatalf("stream malformed key error = %v", err)
	}
}

func TestAdvanceCompactSuffixOriginRejectsOverflow(t *testing.T) {
	if got, err := advanceCompactSuffixOrigin(41, 2); err != nil || got != 43 {
		t.Fatalf("advance suffix origin = %d, %v; want 43", got, err)
	}
	for _, tc := range []struct {
		name    string
		current uint64
		delta   uint64
	}{
		{name: "max plus one", current: ^uint64(0), delta: 1},
		{name: "max minus one plus two", current: ^uint64(0) - 1, delta: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := advanceCompactSuffixOrigin(tc.current, tc.delta); err == nil || !strings.Contains(err.Error(), "overflows") {
				t.Fatalf("advance suffix origin (%d, %d) error = %v", tc.current, tc.delta, err)
			}
		})
	}
}

func TestStreamCompactToStageClosesOnFailureAndPublishesOnSuccess(t *testing.T) {
	opts := newCompactFixture(t)
	pub, err := hex.DecodeString(opts.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	location := recorder.EvidenceLocation{Root: opts.receiptDir, Dir: opts.receiptDir}
	stage := t.TempDir()
	w, proof, err := streamCompactToStage(location, []string{"evidence-proxy-0.jsonl"}, "proxy", ed25519.PublicKey(pub), stage)
	if err != nil || len(w.files) != 1 || proof.v2Count != 1 {
		t.Fatalf("success writer=%#v proof=%#v err=%v", w, proof, err)
	}
	if _, _, err := streamCompactToStage(location, []string{"missing.jsonl"}, "proxy", ed25519.PublicKey(pub), t.TempDir()); err == nil {
		t.Fatal("streamCompactToStage accepted missing source")
	}
	restoreCompactStreamFileHooks(t)
	compactStreamSync = func(*os.File) error { return errors.New("final sync failure") }
	if _, _, err := streamCompactToStage(location, []string{"evidence-proxy-0.jsonl"}, "proxy", ed25519.PublicKey(pub), t.TempDir()); err == nil || !strings.Contains(err.Error(), "final sync") {
		t.Fatalf("stream close error=%v", err)
	}
}

func TestStreamCompactFilesRejectsMalformedAndIncompleteEvidence(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	write := func(t *testing.T, data []byte) recorder.EvidenceLocation {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		return recorder.EvidenceLocation{Root: dir, Dir: dir}
	}
	run := func(location recorder.EvidenceLocation, consume func(compactStreamFile, []byte, recorder.Entry) error) error {
		_, err := streamCompactFiles(location, []string{"evidence-proxy-0.jsonl"}, "proxy", pub, consume)
		return err
	}
	t.Run("parse failure", func(t *testing.T) {
		if err := run(write(t, []byte("not-json\n")), func(compactStreamFile, []byte, recorder.Entry) error { return nil }); err == nil || !strings.Contains(err.Error(), "parse evidence") {
			t.Fatalf("stream error=%v", err)
		}
	})
	t.Run("oversized line", func(t *testing.T) {
		if err := run(write(t, append(make([]byte, recorder.MaxEntryLineBytes+2), '\n')), func(compactStreamFile, []byte, recorder.Entry) error { return nil }); err == nil || !strings.Contains(err.Error(), "read evidence") {
			t.Fatalf("stream error=%v", err)
		}
	})
	t.Run("empty shard", func(t *testing.T) {
		if err := run(write(t, nil), func(compactStreamFile, []byte, recorder.Entry) error { return nil }); err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Fatalf("stream error=%v", err)
		}
	})
	t.Run("missing trailing newline", func(t *testing.T) {
		line := compactTestLine(t, 0)
		if err := run(write(t, bytes.TrimSuffix(line, []byte("\n"))), func(compactStreamFile, []byte, recorder.Entry) error { return nil }); err == nil || !strings.Contains(err.Error(), "does not end in newline") {
			t.Fatalf("stream error=%v", err)
		}
	})
	t.Run("no signed receipt", func(t *testing.T) {
		if err := run(write(t, compactTestLine(t, 0)), func(compactStreamFile, []byte, recorder.Entry) error { return nil }); err == nil || !strings.Contains(err.Error(), "no signed evidence receipts") {
			t.Fatalf("stream error=%v", err)
		}
	})
	t.Run("consumer failure", func(t *testing.T) {
		opts := newCompactFixture(t)
		location := recorder.EvidenceLocation{Root: opts.receiptDir, Dir: opts.receiptDir}
		fixtureKey, decodeErr := hex.DecodeString(opts.publicKey)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		_, err := streamCompactFiles(location, []string{"evidence-proxy-0.jsonl"}, "proxy", fixtureKey, func(compactStreamFile, []byte, recorder.Entry) error { return errors.New("consumer refused") })
		if err == nil || !strings.Contains(err.Error(), "consumer refused") {
			t.Fatalf("stream error=%v", err)
		}
	})
}

func TestCompactOuterVerifierRejectsForeignSession(t *testing.T) {
	v := compactOuterVerifier{}
	err := v.add(recorder.Entry{Sequence: 0, SessionID: "other"}, "proxy")
	if err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Fatalf("outer verifier error=%v", err)
	}
}

func TestCompactOuterVerifierEnforcesChainNamespaceAndOrder(t *testing.T) {
	entry := func(version int, seq uint64, prev string) recorder.Entry {
		e := recorder.Entry{Version: version, Sequence: seq, Timestamp: time.Unix(1, 0).UTC(), SessionID: "proxy", Type: "decision", EventKind: "proxy_decision", Transport: "fetch", Summary: "test", Detail: map[string]string{"test": "value"}, PrevHash: prev}
		if version == 3 {
			e.ChainKind = recorder.ChainKindRecorder
			e.WriterInstanceID = "writer-a"
		}
		e.Hash = recorder.ComputeHash(e)
		return e
	}
	t.Run("accepts a contiguous legacy chain", func(t *testing.T) {
		v := compactOuterVerifier{}
		first := entry(2, 0, recorder.GenesisHash)
		if err := v.add(first, "proxy"); err != nil {
			t.Fatal(err)
		}
		if err := v.add(entry(2, 1, first.Hash), "proxy"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("rejects namespace transitions", func(t *testing.T) {
		legacy := entry(2, 0, recorder.GenesisHash)
		v := compactOuterVerifier{}
		if err := v.add(legacy, "proxy"); err != nil {
			t.Fatal(err)
		}
		if err := v.add(entry(3, 1, legacy.Hash), "proxy"); err == nil || !strings.Contains(err.Error(), "v3 chain") {
			t.Fatalf("legacy to v3=%v", err)
		}
		v = compactOuterVerifier{}
		v3 := entry(3, 0, recorder.GenesisHash)
		if err := v.add(v3, "proxy"); err != nil {
			t.Fatal(err)
		}
		if err := v.add(entry(2, 1, v3.Hash), "proxy"); err == nil || !strings.Contains(err.Error(), "legacy entry") {
			t.Fatalf("v3 to legacy=%v", err)
		}
	})
	t.Run("rejects namespace, hash, and sequence disagreement", func(t *testing.T) {
		v := compactOuterVerifier{}
		first := entry(3, 0, recorder.GenesisHash)
		if err := v.add(first, "proxy"); err != nil {
			t.Fatal(err)
		}
		other := entry(3, 1, first.Hash)
		other.WriterInstanceID = "writer-b"
		other.Hash = recorder.ComputeHash(other)
		if err := v.add(other, "proxy"); err == nil || !strings.Contains(err.Error(), "namespace changed") {
			t.Fatalf("namespace=%v", err)
		}
		badHash := entry(2, 0, recorder.GenesisHash)
		badHash.Hash = "not-a-hash"
		if err := (&compactOuterVerifier{}).add(badHash, "proxy"); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
			t.Fatalf("hash=%v", err)
		}
		badGenesis := entry(2, 1, recorder.GenesisHash)
		if err := (&compactOuterVerifier{}).add(badGenesis, "proxy"); err == nil || !strings.Contains(err.Error(), "invalid recorder genesis") {
			t.Fatalf("genesis=%v", err)
		}
		v = compactOuterVerifier{}
		plain := entry(2, 0, recorder.GenesisHash)
		if err := v.add(plain, "proxy"); err != nil {
			t.Fatal(err)
		}
		if err := v.add(entry(2, 2, plain.Hash), "proxy"); err == nil || !strings.Contains(err.Error(), "sequence or hash chain") {
			t.Fatalf("sequence=%v", err)
		}
	})
	t.Run("rejects schema-invalid entry before trusting its hash", func(t *testing.T) {
		invalid := entry(3, 0, recorder.GenesisHash)
		invalid.WriterInstanceID = ""
		invalid.Hash = recorder.ComputeHash(invalid)
		if err := (&compactOuterVerifier{}).add(invalid, "proxy"); err == nil || !strings.Contains(err.Error(), "writer_instance_id") {
			t.Fatalf("schema error=%v", err)
		}
	})
}

func TestStreamCompactFilesRejectsUnknownRecorderType(t *testing.T) {
	opts := newCompactFixture(t)
	path := filepath.Join(opts.receiptDir, "evidence-proxy-0.jsonl")
	entries, err := recorder.ReadEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	unknown := recorder.Entry{Version: recorder.CurrentWriteEntryVersion, Sequence: 1, Timestamp: time.Unix(2, 0).UTC(), SessionID: "proxy", Type: "unrecognized_proof", EventKind: "proxy_decision", Transport: "fetch", Summary: "must not be skipped", Detail: map[string]string{"reason": "test"}, PrevHash: entries[0].Hash}
	unknown.Hash = recorder.ComputeHash(unknown)
	line, err := json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- test-created evidence shard.
	if f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0); err != nil {
		t.Fatal(err)
	} else {
		if _, err := f.Write(append(line, '\n')); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	pub, err := hex.DecodeString(opts.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	location := recorder.EvidenceLocation{Root: opts.receiptDir, Dir: opts.receiptDir}
	names, err := compactStreamNames(location, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := streamCompactFiles(location, names, "proxy", ed25519.PublicKey(pub), func(compactStreamFile, []byte, recorder.Entry) error { return nil }); err == nil || !strings.Contains(err.Error(), "unknown recorder entry type") {
		t.Fatalf("unknown recorder type error = %v", err)
	}
}

func TestStreamCompactFilesAcceptsMixedV1AndV2ReceiptFamilies(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v1 := receiptForCompactMixedV1(t, priv)
	v2 := compactSignedReceipt(t, priv, 0, contractreceipt.GenesisHash)
	outerPrev := recorder.GenesisHash
	var data bytes.Buffer
	for i, item := range []struct {
		typ    string
		detail any
	}{{"action_receipt", v1}, {contractreceipt.EvidenceEntryType, v2}} {
		e := recorder.Entry{Version: recorder.CurrentWriteEntryVersion, Sequence: uint64(i), Timestamp: time.Unix(int64(i+1), 0).UTC(), SessionID: "proxy", Type: item.typ, EventKind: "proxy_decision", Transport: "fetch", Summary: item.typ, Detail: item.detail, PrevHash: outerPrev}
		e.Hash = recorder.ComputeHash(e)
		outerPrev = e.Hash
		line, marshalErr := json.Marshal(e)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		data.Write(line)
		data.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	location := recorder.EvidenceLocation{Root: dir, Dir: dir}
	if _, err := streamCompactFiles(location, []string{"evidence-proxy-0.jsonl"}, "proxy", pub, func(compactStreamFile, []byte, recorder.Entry) error { return nil }); err != nil {
		t.Fatalf("mixed v1/v2 receipt compaction stream: %v", err)
	}
}

func TestCompactLegacyReceiptTombstoneClassifierFailsClosed(t *testing.T) {
	valid := `{"redacted":true,"detected_patterns":["[REDACTED:AWS access key pattern]"],"original_size":1234}`
	if size, ok := decodeCompactLegacyReceiptTombstone([]byte(valid)); !ok || size != 1234 {
		t.Fatalf("valid historical tombstone = size %d ok %t", size, ok)
	}
	validConfiguredName := `{"redacted":true,"detected_patterns":["[REDACTED:Vendor token [prod]]"],"original_size":2097152}`
	if size, ok := decodeCompactLegacyReceiptTombstone([]byte(validConfiguredName)); !ok || size != 2097152 {
		t.Fatalf("valid configured-name tombstone = size %d ok %t", size, ok)
	}
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "extra field", raw: `{"redacted":true,"detected_patterns":["[REDACTED:x]"],"original_size":1,"extra":true}`},
		{name: "missing field", raw: `{"redacted":true,"original_size":1}`},
		{name: "false", raw: `{"redacted":false,"detected_patterns":["[REDACTED:x]"],"original_size":1}`},
		{name: "empty patterns", raw: `{"redacted":true,"detected_patterns":[],"original_size":1}`},
		{name: "bad marker", raw: `{"redacted":true,"detected_patterns":["secret"],"original_size":1}`},
		{name: "fractional size", raw: `{"redacted":true,"detected_patterns":["[REDACTED:x]"],"original_size":1.5}`},
		{name: "zero size", raw: `{"redacted":true,"detected_patterns":["[REDACTED:x]"],"original_size":0}`},
		{name: "negative size", raw: `{"redacted":true,"detected_patterns":["[REDACTED:x]"],"original_size":-1}`},
		{name: "duplicate key", raw: `{"redacted":true,"redacted":true,"detected_patterns":["[REDACTED:x]"],"original_size":1}`},
		{name: "marshal error tombstone", raw: `{"redacted":true,"reason":"marshal error"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := decodeCompactLegacyReceiptTombstone([]byte(tc.raw)); ok {
				t.Fatal("malformed tombstone accepted")
			}
		})
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := json.Marshal(receiptForCompactV1(t, priv, 0, legacyreceipt.GenesisHash, "not-a-tombstone"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decodeCompactLegacyReceiptTombstone(signed); ok {
		t.Fatal("complete signed v1 receipt was classified as a tombstone")
	}
}

func TestStreamCompactFilesPreservesKnownReceiptDegradation(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first := receiptForCompactV1(t, priv, 0, legacyreceipt.GenesisHash, "first")
	firstHash, err := legacyreceipt.ReceiptHash(first)
	if err != nil {
		t.Fatal(err)
	}
	afterGap := receiptForCompactV1(t, priv, 2, firstHash, "after-gap")
	afterGapHash, err := legacyreceipt.ReceiptHash(afterGap)
	if err != nil {
		t.Fatal(err)
	}
	suffixTail := receiptForCompactV1(t, priv, 3, afterGapHash, "suffix-tail")
	tombstone := map[string]any{"redacted": true, "detected_patterns": []string{"[REDACTED:AWS access key pattern]"}, "original_size": 777}
	path := filepath.Join(dir, "evidence-proxy-0.jsonl")
	writeChain := func(receipts ...legacyreceipt.Receipt) {
		t.Helper()
		outerPrev := recorder.GenesisHash
		var data bytes.Buffer
		details := []any{first, tombstone}
		for _, receipt := range receipts {
			details = append(details, receipt)
		}
		for i, detail := range details {
			e := recorder.Entry{Version: recorder.CurrentWriteEntryVersion, Sequence: uint64(i), Timestamp: time.Unix(int64(i+1), 0).UTC(), SessionID: "proxy", Type: "action_receipt", EventKind: "proxy_decision", Transport: "fetch", Summary: "legacy", Detail: detail, PrevHash: outerPrev}
			e.Hash = recorder.ComputeHash(e)
			outerPrev = e.Hash
			line, marshalErr := json.Marshal(e)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			data.Write(line)
			data.WriteByte('\n')
		}
		if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeChain(afterGap, suffixTail)
	location := recorder.EvidenceLocation{Root: dir, Dir: dir}
	proof, err := streamCompactFiles(location, []string{"evidence-proxy-0.jsonl"}, "proxy", pub, func(compactStreamFile, []byte, recorder.Entry) error { return nil })
	if err != nil {
		t.Fatalf("stream degraded legacy receipts: %v", err)
	}
	if !proof.v1Degraded || proof.v1Count != 3 || proof.v1Head != "" || len(proof.degradations) != 1 || len(proof.v1Suffixes) != 2 || proof.v1Suffixes[0].Count != 1 || proof.v1Suffixes[0].OriginSeq != 0 || proof.v1Suffixes[0].OriginPrevHash != legacyreceipt.GenesisHash || proof.v1Suffixes[1].Count != 2 || proof.v1Suffixes[1].Head == "" {
		t.Fatalf("degraded proof = %+v", proof)
	}
	want := compactReceiptDegradation{File: "evidence-proxy-0.jsonl", RecorderSeq: 1, OriginalSize: 777, Reason: compactLegacyRedactionReason}
	if proof.degradations[0] != want {
		t.Fatalf("degradation = %+v, want %+v", proof.degradations[0], want)
	}
	if proof.degradations[0].CheckpointCovered {
		t.Fatal("gap without a later checkpoint reported checkpoint coverage")
	}
	manifest := manifestReceiptVerification(proof)
	if manifest.Status != "degraded" || manifest.V1ChainHead != "" || len(manifest.Degradations) != 1 || len(manifest.V1Suffixes) != 2 {
		t.Fatalf("manifest receipt proof = %+v", manifest)
	}

	brokenTail := receiptForCompactV1(t, priv, 3, "unrelated-signed-head", "broken-suffix-tail")
	writeChain(afterGap, brokenTail)
	if _, err := streamCompactFiles(location, []string{"evidence-proxy-0.jsonl"}, "proxy", pub, func(compactStreamFile, []byte, recorder.Entry) error { return nil }); err == nil || !strings.Contains(err.Error(), "chain_prev_hash mismatch") {
		t.Fatalf("broken linked suffix error = %v", err)
	}

	afterGap.ActionRecord.Target = "https://api.vendor.example/tampered"
	writeChain(afterGap)
	if _, err := streamCompactFiles(location, []string{"evidence-proxy-0.jsonl"}, "proxy", pub, func(compactStreamFile, []byte, recorder.Entry) error { return nil }); err == nil || !strings.Contains(err.Error(), "after degraded chain") {
		t.Fatalf("tampered receipt after tombstone error = %v", err)
	}
}

func TestStreamCompactFilesHandlesLeadingConsecutiveAndMultipleGaps(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tombstone := map[string]any{"redacted": true, "detected_patterns": []string{"[REDACTED:test pattern]"}, "original_size": 42}
	makeReceipt := func(seq uint64, prev, id string) legacyreceipt.Receipt {
		return receiptForCompactV1(t, priv, seq, prev, id)
	}
	for _, tc := range []struct {
		name          string
		details       []any
		wantGaps      int
		wantSuffixes  int
		wantSuffixSeq []uint64
	}{
		{name: "leading gap", details: []any{tombstone, makeReceipt(1, "unknown-gap-head", "leading-origin")}, wantGaps: 1, wantSuffixes: 1, wantSuffixSeq: []uint64{1}},
		{name: "consecutive gaps", details: []any{makeReceipt(0, legacyreceipt.GenesisHash, "prefix"), tombstone, tombstone, makeReceipt(3, "unknown-two-gap-head", "consecutive-origin")}, wantGaps: 2, wantSuffixes: 2, wantSuffixSeq: []uint64{0, 3}},
		{name: "separated gaps", details: []any{makeReceipt(0, legacyreceipt.GenesisHash, "prefix"), tombstone, makeReceipt(2, "unknown-first-gap-head", "first-origin"), tombstone, makeReceipt(4, "unknown-second-gap-head", "second-origin")}, wantGaps: 2, wantSuffixes: 3, wantSuffixSeq: []uint64{0, 2, 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			outerPrev := recorder.GenesisHash
			var data bytes.Buffer
			for i, detail := range tc.details {
				entry := recorder.Entry{Version: recorder.CurrentWriteEntryVersion, Sequence: uint64(i), Timestamp: time.Unix(int64(i+1), 0).UTC(), SessionID: "proxy", Type: "action_receipt", EventKind: "proxy_decision", Transport: "fetch", Summary: "legacy", Detail: detail, PrevHash: outerPrev}
				entry.Hash = recorder.ComputeHash(entry)
				outerPrev = entry.Hash
				line, marshalErr := json.Marshal(entry)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				data.Write(line)
				data.WriteByte('\n')
			}
			if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), data.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			proof, err := streamCompactFiles(recorder.EvidenceLocation{Root: dir, Dir: dir}, []string{"evidence-proxy-0.jsonl"}, "proxy", pub, func(compactStreamFile, []byte, recorder.Entry) error { return nil })
			if err != nil {
				t.Fatalf("stream gaps: %v", err)
			}
			if len(proof.degradations) != tc.wantGaps || len(proof.v1Suffixes) != tc.wantSuffixes {
				t.Fatalf("proof gaps=%d suffixes=%d, want %d/%d", len(proof.degradations), len(proof.v1Suffixes), tc.wantGaps, tc.wantSuffixes)
			}
			for i, want := range tc.wantSuffixSeq {
				if proof.v1Suffixes[i].OriginSeq != want {
					t.Fatalf("suffix %d origin=%d, want %d", i, proof.v1Suffixes[i].OriginSeq, want)
				}
			}
		})
	}
}

func TestRunCompactPublishesDegradedReceiptProof(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("atomic evidence directory exchange is unsupported")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v1 := receiptForCompactV1(t, priv, 0, legacyreceipt.GenesisHash, "before-redaction")
	tombstone := map[string]any{"redacted": true, "detected_patterns": []string{"[REDACTED:AWS access key pattern]"}, "original_size": 777}
	v1AfterGap := receiptForCompactV1(t, priv, 2, "unknown-destroyed-receipt-head", "after-redaction")
	v2 := compactSignedReceipt(t, priv, 0, contractreceipt.GenesisHash)

	outerPrev := recorder.GenesisHash
	var source bytes.Buffer
	for i, item := range []struct {
		typ    string
		detail any
	}{{"action_receipt", v1}, {"action_receipt", tombstone}, {"action_receipt", v1AfterGap}, {contractreceipt.EvidenceEntryType, v2}} {
		e := recorder.Entry{Version: recorder.CurrentWriteEntryVersion, Sequence: uint64(i), Timestamp: time.Unix(int64(i+1), 0).UTC(), SessionID: "proxy", Type: item.typ, EventKind: "proxy_decision", Transport: "fetch", Summary: item.typ, Detail: item.detail, PrevHash: outerPrev}
		e.Hash = recorder.ComputeHash(e)
		outerPrev = e.Hash
		line, marshalErr := json.Marshal(e)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		source.Write(line)
		source.WriteByte('\n')
	}
	split := bytes.IndexByte(source.Bytes(), '\n') + 1
	if split <= 0 {
		t.Fatal("source has no first JSONL record")
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), source.Bytes()[:split], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-1.jsonl"), source.Bytes()[split:], 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := compactCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--receipt-dir", dir, "--session", "proxy", "--key", hex.EncodeToString(pub)})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--allow-degraded-receipts") {
		t.Fatalf("compact without degraded acknowledgement error = %v", err)
	}
	if first, readErr := os.ReadFile(filepath.Clean(filepath.Join(dir, "evidence-proxy-0.jsonl"))); readErr != nil || !bytes.Equal(first, source.Bytes()[:split]) {
		t.Fatalf("refused compaction changed first source shard: err=%v", readErr)
	}
	if second, readErr := os.ReadFile(filepath.Clean(filepath.Join(dir, "evidence-proxy-1.jsonl"))); readErr != nil || !bytes.Equal(second, source.Bytes()[split:]) {
		t.Fatalf("refused compaction changed second source shard: err=%v", readErr)
	}
	cmd = compactCmd()
	var wrongCountOut bytes.Buffer
	cmd.SetOut(&wrongCountOut)
	cmd.SetArgs([]string{"--receipt-dir", dir, "--session", "proxy", "--key", hex.EncodeToString(pub), "--allow-degraded-receipts=2"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "DEGRADED by 1") {
		t.Fatalf("compact with wrong degraded count error = %v", err)
	}

	cmd = compactCmd()
	out.Reset()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--receipt-dir", dir, "--session", "proxy", "--key", hex.EncodeToString(pub), "--allow-degraded-receipts=1"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("compact degraded legacy receipts: %v", err)
	}
	if !strings.Contains(out.String(), "receipt proof: DEGRADED") {
		t.Fatalf("command output = %q", out.String())
	}
	archives, err := filepath.Glob(filepath.Join(parent, ".pipelock-evidence-archive-*"))
	if err != nil || len(archives) != 1 {
		t.Fatalf("archives = %v, err = %v", archives, err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(archives[0], "compaction-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest compactManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Version != 2 || manifest.ReceiptVerification.Status != "degraded" || manifest.ReceiptVerification.V1ChainHead != "" || len(manifest.ReceiptVerification.Degradations) != 1 {
		t.Fatalf("manifest = %+v", manifest)
	}
	active, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "evidence-proxy-0.jsonl")))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(active, source.Bytes()) {
		t.Fatal("degraded compaction changed JSONL bytes")
	}
}

func TestRunCompactRefusesFirstOrLastV1Gap(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("atomic evidence directory exchange is unsupported")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tombstone := map[string]any{"redacted": true, "detected_patterns": []string{"[REDACTED:test pattern]"}, "original_size": 42}
	for _, tc := range []struct {
		name    string
		details []any
	}{
		{name: "first", details: []any{tombstone, receiptForCompactV1(t, priv, 1, "unknown-gap-head", "suffix")}},
		{name: "last", details: []any{receiptForCompactV1(t, priv, 0, legacyreceipt.GenesisHash, "prefix"), tombstone}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			outerPrev := recorder.GenesisHash
			var source bytes.Buffer
			for i, detail := range tc.details {
				entry := recorder.Entry{Version: recorder.CurrentWriteEntryVersion, Sequence: uint64(i), Timestamp: time.Unix(int64(i+1), 0).UTC(), SessionID: "proxy", Type: "action_receipt", EventKind: "proxy_decision", Transport: "fetch", Summary: "legacy", Detail: detail, PrevHash: outerPrev}
				entry.Hash = recorder.ComputeHash(entry)
				outerPrev = entry.Hash
				line, marshalErr := json.Marshal(entry)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				source.Write(line)
				source.WriteByte('\n')
			}
			path := filepath.Join(dir, "evidence-proxy-0.jsonl")
			if err := os.WriteFile(path, source.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			err := runCompact(compactCmd(), compactOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), allowDegradedReceipts: 1})
			if err == nil || !strings.Contains(err.Error(), "receipt resume cannot load") {
				t.Fatalf("edge-gap compact error=%v", err)
			}
			active, readErr := os.ReadFile(filepath.Clean(path))
			if readErr != nil || !bytes.Equal(active, source.Bytes()) {
				t.Fatalf("refused edge-gap compact changed source: err=%v", readErr)
			}
		})
	}
}

func compactSignedReceipt(t *testing.T, priv ed25519.PrivateKey, seq uint64, prev string) contractreceipt.EvidenceReceipt {
	t.Helper()
	payload, err := json.Marshal(contractreceipt.PayloadShadowDeltaStruct{
		ContractHash: "sha256:test-contract", RuleID: "rule-1", OriginalVerdict: "allow", CandidateVerdict: "block",
		Aggregation: contractreceipt.ShadowDeltaAggregation{WindowStart: "2026-08-23T00:00:00Z", WindowEnd: "2026-08-23T00:01:00Z", LosslessCount: 1, DeltaSampleCount: 1, ExemplarIDs: []string{"sha256:example"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := contractreceipt.EvidenceReceipt{
		RecordType: contractreceipt.RecordTypeEvidenceV2, ReceiptVersion: 2,
		PayloadKind: contractreceipt.PayloadShadowDelta, Canonicalization: contractreceipt.DefaultCanonicalizationProfile(),
		Crit:    contractreceipt.CritForPayloadKind(contractreceipt.PayloadShadowDelta),
		EventID: fmt.Sprintf("01900000-0000-7000-8000-%012d", seq), Timestamp: time.Unix(1, 0).UTC(), Actor: "test",
		ChainSeq: seq, ChainPrevHash: prev, ContractHash: "sha256:test-contract", ActiveManifestHash: "sha256:test-manifest", Payload: payload,
		Signature: contractreceipt.SignatureProof{SignerKeyID: "test-key", KeyPurpose: "receipt-signing", Algorithm: "ed25519"},
	}
	preimage, err := r.SignablePreimage()
	if err != nil {
		t.Fatal(err)
	}
	r.Signature.Signature = "ed25519:" + hex.EncodeToString(ed25519.Sign(priv, preimage))
	return r
}

func receiptForCompactMixedV1(t *testing.T, priv ed25519.PrivateKey) legacyreceipt.Receipt {
	t.Helper()
	return receiptForCompactV1(t, priv, 0, legacyreceipt.GenesisHash, "compact-mixed-v1")
}

func receiptForCompactV1(t *testing.T, priv ed25519.PrivateKey, seq uint64, prev, actionID string) legacyreceipt.Receipt {
	t.Helper()
	r, err := legacyreceipt.Sign(legacyreceipt.ActionRecord{
		Version:       legacyreceipt.ActionRecordVersion,
		ActionID:      actionID,
		ActionType:    legacyreceipt.ActionRead,
		Timestamp:     time.Unix(1, 0).UTC(),
		Target:        "https://api.vendor.example/compact",
		Verdict:       "allow",
		Transport:     "fetch",
		ChainPrevHash: prev,
		ChainSeq:      seq,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func sha256Bytes(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func TestRunCompactRefusesActiveRecorder(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("ceremony locking is unsupported")
	}
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	cmd := compactCmd()
	cmd.SetArgs([]string{"--receipt-dir", dir, "--session", "proxy", "--key", hex.EncodeToString(pub)})
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "requires a stopped recorder") {
		t.Fatalf("err = %v", err)
	}
}

func compactTestLine(t *testing.T, seq uint64) []byte {
	t.Helper()
	e := recorder.Entry{Version: recorder.EntryVersion, Sequence: seq, Timestamp: time.Unix(1, 0).UTC(), SessionID: "proxy", Type: "decision", EventKind: "proxy_decision", Transport: "fetch", Summary: "test", Detail: map[string]string{"test": "value"}, PrevHash: recorder.GenesisHash}
	e.Hash = recorder.ComputeHash(e)
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return append(data, '\n')
}

func TestExchangeEvidenceDirectoriesRejectsSeparateParents(t *testing.T) {
	t.Parallel()
	err := exchangeEvidenceDirectories(filepath.Join(t.TempDir(), "active"), filepath.Join(t.TempDir(), "stage"))
	if err == nil {
		t.Fatal("exchangeEvidenceDirectories accepted separate parents")
	}
}

func TestRunCompactRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		opts compactOptions
		want string
	}{
		{name: "blank-session", opts: compactOptions{}, want: "--session is required"},
		{name: "bad-directory", opts: compactOptions{sessionID: "proxy", receiptDir: filepath.Join(t.TempDir(), "missing")}, want: "no such file"},
		{name: "bad-location", opts: compactOptions{sessionID: "proxy", receiptDir: t.TempDir(), locationID: "../escape", publicKey: "bad"}, want: "resolve evidence location"},
		{name: "bad-key", opts: compactOptions{sessionID: "proxy", receiptDir: t.TempDir(), publicKey: "bad"}, want: "load --key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runCompact(compactCmd(), tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunCompactPropagatesEmptySource(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	err = runCompact(compactCmd(), compactOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub)})
	if err == nil || !strings.Contains(err.Error(), "no evidence shards") {
		t.Fatalf("err = %v", err)
	}
}

func TestCompactLinuxHelpers(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("linux helpers are unsupported")
	}
	t.Run("prepare-success", func(t *testing.T) {
		if err := prepareCompactStage(t.TempDir(), t.TempDir()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("prepare-missing", func(t *testing.T) {
		if err := prepareCompactStage(filepath.Join(t.TempDir(), "missing"), t.TempDir()); err == nil {
			t.Fatal("prepareCompactStage accepted missing source")
		}
	})
	t.Run("metadata-success", func(t *testing.T) {
		source, target := filepath.Join(t.TempDir(), "source"), filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := preserveCompactFileMetadata(source, target); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("metadata-missing", func(t *testing.T) {
		if err := preserveCompactFileMetadata(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "target")); err == nil {
			t.Fatal("preserveCompactFileMetadata accepted missing source")
		}
	})
	t.Run("sync-file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := syncCompactFile(path); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("sync-file-missing", func(t *testing.T) {
		if err := syncCompactFile(filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("syncCompactFile accepted missing file")
		}
	})
	t.Run("sync-directory", func(t *testing.T) {
		if err := syncCompactDirectory(t.TempDir()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("sync-directory-missing", func(t *testing.T) {
		if err := syncCompactDirectory(filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("syncCompactDirectory accepted missing directory")
		}
	})
	t.Run("exchange-missing", func(t *testing.T) {
		parent := t.TempDir()
		if err := exchangeEvidenceDirectories(filepath.Join(parent, "missing-a"), filepath.Join(parent, "missing-b")); err == nil {
			t.Fatal("exchangeEvidenceDirectories accepted missing directories")
		}
	})
}

func TestWriteCompactManifestRejectsMissingDirectory(t *testing.T) {
	t.Parallel()
	err := writeCompactManifest(filepath.Join(t.TempDir(), "missing"), compactManifest{Version: 1})
	if err == nil {
		t.Fatal("writeCompactManifest accepted missing directory")
	}
}

func TestRunCompactFailClosedAtCeremonyBoundaries(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("atomic evidence compaction requires Linux rename exchange")
	}
	tests := []struct {
		name   string
		inject func()
	}{
		{name: "stream-source", inject: func() {
			compactStreamStage = func(recorder.EvidenceLocation, []string, string, ed25519.PublicKey, string) (*compactStreamWriter, compactStreamProof, error) {
				return nil, compactStreamProof{}, errors.New("injected stream source")
			}
		}},
		{name: "too-many-shards", inject: func() {
			compactStreamStage = func(_ recorder.EvidenceLocation, _ []string, _ string, _ ed25519.PublicKey, dir string) (*compactStreamWriter, compactStreamProof, error) {
				return &compactStreamWriter{files: make([]compactStreamFile, recorder.MaxEvidenceReadDirectoryEntries+1), dir: dir}, compactStreamProof{}, nil
			}
		}},
		{name: "make-stage", inject: func() {
			compactMakeStage = func(string, string) (string, error) { return "", errors.New("injected mkdir") }
		}},
		{name: "prepare-stage", inject: func() { compactPrepareStage = func(string, string) error { return errors.New("injected prepare") } }},
		{name: "sync-stage", inject: func() { compactSyncPath = func(string) error { return errors.New("injected sync") } }},
		{name: "post-proof", inject: func() {
			calls := 0
			compactVerifyStream = func(location recorder.EvidenceLocation, names []string, session string, key ed25519.PublicKey, consume func(compactStreamFile, []byte, recorder.Entry) error) (compactStreamProof, error) {
				calls++
				if calls == 1 {
					return compactStreamProof{}, errors.New("injected post proof")
				}
				return streamCompactFiles(location, names, session, key, consume)
			}
		}},
		{name: "stage-lock", inject: func() {
			calls := 0
			compactAcquireLock = func(dir string) (*recorder.EvidenceCeremonyLock, error) {
				calls++
				if calls == 2 {
					return nil, errors.New("injected stage lock")
				}
				return recorder.AcquireEvidenceCeremonyLock(dir)
			}
		}},
		{name: "exchange", inject: func() { compactExchange = func(string, string) error { return errors.New("injected exchange") } }},
		{name: "rename", inject: func() { compactRename = func(string, string) error { return errors.New("injected rename") } }},
		{name: "manifest", inject: func() {
			compactWriteManifest = func(string, compactManifest) error { return errors.New("injected manifest") }
		}},
		{name: "archive-sync", inject: func() {
			calls := 0
			compactSyncPath = func(path string) error {
				calls++
				if calls == 3 {
					return errors.New("injected archive sync")
				}
				return syncCompactDirectory(path)
			}
		}},
		{name: "final-parent-sync", inject: func() {
			calls := 0
			compactSyncPath = func(path string) error {
				calls++
				if calls == 4 {
					return errors.New("injected final sync")
				}
				return syncCompactDirectory(path)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			restoreCompactHooks(t)
			opts := newCompactFixture(t)
			tc.inject()
			err := runCompact(compactCmd(), opts)
			if err == nil {
				t.Fatal("runCompact succeeded across injected ceremony failure")
			}
			if tc.name != "too-many-shards" {
				if !strings.Contains(err.Error(), "injected") {
					t.Fatalf("%s failed for the wrong reason: %v", tc.name, err)
				}
			}
			if _, statErr := os.Stat(filepath.Join(opts.receiptDir, "evidence-proxy-0.jsonl")); statErr != nil {
				t.Fatalf("original shard not restored after %s: %v (run error: %v)", tc.name, statErr, err)
			}
			parent := filepath.Dir(opts.receiptDir)
			for _, pattern := range []string{".pipelock-evidence-compact-*", ".pipelock-evidence-archive-*"} {
				leftover, globErr := filepath.Glob(filepath.Join(parent, pattern))
				if globErr != nil {
					t.Fatal(globErr)
				}
				if len(leftover) != 0 {
					t.Fatalf("%s left ceremony directories %v (run error: %v)", tc.name, leftover, err)
				}
			}
			restoreCompactHooks(t)
			if retryErr := runCompact(compactCmd(), opts); retryErr != nil {
				t.Fatalf("%s left ceremony non-retryable: %v (original error: %v)", tc.name, retryErr, err)
			}
		})
	}
}

func TestRunCompactRejectsStagingAndSourceIdentityDisagreement(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("atomic evidence compaction requires Linux rename exchange")
	}
	for _, tc := range []struct {
		name   string
		inject func(t *testing.T, opts compactOptions)
		want   string
	}{
		{
			name: "stage has no selected shards",
			inject: func(t *testing.T, _ compactOptions) {
				compactStreamStage = func(_ recorder.EvidenceLocation, _ []string, _ string, _ ed25519.PublicKey, dir string) (*compactStreamWriter, compactStreamProof, error) {
					return &compactStreamWriter{dir: dir, files: []compactStreamFile{{name: "expected-output"}}}, compactStreamProof{}, nil
				}
			},
			want: "list staged evidence",
		},
		{
			name: "staged proof differs from source",
			inject: func(t *testing.T, _ compactOptions) {
				compactVerifyStream = func(location recorder.EvidenceLocation, names []string, session string, key ed25519.PublicKey, consume func(compactStreamFile, []byte, recorder.Entry) error) (compactStreamProof, error) {
					proof, err := streamCompactFiles(location, names, session, key, consume)
					if err == nil {
						proof.sum = "different"
					}
					return proof, err
				}
			},
			want: "changed original JSONL bytes",
		},
		{
			name: "source names change after recheck",
			inject: func(t *testing.T, opts compactOptions) {
				calls := 0
				compactVerifyStream = func(location recorder.EvidenceLocation, names []string, session string, key ed25519.PublicKey, consume func(compactStreamFile, []byte, recorder.Entry) error) (compactStreamProof, error) {
					proof, err := streamCompactFiles(location, names, session, key, consume)
					calls++
					if err == nil && calls == 2 {
						if writeErr := os.WriteFile(filepath.Join(opts.receiptDir, "evidence-proxy-1.jsonl"), []byte("not read until the next ceremony\n"), 0o600); writeErr != nil {
							t.Fatal(writeErr)
						}
					}
					return proof, err
				}
			},
			want: "source shard name set changed",
		},
		{
			name: "source proof changes after staging",
			inject: func(t *testing.T, _ compactOptions) {
				calls := 0
				compactVerifyStream = func(location recorder.EvidenceLocation, names []string, session string, key ed25519.PublicKey, consume func(compactStreamFile, []byte, recorder.Entry) error) (compactStreamProof, error) {
					proof, err := streamCompactFiles(location, names, session, key, consume)
					calls++
					if err == nil && calls == 2 {
						proof.sum = "changed-after-stage"
					}
					return proof, err
				}
			},
			want: "source digest changed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restoreCompactHooks(t)
			opts := newCompactFixture(t)
			tc.inject(t, opts)
			err := runCompact(compactCmd(), opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("runCompact error=%v, want %q", err, tc.want)
			}
			if _, statErr := os.Stat(filepath.Join(opts.receiptDir, "evidence-proxy-0.jsonl")); statErr != nil {
				t.Fatalf("active source was not retained: %v", statErr)
			}
		})
	}
}

func TestRunCompactDetectsSourceMutationBeforeExchange(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("atomic evidence compaction requires Linux rename exchange")
	}
	restoreCompactHooks(t)
	opts := newCompactFixture(t)
	calls := 0
	compactAcquireLock = func(dir string) (*recorder.EvidenceCeremonyLock, error) {
		lock, err := recorder.AcquireEvidenceCeremonyLock(dir)
		if err != nil {
			return nil, err
		}
		calls++
		if calls == 2 {
			path := filepath.Join(opts.receiptDir, "evidence-proxy-0.jsonl")
			if writeErr := os.WriteFile(path, append(compactTestLine(t, 0), []byte("changed\n")...), 0o600); writeErr != nil {
				_ = lock.Close()
				return nil, writeErr
			}
		}
		return lock, nil
	}
	err := runCompact(compactCmd(), opts)
	if err == nil || !strings.Contains(err.Error(), "source changed before publication") {
		t.Fatalf("err = %v", err)
	}
}

func restoreCompactHooks(t *testing.T) {
	t.Helper()
	compactAcquireLock = recorder.AcquireEvidenceCeremonyLock
	compactMakeStage = os.MkdirTemp
	compactPrepareStage = prepareCompactStage
	compactSyncPath = syncCompactDirectory
	compactExchange = exchangeEvidenceDirectories
	compactRename = os.Rename
	compactWriteManifest = writeCompactManifest
	compactStreamStage = streamCompactToStage
	compactVerifyStream = streamCompactFiles
	t.Cleanup(func() {
		compactAcquireLock = recorder.AcquireEvidenceCeremonyLock
		compactMakeStage = os.MkdirTemp
		compactPrepareStage = prepareCompactStage
		compactSyncPath = syncCompactDirectory
		compactExchange = exchangeEvidenceDirectories
		compactRename = os.Rename
		compactWriteManifest = writeCompactManifest
		compactStreamStage = streamCompactToStage
		compactVerifyStream = streamCompactFiles
	})
}

func newCompactFixture(t *testing.T) compactOptions {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := compactSignedReceipt(t, priv, 0, contractreceipt.GenesisHash)
	e := recorder.Entry{Version: recorder.CurrentWriteEntryVersion, Sequence: 0, Timestamp: time.Unix(1, 0).UTC(), SessionID: "proxy", Type: contractreceipt.EvidenceEntryType, EventKind: "proxy_decision", Transport: "fetch", Summary: "test", Detail: r, PrevHash: recorder.GenesisHash}
	e.Hash = recorder.ComputeHash(e)
	line, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return compactOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub)}
}
