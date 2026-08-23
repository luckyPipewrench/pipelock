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
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
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

func sha256Bytes(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func TestCompactPackPreservesLineBytesAndNamesFirstSequence(t *testing.T) {
	t.Parallel()
	first := compactTestLine(t, 4)
	second := compactTestLine(t, 5)
	source := []compactShard{{name: "evidence-proxy-4.jsonl", data: append(append([]byte(nil), first...), second...)}}
	got, err := compactPack("proxy", source)
	if err != nil {
		t.Fatalf("compactPack: %v", err)
	}
	if len(got) != 1 || got[0].name != "evidence-proxy-4.jsonl" {
		t.Fatalf("shards = %+v", got)
	}
	if !bytes.Equal(got[0].data, source[0].data) {
		t.Fatalf("compaction altered JSONL bytes\n got %q\nwant %q", got[0].data, source[0].data)
	}
}

func TestCompactSourceRefusesNonSelectedEvidence(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeDoctorEntries(t, dir, "evidence-proxy-0.jsonl", doctorEntryPlan{{session: "proxy", seq: 0, prev: recorder.GenesisHash}})
	writeDoctorEntries(t, dir, "evidence-other-0.jsonl", doctorEntryPlan{{session: "other", seq: 0, prev: recorder.GenesisHash}})
	_, _, err := compactSource(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
	if err == nil {
		t.Fatal("compactSource accepted unrelated active evidence")
	}
}

func TestCompactSourceRefusesNestedDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), compactTestLine(t, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o750); err != nil {
		t.Fatal(err)
	}
	_, _, err := compactSource(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
	if err == nil || !strings.Contains(err.Error(), "refuse nested directory") {
		t.Fatalf("err = %v", err)
	}
}

func TestCompactSourceRefusesShardWithoutTrailingNewline(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	line := compactTestLine(t, 0)
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), bytes.TrimSuffix(line, []byte("\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := compactSource(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
	if err == nil || !strings.Contains(err.Error(), "does not end in newline") {
		t.Fatalf("err = %v", err)
	}
}

func TestCompactSourceRejectsInputBudgets(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), compactTestLine(t, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-1.jsonl"), compactTestLine(t, 1), 0o600); err != nil {
		t.Fatal(err)
	}
	location := recorder.EvidenceLocation{Root: dir, Dir: dir}
	if _, _, err := compactSourceWithLimits(location, "proxy", 1, maxCompactInputBytes); err == nil || !strings.Contains(err.Error(), "directory exceeds") {
		t.Fatalf("shard budget err = %v", err)
	}
	if _, _, err := compactSourceWithLimits(location, "proxy", maxCompactInputShards, 1); err == nil || !strings.Contains(err.Error(), "input byte limit") {
		t.Fatalf("byte budget err = %v", err)
	}
}

func TestCompactSourceRefusesDuplicateStartSymlinkAndOversize(t *testing.T) {
	t.Run("duplicate-start", func(t *testing.T) {
		dir := t.TempDir()
		line := compactTestLine(t, 0)
		for _, name := range []string{"evidence-proxy-0.jsonl", "evidence-proxy-000.jsonl"} {
			if err := os.WriteFile(filepath.Join(dir, name), line, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_, _, err := compactSource(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "ambiguous evidence shard sequence start") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "target.jsonl")
		if err := os.WriteFile(target, compactTestLine(t, 0), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "evidence-proxy-0.jsonl")); err != nil {
			t.Fatal(err)
		}
		_, _, err := compactSource(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "evidence-proxy-0.jsonl")
		// #nosec G304 -- path is inside t.TempDir().
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(recorder.MaxEvidenceReadFileBytes + 1); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		_, _, err = compactSource(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("err = %v", err)
		}
	})
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

func TestCompactSourceRejectsMalformedChains(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		dir := t.TempDir()
		_, _, err := compactSource(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "no evidence shards") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("malformed-json", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), []byte("{bad}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := compactSource(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "validate") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("wrong-entry-session", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), compactTestLineForSession(t, "other", 0), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := compactSource(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "belongs to") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("broken-recorder-chain", func(t *testing.T) {
		dir := t.TempDir()
		data := append(compactTestLineForSession(t, "proxy", 0), compactTestLineForSession(t, "proxy", 1)...)
		if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := compactSource(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "verify recorder chain") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no-receipts", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), compactTestLine(t, 0), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := compactSource(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "no evidence receipts") {
			t.Fatalf("err = %v", err)
		}
	})
}

func compactTestLineForSession(t *testing.T, session string, seq uint64) []byte {
	t.Helper()
	e := recorder.Entry{Version: recorder.EntryVersion, Sequence: seq, Timestamp: time.Unix(1, 0).UTC(), SessionID: session, Type: "decision", EventKind: "proxy_decision", Transport: "fetch", Summary: "test", PrevHash: recorder.GenesisHash}
	e.Hash = recorder.ComputeHash(e)
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func TestCompactHelpersRejectInvalidData(t *testing.T) {
	t.Parallel()
	t.Run("empty-receipt-chain", func(t *testing.T) {
		if err := verifyCompactReceipts(nil, make([]byte, ed25519.PublicKeySize)); err == nil {
			t.Fatal("empty receipt chain verified")
		}
	})
	t.Run("empty-pack", func(t *testing.T) {
		if _, err := compactPack("proxy", nil); err == nil || !strings.Contains(err.Error(), "no compacted") {
			t.Fatalf("empty compactPack err = %v", err)
		}
	})
	t.Run("malformed-pack", func(t *testing.T) {
		if _, err := compactPack("proxy", []compactShard{{data: []byte("{bad}\n")}}); err == nil || !strings.Contains(err.Error(), "parse compacted") {
			t.Fatalf("malformed compactPack err = %v", err)
		}
	})
	t.Run("wrong-session", func(t *testing.T) {
		wrong := compactTestLineForSession(t, "other", 0)
		if _, err := compactPack("proxy", []compactShard{{data: wrong}}); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("wrong-session compactPack err = %v", err)
		}
	})
	t.Run("oversized-stage", func(t *testing.T) {
		oversize := compactShard{name: "evidence-proxy-0.jsonl", data: make([]byte, recorder.MaxEvidenceReadFileBytes+1)}
		if err := writeCompactStage(t.TempDir(), []compactShard{oversize}); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("oversize write err = %v", err)
		}
	})
}

func TestCompactManifestMappingsAndReceiptEquality(t *testing.T) {
	t.Parallel()
	shards := []compactShard{{name: "one", data: []byte("abc"), mappings: []compactByteMapping{{Source: "old", Output: "one", Bytes: 3}}}}
	manifest := manifestShards(shards)
	if len(manifest) != 1 || manifest[0].Name != "one" || manifest[0].Bytes != 3 || manifest[0].SHA256 == "" {
		t.Fatalf("manifest = %+v", manifest)
	}
	if mappings := compactMappings(shards); len(mappings) != 1 || mappings[0].Bytes != 3 {
		t.Fatalf("mappings = %+v", mappings)
	}
	dir := t.TempDir()
	if err := writeCompactManifest(dir, compactManifest{Version: 1, SessionID: "proxy"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "compaction-manifest.json")); err != nil {
		t.Fatal(err)
	}
	if !sameReceiptChain(nil, nil) {
		t.Fatal("equal empty chains differ")
	}
	if sameReceiptChain(nil, []contractreceipt.EvidenceReceipt{{}}) {
		t.Fatal("different-length chains compare equal")
	}
	if sameReceiptChain([]contractreceipt.EvidenceReceipt{{}}, []contractreceipt.EvidenceReceipt{{Actor: "different"}}) {
		t.Fatal("different receipts compare equal")
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

func TestCompactFileAndRollbackHelpers(t *testing.T) {
	if !supportsCompactExchangeTest() {
		t.Skip("atomic evidence directory exchange is unsupported")
	}
	t.Run("write-stage", func(t *testing.T) {
		sourceDir := t.TempDir()
		stage := t.TempDir()
		source := filepath.Join(sourceDir, "source.jsonl")
		if err := os.WriteFile(source, []byte("source\n"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(source, 0o400); err != nil {
			t.Fatal(err)
		}
		shard := compactShard{name: "evidence-proxy-0.jsonl", data: []byte("replacement\n"), sourcePath: source}
		if err := writeCompactStage(stage, []compactShard{shard}); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(stage, shard.name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o400 {
			t.Fatalf("mode = %o", info.Mode().Perm())
		}
	})
	t.Run("write-stage-missing-source", func(t *testing.T) {
		err := writeCompactStage(t.TempDir(), []compactShard{{name: "evidence-proxy-0.jsonl", data: []byte("x\n"), sourcePath: filepath.Join(t.TempDir(), "missing")}})
		if err == nil || !strings.Contains(err.Error(), "preserve compacted shard metadata") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("write-stage-missing-dir", func(t *testing.T) {
		err := writeCompactStage(filepath.Join(t.TempDir(), "missing"), []compactShard{{name: "evidence-proxy-0.jsonl", data: []byte("x\n")}})
		if err == nil || !strings.Contains(err.Error(), "write compacted shard") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("rollback", func(t *testing.T) {
		parent := t.TempDir()
		active := filepath.Join(parent, "active")
		old := filepath.Join(parent, "old")
		if err := os.Mkdir(active, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(old, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(active, "replacement"), []byte("new"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(old, "original"), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(old, "compaction-manifest.json"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cause := errors.New("publication failed")
		if err := rollbackCompactExchange(active, old, cause); !errors.Is(err, cause) {
			t.Fatalf("rollback err = %v", err)
		}
		if _, err := os.Stat(filepath.Join(active, "original")); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("old directory remains: %v", err)
		}
	})
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

func TestCompactPackRejectsOversizedLine(t *testing.T) {
	t.Parallel()
	data := make([]byte, recorder.MaxEvidenceReadFileBytes+1)
	data[len(data)-1] = '\n'
	_, err := compactPack("proxy", []compactShard{{data: data}})
	if err == nil || !strings.Contains(err.Error(), "single JSONL line exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func TestWriteCompactManifestRejectsMissingDirectory(t *testing.T) {
	t.Parallel()
	err := writeCompactManifest(filepath.Join(t.TempDir(), "missing"), compactManifest{Version: 1})
	if err == nil {
		t.Fatal("writeCompactManifest accepted missing directory")
	}
}

func TestRunCompactFailClosedAtCeremonyBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		inject func()
	}{
		{name: "pre-verify", inject: func() {
			compactVerify = func([]contractreceipt.EvidenceReceipt, []byte) error { return errors.New("injected verify") }
		}},
		{name: "pack", inject: func() {
			compactPackRecords = func(string, []compactShard) ([]compactShard, error) { return nil, errors.New("injected pack") }
		}},
		{name: "too-many-shards", inject: func() {
			compactPackRecords = func(string, []compactShard) ([]compactShard, error) {
				return make([]compactShard, recorder.MaxEvidenceReadDirectoryEntries+1), nil
			}
		}},
		{name: "make-stage", inject: func() {
			compactMakeStage = func(string, string) (string, error) { return "", errors.New("injected mkdir") }
		}},
		{name: "prepare-stage", inject: func() { compactPrepareStage = func(string, string) error { return errors.New("injected prepare") } }},
		{name: "write-stage", inject: func() {
			compactWriteShards = func(string, []compactShard) error { return errors.New("injected write") }
		}},
		{name: "corrupt-staged-recorder", inject: func() {
			compactWriteShards = func(dir string, shards []compactShard) error {
				if err := writeCompactStage(dir, shards); err != nil {
					return err
				}
				var entry recorder.Entry
				if err := json.Unmarshal(bytes.TrimSpace(shards[0].data), &entry); err != nil {
					return err
				}
				entry.Summary = "changed without updating recorder hash"
				data, err := json.Marshal(entry)
				if err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(dir, shards[0].name), append(data, '\n'), 0o600)
			}
		}},
		{name: "sync-stage", inject: func() { compactSyncPath = func(string) error { return errors.New("injected sync") } }},
		{name: "extract-stage", inject: func() {
			compactExtract = func(recorder.EvidenceLocation, string) ([]contractreceipt.EvidenceReceipt, error) {
				return nil, errors.New("injected extract")
			}
		}},
		{name: "post-verify", inject: func() {
			calls := 0
			compactVerify = func(receipts []contractreceipt.EvidenceReceipt, key []byte) error {
				calls++
				if calls == 2 {
					return errors.New("injected post verify")
				}
				return verifyCompactReceipts(receipts, key)
			}
		}},
		{name: "chain-mismatch", inject: func() {
			compactSameChain = func([]contractreceipt.EvidenceReceipt, []contractreceipt.EvidenceReceipt) bool { return false }
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
			if tc.name != "too-many-shards" && tc.name != "chain-mismatch" && tc.name != "corrupt-staged-recorder" {
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

func TestSameCompactBytes(t *testing.T) {
	t.Parallel()
	a := []compactShard{{data: []byte("one\n")}, {data: []byte("two\n")}}
	b := []compactShard{{data: []byte("one\ntwo\n")}}
	if !sameCompactBytes(a, b) {
		t.Fatal("same byte stream differs across shard boundaries")
	}
	b[0].data[0] = 'X'
	if sameCompactBytes(a, b) {
		t.Fatal("different byte streams compare equal")
	}
}

func TestRunCompactDetectsSourceMutationBeforeExchange(t *testing.T) {
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
	compactPackRecords = compactPack
	compactMakeStage = os.MkdirTemp
	compactPrepareStage = prepareCompactStage
	compactWriteShards = writeCompactStage
	compactSyncPath = syncCompactDirectory
	compactExtract = contractreceipt.ExtractEvidenceReceiptsFromResolvedSessionDir
	compactVerify = verifyCompactReceipts
	compactSameChain = sameReceiptChain
	compactExchange = exchangeEvidenceDirectories
	compactRename = os.Rename
	compactWriteManifest = writeCompactManifest
	t.Cleanup(func() {
		compactAcquireLock = recorder.AcquireEvidenceCeremonyLock
		compactPackRecords = compactPack
		compactMakeStage = os.MkdirTemp
		compactPrepareStage = prepareCompactStage
		compactWriteShards = writeCompactStage
		compactSyncPath = syncCompactDirectory
		compactExtract = contractreceipt.ExtractEvidenceReceiptsFromResolvedSessionDir
		compactVerify = verifyCompactReceipts
		compactSameChain = sameReceiptChain
		compactExchange = exchangeEvidenceDirectories
		compactRename = os.Rename
		compactWriteManifest = writeCompactManifest
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
