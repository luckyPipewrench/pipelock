//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/anchor"
	anchorcmd "github.com/luckyPipewrench/pipelock/internal/cli/anchor"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	anchorTestFileMode = 0o600
	anchorTestDirMode  = 0o750
)

func TestAuditReceiptChain_BrokenCasesFailClosed(t *testing.T) {
	t.Parallel()

	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	good := buildDashboardChain(t, priv, 3)
	base := good[0].ActionRecord.Timestamp

	gap := append([]receipt.Receipt(nil), good...)
	gap[1] = signDashboardReceipt(t, priv, 2, mustReceiptHash(t, gap[0]), base.Add(time.Second))

	badPrev := append([]receipt.Receipt(nil), good...)
	badPrev[1] = signDashboardReceipt(t, priv, 1, strings.Repeat("a", 64), base.Add(time.Second))

	fork := append([]receipt.Receipt(nil), good[:2]...)
	fork = append(fork, signDashboardReceipt(t, priv, 1, mustReceiptHash(t, good[0]), base.Add(2*time.Second)))

	outOfOrder := []receipt.Receipt{good[1], good[0]}
	hashError := append([]receipt.Receipt(nil), good...)
	hashError[0].Ext = json.RawMessage(`{`)
	otherPub, _ := generateDashboardKey(t)

	tests := []struct {
		name      string
		in        ChainAuditInput
		want      string
		wantGaps  int
		wantForks int
	}{
		{name: "sequence gap", in: ChainAuditInput{SessionID: testSessionID, Receipts: gap, TrustedKeys: []string{keyHex}}, want: "gap", wantGaps: 1},
		{name: "mutated prev hash", in: ChainAuditInput{SessionID: testSessionID, Receipts: badPrev, TrustedKeys: []string{keyHex}}, want: "prev_hash"},
		{name: "fork", in: ChainAuditInput{SessionID: testSessionID, Receipts: fork, TrustedKeys: []string{keyHex}}, want: "fork", wantForks: 1},
		{name: "out of order", in: ChainAuditInput{SessionID: testSessionID, Receipts: outOfOrder, TrustedKeys: []string{keyHex}}, want: "out-of-order"},
		{name: "previous receipt hash error", in: ChainAuditInput{SessionID: testSessionID, Receipts: hashError, TrustedKeys: []string{keyHex}}, want: "could not hash"},
		{name: "empty chain", in: ChainAuditInput{SessionID: testSessionID, TrustedKeys: []string{keyHex}}, want: "no receipts"},
		{name: "missing expected anchor", in: ChainAuditInput{SessionID: testSessionID, Receipts: good, TrustedKeys: []string{keyHex}, AnchorExpected: true}, want: "missing anchor"},
		{name: "unknown key", in: ChainAuditInput{SessionID: testSessionID, Receipts: good}, want: "unknown signer key"},
		{name: "unknown signer with a different trusted key", in: ChainAuditInput{SessionID: testSessionID, Receipts: good, TrustedKeys: []string{hex.EncodeToString(otherPub)}}, want: "not in the trusted set"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := AuditReceiptChain(tc.in)
			if got.Consistent || got.Failures == 0 {
				t.Fatalf("audit = %+v, want fail-closed inconsistency", got)
			}
			if !strings.Contains(strings.ToLower(got.Detail), tc.want) {
				t.Fatalf("detail = %q, want %q", got.Detail, tc.want)
			}
			if got.Gaps != tc.wantGaps || got.Forks != tc.wantForks {
				t.Fatalf("gaps/forks = %d/%d, want %d/%d", got.Gaps, got.Forks, tc.wantGaps, tc.wantForks)
			}
		})
	}
}

func TestAuditReceiptChain_ConsistentAndStaleAnchor(t *testing.T) {
	t.Parallel()

	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildDashboardChain(t, priv, 3)
	logPath := t.TempDir() + "/anchors.jsonl"
	backend := anchor.LocalLog{Path: logPath, LogID: "audit-test-log"}
	checkpoint, err := anchor.BuildCheckpoint(testSessionID, chain[:2], []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	proof, err := backend.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	bundle := anchor.NewBundle(checkpoint, proof)

	t.Run("good chain without expected anchor", func(t *testing.T) {
		got := AuditReceiptChain(ChainAuditInput{SessionID: testSessionID, Receipts: chain, TrustedKeys: []string{keyHex}})
		if !got.Consistent || got.Failures != 0 || got.Gaps != 0 {
			t.Fatalf("audit = %+v, want chain consistent", got)
		}
	})

	t.Run("single receipt is a complete chain", func(t *testing.T) {
		got := AuditReceiptChain(ChainAuditInput{SessionID: testSessionID, Receipts: chain[:1], TrustedKeys: []string{keyHex}})
		if !got.Consistent || got.Failures != 0 || got.Gaps != 0 || got.Forks != 0 {
			t.Fatalf("audit = %+v, want single-receipt chain consistent", got)
		}
	})

	t.Run("stale anchor is loud failure", func(t *testing.T) {
		got := AuditReceiptChain(ChainAuditInput{
			SessionID: testSessionID, Receipts: chain, TrustedKeys: []string{keyHex},
			AnchorExpected: true, AnchorBundle: &bundle, AnchorBackend: backend,
		})
		if got.Consistent || got.Failures == 0 || got.AnchorStatus != AnchorStale {
			t.Fatalf("audit = %+v, want stale-anchor failure", got)
		}
	})

	for _, tc := range []struct {
		name  string
		count uint64
	}{
		{name: "zero receipt count", count: 0},
		{name: "receipt count beyond chain", count: uint64(len(chain) + 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := bundle
			invalid.Checkpoint.ReceiptCount = tc.count
			got := AuditReceiptChain(ChainAuditInput{
				SessionID: testSessionID, Receipts: chain, TrustedKeys: []string{keyHex},
				AnchorExpected: true, AnchorBundle: &invalid, AnchorBackend: backend,
			})
			if got.Consistent || got.AnchorStatus != AnchorFailure || !strings.Contains(got.Detail, "range is invalid") {
				t.Fatalf("audit = %+v, want invalid receipt range failure", got)
			}
		})
	}
}

func TestFileAnchorResolver_VerifiesExistingMarkerMaterial(t *testing.T) {
	t.Parallel()

	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildDashboardChain(t, priv, 2)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "anchors.jsonl")
	bundlePath := filepath.Join(dir, "bundle.json")
	backend := anchor.LocalLog{Path: logPath, LogID: "resolver-test-log"}
	checkpoint, err := anchor.BuildCheckpoint(testSessionID, chain, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	proof, err := backend.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	bundle := anchor.NewBundle(checkpoint, proof)
	if err := anchor.WriteBundle(bundlePath, bundle); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	bundleBytes, err := os.ReadFile(filepath.Clean(bundlePath))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	bundleSum := sha256.Sum256(bundleBytes)
	if err := anchor.WriteStateMarker(dir, anchor.StateMarker{
		SessionID: testSessionID, FinalSeq: checkpoint.FinalSeq, RootHash: checkpoint.RootHash,
		Backend: proof.Backend, LogIndex: proof.LogIndex, AnchoredAt: time.Now().Add(-time.Minute),
		BundleSHA256: hex.EncodeToString(bundleSum[:]), BundlePath: filepath.Base(bundlePath),
	}); err != nil {
		t.Fatalf("WriteStateMarker: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "receipt-alias")
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatalf("Symlink receipt dir: %v", err)
	}
	markers, err := loadAnchorMarkers(dir)
	if err != nil {
		t.Fatalf("loadAnchorMarkers: %v", err)
	}
	if len(markers) != 1 {
		t.Fatalf("markers = %+v, want %q", markers, testSessionID)
	}
	resolvedMarkers, err := loadAnchorMarkers(alias)
	if err != nil {
		t.Fatalf("loadAnchorMarkers alias: %v", err)
	}
	if len(resolvedMarkers) != 1 || resolvedMarkers[0] != markers[0] {
		t.Fatalf("alias markers = %+v, want %+v", resolvedMarkers, markers)
	}
	resolver, err := NewFileAnchorResolver(dir, logPath, nil, false)
	if err != nil {
		t.Fatalf("NewFileAnchorResolver: %v", err)
	}
	gotBundle, gotBackend, expected, err := resolver(testSessionID)
	if err != nil || gotBundle == nil || gotBackend == nil || !expected {
		t.Fatalf("resolve bundle=%v backend=%T expected=%t err=%v", gotBundle, gotBackend, expected, err)
	}
	got := AuditReceiptChain(ChainAuditInput{
		SessionID: testSessionID, Receipts: chain, TrustedKeys: []string{keyHex},
		AnchorExpected: expected, AnchorBundle: gotBundle, AnchorBackend: gotBackend,
	})
	if !got.Consistent || got.AnchorStatus != AnchorCurrent {
		t.Fatalf("audit = %+v, want current consistent anchor", got)
	}
	if err := os.WriteFile(bundlePath, append(bundleBytes, '\n'), 0o600); err != nil {
		t.Fatalf("mutate bundle: %v", err)
	}
	if _, _, _, err := resolver(testSessionID); err == nil || !strings.Contains(err.Error(), "hash does not match") {
		t.Fatalf("mutated anchor bundle error = %v, want hash mismatch", err)
	}
}

func TestLoadAnchorMarkersIgnoresWriterTempFiles(t *testing.T) {
	t.Parallel()

	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildDashboardChain(t, priv, 2)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "anchors.jsonl")
	bundlePath := filepath.Join(dir, "bundle.json")
	backend := anchor.LocalLog{Path: logPath, LogID: "resolver-test-log"}
	checkpoint, err := anchor.BuildCheckpoint(testSessionID, chain, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	proof, err := backend.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	bundle := anchor.NewBundle(checkpoint, proof)
	if err := anchor.WriteBundle(bundlePath, bundle); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	bundleBytes, err := os.ReadFile(filepath.Clean(bundlePath))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	bundleSum := sha256.Sum256(bundleBytes)
	if err := anchor.WriteStateMarker(dir, anchor.StateMarker{
		SessionID: testSessionID, FinalSeq: checkpoint.FinalSeq, RootHash: checkpoint.RootHash,
		Backend: proof.Backend, LogIndex: proof.LogIndex, AnchoredAt: time.Now().Add(-time.Minute),
		BundleSHA256: hex.EncodeToString(bundleSum[:]), BundlePath: filepath.Base(bundlePath),
	}); err != nil {
		t.Fatalf("WriteStateMarker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anchor-state.d", ".anchor-state-123456789.tmp"), []byte("partial"), anchorTestFileMode); err != nil {
		t.Fatalf("WriteFile temp marker: %v", err)
	}
	markers, err := loadAnchorMarkers(dir)
	if err != nil {
		t.Fatalf("loadAnchorMarkers: %v", err)
	}
	if len(markers) != 1 || markers[0].SessionID != testSessionID {
		t.Fatalf("markers = %+v, want committed marker only", markers)
	}
}

func TestFileAnchorResolverDiscoversIndexedIndependentSessions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	first, firstBytes, firstMarker := resolverFixture(t)
	firstPath := filepath.Join(dir, firstMarker.BundlePath)
	if err := os.WriteFile(firstPath, firstBytes, anchorTestFileMode); err != nil {
		t.Fatalf("WriteFile first bundle: %v", err)
	}
	if err := anchor.WriteStateMarker(dir, firstMarker); err != nil {
		t.Fatalf("WriteStateMarker first: %v", err)
	}

	second := first
	second.Checkpoint.SessionID = "session-beta"
	second.Checkpoint.FinalSeq = 2
	second.Checkpoint.RootHash = strings.Repeat("c", 64)
	secondBytes, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("Marshal second bundle: %v", err)
	}
	secondSum := sha256.Sum256(secondBytes)
	secondMarker := firstMarker
	secondMarker.SessionID = second.Checkpoint.SessionID
	secondMarker.FinalSeq = second.Checkpoint.FinalSeq
	secondMarker.RootHash = second.Checkpoint.RootHash
	secondMarker.BundleSHA256 = hex.EncodeToString(secondSum[:])
	secondMarker.BundlePath = "bundle-beta.json"
	if err := os.WriteFile(filepath.Join(dir, secondMarker.BundlePath), secondBytes, anchorTestFileMode); err != nil {
		t.Fatalf("WriteFile second bundle: %v", err)
	}
	if err := anchor.WriteStateMarker(dir, secondMarker); err != nil {
		t.Fatalf("WriteStateMarker second: %v", err)
	}

	resolver, err := NewFileAnchorResolver(dir, filepath.Join(dir, "anchors.jsonl"), nil, false)
	if err != nil {
		t.Fatalf("NewFileAnchorResolver: %v", err)
	}
	for _, sessionID := range []string{first.Checkpoint.SessionID, second.Checkpoint.SessionID} {
		got, backend, expected, err := resolver(sessionID)
		if err != nil || got == nil || backend == nil || !expected {
			t.Fatalf("resolve %q bundle=%v backend=%T expected=%t err=%v", sessionID, got, backend, expected, err)
		}
		if got.Checkpoint.SessionID != sessionID {
			t.Fatalf("resolve %q got session %q", sessionID, got.Checkpoint.SessionID)
		}
	}
}

func TestFileAnchorResolverFailsClosedOnCorruptIndexedMarker(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, bundleBytes, marker := resolverFixture(t)
	if err := os.WriteFile(filepath.Join(dir, marker.BundlePath), bundleBytes, anchorTestFileMode); err != nil {
		t.Fatalf("WriteFile bundle: %v", err)
	}
	if err := anchor.WriteStateMarker(dir, marker); err != nil {
		t.Fatalf("WriteStateMarker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anchor-state.d", "corrupt.json"), []byte(`{"schema":`), anchorTestFileMode); err != nil {
		t.Fatalf("WriteFile corrupt marker: %v", err)
	}
	resolver, err := NewFileAnchorResolver(dir, filepath.Join(dir, "anchors.jsonl"), nil, false)
	if err != nil {
		t.Fatalf("NewFileAnchorResolver: %v", err)
	}
	if _, _, _, err := resolver(testSessionID); err == nil || !strings.Contains(err.Error(), "parse anchor-state marker") {
		t.Fatalf("resolver err = %v, want corrupt index failure", err)
	}
}

func TestFileAnchorResolverVerifiesProducerRelativeBundlePath(t *testing.T) {
	t.Parallel()

	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	chain := buildDashboardChain(t, priv, 2)
	dir := t.TempDir()
	receiptsPath := writeDashboardReceiptsJSONL(t, dir, chain)
	logPath := filepath.Join(dir, "anchors.jsonl")

	cmd := anchorcmd.Cmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		"receipts",
		receiptsPath,
		"--key", keyHex,
		"--local-log", logPath,
		"--log-id", "dashboard-roundtrip-log",
		"--out", "bundle.json",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute anchor receipts: %v", err)
	}

	resolver, err := NewFileAnchorResolver(dir, logPath, nil, false)
	if err != nil {
		t.Fatalf("NewFileAnchorResolver: %v", err)
	}
	gotBundle, gotBackend, expected, err := resolver("file")
	if err != nil || gotBundle == nil || gotBackend == nil || !expected {
		t.Fatalf("resolve bundle=%v backend=%T expected=%t err=%v", gotBundle, gotBackend, expected, err)
	}
	got := AuditReceiptChain(ChainAuditInput{
		SessionID: "file", Receipts: chain, TrustedKeys: []string{keyHex},
		AnchorExpected: expected, AnchorBundle: gotBundle, AnchorBackend: gotBackend,
	})
	if !got.Consistent || got.AnchorStatus != AnchorCurrent {
		t.Fatalf("audit = %+v, want producer bundle to verify through dashboard confinement", got)
	}
}

func TestFileAnchorResolver_FailsClosedOnMalformedState(t *testing.T) {
	t.Parallel()

	if resolver, err := NewFileAnchorResolver(t.TempDir(), "", []string{"not-a-key"}, false); err == nil || resolver != nil {
		t.Fatalf("invalid Rekor key resolver configured=%t err=%v", resolver != nil, err)
	}

	t.Run("missing marker follows policy", func(t *testing.T) {
		resolver, err := NewFileAnchorResolver(t.TempDir(), "", nil, true)
		if err != nil {
			t.Fatalf("NewFileAnchorResolver: %v", err)
		}
		bundle, backend, expected, err := resolver(testSessionID)
		if err != nil || bundle != nil || backend != nil || !expected {
			t.Fatalf("bundle=%v backend=%T expected=%t err=%v", bundle, backend, expected, err)
		}
	})

	t.Run("marker overwritten by another session is loud", func(t *testing.T) {
		dir := t.TempDir()
		if err := anchor.WriteStateMarker(dir, anchor.StateMarker{
			SessionID: "different-session", FinalSeq: 1, RootHash: strings.Repeat("a", 64), Backend: anchor.LocalBackend,
			AnchoredAt: time.Now().Add(-time.Minute), BundleSHA256: strings.Repeat("b", 64), BundlePath: filepath.Join(dir, "other.json"),
		}); err != nil {
			t.Fatalf("WriteStateMarker: %v", err)
		}
		resolver, err := NewFileAnchorResolver(dir, "", nil, false)
		if err != nil {
			t.Fatalf("NewFileAnchorResolver: %v", err)
		}
		bundle, backend, expected, err := resolver(testSessionID)
		if err != nil || bundle != nil || backend != nil || !expected {
			t.Fatalf("bundle=%v backend=%T expected=%t err=%v; overwritten session marker must make the missing anchor loud", bundle, backend, expected, err)
		}
	})

	t.Run("malformed marker", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "anchor-state.json"), []byte(`{"schema":`), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		resolver, err := NewFileAnchorResolver(dir, "", nil, false)
		if err != nil {
			t.Fatalf("NewFileAnchorResolver: %v", err)
		}
		if _, _, _, err := resolver(testSessionID); err == nil || !strings.Contains(err.Error(), "parse anchor-state") {
			t.Fatalf("marker error = %v", err)
		}
	})

	t.Run("missing bundle", func(t *testing.T) {
		dir := t.TempDir()
		missing := "missing-bundle.json"
		if err := anchor.WriteStateMarker(dir, anchor.StateMarker{
			SessionID: testSessionID, FinalSeq: 1, RootHash: strings.Repeat("a", 64), Backend: anchor.LocalBackend,
			AnchoredAt: time.Now().Add(-time.Minute), BundleSHA256: strings.Repeat("b", 64), BundlePath: missing,
		}); err != nil {
			t.Fatalf("WriteStateMarker: %v", err)
		}
		resolver, err := NewFileAnchorResolver(dir, "", nil, false)
		if err != nil {
			t.Fatalf("NewFileAnchorResolver: %v", err)
		}
		if _, _, _, err := resolver(testSessionID); err == nil || !strings.Contains(err.Error(), "read anchor bundle") {
			t.Fatalf("bundle error = %v", err)
		}
	})
}

func TestFileAnchorResolver_FailsClosedOnResolverMaterialMismatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		localLogPath func(string) string
		mutateMarker func(anchor.StateMarker) anchor.StateMarker
		wantErr      string
	}{
		{
			name: "bundle marker field mismatch",
			localLogPath: func(dir string) string {
				return filepath.Join(dir, "anchors.jsonl")
			},
			mutateMarker: func(marker anchor.StateMarker) anchor.StateMarker {
				marker.RootHash = strings.Repeat("c", 64)
				return marker
			},
			wantErr: "does not match anchor-state marker",
		},
		{
			name: "backend error",
			localLogPath: func(string) string {
				return ""
			},
			wantErr: "local anchor log path is required",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_, bundleBytes, marker := resolverFixture(t)
			if tc.mutateMarker != nil {
				marker = tc.mutateMarker(marker)
			}
			if err := os.WriteFile(filepath.Join(dir, marker.BundlePath), bundleBytes, anchorTestFileMode); err != nil {
				t.Fatalf("WriteFile bundle: %v", err)
			}
			writeResolverMarker(t, dir, marker)
			resolver, err := NewFileAnchorResolver(dir, tc.localLogPath(dir), nil, false)
			if err != nil {
				t.Fatalf("NewFileAnchorResolver: %v", err)
			}
			if _, _, _, err := resolver(testSessionID); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("resolver err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestFileAnchorResolver_ConfinesAndBoundsEvidenceFiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		arrange func(t *testing.T, dir string, bundleBytes []byte, marker anchor.StateMarker)
		wantErr string
	}{
		{
			name: "bundle path escapes receipt directory",
			arrange: func(t *testing.T, dir string, bundleBytes []byte, marker anchor.StateMarker) {
				t.Helper()
				outside := filepath.Join(filepath.Dir(dir), "outside-bundle.json")
				if err := os.WriteFile(outside, bundleBytes, anchorTestFileMode); err != nil {
					t.Fatalf("WriteFile outside bundle: %v", err)
				}
				marker.BundlePath = filepath.Join("..", filepath.Base(outside))
				writeResolverMarker(t, dir, marker)
			},
			wantErr: "escapes receipt directory",
		},
		{
			name: "absolute bundle path",
			arrange: func(t *testing.T, dir string, _ []byte, marker anchor.StateMarker) {
				t.Helper()
				marker.BundlePath = filepath.Join(dir, "bundle.json")
				writeResolverMarker(t, dir, marker)
			},
			wantErr: "must be relative",
		},
		{
			name: "bundle symlink",
			arrange: func(t *testing.T, dir string, bundleBytes []byte, marker anchor.StateMarker) {
				t.Helper()
				target := filepath.Join(dir, "bundle-target.json")
				if err := os.WriteFile(target, bundleBytes, anchorTestFileMode); err != nil {
					t.Fatalf("WriteFile bundle target: %v", err)
				}
				if err := os.Symlink(filepath.Base(target), filepath.Join(dir, marker.BundlePath)); err != nil {
					t.Fatalf("Symlink bundle: %v", err)
				}
				writeResolverMarker(t, dir, marker)
			},
			wantErr: "symlink",
		},
		{
			name: "bundle is not regular",
			arrange: func(t *testing.T, dir string, _ []byte, marker anchor.StateMarker) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(dir, marker.BundlePath), anchorTestDirMode); err != nil {
					t.Fatalf("Mkdir bundle path: %v", err)
				}
				writeResolverMarker(t, dir, marker)
			},
			wantErr: "not a regular file",
		},
		{
			name: "bundle is oversized",
			arrange: func(t *testing.T, dir string, _ []byte, marker anchor.StateMarker) {
				t.Helper()
				oversized := make([]byte, maxAnchorBundleBytes+1)
				if err := os.WriteFile(filepath.Join(dir, marker.BundlePath), oversized, anchorTestFileMode); err != nil {
					t.Fatalf("WriteFile oversized bundle: %v", err)
				}
				sum := sha256.Sum256(oversized)
				marker.BundleSHA256 = hex.EncodeToString(sum[:])
				writeResolverMarker(t, dir, marker)
			},
			wantErr: "exceeds size limit",
		},
		{
			name: "marker symlink",
			arrange: func(t *testing.T, dir string, bundleBytes []byte, marker anchor.StateMarker) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, marker.BundlePath), bundleBytes, anchorTestFileMode); err != nil {
					t.Fatalf("WriteFile bundle: %v", err)
				}
				markerPath := filepath.Join(dir, "marker-target.json")
				writeResolverMarkerAt(t, markerPath, marker)
				if err := os.Symlink(filepath.Base(markerPath), filepath.Join(dir, "anchor-state.json")); err != nil {
					t.Fatalf("Symlink marker: %v", err)
				}
			},
			wantErr: "not a regular file",
		},
		{
			name: "marker is not regular",
			arrange: func(t *testing.T, dir string, bundleBytes []byte, marker anchor.StateMarker) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, marker.BundlePath), bundleBytes, anchorTestFileMode); err != nil {
					t.Fatalf("WriteFile bundle: %v", err)
				}
				if err := os.Mkdir(filepath.Join(dir, "anchor-state.json"), anchorTestDirMode); err != nil {
					t.Fatalf("Mkdir marker path: %v", err)
				}
			},
			wantErr: "not a regular file",
		},
		{
			name: "marker is oversized",
			arrange: func(t *testing.T, dir string, bundleBytes []byte, marker anchor.StateMarker) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, marker.BundlePath), bundleBytes, anchorTestFileMode); err != nil {
					t.Fatalf("WriteFile bundle: %v", err)
				}
				data, err := json.Marshal(marker)
				if err != nil {
					t.Fatalf("Marshal marker: %v", err)
				}
				data = append(data, make([]byte, maxAnchorMarkerBytes+1-len(data))...)
				if err := os.WriteFile(filepath.Join(dir, "anchor-state.json"), data, anchorTestFileMode); err != nil {
					t.Fatalf("WriteFile oversized marker: %v", err)
				}
			},
			wantErr: "exceeds size limit",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_, bundleBytes, marker := resolverFixture(t)
			tc.arrange(t, dir, bundleBytes, marker)
			resolver, err := NewFileAnchorResolver(dir, "", nil, false)
			if err != nil {
				t.Fatalf("NewFileAnchorResolver: %v", err)
			}
			if _, _, _, err := resolver(testSessionID); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("resolver error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestFileAnchorResolver_ParsesExactlyHashedBytes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	original, originalBytes, marker := resolverFixture(t)
	bundlePath := filepath.Join(dir, marker.BundlePath)
	if err := os.WriteFile(bundlePath, originalBytes, anchorTestFileMode); err != nil {
		t.Fatalf("WriteFile original bundle: %v", err)
	}
	writeResolverMarker(t, dir, marker)

	replacement := original
	replacement.Checkpoint.SessionID = "swapped-session"
	replacementBytes, err := json.Marshal(replacement)
	if err != nil {
		t.Fatalf("Marshal replacement: %v", err)
	}
	resolver, err := newFileAnchorResolver(dir, filepath.Join(dir, "anchors.jsonl"), nil, false, func(hashedBytes []byte) (anchor.Bundle, error) {
		if err := os.WriteFile(bundlePath, replacementBytes, anchorTestFileMode); err != nil {
			t.Fatalf("swap bundle: %v", err)
		}
		return anchor.LoadBundleBytes(hashedBytes)
	})
	if err != nil {
		t.Fatalf("newFileAnchorResolver: %v", err)
	}
	got, _, _, err := resolver(testSessionID)
	if err != nil {
		t.Fatalf("resolve after swap: %v", err)
	}
	if got == nil || got.Checkpoint.SessionID != original.Checkpoint.SessionID {
		t.Fatalf("parsed session = %v, want hashed session %q", got, original.Checkpoint.SessionID)
	}
}

func resolverFixture(t *testing.T) (anchor.Bundle, []byte, anchor.StateMarker) {
	t.Helper()
	bundle := anchor.Bundle{
		Version:   anchor.BundleVersion,
		Backend:   anchor.LocalBackend,
		CreatedAt: time.Now().Add(-time.Minute),
		Checkpoint: anchor.Checkpoint{
			SessionID: testSessionID,
			FinalSeq:  1,
			RootHash:  strings.Repeat("a", 64),
		},
		Proof: anchor.Proof{Backend: anchor.LocalBackend, LogIndex: 7},
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("Marshal bundle: %v", err)
	}
	sum := sha256.Sum256(data)
	marker := anchor.StateMarker{
		Schema:       "pipelock.anchorstate.v1",
		SessionID:    bundle.Checkpoint.SessionID,
		FinalSeq:     bundle.Checkpoint.FinalSeq,
		RootHash:     bundle.Checkpoint.RootHash,
		Backend:      bundle.Backend,
		LogIndex:     bundle.Proof.LogIndex,
		AnchoredAt:   time.Now().Add(-time.Minute),
		BundleSHA256: hex.EncodeToString(sum[:]),
		BundlePath:   "bundle.json",
	}
	return bundle, data, marker
}

func writeDashboardReceiptsJSONL(t *testing.T, dir string, receipts []receipt.Receipt) string {
	t.Helper()
	var buf bytes.Buffer
	for _, r := range receipts {
		line, err := receipt.Marshal(r)
		if err != nil {
			t.Fatalf("Marshal receipt: %v", err)
		}
		_, _ = buf.Write(line)
		_ = buf.WriteByte('\n')
	}
	path := filepath.Join(dir, "receipts.jsonl")
	if err := os.WriteFile(path, buf.Bytes(), anchorTestFileMode); err != nil {
		t.Fatalf("WriteFile receipts: %v", err)
	}
	return path
}

func writeResolverMarker(t *testing.T, dir string, marker anchor.StateMarker) {
	t.Helper()
	writeResolverMarkerAt(t, filepath.Join(dir, "anchor-state.json"), marker)
}

func writeResolverMarkerAt(t *testing.T, path string, marker anchor.StateMarker) {
	t.Helper()
	data, err := json.Marshal(marker)
	if err != nil {
		t.Fatalf("Marshal marker: %v", err)
	}
	if err := os.WriteFile(path, data, anchorTestFileMode); err != nil {
		t.Fatalf("WriteFile marker: %v", err)
	}
}

func TestLoadAnchorMarkerAndBackendFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
	}{
		{name: "duplicate", data: `{"schema":"x","schema":"y"}`},
		{name: "trailing", data: `{}` + `{}`},
		{name: "invalid required fields", data: `{}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "anchor-state.json")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, _, err := loadAnchorMarker(dir); err == nil {
				t.Fatal("malformed marker unexpectedly accepted")
			}
		})
	}

	pub, _ := generateDashboardKey(t)
	backendTests := []struct {
		name   string
		bundle anchor.Bundle
		log    string
		keys   []crypto.PublicKey
		want   string
	}{
		{name: "local missing log", bundle: anchor.Bundle{Backend: anchor.LocalBackend}, want: "local anchor log"},
		{name: "Rekor missing key", bundle: anchor.Bundle{Backend: anchor.RekorBackend}, want: "pinned Rekor"},
		{name: "unknown backend", bundle: anchor.Bundle{Backend: "unknown"}, want: "unsupported"},
		{name: "Rekor configured", bundle: anchor.Bundle{Backend: anchor.RekorBackend}, keys: []crypto.PublicKey{pub}},
	}
	for _, tc := range backendTests {
		t.Run(tc.name, func(t *testing.T) {
			backend, err := anchorBackend(tc.bundle, tc.log, tc.keys)
			if tc.want == "" {
				if err != nil || backend == nil {
					t.Fatalf("backend=%T err=%v", backend, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBuildTrustKeyRows_BlastRadiusFromVerifiedSignatures(t *testing.T) {
	t.Parallel()

	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	otherPub, _ := generateDashboardKey(t)
	otherHex := hex.EncodeToString(otherPub)
	chain := buildDashboardChain(t, priv, 2)
	chain[0].ActionRecord.ActionType = receipt.ActionRead
	chain[0], _ = receipt.Sign(chain[0].ActionRecord, priv)
	chain[1].ActionRecord.ActionType = receipt.ActionWrite
	chain[1], _ = receipt.Sign(chain[1].ActionRecord, priv)

	rows := BuildTrustKeyRows(map[string]TrustedKey{
		keyHex:   {Source: "static operator import"},
		otherHex: {Source: "unused static import"},
	}, map[string][]receipt.Receipt{testSessionID: chain}, nil, nil)
	byKey := rowsByPublicKey(rows)
	if got := byKey[keyHex].BlastRadius; len(got) != 2 || got[0] != string(receipt.ActionRead) || got[1] != string(receipt.ActionWrite) {
		t.Fatalf("blast radius = %v, want exactly [read write]", got)
	}
	if got := byKey[otherHex].BlastRadius; len(got) != 0 {
		t.Fatalf("unused key blast radius = %v, want empty", got)
	}
}

func TestBuildTrustKeyRows_RevocationIdentityMustBeVerified(t *testing.T) {
	t.Parallel()

	trustedPub, _ := generateDashboardKey(t)
	_, attackerPriv := generateDashboardKey(t)
	trustedHex := hex.EncodeToString(trustedPub)
	forged := buildDashboardChain(t, attackerPriv, 1)[0]
	forged.SignerKey = trustedHex
	unsigned := forged
	unsigned.Signature = ""
	fingerprint, err := TrustKeyFingerprint(trustedHex)
	if err != nil {
		t.Fatalf("TrustKeyFingerprint: %v", err)
	}
	crl := &license.CRL{Payload: license.CRLPayload{RevokedIntermediates: []license.RevokedIntermediate{{
		Serial: fingerprint, Reason: "receipt signer retired", RevokedAt: time.Now().Add(-time.Hour).Unix(),
	}}}}

	rows := BuildTrustKeyRows(
		map[string]TrustedKey{trustedHex: {Source: "static operator import"}},
		map[string][]receipt.Receipt{testSessionID: {forged, unsigned}}, crl, nil,
	)
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].RevocationStatus != RevocationUnbound || !strings.Contains(rows[0].RevocationReason, "serial binding") {
		t.Fatalf("revocation = %q (%q), want fail-closed missing serial binding", rows[0].RevocationStatus, rows[0].RevocationReason)
	}
	if len(rows[0].BlastRadius) != 0 || rows[0].VerifiedReceipts != 0 || rows[0].RejectedReceipts != 2 {
		t.Fatalf("forged signature influenced trust row: %+v", rows[0])
	}
}

func TestBuildTrustKeyRows_CorruptCRLFailsClosed(t *testing.T) {
	t.Parallel()

	pub, _ := generateDashboardKey(t)
	rows := BuildTrustKeyRows(map[string]TrustedKey{hex.EncodeToString(pub): {Source: "static"}}, nil, nil, errTestCRL)
	if len(rows) != 1 || rows[0].RevocationStatus != RevocationFailure {
		t.Fatalf("rows = %+v, want CRL failure", rows)
	}
}

func TestTrustKeysRouteUsesDedicatedPermission(t *testing.T) {
	t.Parallel()

	var got Permission
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(), HasFeature: allowAgentsFeature,
		Authorize: func(*http.Request) error { return nil },
		AuthorizePermission: func(_ *http.Request, permission Permission) error {
			got = permission
			return nil
		},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/trust-keys", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || got != PermissionTrustKeysRead {
		t.Fatalf("status=%d permission=%q body=%s", rec.Code, got, rec.Body.String())
	}
}

func TestTrustKeysPermissionCannotReachOtherRoutes(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(), HasFeature: allowAgentsFeature,
		Authorize: func(*http.Request) error { return nil },
		AuthorizePermission: func(_ *http.Request, permission Permission) error {
			if permission == PermissionTrustKeysRead {
				return nil
			}
			return errTestCRL
		},
	})
	for _, path := range []string{"/", "/agents", "/session/hostile"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("GET %s status=%d, want 403 for trust-keys-only capability", path, rec.Code)
		}
	}
}

func TestTrustKeysTemplateEscapesHostileMetadata(t *testing.T) {
	t.Parallel()

	pub, _ := generateDashboardKey(t)
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(), HasFeature: allowAgentsFeature,
		TrustedKeys: map[string]TrustedKey{hex.EncodeToString(pub): {
			Source: `<script>alert("source")</script>`, ProvenanceKind: `<img src=x onerror=alert(1)>`, Location: `"><svg/onload=alert(2)>`,
		}},
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/trust-keys", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, raw := range []string{"<script>", "<img", "<svg"} {
		if strings.Contains(body, raw) {
			t.Fatalf("hostile metadata rendered as markup: found %q in %s", raw, body)
		}
	}
	for _, escaped := range []string{"&lt;script&gt;", "&lt;img", "&lt;svg"} {
		if !strings.Contains(body, escaped) {
			t.Fatalf("escaped hostile metadata missing %q from %s", escaped, body)
		}
	}
}

func TestTrustKeysHandlerFailures(t *testing.T) {
	t.Parallel()

	t.Run("wrong path", func(t *testing.T) {
		d := &dashboardHandler{model: NewReadModel(Options{ReceiptDir: t.TempDir()})}
		rec := httptest.NewRecorder()
		d.handleTrustKeys(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/wrong", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	tests := []struct {
		name   string
		method string
		dir    string
		want   int
	}{
		{name: "method", method: http.MethodPost, dir: t.TempDir(), want: http.StatusMethodNotAllowed},
		{name: "read failure", method: http.MethodGet, dir: filepath.Join(t.TempDir(), "missing"), want: http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := New(Options{
				TrustedOuterAuth: true, ReceiptDir: tc.dir, HasFeature: allowAgentsFeature,
			})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), tc.method, "/trust-keys", nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func mustReceiptHash(t *testing.T, r receipt.Receipt) string {
	t.Helper()
	hash, err := receipt.ReceiptHash(r)
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}
	return hash
}

func rowsByPublicKey(rows []TrustKeyRow) map[string]TrustKeyRow {
	out := make(map[string]TrustKeyRow, len(rows))
	for _, row := range rows {
		out[row.PublicKey] = row
	}
	return out
}

var errTestCRL = &testTrustError{"corrupt CRL"}

type testTrustError struct{ message string }

func (e *testTrustError) Error() string { return e.message }

var _ ed25519.PublicKey

func TestFileAnchorResolverRejectsHostileIndexEntries(t *testing.T) {
	t.Parallel()
	_, bundleBytes, marker := resolverFixture(t)

	mkIndexDir := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, "anchor-state.d"), 0o750); err != nil {
			t.Fatalf("mkdir index: %v", err)
		}
	}
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{name: "symlinked index directory", setup: func(t *testing.T, dir string) {
			if runtime.GOOS == "windows" {
				t.Skip("symlink creation needs privileges on Windows")
			}
			if err := os.Symlink(t.TempDir(), filepath.Join(dir, "anchor-state.d")); err != nil {
				t.Fatalf("symlink index dir: %v", err)
			}
		}},
		{name: "non json entry", setup: func(t *testing.T, dir string) {
			mkIndexDir(t, dir)
			if err := os.WriteFile(filepath.Join(dir, "anchor-state.d", "note.txt"), []byte("x"), anchorTestFileMode); err != nil {
				t.Fatalf("write entry: %v", err)
			}
		}},
		{name: "symlinked marker entry", setup: func(t *testing.T, dir string) {
			if runtime.GOOS == "windows" {
				t.Skip("symlink creation needs privileges on Windows")
			}
			mkIndexDir(t, dir)
			target := filepath.Join(dir, "target.json")
			if err := os.WriteFile(target, []byte("{}"), anchorTestFileMode); err != nil {
				t.Fatalf("write target: %v", err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "anchor-state.d", "link.json")); err != nil {
				t.Fatalf("symlink entry: %v", err)
			}
		}},
		{name: "identity mismatch filename", setup: func(t *testing.T, dir string) {
			mkIndexDir(t, dir)
			data, err := json.Marshal(marker)
			if err != nil {
				t.Fatalf("marshal marker: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "anchor-state.d", "wrong-name.json"), data, anchorTestFileMode); err != nil {
				t.Fatalf("write marker: %v", err)
			}
		}},
		{name: "duplicate legacy and index identity", setup: func(t *testing.T, dir string) {
			if err := anchor.WriteStateMarker(dir, marker); err != nil {
				t.Fatalf("write indexed marker: %v", err)
			}
			data, err := json.Marshal(marker)
			if err != nil {
				t.Fatalf("marshal marker: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "anchor-state.json"), data, anchorTestFileMode); err != nil {
				t.Fatalf("write legacy marker: %v", err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, marker.BundlePath), bundleBytes, anchorTestFileMode); err != nil {
				t.Fatalf("write bundle: %v", err)
			}
			tc.setup(t, dir)
			resolver, err := NewFileAnchorResolver(dir, filepath.Join(dir, "anchors.jsonl"), nil, false)
			if err != nil {
				t.Fatalf("NewFileAnchorResolver: %v", err)
			}
			if _, _, _, err := resolver(testSessionID); err == nil {
				t.Fatal("resolver accepted hostile index state")
			}
		})
	}
}

func TestFileAnchorResolverRejectsAmbiguousSessionMarkers(t *testing.T) {
	t.Parallel()
	_, bundleBytes, marker := resolverFixture(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, marker.BundlePath), bundleBytes, anchorTestFileMode); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := anchor.WriteStateMarker(dir, marker); err != nil {
		t.Fatalf("write indexed marker: %v", err)
	}
	second := marker
	second.FinalSeq = marker.FinalSeq + 1
	data, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anchor-state.json"), data, anchorTestFileMode); err != nil {
		t.Fatalf("write legacy marker: %v", err)
	}
	resolver, err := NewFileAnchorResolver(dir, filepath.Join(dir, "anchors.jsonl"), nil, false)
	if err != nil {
		t.Fatalf("NewFileAnchorResolver: %v", err)
	}
	if _, _, _, err := resolver(testSessionID); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("resolver err = %v, want ambiguous", err)
	}
}
