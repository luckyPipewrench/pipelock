// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	auditpacket "github.com/luckyPipewrench/pipelock/sdk/audit-packet"
)

// Test-local constants to keep goconst happy.
const (
	tHTTPS         = "https"
	tNotPipelock   = "not-pipelock"
	verdictAllowed = "allow"
	v2SignerID     = "receipt-signing-v2-test"
	v2ContractHash = "sha256:v2-contract"
)

// fixture holds a fully signed chain of receipts plus the keys that signed
// them. Tests reuse this shape to derive packets, evidence files, and
// signing-key files.
type fixture struct {
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	receipts []receipt.Receipt
	keyHex   string
}

type evidenceFixture struct {
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	receipts []contractreceipt.EvidenceReceipt
	keyHex   string
}

func newEvidenceFixture(t *testing.T, n int) *evidenceFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	receipts := make([]contractreceipt.EvidenceReceipt, 0, n)
	prev := contractreceipt.GenesisHash
	base := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	for i := range n {
		payload := contractreceipt.PayloadShadowDeltaStruct{
			ContractHash:     v2ContractHash,
			RuleID:           "rule-api",
			OriginalVerdict:  "allow",
			CandidateVerdict: "block",
			Aggregation: contractreceipt.ShadowDeltaAggregation{
				WindowStart:      base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339Nano),
				WindowEnd:        base.Add(time.Duration(i+1) * time.Minute).Format(time.RFC3339Nano),
				LosslessCount:    1,
				DeltaSampleCount: 1,
				ExemplarIDs:      []string{fmt.Sprintf("sha256:exemplar-%d", i)},
			},
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		r := contractreceipt.EvidenceReceipt{
			RecordType:       contractreceipt.RecordTypeEvidenceV2,
			ReceiptVersion:   2,
			PayloadKind:      contractreceipt.PayloadShadowDelta,
			Canonicalization: contractreceipt.DefaultCanonicalizationProfile(),
			Crit:             contractreceipt.CritForPayloadKind(contractreceipt.PayloadShadowDelta),
			EventID:          fmt.Sprintf("019e0000-0000-7000-8000-%012d", i+1),
			Timestamp:        base.Add(time.Duration(i) * time.Second),
			Principal:        "learn",
			Actor:            "shadow",
			ChainSeq:         uint64(i),
			ChainPrevHash:    prev,
			ContractHash:     v2ContractHash,
			SelectorID:       "selector-a",
			Payload:          payloadJSON,
		}
		preimage, err := r.SignablePreimage()
		if err != nil {
			t.Fatalf("preimage: %v", err)
		}
		r.Signature = contractreceipt.SignatureProof{
			SignerKeyID: v2SignerID,
			KeyPurpose:  "receipt-signing",
			Algorithm:   "ed25519",
			Signature:   "ed25519:" + hex.EncodeToString(ed25519.Sign(priv, preimage)),
		}
		h, err := contractreceipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("receipt hash: %v", err)
		}
		prev = h
		receipts = append(receipts, r)
	}
	return &evidenceFixture{
		pub:      pub,
		priv:     priv,
		receipts: receipts,
		keyHex:   hex.EncodeToString(pub),
	}
}

func (f *evidenceFixture) writeEvidenceJSONL(t *testing.T, path string) {
	t.Helper()
	var buf bytes.Buffer
	for _, r := range f.receipts {
		entry := map[string]any{
			"type":   "evidence_receipt",
			"detail": r,
		}
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal evidence entry: %v", err)
		}
		_, _ = buf.Write(line)
		_ = buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write evidence jsonl: %v", err)
	}
}

func newFixture(t *testing.T, n int) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	receipts := make([]receipt.Receipt, 0, n)
	prev := receipt.GenesisHash
	base := time.Date(2026, 5, 10, 14, 0, 0, 0, time.UTC)
	for i := range n {
		ar := receipt.ActionRecord{
			Version:       receipt.ActionRecordVersion,
			ActionID:      receipt.NewActionID(),
			ActionType:    receipt.ActionRead,
			Timestamp:     base.Add(time.Duration(i) * time.Second),
			Target:        "https://example.com/" + verdictAllowed,
			Verdict:       verdictAllowed,
			Transport:     tHTTPS,
			ChainPrevHash: prev,
			ChainSeq:      uint64(i),
			PolicyHash:    "policy-fixture",
		}
		r, err := receipt.Sign(ar, priv)
		if err != nil {
			t.Fatalf("Sign[%d]: %v", i, err)
		}
		h, err := receipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash[%d]: %v", i, err)
		}
		prev = h
		receipts = append(receipts, r)
	}
	return &fixture{
		pub:      pub,
		priv:     priv,
		receipts: receipts,
		keyHex:   hex.EncodeToString(pub),
	}
}

// writePacketDir lays out evidence.jsonl + verifier.txt + packet.json under
// dir. If mutate is non-nil it is called on the packet just before writing
// so individual tests can tamper specific fields.
func (f *fixture) writePacketDir(t *testing.T, dir string, mutate func(*auditpacket.Packet)) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	evidence := filepath.Join(dir, "evidence.jsonl")
	fhandle, err := os.OpenFile(filepath.Clean(evidence), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	prev := recorder.GenesisHash
	base := time.Date(2026, 5, 10, 14, 0, 0, 0, time.UTC)
	for i, r := range f.receipts {
		entry := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  uint64(i),
			Timestamp: base.Add(time.Duration(i) * time.Second),
			SessionID: "proxy",
			Type:      "action_receipt",
			Transport: tHTTPS,
			Summary:   verdictAllowed,
			Detail:    r,
			PrevHash:  prev,
		}
		entry.Hash = recorder.ComputeHash(entry)
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("Marshal entry: %v", err)
		}
		prev = entry.Hash
		if _, err := fhandle.Write(line); err != nil {
			t.Fatalf("write evidence: %v", err)
		}
		if _, err := fhandle.WriteString("\n"); err != nil {
			t.Fatalf("write newline: %v", err)
		}
	}
	if err := fhandle.Close(); err != nil {
		t.Fatalf("close evidence: %v", err)
	}
	verifier := filepath.Join(dir, "verifier.txt")
	if err := os.WriteFile(verifier, []byte("synthetic\n"), 0o600); err != nil {
		t.Fatalf("write verifier.txt: %v", err)
	}
	pkt := f.basePacket(len(f.receipts))
	if mutate != nil {
		mutate(&pkt)
	}
	pktPath := filepath.Join(dir, "packet.json")
	pktBytes, err := json.MarshalIndent(pkt, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if err := os.WriteFile(pktPath, pktBytes, 0o600); err != nil {
		t.Fatalf("write packet.json: %v", err)
	}
	return pktPath
}

// basePacket builds a v0-conformant packet that matches the fixture's chain.
// All counts go to summary.totals.allow, since the fixture mints `allowed`
// verdicts. trusted=true and verdict=valid because the fixture pins a key.
func (f *fixture) basePacket(n int) auditpacket.Packet {
	return auditpacket.Packet{
		SchemaVersion: auditpacket.SchemaVersion,
		GeneratedAt:   "2026-05-10T14:00:00Z",
		Run: auditpacket.Run{
			Provider:      auditpacket.ProviderLocal,
			AgentIdentity: "fixture-agent",
			StartedAt:     "2026-05-10T14:00:00Z",
		},
		Policy: auditpacket.Policy{
			PolicyHashes: []string{"policy-fixture"},
		},
		Summary: auditpacket.Summary{
			ReceiptCount: n,
			Totals: auditpacket.Totals{
				Allow: n,
			},
		},
		Verifier: auditpacket.Verifier{
			Verdict:   auditpacket.VerdictValid,
			Trusted:   true,
			SignerKey: f.keyHex,
		},
		Posture: auditpacket.Posture{
			EnforcementMode:        "linux_netns_iptables_setpriv",
			RunnerOS:               "Linux",
			RawSocketStatus:        auditpacket.StatusDenied,
			DockerSocketStatus:     auditpacket.StatusMasked,
			DNSUDPStatus:           auditpacket.StatusDenied,
			BrowserProxyStatus:     auditpacket.StatusForced,
			WebsocketFrameScanning: auditpacket.WebsocketFrameScanningExplicitProxyPathRequired,
			UnsupportedPaths:       []string{"mcp_transports", "ssh_egress"},
		},
		Artifacts: auditpacket.Artifacts{
			Packet:   "packet.json",
			Summary:  "summary.md",
			Evidence: "evidence.jsonl",
			Verifier: "verifier.txt",
		},
	}
}

// runRoot drives the full cobra root with the given args and captures
// stdout, stderr, and the resolved exit code.
func runRoot(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := root.Execute()
	return stdout.String(), stderr.String(), exitCodeFor(err)
}

func TestAuditPacket_HappyPath(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 3)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)

	stdout, stderr, code := runRoot(t, "audit-packet", dir)
	if code != cliutil.ExitOK {
		t.Fatalf("exit code = %d, stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "VALID") {
		t.Errorf("stdout missing VALID: %s", stdout)
	}
}

func TestAuditPacket_OfflineMode(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	pkt := fix.writePacketDir(t, dir, nil)

	// Delete evidence.jsonl to prove --offline does not read it.
	if err := os.Remove(filepath.Join(dir, "evidence.jsonl")); err != nil {
		t.Fatalf("remove evidence: %v", err)
	}

	stdout, stderr, code := runRoot(t, "audit-packet", "--offline", pkt)
	if code != cliutil.ExitOK {
		t.Fatalf("offline mode failed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "chain:        skipped") {
		t.Errorf("expected chain skipped marker, got %s", stdout)
	}
}

func TestAuditPacket_SchemaViolation(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, func(p *auditpacket.Packet) {
		p.SchemaVersion = "pipelock.audit_packet.v999" // forbidden
	})

	stdout, stderr, code := runRoot(t, "audit-packet", dir)
	if code == cliutil.ExitOK {
		t.Fatalf("expected non-zero exit on schema violation, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stderr, "schema") {
		t.Errorf("expected schema error in stderr, got %q", stderr)
	}
}

func TestAuditPacket_TotalsMismatch(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 4)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, func(p *auditpacket.Packet) {
		// Tamper: claim 3 allows + 1 block when chain has 4 allows.
		p.Summary.Totals.Allow = 3
		p.Summary.Totals.Block = 1
	})

	stdout, stderr, code := runRoot(t, "audit-packet", dir)
	if code == cliutil.ExitOK {
		t.Fatalf("expected mismatch failure, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stderr, "totals") {
		t.Errorf("expected totals error in stderr, got %q", stderr)
	}
}

func TestAuditPacket_ReceiptCountMismatch(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 3)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, func(p *auditpacket.Packet) {
		// receipt_count claims 2 but chain has 3. Totals must still sum to
		// receipt_count for the schema to pass, so adjust both.
		p.Summary.ReceiptCount = 2
		p.Summary.Totals.Allow = 2
	})

	_, stderr, code := runRoot(t, "audit-packet", dir)
	if code == cliutil.ExitOK {
		t.Fatalf("expected receipt_count mismatch failure, stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "receipt_count") {
		t.Errorf("expected receipt_count error in stderr, got %q", stderr)
	}
}

func TestAuditPacket_VerdictTamperedToInvalid(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, func(p *auditpacket.Packet) {
		// Schema requires verdict=valid <-> trusted=true. Tamper consistently
		// across both fields to pass schema, fail cross-check.
		p.Verifier.Verdict = auditpacket.VerdictInvalid
		p.Verifier.Trusted = false
	})

	_, stderr, code := runRoot(t, "audit-packet", dir)
	if code == cliutil.ExitOK {
		t.Fatalf("expected verdict-vs-chain mismatch failure, stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "chain re-verified") {
		t.Errorf("expected chain re-verified note, got %q", stderr)
	}
}

func TestAuditPacket_SelfConsistentOnly_DefaultRejected(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, func(p *auditpacket.Packet) {
		// Schema requires Trusted=false on self_consistent_only and signer_key
		// must be omitted (we omit it here even though the chain pins one,
		// because that is exactly the ephemeral-key shape).
		p.Verifier.Verdict = auditpacket.VerdictSelfConsistentOnly
		p.Verifier.Trusted = false
		p.Verifier.SignerKey = ""
	})

	_, _, code := runRoot(t, "audit-packet", dir)
	if code == cliutil.ExitOK {
		t.Fatalf("self_consistent_only should be rejected without --allow-self-consistent-only")
	}
}

func TestAuditPacket_SelfConsistentOnly_Allowed(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, func(p *auditpacket.Packet) {
		p.Verifier.Verdict = auditpacket.VerdictSelfConsistentOnly
		p.Verifier.Trusted = false
		p.Verifier.SignerKey = ""
	})

	stdout, stderr, code := runRoot(t, "audit-packet", "--allow-self-consistent-only", dir)
	if code != cliutil.ExitOK {
		t.Fatalf("expected pass with allow-self-consistent-only, code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestAuditPacket_NoTrustRequired(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, func(p *auditpacket.Packet) {
		// Use error verdict to prove the flag relaxes any verdict.
		p.Verifier.Verdict = auditpacket.VerdictError
		p.Verifier.Trusted = false
		p.Verifier.SignerKey = ""
	})

	// Without --no-trust-required this would fail; cross-check still runs
	// against an error-verdict packet, so we also need a tampered chain
	// claim set to error to bypass the verdict-vs-chain agreement check.
	_, stderr, code := runRoot(t, "audit-packet", "--no-trust-required", dir)
	if code != cliutil.ExitOK {
		t.Fatalf("--no-trust-required should pass error verdict, stderr=%q", stderr)
	}
}

func TestAuditPacket_ExpectedSHAMismatch(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	pkt := fix.writePacketDir(t, dir, nil)

	_, stderr, code := runRoot(t, "audit-packet", "--expect-sha256", strings.Repeat("a", 64), pkt)
	if code == cliutil.ExitOK {
		t.Fatalf("expected sha mismatch failure, stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "sha256 mismatch") {
		t.Errorf("expected sha256 mismatch text, got %q", stderr)
	}
}

func TestAuditPacket_ExpectedSHAMatch(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	pkt := fix.writePacketDir(t, dir, nil)
	raw, err := os.ReadFile(filepath.Clean(pkt))
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	sum := sha256Hex(raw)

	_, stderr, code := runRoot(t, "audit-packet", "--expect-sha256", sum, pkt)
	if code != cliutil.ExitOK {
		t.Fatalf("matching sha should pass, stderr=%q", stderr)
	}
}

func TestAuditPacket_PathContainmentRejected(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, func(p *auditpacket.Packet) {
		// Forced-build a packet that would resolve outside the directory.
		// Schema validation should reject this before we reach the resolver,
		// but we exercise the outside-dir resolver path explicitly via
		// resolveArtifactPath in a second sub-test below.
		p.Artifacts.Evidence = "../../../etc/passwd"
	})

	_, stderr, code := runRoot(t, "audit-packet", dir)
	if code == cliutil.ExitOK {
		t.Fatalf("expected containment rejection, stderr=%q", stderr)
	}
}

func TestAuditPacket_JSONOutput(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)

	stdout, _, code := runRoot(t, "audit-packet", "--json", dir)
	if code != cliutil.ExitOK {
		t.Fatalf("happy path failed under --json: code=%d", code)
	}
	var report auditPacketReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("json output not parseable: %v\nstdout=%s", err, stdout)
	}
	if !report.Valid {
		t.Errorf("expected valid=true, got %+v", report)
	}
	if report.Summary.ReceiptCount != 2 {
		t.Errorf("expected receipt_count=2, got %d", report.Summary.ReceiptCount)
	}
}

func TestAuditPacket_PacketAsFileArg(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	pkt := fix.writePacketDir(t, dir, nil)

	_, stderr, code := runRoot(t, "audit-packet", pkt)
	if code != cliutil.ExitOK {
		t.Fatalf("file-arg form should pass, stderr=%q", stderr)
	}
}

func TestAuditPacket_MissingPacket(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, stderr, code := runRoot(t, "audit-packet", filepath.Join(dir, "nonexistent.json"))
	if code == cliutil.ExitOK {
		t.Fatalf("expected non-zero exit, stderr=%q", stderr)
	}
}

func TestAuditPacket_BadJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pkt := filepath.Join(dir, "packet.json")
	if err := os.WriteFile(pkt, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write bad packet: %v", err)
	}

	_, stderr, code := runRoot(t, "audit-packet", pkt)
	if code == cliutil.ExitOK {
		t.Fatalf("expected non-zero on bad json, stderr=%q", stderr)
	}
}

func TestChain_Valid(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 3)
	dir := t.TempDir()
	pkt := fix.writePacketDir(t, dir, nil)
	_ = pkt
	evidence := filepath.Join(dir, "evidence.jsonl")

	stdout, _, code := runRoot(t, "chain", "--key", fix.keyHex, evidence)
	if code != cliutil.ExitOK {
		t.Fatalf("valid chain should pass, stdout=%q", stdout)
	}
	if !strings.Contains(stdout, "CHAIN VALID") {
		t.Errorf("missing CHAIN VALID marker, got %q", stdout)
	}
}

func TestChain_ActionWithoutKeyFailsUnpinned(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)
	evidence := filepath.Join(dir, "evidence.jsonl")

	stdout, stderr, code := runRoot(t, "chain", evidence)
	if code == cliutil.ExitOK {
		t.Fatalf("unpinned action chain should fail, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stderr, "CHAIN UNPINNED") {
		t.Fatalf("stderr = %q, want CHAIN UNPINNED", stderr)
	}
	if !strings.Contains(stderr, unpinnedReceiptBanner) {
		t.Fatalf("stderr = %q, want unpinned warning", stderr)
	}
}

func TestChain_ActionAllowUnpinned(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)
	evidence := filepath.Join(dir, "evidence.jsonl")

	stdout, stderr, code := runRoot(t, "chain", "--allow-unpinned", evidence)
	if code != cliutil.ExitOK {
		t.Fatalf("allow-unpinned action chain should pass, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, "CHAIN UNPINNED") {
		t.Fatalf("stdout = %q, want CHAIN UNPINNED", stdout)
	}
	if !strings.Contains(stdout, "warning:") {
		t.Fatalf("stdout = %q, want warning", stdout)
	}
}

func TestChain_TamperedSignature(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)
	evidence := filepath.Join(dir, "evidence.jsonl")

	// Corrupt the JSONL file by appending a malformed line; the chain
	// extractor should drop it but this also exercises the empty-or-broken
	// handling.
	raw, err := os.ReadFile(filepath.Clean(evidence))
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	// Tamper the first receipt's signature byte.
	tampered := bytes.Replace(raw, []byte(`"signature":"`), []byte(`"signature":"X`), 1)
	if err := os.WriteFile(evidence, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	_, stderr, code := runRoot(t, "chain", evidence)
	if code == cliutil.ExitOK {
		t.Fatalf("tampered chain should fail")
	}
	if !strings.Contains(stderr, "CHAIN BROKEN") && !strings.Contains(stderr, "rejected") {
		t.Errorf("expected broken-chain message, got %q", stderr)
	}
}

func TestChain_JSONOutput(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)
	evidence := filepath.Join(dir, "evidence.jsonl")

	stdout, _, code := runRoot(t, "chain", "--key", fix.keyHex, "--json", evidence)
	if code != cliutil.ExitOK {
		t.Fatalf("valid chain --json should pass")
	}
	var rpt chainReport
	if err := json.Unmarshal([]byte(stdout), &rpt); err != nil {
		t.Fatalf("json output not parseable: %v\nstdout=%s", err, stdout)
	}
	if !rpt.Valid || rpt.ReceiptCount != 2 {
		t.Errorf("unexpected report: %+v", rpt)
	}
}

func TestChain_DirAsFileFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, stderr, code := runRoot(t, "chain", dir)
	if code == cliutil.ExitOK {
		t.Fatalf("passing a dir without --dir should fail, stderr=%q", stderr)
	}
}

func TestChain_NotFound(t *testing.T) {
	t.Parallel()
	_, _, code := runRoot(t, "chain", filepath.Join(t.TempDir(), "missing.jsonl"))
	if code == cliutil.ExitOK {
		t.Fatalf("missing file should fail")
	}
}

func TestReceipt_Valid(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "r.json")
	data, err := receipt.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write receipt: %v", err)
	}

	stdout, _, code := runRoot(t, "receipt", "--key", fix.keyHex, rPath)
	if code != cliutil.ExitOK {
		t.Fatalf("valid receipt should pass, stdout=%q", stdout)
	}
}

func TestReceipt_TamperedSignature(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "r.json")
	r := fix.receipts[0]
	r.Signature = "ed25519:" + strings.Repeat("0", 128)
	data, err := receipt.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	_, stderr, code := runRoot(t, "receipt", "--allow-unpinned", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("tampered receipt should fail, stderr=%q", stderr)
	}
}

func TestReceipt_JSONOutput(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "r.json")
	data, err := receipt.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write receipt: %v", err)
	}

	stdout, _, code := runRoot(t, "receipt", "--key", fix.keyHex, "--json", rPath)
	if code != cliutil.ExitOK {
		t.Fatalf("valid receipt --json should pass")
	}
	var rpt receiptReport
	if err := json.Unmarshal([]byte(stdout), &rpt); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if !rpt.Valid {
		t.Errorf("expected valid=true, got %+v", rpt)
	}
}

func TestReceipt_V1WithoutKeyIsNotProvenance(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "r.json")
	data, err := receipt.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write receipt: %v", err)
	}

	stdout, _, code := runRoot(t, "receipt", "--json", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("unpinned v1 receipt should exit non-zero")
	}
	var rpt receiptReport
	if err := json.Unmarshal([]byte(stdout), &rpt); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if rpt.Valid {
		t.Fatalf("expected valid=false, got %+v", rpt)
	}
	if !rpt.Unpinned {
		t.Fatalf("expected unpinned=true, got %+v", rpt)
	}
	// Without a pinned --key, v1 verifies against the embedded signer key
	// (self-consistency), which is not provenance — mirror the v2 contract.
	if rpt.SignaturesVerified {
		t.Error("v1 receipt without --key must report signatures_verified=false")
	}
}

func TestReceipt_V1AllowUnpinned(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "r.json")
	data, err := receipt.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write receipt: %v", err)
	}

	stdout, stderr, code := runRoot(t, "receipt", "--allow-unpinned", rPath)
	if code != cliutil.ExitOK {
		t.Fatalf("allow-unpinned receipt should pass, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, "RECEIPT UNPINNED") {
		t.Fatalf("stdout = %q, want RECEIPT UNPINNED", stdout)
	}
	if !strings.Contains(stdout, "signature is self-consistent") {
		t.Fatalf("stdout = %q, want unpinned warning", stdout)
	}
}

func TestReceipt_EvidenceV2PinnedKey(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "shadow-delta.json")
	data, err := json.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("Marshal evidence receipt: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write evidence receipt: %v", err)
	}

	stdout, stderr, code := runRoot(t,
		"receipt",
		"--key", fix.keyHex,
		"--expect-payload-kind", string(contractreceipt.PayloadShadowDelta),
		"--expect-contract", v2ContractHash,
		rPath,
	)
	if code != cliutil.ExitOK {
		t.Fatalf("v2 receipt should pass, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, "signature:    verified") {
		t.Fatalf("stdout = %q, want signature verified", stdout)
	}
}

func TestReceipt_EvidenceV2WithoutKeyIsNotProvenance(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "shadow-delta.json")
	data, err := json.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("Marshal evidence receipt: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write evidence receipt: %v", err)
	}

	stdout, stderr, code := runRoot(t, "receipt", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("v2 receipt without key should exit non-zero, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stderr, "RECEIPT UNPINNED") {
		t.Fatalf("stderr = %q, want unpinned trust boundary", stderr)
	}
}

func TestReceipt_EvidenceV2AllowUnpinned(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "shadow-delta.json")
	data, err := json.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("Marshal evidence receipt: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write evidence receipt: %v", err)
	}

	stdout, stderr, code := runRoot(t, "receipt", "--allow-unpinned", rPath)
	if code != cliutil.ExitOK {
		t.Fatalf("allow-unpinned v2 receipt should pass, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, "RECEIPT UNPINNED") {
		t.Fatalf("stdout = %q, want RECEIPT UNPINNED", stdout)
	}
	if !strings.Contains(stdout, "signature:    not checked") {
		t.Fatalf("stdout = %q, want signature not checked", stdout)
	}
}

func TestReceipt_EvidenceV2WithoutKeyValidationFailure(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	bad := fix.receipts[0]
	bad.ReceiptVersion = 99
	dir := t.TempDir()
	rPath := filepath.Join(dir, "shadow-delta.json")
	data, err := json.Marshal(bad)
	if err != nil {
		t.Fatalf("Marshal evidence receipt: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write evidence receipt: %v", err)
	}

	_, stderr, code := runRoot(t, "receipt", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("invalid v2 receipt should fail, stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "RECEIPT INVALID") {
		t.Fatalf("stderr = %q, want RECEIPT INVALID", stderr)
	}
}

func TestReceipt_EvidenceV2RecheckSourceSpan(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.txt")
	if err := os.WriteFile(sourcePath, []byte("https://example.com/[redacted-value]"), 0o600); err != nil {
		t.Fatalf("write recheck source: %v", err)
	}
	receiptPath := filepath.Clean(filepath.Join("..", "..", "internal", "contract", "testdata", "golden", "valid_evidence_receipt_proxy_decision_with_spans.json"))
	keyHex := strings.Join([]string{
		"d75a980182b10ab7",
		"d54bfed3c964073a",
		"0ee172f3daa62325",
		"af021a68f707511a",
	}, "")
	stdout, stderr, code := runRoot(t,
		"receipt",
		"--json",
		"--key", keyHex,
		"--expect-payload-kind", string(contractreceipt.PayloadProxyDecisionWithSpans),
		"--recheck-source", sourcePath,
		receiptPath,
	)
	if code != cliutil.ExitOK {
		t.Fatalf("v2 recheck should pass, stdout=%q stderr=%q", stdout, stderr)
	}
	var rpt receiptReport
	if err := json.Unmarshal([]byte(stdout), &rpt); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if rpt.RecheckValid == nil || !*rpt.RecheckValid {
		t.Fatalf("expected recheck_valid=true, got %+v", rpt)
	}
	if rpt.RecheckView != contractreceipt.NormalizedViewSanitizedTarget {
		t.Fatalf("recheck_view=%q", rpt.RecheckView)
	}
}

func TestReceipt_EvidenceV2RecheckSourceSpanMismatchReportsInvalid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.txt")
	if err := os.WriteFile(sourcePath, []byte("https://example.com/xxxxxxxxxxxxxxxx"), 0o600); err != nil {
		t.Fatalf("write recheck source: %v", err)
	}
	receiptPath := filepath.Clean(filepath.Join("..", "..", "internal", "contract", "testdata", "golden", "valid_evidence_receipt_proxy_decision_with_spans.json"))
	keyHex := strings.Join([]string{
		"d75a980182b10ab7",
		"d54bfed3c964073a",
		"0ee172f3daa62325",
		"af021a68f707511a",
	}, "")
	stdout, stderr, code := runRoot(t,
		"receipt",
		"--json",
		"--key", keyHex,
		"--expect-payload-kind", string(contractreceipt.PayloadProxyDecisionWithSpans),
		"--recheck-source", sourcePath,
		receiptPath,
	)
	if code == cliutil.ExitOK {
		t.Fatalf("v2 recheck mismatch should fail, stdout=%q stderr=%q", stdout, stderr)
	}
	var rpt receiptReport
	if err := json.Unmarshal([]byte(stdout), &rpt); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if rpt.Valid {
		t.Fatalf("expected valid=false, got %+v", rpt)
	}
	if rpt.RecheckValid == nil || *rpt.RecheckValid {
		t.Fatalf("expected recheck_valid=false, got %+v", rpt)
	}
	if !strings.Contains(rpt.Error, "redacted_sample mismatch") {
		t.Fatalf("error=%q", rpt.Error)
	}
}

func TestReceipt_EvidenceV2RecheckSourceSpanMismatchWithoutKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.txt")
	if err := os.WriteFile(sourcePath, []byte("https://example.com/xxxxxxxxxxxxxxxx"), 0o600); err != nil {
		t.Fatalf("write recheck source: %v", err)
	}
	receiptPath := filepath.Clean(filepath.Join("..", "..", "internal", "contract", "testdata", "golden", "valid_evidence_receipt_proxy_decision_with_spans.json"))
	_, stderr, code := runRoot(t,
		"receipt",
		"--recheck-source", sourcePath,
		receiptPath,
	)
	if code == cliutil.ExitOK {
		t.Fatalf("v2 recheck mismatch without key should fail, stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "redacted_sample mismatch") {
		t.Fatalf("stderr=%q, want redacted_sample mismatch", stderr)
	}
}

func TestReceipt_EvidenceV2RejectsWrongPinnedKey(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	wrong := newEvidenceFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "shadow-delta.json")
	data, err := json.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("Marshal evidence receipt: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write evidence receipt: %v", err)
	}

	_, stderr, code := runRoot(t, "receipt", "--key", wrong.keyHex, rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("v2 receipt signed by wrong key should fail, stderr=%q", stderr)
	}
}

func TestReceipt_EvidenceV2ExpectationMismatch(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "shadow-delta.json")
	data, err := json.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("Marshal evidence receipt: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write evidence receipt: %v", err)
	}

	_, stderr, code := runRoot(t, "receipt", "--expect-contract", "sha256:other", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("v2 receipt contract mismatch should fail, stderr=%q", stderr)
	}
}

func TestReceipt_BadJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rPath := filepath.Join(dir, "r.json")
	if err := os.WriteFile(rPath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write bad: %v", err)
	}

	_, stderr, code := runRoot(t, "receipt", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("bad json should fail, stderr=%q", stderr)
	}
}

func TestResolveSignerKey(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hexKey := hex.EncodeToString(pub)

	t.Run("empty", func(t *testing.T) {
		got, err := resolveSignerKey("")
		if err != nil || got != "" {
			t.Errorf("want empty ok, got %q err=%v", got, err)
		}
	})

	t.Run("raw_hex", func(t *testing.T) {
		got, err := resolveSignerKey(hexKey)
		if err != nil || got != hexKey {
			t.Errorf("hex roundtrip failed: %q vs %q err=%v", got, hexKey, err)
		}
	})

	t.Run("file_path", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "key.txt")
		if err := os.WriteFile(f, []byte(hexKey), 0o600); err != nil {
			t.Fatalf("write key: %v", err)
		}
		got, err := resolveSignerKey(f)
		if err != nil || got != hexKey {
			t.Errorf("file path failed: %q vs %q err=%v", got, hexKey, err)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		if _, err := resolveSignerKey("not-a-key"); err == nil {
			t.Errorf("expected error on bad key")
		}
	})
}

func TestSha256Hex_Deterministic(t *testing.T) {
	t.Parallel()
	a := sha256Hex([]byte("hello"))
	b := sha256Hex([]byte("hello"))
	if a != b {
		t.Errorf("not deterministic: %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Errorf("expected 64-char hex, got %d", len(a))
	}
}

func TestExitCodeFor(t *testing.T) {
	t.Parallel()
	if got := exitCodeFor(nil); got != cliutil.ExitOK {
		t.Errorf("nil err -> %d, want %d", got, cliutil.ExitOK)
	}
	if got := exitCodeFor(errors.New("plain")); got != cliutil.ExitGeneral {
		t.Errorf("plain err -> %d, want %d", got, cliutil.ExitGeneral)
	}
	wrapped := cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("cfg"))
	if got := exitCodeFor(wrapped); got != cliutil.ExitConfig {
		t.Errorf("wrapped err -> %d, want %d", got, cliutil.ExitConfig)
	}
}

func TestUsageErrorsExit64(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing subcommand", args: []string{"audit-packet"}},
		{name: "unknown flag", args: []string{"chain", "--definitely-not-a-flag", "evidence.jsonl"}},
		{name: "unknown command", args: []string{"definitely-not-a-command"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, code := runRoot(t, tt.args...)
			if code != exitUsage {
				t.Fatalf("exit code = %d, want %d", code, exitUsage)
			}
		})
	}
}

func TestResolveArtifactPath(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	cases := []struct {
		name    string
		rel     string
		wantErr bool
	}{
		{"ok_relative", "evidence.jsonl", false},
		{"ok_subdir", filepath.Join("artifacts", "evidence.jsonl"), false},
		{"empty_path", "", true},
		{"absolute", "/etc/passwd", true},
		{"backslash", "evidence\\jsonl", true},
		{"colon", "C:evidence.jsonl", true},
		{"escape", "../escape", true},
		{"escape_deep", filepath.Join("..", "..", "..", "etc", "passwd"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Windows path semantics diverge from POSIX in three of the
			// subtests here, so they are skipped rather than asserting
			// Unix-specific behavior:
			//   - "backslash": legitimate path separator on Windows.
			//   - "ok_subdir": filepath.Join produces "artifacts\\..."
			//     on Windows, which the validator rejects (it shouldn't
			//     contain the backslash on Windows-built paths).
			//   - "absolute": "/etc/passwd" is not absolute on Windows
			//     (no drive letter), so the validator does not flag it.
			if runtime.GOOS == "windows" {
				switch tc.name {
				case "backslash":
					t.Skip("backslash is a valid path separator on Windows")
				case "ok_subdir":
					t.Skip("filepath.Join produces backslash-separated paths on Windows; the validator rejects backslashes")
				case "absolute":
					t.Skip("Unix-style /etc/passwd is not an absolute path on Windows")
				}
			}
			_, err := resolveArtifactPath(base, tc.rel)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q", tc.rel)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tc.rel, err)
			}
		})
	}
}

func TestResolveArtifactPath_SymlinkContainmentRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Symlink on Windows requires SeCreateSymbolicLinkPrivilege which non-admin shells lack; symlink containment is verified on Unix CI")
	}
	t.Parallel()
	base := t.TempDir()
	outside := t.TempDir()
	outsideTarget := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideTarget, []byte("secret\n"), 0o600); err != nil {
		t.Fatalf("write outside target: %v", err)
	}
	link := filepath.Join(base, "evidence.jsonl")
	if err := os.Symlink(outsideTarget, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := resolveArtifactPath(base, "evidence.jsonl"); err == nil {
		t.Fatalf("symlinked artifact pointing outside packet dir should be rejected")
	}
}

func TestVerifyExpectedSHA(t *testing.T) {
	t.Parallel()
	data := []byte("payload")
	good := sha256Hex(data)
	if err := verifyExpectedSHA(data, good); err != nil {
		t.Errorf("matching sha rejected: %v", err)
	}
	if err := verifyExpectedSHA(data, "GOOD"+strings.Repeat("0", 60)); err == nil {
		t.Errorf("mismatch accepted")
	}
	// Whitespace + uppercase tolerated.
	if err := verifyExpectedSHA(data, "  "+strings.ToUpper(good)+"  "); err != nil {
		t.Errorf("normalized sha rejected: %v", err)
	}
}

func TestComputeTotals(t *testing.T) {
	t.Parallel()
	// Empty receipts -> all zero buckets.
	totals := computeTotals(nil)
	for _, k := range []string{"allow", "block", "warn", "ask", "strip", "forward", "redirect", "other"} {
		if totals[k] != 0 {
			t.Errorf("expected %s=0 got %d", k, totals[k])
		}
	}

	// Build a synthetic mix exercising the unknown-verdict -> "other" branch.
	receipts := []receipt.Receipt{
		{ActionRecord: receipt.ActionRecord{Verdict: "allow"}},
		{ActionRecord: receipt.ActionRecord{Verdict: "block"}},
		{ActionRecord: receipt.ActionRecord{Verdict: "weird"}},
	}
	totals = computeTotals(receipts)
	if totals["allow"] != 1 || totals["block"] != 1 || totals["other"] != 1 {
		t.Errorf("unexpected totals: %+v", totals)
	}
}

func TestSortedKeys(t *testing.T) {
	t.Parallel()
	in := map[string]int{"c": 3, "a": 1, "b": 2}
	got := sortedKeys(in)
	want := []string{"a", "b", "c"}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("sortedKeys[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestRootVersionFlag(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runRoot(t, "--version")
	if !strings.Contains(stdout, "pipelock-verifier") {
		t.Errorf("expected version banner, got %q", stdout)
	}
}

func TestAuditPacket_VerdictTamperedToValidWithBrokenChain(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	pkt := fix.writePacketDir(t, dir, nil)
	_ = pkt
	// Break the chain after writing the packet to force chain.Valid=false
	// while the packet still claims verdict=valid.
	evidence := filepath.Join(dir, "evidence.jsonl")
	raw, err := os.ReadFile(filepath.Clean(evidence))
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	tampered := bytes.Replace(raw, []byte(`"chain_seq":1`), []byte(`"chain_seq":99`), 1)
	if err := os.WriteFile(evidence, tampered, 0o600); err != nil {
		t.Fatalf("write tampered evidence: %v", err)
	}

	_, stderr, code := runRoot(t, "audit-packet", dir)
	if code == cliutil.ExitOK {
		t.Fatalf("broken chain with valid claim should fail, stderr=%q", stderr)
	}
}

func TestChain_DirMode(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)
	// session-dir mode expects evidence-{session}-{N}.jsonl files. Rename
	// our evidence.jsonl into that shape and pass --dir.
	src := filepath.Join(dir, "evidence.jsonl")
	dst := filepath.Join(dir, "evidence-proxy-0.jsonl")
	if err := os.Rename(src, dst); err != nil {
		t.Fatalf("rename: %v", err)
	}
	stdout, _, code := runRoot(t, "chain", "--key", fix.keyHex, "--dir", dir)
	if code != cliutil.ExitOK {
		t.Fatalf("--dir mode should pass, stdout=%q", stdout)
	}
	if !strings.Contains(stdout, "session proxy") {
		t.Errorf("expected session label, got %q", stdout)
	}
}

func TestChain_WithExplicitKey(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)
	keyPath := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(keyPath, []byte(fix.keyHex), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	evidence := filepath.Join(dir, "evidence.jsonl")
	_, _, code := runRoot(t, "chain", "--key", keyPath, evidence)
	if code != cliutil.ExitOK {
		t.Fatalf("chain --key should pass")
	}
}

func TestChain_EvidenceV2PinnedKey(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 2)
	dir := t.TempDir()
	evidence := filepath.Join(dir, "evidence.jsonl")
	fix.writeEvidenceJSONL(t, evidence)

	stdout, stderr, code := runRoot(t,
		"chain",
		"--key", fix.keyHex,
		"--expect-signer-id", v2SignerID,
		"--expect-payload-kind", string(contractreceipt.PayloadShadowDelta),
		"--expect-contract", v2ContractHash,
		evidence,
	)
	if code != cliutil.ExitOK {
		t.Fatalf("v2 chain should pass, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, "signatures: verified") {
		t.Fatalf("stdout = %q, want signatures verified", stdout)
	}
}

func TestChain_EvidenceV2WithoutKeyFailsUnpinned(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 2)
	dir := t.TempDir()
	evidence := filepath.Join(dir, "evidence.jsonl")
	fix.writeEvidenceJSONL(t, evidence)

	stdout, stderr, code := runRoot(t, "chain", evidence)
	if code == cliutil.ExitOK {
		t.Fatalf("unpinned v2 chain should fail, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stderr, "CHAIN UNPINNED") {
		t.Fatalf("stderr = %q, want CHAIN UNPINNED", stderr)
	}
}

func TestChain_EvidenceV2AllowUnpinned(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 2)
	dir := t.TempDir()
	evidence := filepath.Join(dir, "evidence.jsonl")
	fix.writeEvidenceJSONL(t, evidence)

	stdout, stderr, code := runRoot(t, "chain", "--allow-unpinned", evidence)
	if code != cliutil.ExitOK {
		t.Fatalf("allow-unpinned v2 chain should pass, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, "CHAIN UNPINNED") {
		t.Fatalf("stdout = %q, want CHAIN UNPINNED", stdout)
	}
	if !strings.Contains(stdout, "signatures: not checked") {
		t.Fatalf("stdout = %q, want signatures not checked", stdout)
	}
}

func TestChain_EvidenceAliasDirMode(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 2)
	dir := t.TempDir()
	fix.writeEvidenceJSONL(t, filepath.Join(dir, "evidence-proxy-0.jsonl"))

	stdout, stderr, code := runRoot(t, "evidence", "--dir", "--key", fix.keyHex, dir)
	if code != cliutil.ExitOK {
		t.Fatalf("v2 evidence alias dir mode should pass, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, "record_type: evidence_receipt_v2") {
		t.Fatalf("stdout = %q, want v2 record type", stdout)
	}
}

func TestChain_EvidenceV2WrongPinnedKey(t *testing.T) {
	t.Parallel()
	forged := newEvidenceFixture(t, 2)
	legit := newEvidenceFixture(t, 1)
	dir := t.TempDir()
	evidence := filepath.Join(dir, "evidence.jsonl")
	forged.writeEvidenceJSONL(t, evidence)

	_, stderr, code := runRoot(t, "chain", "--key", legit.keyHex, evidence)
	if code == cliutil.ExitOK {
		t.Fatalf("v2 chain signed by wrong key should fail, stderr=%q", stderr)
	}
}

func TestChain_BadKey(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)
	evidence := filepath.Join(dir, "evidence.jsonl")
	_, _, code := runRoot(t, "chain", "--key", "not-a-key", evidence)
	if code == cliutil.ExitOK {
		t.Fatalf("invalid key should fail")
	}
}

func TestChain_EmptyChain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	evidence := filepath.Join(dir, "evidence.jsonl")
	if err := os.WriteFile(evidence, []byte(""), 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	_, _, code := runRoot(t, "chain", evidence)
	if code == cliutil.ExitOK {
		t.Fatalf("empty chain should fail")
	}
}

func TestReceipt_BadKey(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "r.json")
	data, err := receipt.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, code := runRoot(t, "receipt", "--key", "not-a-key", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("invalid key should fail")
	}
}

func TestReceipt_NotFound(t *testing.T) {
	t.Parallel()
	_, _, code := runRoot(t, "receipt", filepath.Join(t.TempDir(), "missing.json"))
	if code == cliutil.ExitOK {
		t.Fatalf("missing receipt should fail")
	}
}

func TestAuditPacket_BadSignerKey(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)
	_, _, code := runRoot(t, "audit-packet", "--key", "not-a-key", dir)
	if code == cliutil.ExitOK {
		t.Fatalf("bad --key should fail")
	}
}

func TestAuditPacket_BadEvidence(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)
	// Replace evidence with an unparseable file; ExtractReceipts should
	// surface the parse error and the audit-packet command should fail.
	if err := os.WriteFile(filepath.Join(dir, "evidence.jsonl"), []byte("not a recorder line\n"), 0o600); err != nil {
		t.Fatalf("write bad evidence: %v", err)
	}
	_, _, code := runRoot(t, "audit-packet", dir)
	if code == cliutil.ExitOK {
		t.Fatalf("bad evidence should fail")
	}
}

func TestTrustVerdict_DefaultBranch(t *testing.T) {
	t.Parallel()
	pkt := &auditpacket.Packet{Verifier: auditpacket.Verifier{Verdict: auditpacket.VerdictError}}
	if trustVerdict(pkt, auditPacketOptions{}) {
		t.Errorf("error verdict should not be trusted by default")
	}
	if !trustVerdict(pkt, auditPacketOptions{relaxTrust: true}) {
		t.Errorf("--no-trust-required should override")
	}
	pkt.Verifier.Verdict = auditpacket.VerdictNotRun
	if trustVerdict(pkt, auditPacketOptions{}) {
		t.Errorf("not_run should not be trusted by default")
	}
	pkt.Verifier.Verdict = auditpacket.VerdictInvalid
	if trustVerdict(pkt, auditPacketOptions{}) {
		t.Errorf("invalid should not be trusted by default")
	}
}

func TestAuditPacket_FinalSeqAndRootHashCrossCheck(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 3)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, func(p *auditpacket.Packet) {
		// Tamper the final_seq claim. v0 schema allows the field optional;
		// when set it must match the chain.
		p.Verifier.FinalSeq = 99
	})
	_, stderr, code := runRoot(t, "audit-packet", dir)
	if code == cliutil.ExitOK {
		t.Fatalf("final_seq mismatch should fail")
	}
	if !strings.Contains(stderr, "final_seq mismatch") {
		t.Errorf("expected final_seq mismatch error, got %q", stderr)
	}

	dir2 := t.TempDir()
	fix.writePacketDir(t, dir2, func(p *auditpacket.Packet) {
		p.Verifier.RootHash = strings.Repeat("a", 64)
	})
	_, stderr, code = runRoot(t, "audit-packet", dir2)
	if code == cliutil.ExitOK {
		t.Fatalf("root_hash mismatch should fail")
	}
	if !strings.Contains(stderr, "root_hash mismatch") {
		t.Errorf("expected root_hash mismatch error, got %q", stderr)
	}
}

func TestWriteJSON_MarshalFailure(t *testing.T) {
	t.Parallel()
	// chan values are not encodable; writeJSON should fall back to the
	// inline error envelope rather than panic.
	var buf bytes.Buffer
	writeJSON(&buf, make(chan int))
	if !strings.Contains(buf.String(), "json marshal failed") {
		t.Errorf("expected fallback envelope, got %q", buf.String())
	}
}

func TestEmitReport_HumanWithErrorsAndWarnings(t *testing.T) {
	t.Parallel()
	r := auditPacketReport{
		Path:        "/tmp/p",
		Verdict:     "valid",
		Trusted:     true,
		Valid:       true,
		SchemaCheck: "pass",
		ChainCheck:  "pass",
		CrossCheck:  "pass",
		Errors:      []string{"err1"},
		Warnings:    []string{"warn1"},
	}
	var stdout, stderr bytes.Buffer
	emitReport(&stdout, &stderr, r, false)
	if !strings.Contains(stdout.String(), "VALID") {
		t.Errorf("missing VALID, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "err1") || !strings.Contains(stderr.String(), "warn1") {
		t.Errorf("expected err1+warn1 in stderr, got %q", stderr.String())
	}
}

// TestAuditPacket_ReportContainsRunMetadata locks the JSON shape so consumers
// can grep stable field names.
func TestAuditPacket_ReportContainsRunMetadata(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 1)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, func(p *auditpacket.Packet) {
		p.Run.Repository = "owner/" + tNotPipelock
		p.Run.SHA = "deadbeefcafebabe"
	})

	stdout, _, code := runRoot(t, "audit-packet", "--json", dir)
	if code != cliutil.ExitOK {
		t.Fatalf("happy path failed: stdout=%q", stdout)
	}
	var report auditPacketReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if report.Run.Repository != "owner/"+tNotPipelock {
		t.Errorf("repository propagation failed: %q", report.Run.Repository)
	}
	if report.Run.SHA == "" {
		t.Errorf("sha missing")
	}
}

// ---------------------------------------------------------------------------
// Coverage-raising tests for CodeRabbit review fixes
// ---------------------------------------------------------------------------

func TestReceipt_MalformedJSON_PropagatesParseError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Write something that is valid JSON but has a v2 record_type marker
	// followed by invalid structure to trigger decodeEvidenceReceipt failure.
	rPath := filepath.Join(dir, "bad-v2.json")
	// Truncated JSON: record_type present but rest is garbage.
	if err := os.WriteFile(rPath, []byte(`{"record_type":"evidence_receipt_v2","receipt_version":"not-an-int"}`), 0o600); err != nil {
		t.Fatalf("write bad v2 receipt: %v", err)
	}
	_, stderr, code := runRoot(t, "receipt", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("malformed v2 receipt should fail, stderr=%q", stderr)
	}
	// Should surface a parse error, not a generic "require record_type" error.
	if strings.Contains(stderr, "require record_type") {
		t.Errorf("should surface parse error, not misroute to v1; stderr=%q", stderr)
	}
}

func TestReceipt_TruncatedJSON_PropagatesDetectError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rPath := filepath.Join(dir, "truncated.json")
	if err := os.WriteFile(rPath, []byte(`{"record_type": "evidence_re`), 0o600); err != nil {
		t.Fatalf("write truncated: %v", err)
	}
	_, stderr, code := runRoot(t, "receipt", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("truncated JSON should fail, stderr=%q", stderr)
	}
	// The error should mention JSON parsing, not "require record_type".
	if strings.Contains(stderr, "require record_type") {
		t.Errorf("truncated JSON should surface parse error; stderr=%q", stderr)
	}
}

func TestReceipt_UnsupportedRecordType(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rPath := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(rPath, []byte(`{"record_type":"future_v99"}`), 0o600); err != nil {
		t.Fatalf("write unknown type: %v", err)
	}
	_, stderr, code := runRoot(t, "receipt", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("unsupported record_type should fail, stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "unsupported receipt record_type") {
		t.Errorf("expected unsupported error, got stderr=%q", stderr)
	}
}

func TestReceipt_V2DuplicateKeysRejected(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	data, err := json.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Inject a duplicate "record_type" key to trigger RejectDuplicateKeys.
	dup := strings.Replace(string(data), `"record_type"`, `"record_type":"x","record_type"`, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "dup-keys.json")
	if err := os.WriteFile(rPath, []byte(dup), 0o600); err != nil {
		t.Fatalf("write dup: %v", err)
	}
	_, stderr, code := runRoot(t, "receipt", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("duplicate keys should be rejected, stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "duplicate") {
		t.Errorf("expected duplicate key error, got stderr=%q", stderr)
	}
}

func TestChain_EvidenceV2MalformedLine(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 2)
	dir := t.TempDir()
	evidence := filepath.Join(dir, "evidence.jsonl")
	fix.writeEvidenceJSONL(t, evidence)

	// Append a malformed evidence line.
	f, err := os.OpenFile(filepath.Clean(evidence), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	_, _ = f.WriteString(`{"type":"evidence_receipt","detail":"not-an-object"}` + "\n")
	_ = f.Close()

	_, stderr, code := runRoot(t, "chain", evidence)
	if code == cliutil.ExitOK {
		t.Fatalf("malformed evidence line should cause chain failure, stderr=%q", stderr)
	}
}

func TestChain_EvidenceV2DirHappyPath(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 3)
	dir := t.TempDir()
	fix.writeEvidenceJSONL(t, filepath.Join(dir, "evidence-proxy-0.jsonl"))

	stdout, stderr, code := runRoot(t,
		"chain", "--dir",
		"--key", fix.keyHex,
		"--expect-signer-id", v2SignerID,
		dir,
	)
	if code != cliutil.ExitOK {
		t.Fatalf("v2 dir happy path should pass, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, "signatures: verified") {
		t.Errorf("expected signatures verified, got stdout=%q", stdout)
	}
}

func TestChain_EvidenceV2DirMalformed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bad := filepath.Join(dir, "evidence-proxy-0.jsonl")
	if err := os.WriteFile(bad, []byte("not valid jsonl\n"), 0o600); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	_, stderr, code := runRoot(t, "chain", "--dir", dir)
	if code == cliutil.ExitOK {
		t.Fatalf("malformed dir evidence should fail, stderr=%q", stderr)
	}
}

func TestChain_EvidenceV2ExpectMismatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "signer_id_mismatch",
			args: []string{"--expect-signer-id", "wrong-signer"},
		},
		{
			name: "contract_mismatch",
			args: []string{"--expect-contract", "sha256:wrong"},
		},
		{
			name: "manifest_mismatch",
			args: []string{"--expect-manifest", "sha256:wrong"},
		},
		{
			name: "payload_kind_mismatch",
			args: []string{"--expect-payload-kind", "wrong_kind"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fix := newEvidenceFixture(t, 2)
			dir := t.TempDir()
			evidence := filepath.Join(dir, "evidence.jsonl")
			fix.writeEvidenceJSONL(t, evidence)
			args := append([]string{"chain", "--key", fix.keyHex}, tt.args...)
			args = append(args, evidence)
			_, stderr, code := runRoot(t, args...)
			if code == cliutil.ExitOK {
				t.Fatalf("expect mismatch should fail, stderr=%q", stderr)
			}
		})
	}
}

func TestDecodePinnedEvidenceKey_Errors(t *testing.T) {
	t.Parallel()
	t.Run("invalid_hex", func(t *testing.T) {
		t.Parallel()
		_, err := decodePinnedEvidenceKey("not-hex")
		if err == nil {
			t.Fatal("expected error on invalid hex")
		}
	})
	t.Run("wrong_length", func(t *testing.T) {
		t.Parallel()
		// Valid hex but wrong length (16 bytes instead of 32).
		_, err := decodePinnedEvidenceKey(strings.Repeat("ab", 16))
		if err == nil {
			t.Fatal("expected error on wrong key length")
		}
		if !strings.Contains(err.Error(), "pinned key length") {
			t.Errorf("expected pinned key length error, got %v", err)
		}
	})
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		key, err := decodePinnedEvidenceKey("")
		if err != nil {
			t.Fatalf("empty should succeed: %v", err)
		}
		if key != nil {
			t.Errorf("empty should return nil key, got %v", key)
		}
	})
}

func TestDetectSingleReceiptRecordType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		data     string
		wantType string
		wantErr  bool
	}{
		{name: "v2", data: `{"record_type":"evidence_receipt_v2"}`, wantType: recordTypeEvidenceV2},
		{name: "v1_explicit", data: `{"record_type":"action_receipt_v1"}`, wantType: recordTypeActionV1},
		{name: "v1_implicit", data: `{"version":1}`, wantType: recordTypeActionV1},
		{name: "empty_object", data: `{}`, wantType: ""},
		{name: "invalid_json", data: `{not json`, wantErr: true},
		{name: "truncated", data: `{"record_type":`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := detectSingleReceiptRecordType([]byte(tt.data))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantType {
				t.Errorf("got %q, want %q", got, tt.wantType)
			}
		})
	}
}

func TestVerifyEvidenceReceipt_ValidateOnlyPath(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	// Without a pinned key, verifyEvidenceReceipt does validate + hash only.
	sigVerified, err := verifyEvidenceReceipt(fix.receipts[0], "", evidenceBindingOptions{})
	if err != nil {
		t.Fatalf("validate-only should succeed: %v", err)
	}
	if sigVerified {
		t.Error("without pinned key, sigVerified should be false")
	}
}

func TestVerifyEvidenceReceipt_ManifestMismatch(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	_, err := verifyEvidenceReceipt(fix.receipts[0], fix.keyHex, evidenceBindingOptions{
		expectManifestHash: "sha256:wrong-manifest",
	})
	if err == nil {
		t.Fatal("expected manifest mismatch error")
	}
	if !strings.Contains(err.Error(), "active_manifest_hash") {
		t.Errorf("expected manifest error, got %v", err)
	}
}

func TestChainVerifyOptions_BadKey(t *testing.T) {
	t.Parallel()
	opts := evidenceBindingOptions{}
	_, err := opts.chainVerifyOptions("not-valid-hex")
	if err == nil {
		t.Fatal("expected error on bad hex key")
	}
}

func TestReceipt_EvidenceV2ExpectSignerIDMismatch(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "r.json")
	data, err := json.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, stderr, code := runRoot(t, "receipt", "--expect-signer-id", "wrong-signer", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("signer mismatch should fail, stderr=%q", stderr)
	}
}

func TestReceipt_EvidenceV2ExpectManifestMismatch(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "r.json")
	data, err := json.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, stderr, code := runRoot(t, "receipt", "--expect-manifest", "sha256:wrong", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("manifest mismatch should fail, stderr=%q", stderr)
	}
}

func TestReceipt_EvidenceV2ExpectPayloadKindMismatch(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	dir := t.TempDir()
	rPath := filepath.Join(dir, "r.json")
	data, err := json.Marshal(fix.receipts[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(rPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, stderr, code := runRoot(t, "receipt", "--expect-payload-kind", "wrong_kind", rPath)
	if code == cliutil.ExitOK {
		t.Fatalf("payload kind mismatch should fail, stderr=%q", stderr)
	}
}

func TestVerifyEvidenceReceipt_ValidateError(t *testing.T) {
	t.Parallel()
	// Build a receipt with an empty EventID so Validate() fails.
	fix := newEvidenceFixture(t, 1)
	r := fix.receipts[0]
	r.EventID = "" // Validate requires non-empty EventID
	_, err := verifyEvidenceReceipt(r, "", evidenceBindingOptions{})
	if err == nil {
		t.Fatal("expected validate error for empty EventID")
	}
}

func TestChain_EvidenceV2WithExpectFlagsOnV1Fails(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)
	evidence := filepath.Join(dir, "evidence.jsonl")

	// Pass --expect-signer-id on a v1 chain. The chain subcommand should
	// reject the mismatch and exit non-zero.
	_, _, code := runRoot(t, "chain", "--expect-signer-id", "some-id", evidence)
	if code == cliutil.ExitOK {
		t.Fatalf("v2 expect flags on v1 chain should fail")
	}
}
