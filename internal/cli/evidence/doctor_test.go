// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
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
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestEvidenceDoctorCleanDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeDoctorEntries(t, dir, "evidence-proxy-0.jsonl", doctorEntryPlan{
		{session: "proxy", seq: 0, prev: recorder.GenesisHash},
		{session: "proxy", seq: 1},
	})

	report, err := runEvidenceDoctor(dir)
	if err != nil {
		t.Fatalf("runEvidenceDoctor: %v", err)
	}
	if report.Damaged() {
		t.Fatalf("clean directory reported damage: %+v", report.Findings)
	}

	var stdout bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"doctor", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("doctor command clean dir: %v", err)
	}
	if !strings.Contains(stdout.String(), "healthy") {
		t.Fatalf("doctor output = %q, want healthy", stdout.String())
	}
}

func TestEvidenceDoctorDamageFindings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		setup    func(t *testing.T, dir string)
		wantKind string
	}{
		{
			name: "duplicate sequence",
			setup: func(t *testing.T, dir string) {
				writeDoctorEntries(t, dir, "evidence-proxy-0.jsonl", doctorEntryPlan{
					{session: "proxy", seq: 0, prev: recorder.GenesisHash},
				})
				writeDoctorEntries(t, dir, "evidence-proxy-1.jsonl", doctorEntryPlan{
					{session: "proxy", seq: 0, prev: recorder.GenesisHash, summary: "fork"},
				})
			},
			wantKind: "duplicate_recorder_seq",
		},
		{
			name: "conflicting prev hash",
			setup: func(t *testing.T, dir string) {
				writeDoctorEntries(t, dir, "evidence-proxy-0.jsonl", doctorEntryPlan{
					{session: "proxy", seq: 0, prev: recorder.GenesisHash},
					{session: "proxy", seq: 1, prev: "left-prev"},
				})
				writeDoctorEntries(t, dir, "evidence-proxy-2.jsonl", doctorEntryPlan{
					{session: "proxy", seq: 1, prev: "right-prev"},
				})
			},
			wantKind: "conflicting_recorder_prev_hash",
		},
		{
			name: "escrow collision",
			setup: func(t *testing.T, dir string) {
				writeDoctorEntries(t, dir, "evidence-proxy-0.jsonl", doctorEntryPlan{
					{session: "proxy", seq: 0, prev: recorder.GenesisHash, rawRef: "evidence-proxy-0.raw.enc"},
					{session: "proxy", seq: 1, rawRef: "evidence-proxy-0.raw.enc"},
				})
				if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.raw.enc"), []byte("ciphertext"), 0o600); err != nil {
					t.Fatalf("write sidecar: %v", err)
				}
			},
			wantKind: "escrow_collision",
		},
		{
			name: "missing genesis",
			setup: func(t *testing.T, dir string) {
				writeDoctorEntries(t, dir, "evidence-proxy-1.jsonl", doctorEntryPlan{
					{session: "proxy", seq: 1, prev: "not-genesis"},
				})
			},
			wantKind: "missing_genesis",
		},
		{
			name: "chain gap",
			setup: func(t *testing.T, dir string) {
				writeDoctorEntries(t, dir, "evidence-proxy-0.jsonl", doctorEntryPlan{
					{session: "proxy", seq: 0, prev: recorder.GenesisHash},
					{session: "proxy", seq: 2},
				})
			},
			wantKind: "chain_gap",
		},
		{
			name: "malformed json line",
			setup: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), []byte("{\n"), 0o600); err != nil {
					t.Fatalf("write malformed evidence: %v", err)
				}
			},
			wantKind: "malformed_jsonl",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			tc.setup(t, dir)

			report, err := runEvidenceDoctor(dir)
			if err != nil {
				t.Fatalf("runEvidenceDoctor: %v", err)
			}
			if !hasDoctorFinding(report, tc.wantKind) {
				t.Fatalf("findings = %+v, want %s", report.Findings, tc.wantKind)
			}
		})
	}
}

func TestEvidenceDoctorDuplicateV2ChainSeqIgnoresPayloadKind(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := minimalDoctorV2Receipt(t, 0, recorder.GenesisHash, "proxy_decision")
	second := minimalDoctorV2Receipt(t, 0, "other-prev", "shadow_delta")
	writeDoctorRawEntries(t, dir, "evidence-proxy-0.jsonl", []recorder.Entry{
		doctorRawReceiptEntry(t, "proxy", 0, recorder.GenesisHash, first),
		doctorRawReceiptEntry(t, "proxy", 1, recorder.ComputeHash(doctorRawReceiptEntry(t, "proxy", 0, recorder.GenesisHash, first)), second),
	})

	report, err := runEvidenceDoctor(dir)
	if err != nil {
		t.Fatalf("runEvidenceDoctor: %v", err)
	}
	if !hasDoctorFinding(report, "duplicate_receipt_chain_seq") {
		t.Fatalf("findings = %+v, want duplicate v2 receipt chain_seq", report.Findings)
	}
	got := strings.Join(doctorFindingMessages(report), "\n")
	if !strings.Contains(got, "proxy_decision") || !strings.Contains(got, "shadow_delta") {
		t.Fatalf("duplicate finding should include both payload kinds, got:\n%s", got)
	}
}

func TestEvidenceDoctorExitCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		damaged  bool
		wantCode int
	}{
		{name: "clean", wantCode: cliutil.ExitOK},
		{name: "damaged", damaged: true, wantCode: cliutil.ExitGeneral},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if tc.damaged {
				writeDoctorEntries(t, dir, "evidence-proxy-1.jsonl", doctorEntryPlan{
					{session: "proxy", seq: 1, prev: "not-genesis"},
				})
			} else {
				writeDoctorEntries(t, dir, "evidence-proxy-0.jsonl", doctorEntryPlan{
					{session: "proxy", seq: 0, prev: recorder.GenesisHash},
				})
			}

			cmd := Cmd()
			cmd.SetOut(new(bytes.Buffer))
			cmd.SetErr(new(bytes.Buffer))
			cmd.SetArgs([]string{"doctor", dir})
			err := cmd.Execute()
			gotCode := cliutil.ExitOK
			if err != nil {
				gotCode = cliutil.ExitCodeOf(err)
			}
			if gotCode != tc.wantCode {
				t.Fatalf("exit code = %d, want %d (err=%v)", gotCode, tc.wantCode, err)
			}
		})
	}
}

func TestEvidenceDoctorDirectoryReadFailures(t *testing.T) {
	t.Parallel()
	// A directory past the recorder's resume cap is the exact state the doctor
	// exists to diagnose, so it must scan rather than refuse. Refusing here
	// would blind the operator to the damage that pushed the count over the cap
	// in the first place.
	t.Run("over recorder cap still scans", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		// Sidecars count toward the file budget without being parsed as JSONL,
		// so they push the directory past the recorder cap without inventing
		// empty chain shards that would themselves be a finding.
		for i := 0; i <= recorder.MaxEvidenceReadDirectoryEntries; i++ {
			name := fmt.Sprintf("evidence-proxy-%d.raw.enc", i)
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
		writeDoctorEntries(t, dir, "evidence-proxy-0.jsonl", doctorEntryPlan{
			{session: "proxy", seq: 0, prev: recorder.GenesisHash},
		})
		report, err := runEvidenceDoctor(dir)
		if err != nil {
			t.Fatalf("runEvidenceDoctor: %v", err)
		}
		if hasDoctorFinding(report, "directory_read_error") {
			t.Fatalf("doctor refused an over-recorder-cap directory: %+v", report.Findings)
		}
		if !report.Conclusive() {
			t.Fatal("report should be conclusive below the doctor budget")
		}
		if report.FilesRead == 0 {
			t.Fatal("FilesRead = 0, doctor read nothing")
		}
	})

	// Past the doctor's own budget the scan is genuinely partial. It must say so
	// and must not be reported as healthy: no findings over a partial view is
	// not evidence of an intact chain.
	t.Run("over doctor budget is inconclusive not healthy", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		for i := 0; i <= maxEvidenceDoctorFiles; i++ {
			name := fmt.Sprintf("evidence-proxy-%d.raw.enc", i)
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
		report, err := runEvidenceDoctor(dir)
		if err != nil {
			t.Fatalf("runEvidenceDoctor: %v", err)
		}
		if report.Conclusive() {
			t.Fatal("a truncated scan must not be reported as conclusive")
		}
		if report.FilesSkipped == 0 {
			t.Fatal("FilesSkipped = 0 on a truncated scan")
		}
		var buf bytes.Buffer
		cmd := Cmd()
		cmd.SetOut(&buf)
		printEvidenceDoctorReport(cmd, report)
		out := buf.String()
		if strings.Contains(out, "healthy") {
			t.Fatalf("truncated scan reported as healthy: %q", out)
		}
		if !strings.Contains(out, "inconclusive") {
			t.Fatalf("truncated clean scan should read inconclusive: %q", out)
		}
		if !strings.Contains(out, "absence of damage is NOT confirmed") {
			t.Fatalf("truncated scan must state its own incompleteness: %q", out)
		}
	})

	t.Run("unreadable directory fails closed", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if os.Geteuid() == 0 {
			t.Skip("root can read chmod 0 directories")
		}
		if err := os.Chmod(dir, 0); err != nil {
			t.Fatalf("chmod unreadable: %v", err)
		}
		// Restore search bits so t.TempDir cleanup can remove the directory.
		const restoreMode os.FileMode = 0o700
		t.Cleanup(func() { _ = os.Chmod(dir, restoreMode) })
		report, err := runEvidenceDoctor(dir)
		if err != nil {
			t.Fatalf("runEvidenceDoctor: %v", err)
		}
		if !hasDoctorFinding(report, "directory_read_error") {
			t.Fatalf("findings = %+v, want directory_read_error", report.Findings)
		}
	})
}

type doctorEntrySpec struct {
	session string
	seq     uint64
	prev    string
	rawRef  string
	summary string
}

type doctorEntryPlan []doctorEntrySpec

func writeDoctorEntries(t *testing.T, dir, name string, plan doctorEntryPlan) {
	t.Helper()
	entries := make([]recorder.Entry, 0, len(plan))
	prev := recorder.GenesisHash
	for i, spec := range plan {
		if spec.prev != "" {
			prev = spec.prev
		}
		summary := spec.summary
		if summary == "" {
			summary = "test"
		}
		entry := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  spec.seq,
			Timestamp: doctorTestTime(t, 1700000000, i),
			SessionID: spec.session,
			Type:      "decision",
			EventKind: "proxy_decision",
			Transport: "fetch",
			Summary:   summary,
			Detail:    map[string]string{"summary": summary},
			RawRef:    spec.rawRef,
			PrevHash:  prev,
		}
		entry.Hash = recorder.ComputeHash(entry)
		entries = append(entries, entry)
		prev = entry.Hash
	}
	writeDoctorRawEntries(t, dir, name, entries)
}

func writeDoctorRawEntries(t *testing.T, dir, name string, entries []recorder.Entry) {
	t.Helper()
	var data []byte
	for _, entry := range entries {
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		data = append(data, line...)
		data = append(data, '\n')
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
}

func minimalDoctorV2Receipt(t *testing.T, seq uint64, prevHash, kind string) json.RawMessage {
	t.Helper()
	data := fmt.Sprintf(`{
		"record_type":"evidence_receipt_v2",
		"receipt_version":2,
		"payload_kind":%q,
		"signature":{"signer_key_id":"signer-a"},
		"chain_seq":%d,
		"chain_prev_hash":%q,
		"payload":{}
	}`, kind, seq, prevHash)
	return json.RawMessage(data)
}

func doctorRawReceiptEntry(t *testing.T, session string, seq uint64, prev string, detail json.RawMessage) recorder.Entry {
	t.Helper()
	entry := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  seq,
		Timestamp: doctorTestTime(t, 1700000100, 0),
		SessionID: session,
		Type:      "evidence_receipt",
		EventKind: "proxy_decision",
		Transport: "fetch",
		Summary:   "v2",
		Detail:    detail,
		PrevHash:  prev,
	}
	entry.Hash = recorder.ComputeHash(entry)
	return entry
}

// doctorTestTime builds a fixture timestamp. The offset is a signed index
// rather than a recorder sequence, so no unsigned-to-signed widening is needed.
// The doctor never inspects timestamps; they only have to be valid.
func doctorTestTime(t *testing.T, base int64, offsetSeconds int) time.Time {
	t.Helper()
	const maxDoctorTestOffset = 1_000_000
	if offsetSeconds < 0 || offsetSeconds > maxDoctorTestOffset {
		t.Fatalf("offset %d outside test timestamp bound [0,%d]", offsetSeconds, maxDoctorTestOffset)
	}
	return time.Unix(base+int64(offsetSeconds), 0).UTC()
}

func hasDoctorFinding(report evidenceDoctorReport, kind string) bool {
	for _, finding := range report.Findings {
		if finding.Kind == kind {
			return true
		}
	}
	return false
}

func doctorFindingMessages(report evidenceDoctorReport) []string {
	out := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		out = append(out, finding.Message)
	}
	return out
}

func TestEvidenceDoctorCapConstant(t *testing.T) {
	t.Parallel()
	if recorder.MaxEvidenceReadDirectoryEntries != 256 {
		t.Fatalf("MaxEvidenceReadDirectoryEntries = %d, want 256", recorder.MaxEvidenceReadDirectoryEntries)
	}
}

func TestEvidenceDoctorNonDirectory(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "evidence-file")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := runEvidenceDoctor(path); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("runEvidenceDoctor non-directory err = %v, want not a directory", err)
	}
}

func TestEvidenceDoctorMissingDirectory(t *testing.T) {
	t.Parallel()
	_, err := runEvidenceDoctor(filepath.Join(t.TempDir(), "missing"))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runEvidenceDoctor missing dir err = %v, want not exist", err)
	}
}

// TestEvidenceDoctorMalformedReceiptDetail covers the receipt-decode failure
// paths. A receipt the doctor cannot parse must be reported, not skipped:
// silently ignoring an unreadable receipt would let real damage hide behind a
// clean verdict.
func TestEvidenceDoctorMalformedReceiptDetail(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		entryType string
		detail    any
		rawDetail json.RawMessage
		wantMsg   string
	}{
		{
			name:      "v1 detail is not encodable",
			entryType: "action_receipt",
			detail:    make(chan int), // json.Marshal cannot encode a channel
			wantMsg:   "action_receipt detail is not JSON",
		},
		{
			name:      "v1 detail is not a receipt",
			entryType: "action_receipt",
			rawDetail: json.RawMessage(`{"not":"a receipt"}`),
			wantMsg:   "decode action_receipt",
		},
		{
			name:      "v2 detail is not encodable",
			entryType: "evidence_receipt",
			detail:    make(chan int),
			wantMsg:   "evidence_receipt detail is not JSON",
		},
		{
			name:      "v2 detail is not valid json",
			entryType: "evidence_receipt",
			rawDetail: json.RawMessage(`{"chain_seq":`),
			wantMsg:   "decode evidence_receipt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := &evidenceDoctor{
				dir:          t.TempDir(),
				sidecarFiles: make(map[string]struct{}),
				receiptRefs:  make(map[string][]doctorChainRef),
				escrowRefs:   make(map[string][]doctorEntryRef),
			}
			d.scanReceiptEntry("evidence-proxy-0.jsonl", recorder.Entry{
				Version:   recorder.EntryVersion,
				Sequence:  0,
				SessionID: "proxy",
				Type:      tc.entryType,
				Detail:    tc.detail,
				RawDetail: tc.rawDetail,
			})
			report := evidenceDoctorReport{Findings: d.findings}
			if !hasDoctorFinding(report, "malformed_receipt") {
				t.Fatalf("findings = %+v, want malformed_receipt", d.findings)
			}
			if got := strings.Join(doctorFindingMessages(report), "\n"); !strings.Contains(got, tc.wantMsg) {
				t.Fatalf("message = %q, want substring %q", got, tc.wantMsg)
			}
			// A receipt that cannot be parsed must not be silently admitted to a chain.
			if len(d.receiptRefs) != 0 {
				t.Fatalf("unparseable receipt was added to a chain: %+v", d.receiptRefs)
			}
		})
	}
}

// TestRawEntryDetailSources covers the three ways a detail payload reaches the
// doctor, plus the unencodable case that must report failure rather than
// returning empty bytes that would later decode as "no receipt".
func TestRawEntryDetailSources(t *testing.T) {
	t.Parallel()

	t.Run("raw detail wins", func(t *testing.T) {
		t.Parallel()
		got, ok := rawEntryDetail(recorder.Entry{
			RawDetail: json.RawMessage(`{"from":"raw"}`),
			Detail:    map[string]string{"from": "struct"},
		})
		if !ok || !strings.Contains(string(got), `"raw"`) {
			t.Fatalf("got %q ok=%v, want the RawDetail bytes", got, ok)
		}
	})

	t.Run("json.RawMessage detail", func(t *testing.T) {
		t.Parallel()
		got, ok := rawEntryDetail(recorder.Entry{Detail: json.RawMessage(`{"a":1}`)})
		if !ok || string(got) != `{"a":1}` {
			t.Fatalf("got %q ok=%v", got, ok)
		}
	})

	t.Run("marshalable struct detail", func(t *testing.T) {
		t.Parallel()
		got, ok := rawEntryDetail(recorder.Entry{Detail: map[string]int{"a": 1}})
		if !ok || string(got) != `{"a":1}` {
			t.Fatalf("got %q ok=%v", got, ok)
		}
	})

	t.Run("unencodable detail reports failure", func(t *testing.T) {
		t.Parallel()
		got, ok := rawEntryDetail(recorder.Entry{Detail: make(chan int)})
		if ok {
			t.Fatalf("unencodable detail reported success with %q", got)
		}
		if got != nil {
			t.Fatalf("got %q, want nil on failure", got)
		}
	})
}

// TestEvidenceDoctorCommandExitPaths covers the command-level outcomes an
// operator or CI job actually observes. The inconclusive case matters most: a
// partial scan must not exit zero, or a CI gate would go green on a directory
// nobody fully read.
func TestEvidenceDoctorCommandExitPaths(t *testing.T) {
	t.Parallel()

	t.Run("missing directory is a config error", func(t *testing.T) {
		t.Parallel()
		cmd := Cmd()
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"doctor", filepath.Join(t.TempDir(), "does-not-exist")})
		err := cmd.Execute()
		if err == nil {
			t.Fatal("missing directory should be an error")
		}
		if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
			t.Fatalf("exit code = %d, want ExitConfig %d", got, cliutil.ExitConfig)
		}
	})

	t.Run("a file instead of a directory is a config error", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		cmd := Cmd()
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"doctor", path})
		if err := cmd.Execute(); err == nil {
			t.Fatal("a regular file should be rejected")
		}
	})

	t.Run("truncated scan exits nonzero", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		for i := 0; i <= maxEvidenceDoctorFiles; i++ {
			name := fmt.Sprintf("evidence-proxy-%d.raw.enc", i)
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
		var out bytes.Buffer
		cmd := Cmd()
		cmd.SetOut(&out)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"doctor", dir})
		err := cmd.Execute()
		if err == nil {
			t.Fatalf("truncated scan exited zero; output=%q", out.String())
		}
		if got := cliutil.ExitCodeOf(err); got != cliutil.ExitGeneral {
			t.Fatalf("exit code = %d, want ExitGeneral %d", got, cliutil.ExitGeneral)
		}
	})
}

// TestEvidenceDoctorDetectsTamperedEntry is the guard for the doctor's core
// promise. Operators reach for it to tell fork damage apart from tampering, so
// it must recompute each entry's hash rather than trusting the stored field. An
// edited record that keeps its original hash value is exactly the case a
// trusting implementation would report as healthy.
func TestEvidenceDoctorDetectsTamperedEntry(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeDoctorEntries(t, dir, "evidence-proxy-0.jsonl", doctorEntryPlan{
		{session: "proxy", seq: 0, prev: recorder.GenesisHash, summary: "original"},
	})
	path := filepath.Join(dir, "evidence-proxy-0.jsonl")

	// Edit the payload while leaving the recorded hash untouched.
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	tampered := bytes.Replace(raw, []byte(`"original"`), []byte(`"tampered"`), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("fixture did not contain the expected payload to tamper with")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	report, err := runEvidenceDoctor(dir)
	if err != nil {
		t.Fatalf("runEvidenceDoctor: %v", err)
	}
	if !hasDoctorFinding(report, "entry_hash_mismatch") {
		t.Fatalf("tampered entry not detected; findings = %+v", report.Findings)
	}
}

// TestEvidenceDoctorFlagsEmptyShard covers the other way damage hides: a shard
// that was emptied or truncated contributes no entries, so every linkage check
// passes over it silently unless its emptiness is itself reported.
func TestEvidenceDoctorFlagsEmptyShard(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), []byte(""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	report, err := runEvidenceDoctor(dir)
	if err != nil {
		t.Fatalf("runEvidenceDoctor: %v", err)
	}
	if !hasDoctorFinding(report, "empty_evidence_file") {
		t.Fatalf("empty shard not reported; findings = %+v", report.Findings)
	}
}

// TestEvidenceDoctorDirectoryShapes covers what the scan encounters in a real
// recorder directory beyond a single clean session: nested directories it must
// ignore, more than one session, and a shard it cannot read. An unreadable
// shard in particular must be reported rather than skipped, because silently
// passing over a file the doctor could not examine would let damage hide inside
// it while the verdict still read clean.
func TestEvidenceDoctorDirectoryShapes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// A nested directory must be ignored, not treated as evidence.
	if err := os.Mkdir(filepath.Join(dir, "evidence-proxy-sub.jsonl"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Two distinct sessions exercise the cross-session ordering path.
	writeDoctorEntries(t, dir, "evidence-alpha-0.jsonl", doctorEntryPlan{
		{session: "alpha", seq: 0, prev: recorder.GenesisHash},
	})
	writeDoctorEntries(t, dir, "evidence-proxy-0.jsonl", doctorEntryPlan{
		{session: "proxy", seq: 0, prev: recorder.GenesisHash},
	})

	report, err := runEvidenceDoctor(dir)
	if err != nil {
		t.Fatalf("runEvidenceDoctor: %v", err)
	}
	if report.Damaged() {
		t.Fatalf("two clean sessions plus a nested directory reported damage: %+v", report.Findings)
	}
	if report.FilesRead != 2 {
		t.Fatalf("FilesRead = %d, want 2 (the nested directory must not be read)", report.FilesRead)
	}

	t.Run("unreadable shard is reported", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("chmod does not restrict reads on Windows, so the file stays readable")
		}
		if os.Geteuid() == 0 {
			t.Skip("root can read a mode-0000 file")
		}
		blocked := filepath.Join(dir, "evidence-proxy-9.jsonl")
		if err := os.WriteFile(blocked, []byte("{}\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(blocked, 0o600) })

		report, err := runEvidenceDoctor(dir)
		if err != nil {
			t.Fatalf("runEvidenceDoctor: %v", err)
		}
		if !hasDoctorFinding(report, "file_read_error") {
			t.Fatalf("unreadable shard was silently skipped; findings = %+v", report.Findings)
		}
	})
}

// minimalDoctorV1Receipt builds a v1 action receipt payload. Field presence is
// not enforced by Unmarshal, so this carries only what the doctor reads.
func minimalDoctorV1Receipt(t *testing.T, chainSeq uint64, chainPrev, signer string) json.RawMessage {
	t.Helper()
	return json.RawMessage(fmt.Sprintf(`{
		"version":1,
		"action_record":{"version":1,"chain_seq":%d,"chain_prev_hash":%q},
		"signer_key":%q
	}`, chainSeq, chainPrev, signer))
}

// doctorV1ReceiptEntry builds a v1 action-receipt entry. The session is fixed:
// these cases exercise chain handling within one writer session.
func doctorV1ReceiptEntry(t *testing.T, seq uint64, prev string, detail json.RawMessage) recorder.Entry {
	t.Helper()
	entry := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  seq,
		Timestamp: doctorTestTime(t, 1700000200, 0),
		SessionID: "proxy",
		Type:      "action_receipt",
		EventKind: "proxy_decision",
		Transport: "fetch",
		Summary:   "v1",
		Detail:    detail,
		PrevHash:  prev,
	}
	entry.Hash = recorder.ComputeHash(entry)
	return entry
}

// TestEvidenceDoctorV1ReceiptChain covers the v1 action-receipt path, including
// the decision to key chains on the recorder session rather than the signer. A
// documented signing-key rotation continues one writer chain, so a signer-keyed
// implementation would split it and report a false gap at the rotation point.
func TestEvidenceDoctorV1ReceiptChain(t *testing.T) {
	t.Parallel()

	t.Run("clean chain across a signer rotation", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		first := doctorV1ReceiptEntry(t, 0, recorder.GenesisHash,
			minimalDoctorV1Receipt(t, 0, recorder.GenesisHash, "signer-old"))
		firstHash, err := doctorV1ReceiptHash(t, first)
		if err != nil {
			t.Fatalf("hash first receipt: %v", err)
		}
		// Same writer chain, new signing key: this must not read as a new chain.
		second := doctorV1ReceiptEntry(t, 1, first.Hash,
			minimalDoctorV1Receipt(t, 1, firstHash, "signer-new"))
		writeDoctorRawEntries(t, dir, "evidence-proxy-0.jsonl", []recorder.Entry{first, second})

		report, err := runEvidenceDoctor(dir)
		if err != nil {
			t.Fatalf("runEvidenceDoctor: %v", err)
		}
		if report.Damaged() {
			t.Fatalf("a signer rotation was reported as damage: %+v", report.Findings)
		}
	})

	t.Run("duplicate v1 chain seq is detected", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		a := doctorV1ReceiptEntry(t, 0, recorder.GenesisHash,
			minimalDoctorV1Receipt(t, 0, recorder.GenesisHash, "signer-a"))
		b := doctorV1ReceiptEntry(t, 1, a.Hash,
			minimalDoctorV1Receipt(t, 0, "other-prev", "signer-a"))
		writeDoctorRawEntries(t, dir, "evidence-proxy-0.jsonl", []recorder.Entry{a, b})

		report, err := runEvidenceDoctor(dir)
		if err != nil {
			t.Fatalf("runEvidenceDoctor: %v", err)
		}
		if !hasDoctorFinding(report, "duplicate_receipt_chain_seq") {
			t.Fatalf("findings = %+v, want duplicate v1 receipt chain_seq", report.Findings)
		}
	})
}

func doctorV1ReceiptHash(t *testing.T, entry recorder.Entry) (string, error) {
	t.Helper()
	raw, ok := rawEntryDetail(entry)
	if !ok {
		t.Fatal("entry detail is not JSON")
	}
	r, err := receipt.Unmarshal(raw)
	if err != nil {
		return "", err
	}
	return receipt.ReceiptHash(r)
}
