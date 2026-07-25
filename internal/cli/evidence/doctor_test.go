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
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
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
		for i := 0; i <= recorder.MaxEvidenceReadDirectoryEntries; i++ {
			name := fmt.Sprintf("evidence-proxy-%d.jsonl", i)
			if err := os.WriteFile(filepath.Join(dir, name), []byte(""), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
		report, err := runEvidenceDoctor(dir)
		if err != nil {
			t.Fatalf("runEvidenceDoctor: %v", err)
		}
		if hasDoctorFinding(report, "directory_read_error") {
			t.Fatalf("doctor refused an over-recorder-cap directory: %+v", report.Findings)
		}
		if hasDoctorFinding(report, "scan_truncated") {
			t.Fatalf("scan truncated below the doctor budget: %+v", report.Findings)
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
			name := fmt.Sprintf("evidence-proxy-%d.jsonl", i)
			if err := os.WriteFile(filepath.Join(dir, name), []byte(""), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
		report, err := runEvidenceDoctor(dir)
		if err != nil {
			t.Fatalf("runEvidenceDoctor: %v", err)
		}
		if !hasDoctorFinding(report, "scan_truncated") {
			t.Fatalf("findings = %+v, want scan_truncated", report.Findings)
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
		if strings.Contains(buf.String(), "healthy") {
			t.Fatalf("truncated scan reported as healthy: %q", buf.String())
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
