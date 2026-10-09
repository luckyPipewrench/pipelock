// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestDoctorReadLimitIsInconclusive(t *testing.T) {
	dir := t.TempDir()
	writeActualDoctorReceipt(t, dir)
	var name string
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".jsonl") {
			name = file.Name()
			break
		}
	}
	if name == "" {
		t.Fatal("producer wrote no shard")
	}
	path := filepath.Join(dir, name)
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, bytes.Repeat([]byte("\n"), int(recorder.MaxEvidenceReadFileBytes))...), 0o600); err != nil {
		t.Fatal(err)
	}
	// Blank lines are accepted by the producer format and preserve every signed record.
	if _, err := recorder.ReadHistoryEntries(path); err != nil {
		t.Fatalf("authoritative positive control: %v", err)
	}
	report, err := runEvidenceDoctor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Damaged() || report.Conclusive() {
		t.Fatalf("valid oversized evidence should be inconclusive: %+v", report)
	}
	var out bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	metric := filepath.Join(t.TempDir(), "health.prom")
	cmd.SetArgs([]string{"doctor", dir, "--prometheus-textfile", metric})
	if err := cmd.Execute(); err == nil || cliutil.ExitCodeOf(err) != cliutil.ExitGeneral || strings.Contains(err.Error(), "structural damage") {
		t.Fatalf("incomplete exit: %v", err)
	}
	data, err := os.ReadFile(filepath.Clean(metric))
	if err != nil || !strings.Contains(string(data), "pipelock_evidence_corpus_integrity_ok 0") {
		t.Fatalf("incomplete health metric: %s, %v", data, err)
	}
	if !strings.Contains(out.String(), "inconclusive") || strings.Contains(out.String(), "doctor: damaged") {
		t.Fatalf("verdict: %s", out.String())
	}
}

func TestDoctorIncompleteReadDoesNotInventChainDamage(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		d := evidenceDoctor{readIncomplete: !truncated, scanTruncated: truncated}
		d.detectChainDamage("partial", []doctorChainRef{
			{Seq: 2, Hash: "second", PrevHash: "unread first"},
			{Seq: 4, Hash: "fourth", PrevHash: "unread third"},
		}, true)
		if d.structuralDamage || len(d.findings) != 0 {
			t.Fatalf("partial observation invented missing history: %+v", d.findings)
		}
		// A mismatch between two observed adjacent records is still real damage.
		d.detectChainDamage("observed", []doctorChainRef{
			{Seq: 2, Hash: "second"}, {Seq: 3, PrevHash: "wrong second"},
		}, true)
		if !d.structuralDamage {
			t.Fatal("incomplete read hid observed adjacent mismatch")
		}
	}
}

func TestDoctorSuppressedDamageRetainsVerdict(t *testing.T) {
	d := evidenceDoctor{readIncomplete: true}
	for range maxEvidenceDoctorFindings {
		d.addFinding("file_read_limit", "budget")
	}
	d.addFinding("prev_hash_mismatch", "observed damage")
	report := evidenceDoctorReport{Findings: d.findings, StructuralDamage: d.structuralDamage, ReadIncomplete: d.readIncomplete}
	if !report.Damaged() || report.Conclusive() {
		t.Fatalf("suppressed damage lost or partial scan certified: %+v", report)
	}
}

func TestDoctorEntryLimitIsInconclusive(t *testing.T) {
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, MaxEntriesPerFile: recorder.MaxEvidenceReadEntries + 2}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range recorder.MaxEvidenceReadEntries + 1 {
		if err := rec.Record(recorder.Entry{SessionID: "doctorentries", Type: "decision", Summary: "observed", Transport: "fetch"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	count := 0
	if err := recorder.WalkSessionHistory(dir, "doctorentries", func(recorder.Entry) error { count++; return nil }); err != nil || count < recorder.MaxEvidenceReadEntries+1 {
		t.Fatalf("producer positive control: count=%d err=%v", count, err)
	}
	report, err := runEvidenceDoctor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Damaged() || report.Conclusive() || !hasDoctorFinding(report, "file_read_limit") {
		t.Fatalf("entry display budget became corruption: %+v", report)
	}
}
