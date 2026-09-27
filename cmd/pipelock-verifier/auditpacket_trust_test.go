// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	auditpacket "github.com/luckyPipewrench/pipelock/sdk/audit-packet"
)

func auditPacketJSON(t *testing.T, args ...string) (auditPacketReport, int) {
	t.Helper()
	stdout, stderr, code := runRoot(t, append([]string{"audit-packet", "--json"}, args...)...)
	var report auditPacketReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("decode report: %v\nstdout=%q stderr=%q", err, stdout, stderr)
	}
	return report, code
}

// A packet claims verdict=valid and trusted=true. When full verification
// fails, the report must not repeat that claim.
func TestAuditPacket_FailedVerificationDoesNotClaimTrust(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	wrongKey := newFixture(t, 1).keyHex

	// Positive control: the unmodified packet verifies and keeps its claim.
	okDir := t.TempDir()
	fix.writePacketDir(t, okDir, nil)
	ok, code := auditPacketJSON(t, "--key", fix.keyHex, okDir)
	if code != cliutil.ExitOK || !ok.Valid || ok.Verdict != auditpacket.VerdictValid || !ok.Trusted {
		t.Fatalf("control: code=%d valid=%v verdict=%q trusted=%v", code, ok.Valid, ok.Verdict, ok.Trusted)
	}

	cases := []struct {
		name  string
		key   string
		setup func(t *testing.T, dir string)
		check string
	}{
		{
			name: "tampered chain",
			key:  fix.keyHex,
			setup: func(t *testing.T, dir string) {
				evidence := filepath.Join(dir, "evidence.jsonl")
				raw, err := os.ReadFile(filepath.Clean(evidence))
				if err != nil {
					t.Fatal(err)
				}
				tampered := bytes.Replace(raw, []byte(`"chain_seq":1`), []byte(`"chain_seq":99`), 1)
				if bytes.Equal(tampered, raw) {
					t.Fatal("tamper did not apply")
				}
				if err := os.WriteFile(evidence, tampered, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			check: statusFail,
		},
		{
			name: "malformed recorder tail",
			key:  fix.keyHex,
			setup: func(t *testing.T, dir string) {
				evidence := filepath.Join(dir, "evidence.jsonl")
				f, err := os.OpenFile(filepath.Clean(evidence), os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.WriteString("not-json\n"); err != nil {
					_ = f.Close()
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			},
			check: statusFail,
		},
		{name: "wrong key", key: wrongKey, check: statusFail},
		{
			name: "cross-check mismatch",
			key:  fix.keyHex,
			setup: func(t *testing.T, dir string) {
				fix.writePacketDir(t, dir, func(p *auditpacket.Packet) { p.Summary.ReceiptCount = 5; p.Summary.Totals.Allow = 5 })
			},
			check: statusPass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			fix.writePacketDir(t, dir, nil)
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			report, code := auditPacketJSON(t, "--key", tc.key, dir)
			if code == cliutil.ExitOK {
				t.Fatal("verification should fail")
			}
			if report.ChainCheck != tc.check {
				t.Fatalf("chain_check=%q, want %q (the failure must come from the intended stage)", report.ChainCheck, tc.check)
			}
			if report.Valid || report.Trusted || report.Verdict != auditpacket.VerdictInvalid {
				t.Fatalf("valid=%v trusted=%v verdict=%q, want valid=false trusted=false verdict=%q",
					report.Valid, report.Trusted, report.Verdict, auditpacket.VerdictInvalid)
			}
		})
	}
}

// Offline mode already reports trust as unverified; it must not change.
func TestAuditPacket_OfflineVerdictUnchanged(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)
	report, _ := auditPacketJSON(t, "--offline", dir)
	if report.Verdict != statusSchemaCheckedTrustUnverified || report.Trusted || report.Valid {
		t.Fatalf("offline: verdict=%q trusted=%v valid=%v", report.Verdict, report.Trusted, report.Valid)
	}
}

func TestAuditPacket_RawActionJSONLCompatibility(t *testing.T) {
	t.Parallel()
	fix := newFixture(t, 2)
	dir := t.TempDir()
	fix.writePacketDir(t, dir, nil)
	var raw bytes.Buffer
	for _, r := range fix.receipts {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		raw.Write(line)
		raw.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence.jsonl"), raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	report, code := auditPacketJSON(t, "--key", fix.keyHex, dir)
	if code != cliutil.ExitOK || !report.Valid || !report.Trusted {
		t.Fatalf("raw action JSONL compatibility: code=%d report=%+v", code, report)
	}
}
