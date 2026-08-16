// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	posturepkg "github.com/luckyPipewrench/pipelock/internal/posture"
)

func TestFormatVerifyAgeCeilsPartialDay(t *testing.T) {
	t.Parallel()

	if got := formatVerifyAge(time.Now().Add(-time.Hour)); got != "1d" {
		t.Fatalf("one-hour age = %q, want 1d", got)
	}
}

func TestLoadProofFileRejectsMissingAndTrailingJSON(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing.json")
	if _, err := loadProofFile(missing); err == nil || !strings.Contains(err.Error(), "reading") {
		t.Fatalf("missing proof err = %v", err)
	}

	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, []byte(`{}{"extra":true}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadProofFile(path); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("trailing JSON err = %v", err)
	}
}

func TestPrintVerifyResultFailStaleAndMismatch(t *testing.T) {
	t.Parallel()

	match := false
	cmd := postureCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	printVerifyResult(cmd, &posturepkg.VerifyResult{
		Passed: false,
		Score:  40,
		Policy: "standard",
		FactorScores: posturepkg.FactorScores{
			TransportRatio:       posturepkg.FactorDetail{RawPercent: 50, Weight: 40, Weighted: 20},
			RecorderHealth:       posturepkg.FactorDetail{RawPercent: 50, Weight: 20, Weighted: 10},
			SimulatePassRate:     posturepkg.FactorDetail{RawPercent: 100, Weight: 20, Weighted: 20},
			DiscoveryCleanliness: posturepkg.FactorDetail{RawPercent: 80, Weight: 20, Weighted: 16},
		},
		HardFailures:    []posturepkg.HardFailure{{Rule: "min_score", Detail: "score 40 < 70"}},
		Warnings:        []string{"recorder stale"},
		ConfigHashMatch: &match,
	}, &posturepkg.Capsule{
		GeneratedAt: time.Now().Add(-2 * time.Hour),
		Evidence: posturepkg.EvidenceBundle{
			Discover: posturepkg.DiscoverEvidence{
				TotalServers:      2,
				ProtectedPipelock: 1,
				Unprotected:       1,
			},
			VerifyInstall: posturepkg.VerifyInstallEvidence{
				FlightRecorderActive: true,
				ReceiptCount:         3,
			},
		},
	}, 30)

	out := buf.String()
	for _, want := range []string{
		"Posture Verification: FAIL",
		"1/2 protected",
		"active, 3 receipts, stale",
		"FAIL: min_score -- score 40 < 70",
		"WARN: recorder stale",
		"max: 30d",
		"Config hash: mismatch",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestExitVerifyIntegrityErrorJSONIncludesCapsuleTimes(t *testing.T) {
	t.Parallel()

	generated := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	expires := generated.Add(24 * time.Hour)
	last := generated.Add(time.Hour)
	cmd := postureCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := exitVerifyIntegrityError(cmd, true, "standard", &posturepkg.Capsule{
		GeneratedAt: generated,
		ExpiresAt:   expires,
		Evidence: posturepkg.EvidenceBundle{
			FlightRecorder: posturepkg.FlightRecorderCounts{LastReceiptAt: &last},
		},
	}, errors.New("signature mismatch"))
	if err == nil || cliutil.ExitCodeOf(err) != exitVerifyIntegrity {
		t.Fatalf("exit err = %v", err)
	}

	var decoded posturepkg.VerifyResult
	if decodeErr := json.Unmarshal(buf.Bytes(), &decoded); decodeErr != nil {
		t.Fatalf("json: %v\n%s", decodeErr, buf.String())
	}
	if decoded.Verified || decoded.Passed {
		t.Fatalf("json verdict = %+v", decoded)
	}
	if decoded.Error != "signature mismatch" {
		t.Fatalf("json error = %q", decoded.Error)
	}
	if !decoded.GeneratedAt.Equal(generated) || !decoded.ExpiresAt.Equal(expires) {
		t.Fatalf("capsule times = %v %v", decoded.GeneratedAt, decoded.ExpiresAt)
	}
	if decoded.LastReceiptAt == nil || !decoded.LastReceiptAt.Equal(last) {
		t.Fatalf("last receipt = %v", decoded.LastReceiptAt)
	}
}

func TestRejectTrailingJSON(t *testing.T) {
	t.Parallel()

	dec := json.NewDecoder(bytes.NewReader([]byte(`{"ok":true}`)))
	var first map[string]bool
	if err := dec.Decode(&first); err != nil {
		t.Fatalf("first decode: %v", err)
	}
	if err := rejectTrailingJSON(dec); err != nil {
		t.Fatalf("single value: %v", err)
	}

	dec = json.NewDecoder(bytes.NewReader([]byte(`{"ok":true}{"x":1}`)))
	if err := dec.Decode(&first); err != nil {
		t.Fatalf("first of two: %v", err)
	}
	if err := rejectTrailingJSON(dec); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("two values err = %v", err)
	}
}
