// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestBaseReportSnapshotChecksEveryExit(t *testing.T) {
	fixture := "../../sdk/conformance/testdata/run-chains"
	key, err := os.ReadFile(filepath.Join(fixture, "signer-key.hex"))
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []bool{false, true} {
		dir := t.TempDir()
		entries, err := os.ReadDir(filepath.Join(fixture, "valid"))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			raw, err := os.ReadFile(filepath.Clean(filepath.Join(fixture, "valid", entry.Name())))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, entry.Name()), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		err = WithBaseHistorySnapshot(dir, "proxy", func() error {
			report, err := VerifyBase(dir, "proxy", BaseVerifyOptions{TrustedKeys: []string{strings.TrimSpace(string(key))}})
			if err != nil || !report.Healthy() {
				t.Fatalf("producer control: %+v, %v", report, err)
			}
			if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-999.jsonl"), []byte("not-json\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if failure {
				return errors.New("consumer failed")
			}
			return nil
		})
		if !errors.Is(err, recorder.ErrEvidenceChanged) {
			t.Fatalf("mixed base reached a verdict: %v", err)
		}
	}
}
