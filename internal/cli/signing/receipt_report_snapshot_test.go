// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestDirectoryReportSnapshotDiscardsMixedVerdicts(t *testing.T) {
	for _, whole := range []bool{false, true} {
		for _, failure := range []bool{false, true} {
			dir := parityFixture(t)
			location := recorder.EvidenceLocation{Root: dir, Dir: dir}
			var output bytes.Buffer
			err := withDirectoryReportSnapshot(&output, location, "proxy", func(out io.Writer) error {
				var err error
				if whole {
					err = verifyWholeRecorderDirInner(out, location, "proxy", false, []string{parityKey(t)}, verifyReceiptOptions{})
				} else {
					err = verifyChainDirWithContinuityInner(out, location, "proxy", false, []string{parityKey(t)}, verifyReceiptOptions{})
				}
				if err != nil {
					t.Fatalf("producer control: %v", err)
				}
				if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-999.jsonl"), []byte("not-json\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if failure {
					return errors.New("consumer read failed")
				}
				return nil
			})
			if !errors.Is(err, recorder.ErrEvidenceChanged) || !strings.Contains(output.String(), "VERIFICATION INCOMPLETE") || strings.Contains(output.String(), "VALID:") {
				t.Fatalf("mixed verdict escaped: output=%s err=%v", output.String(), err)
			}
		}
	}
}
