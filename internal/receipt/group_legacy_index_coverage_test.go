// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !js || !wasm

package receipt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyExclusionIndexRefusesUnavailableInventoryAndScratch(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	if sessions, err := ResolveBaseSessionsExcludingReceiptGroups(missing, "proxy"); sessions != nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing legacy inventory sessions=%v err=%v", sessions, err)
	}
	if report, err := VerifyBase(missing, "proxy", BaseVerifyOptions{ExcludeReceiptGroupSessions: true}); err == nil || report.Base != "proxy" || !strings.Contains(err.Error(), "listing sessions") {
		t.Fatalf("missing excluded base report=%+v err=%v", report, err)
	}
	t.Setenv("TMPDIR", missing)
	if index, err := indexRecorderFilesExcludingGroupsSpill(dir); index != nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unavailable scratch index=%v err=%v", index, err)
	}
}
