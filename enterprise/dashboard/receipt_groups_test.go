//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionOnlyDashboardRefusesReceiptGroupDirectory(t *testing.T) {
	dir := t.TempDir()
	model := NewReadModel(Options{ReceiptDir: dir})
	if _, err := model.Sessions(); err != nil {
		t.Fatalf("empty legacy directory refused: %v", err)
	}
	artifact := filepath.Join(dir, "receipt-group-"+strings.Repeat("a", 32)+"-open.json")
	if err := os.WriteFile(artifact, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, read := range map[string]func() error{
		"sessions":   func() error { _, err := model.Sessions(); return err },
		"session":    func() error { _, err := model.Session("proxy"); return err },
		"trust keys": func() error { _, err := model.TrustKeys(); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := read(); err == nil || !strings.Contains(err.Error(), "receipt group evidence requires group verification") {
				t.Fatalf("session-only view accepted group evidence: %v", err)
			}
		})
	}
	recorder := httptest.NewRecorder()
	writeEvidenceReadError(recorder, errReceiptGroupNeedsVerification, "unavailable")
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "verify-receipt") {
		t.Fatalf("group evidence response = %d %q", recorder.Code, recorder.Body.String())
	}
}
