// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEvidenceHealthIncludesTornTail(t *testing.T) {
	h, m, _, _ := newEvidenceHealthTestMonitor(t, nil)
	m.RecordEvidenceTornTail("evidence-run-0.jsonl", 42)
	stats, ok := h.stats()
	if !ok || stats.TornTails.Total != 1 || stats.TornTails.Last == nil || stats.TornTails.Last.Offset != 42 {
		t.Fatalf("health = %+v available=%v", stats, ok)
	}
	w := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil))
	for _, want := range []string{`"torn_tails":{"total":1`, `"path":"evidence-run-0.jsonl"`, `"offset":42`, `"observed_at":`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("stats missing %s: %s", want, w.Body.String())
		}
	}
}
