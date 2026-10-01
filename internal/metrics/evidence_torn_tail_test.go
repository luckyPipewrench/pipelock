// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEvidenceTornTailSnapshotAndCounter(t *testing.T) {
	m := New()
	if got := m.EvidenceTornTailSnapshot(); got.Total != 0 || got.Last != nil {
		t.Fatalf("initial state = %+v", got)
	}
	m.RecordEvidenceTornTail("evidence-run-0.jsonl", 42)
	first := m.EvidenceTornTailSnapshot()
	m.RecordEvidenceTornTail("evidence-run-0.jsonl", 42)
	got := m.EvidenceTornTailSnapshot()
	if got.Total != 1 || got.Last == nil || got.Last.Path != "evidence-run-0.jsonl" || got.Last.Offset != 42 || got.Last.ObservedAt.IsZero() || !got.Last.ObservedAt.Equal(first.Last.ObservedAt) {
		t.Fatalf("deduped state = %+v", got)
	}
	got.Last.Path = "mutated"
	if m.EvidenceTornTailSnapshot().Last.Path != "evidence-run-0.jsonl" {
		t.Fatal("snapshot aliases stored state")
	}
	m.RecordEvidenceTornTail("evidence-run-0.jsonl", 43)
	m.RecordEvidenceTornTail("evidence-next-0.jsonl", 42)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if !strings.Contains(w.Body.String(), "pipelock_evidence_torn_tails_total 3\n") {
		t.Fatalf("counter missing: %s", w.Body.String())
	}
	var absent *Metrics
	absent.RecordEvidenceTornTail("ignored", 0)
	if absent.EvidenceTornTailSnapshot().Total != 0 {
		t.Fatal("nil metrics recorded state")
	}
}
