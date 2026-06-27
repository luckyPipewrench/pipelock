// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

func assertMetricsContain(t *testing.T, m *metrics.Metrics, want string) {
	t.Helper()
	rec := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if body := rec.Body.String(); !strings.Contains(body, want) {
		t.Fatalf("missing metric line %q:\n%s", want, body)
	}
}

func assertMetricsNotContain(t *testing.T, m *metrics.Metrics, unwanted string) {
	t.Helper()
	rec := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if body := rec.Body.String(); strings.Contains(body, unwanted) {
		t.Fatalf("unexpected metric line %q:\n%s", unwanted, body)
	}
}
