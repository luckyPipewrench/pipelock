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
	body := rec.Body.String()
	for _, line := range strings.Split(body, "\n") {
		if line == want {
			return
		}
	}
	t.Fatalf("missing metric line %q:\n%s", want, body)
}

func assertMetricsNotContain(t *testing.T, m *metrics.Metrics, unwanted string) {
	t.Helper()
	rec := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, line := range strings.Split(body, "\n") {
		if line == unwanted {
			t.Fatalf("unexpected metric line %q:\n%s", unwanted, body)
		}
	}
}
