// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const fragmentMemoryMetric = "pipelock_cross_request_fragment_buffer_bytes"

func TestPrometheusHandler_CEELiveState(t *testing.T) {
	t.Parallel()
	m := New()
	handler := m.PrometheusHandler()
	var retained atomic.Int64
	for _, tc := range []struct {
		name  string
		setup func()
		want  int
	}{
		{"manual gauge", func() { m.SetCrossRequestFragmentBytes(13) }, 13},
		{"callback installed after handler", func() {
			retained.Store(78)
			m.SetCEEStatsFunc(func() CEEStats {
				return CEEStats{FragmentBufferActive: true, FragmentBufferBytes: int(retained.Load())}
			})
		}, 78},
		{"retained bytes grow", func() { retained.Store(120) }, 120},
		{"retained bytes cleared", func() { retained.Store(0) }, 0},
		{"callback replaced", func() {
			m.SetCEEStatsFunc(func() CEEStats { return CEEStats{FragmentBufferBytes: 9} })
		}, 9},
		{"callback removed preserves manual setter", func() {
			m.SetCEEStatsFunc(nil)
			m.SetCrossRequestFragmentBytes(27)
		}, 27},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
			want := fmt.Sprintf("\n%s %d\n", fragmentMemoryMetric, tc.want)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) {
				t.Fatalf("scrape status=%d, missing sample %q", w.Code, want)
			}
		})
	}
}

func TestPrometheusHandler_CEECallbackOutsideLock(t *testing.T) {
	t.Parallel()
	m := New()
	m.SetCEEStatsFunc(func() CEEStats {
		// Taking the registration lock here must not deadlock the scrape.
		m.SetCEEStatsFunc(nil)
		return CEEStats{FragmentBufferActive: true, FragmentBufferBytes: 41}
	})
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if !strings.Contains(w.Body.String(), "\n"+fragmentMemoryMetric+" 41\n") {
		t.Fatal("live callback did not supply the scraped sample")
	}
}

func TestPrometheusHandler_CEEConcurrentReplacement(t *testing.T) {
	t.Parallel()
	m := New()
	handler := m.PrometheusHandler()
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; i < 40; i++ {
			value := i
			m.SetCEEStatsFunc(func() CEEStats { return CEEStats{FragmentBufferBytes: value} })
		}
	})
	for i := 0; i < 4; i++ {
		wg.Go(func() {
			for j := 0; j < 10; j++ {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
				if w.Code != http.StatusOK {
					t.Errorf("concurrent scrape status=%d", w.Code)
				}
			}
		})
	}
	wg.Wait()
	// Once writers settle, both operator views must agree on the current value.
	m.SetCEEStatsFunc(func() CEEStats { return CEEStats{FragmentBufferBytes: 53} })
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if !strings.Contains(w.Body.String(), "\n"+fragmentMemoryMetric+" 53\n") {
		t.Fatal("scrape did not observe the final callback")
	}
	w = httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil))
	var stats statsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.CEE.FragmentBufferBytes != 53 {
		t.Fatalf("JSON retained bytes=%d, want 53", stats.CEE.FragmentBufferBytes)
	}
}
