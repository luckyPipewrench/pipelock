// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/emit"
)

func TestAuditSinkDeliveryFailureIsExposedByPrometheus(t *testing.T) {
	requestSeen := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		requestSeen <- struct{}{}
	}))
	defer srv.Close()

	sink := emit.NewWebhookSink(srv.URL)
	emitter := emit.NewEmitter("test", sink)
	t.Cleanup(func() { _ = emitter.Close() })
	m := New()
	m.SetAuditSinkHealthSnapshot(emitter.SinkHealth)

	emitter.EmitWithSeverity(t.Context(), emit.SeverityWarn, emit.EventBlocked, nil)
	select {
	case <-requestSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for simulated sink failure")
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(2 * time.Second)
	for sink.Stats().Failed == 0 {
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatal("timed out waiting for failure accounting")
		}
	}
	if stats := sink.Stats(); stats.Failed != 1 || !stats.Degraded || stats.LastError == "" {
		t.Fatalf("simulated failure stats = %+v", stats)
	}

	rec := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`pipelock_audit_sink_failed_total{sink="webhook"} 1`,
		`pipelock_audit_sink_degraded{sink="webhook"} 1`,
		`pipelock_audit_sink_last_error_present{sink="webhook"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "HTTP 500") {
		t.Fatalf("last error text leaked into Prometheus output:\n%s", body)
	}
}

func TestAuditSinkMetricsUseOnlyBoundedSinkLabel(t *testing.T) {
	m := New()
	m.SetAuditSinkHealthSnapshot(func() []emit.SinkHealth {
		return []emit.SinkHealth{
			{Sink: emit.SinkWebhook, QueueCap: 64},
			{Sink: emit.SinkSyslog, QueueCap: 64},
			{Sink: emit.SinkOTLP, QueueCap: 256},
		}
	})
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if !strings.HasPrefix(family.GetName(), "pipelock_audit_sink_") {
			continue
		}
		for _, metric := range family.GetMetric() {
			if len(metric.GetLabel()) != 1 || metric.GetLabel()[0].GetName() != "sink" {
				t.Fatalf("%s labels = %+v, want only bounded sink label", family.GetName(), metric.GetLabel())
			}
		}
	}
}

func TestAuditSinkMetricsRejectUnknownSinkLabelValues(t *testing.T) {
	m := New()
	m.SetAuditSinkHealthSnapshot(func() []emit.SinkHealth {
		return []emit.SinkHealth{
			{Sink: emit.SinkWebhook, Delivered: 1},
			{Sink: "attacker-" + strings.Repeat("x", 4096), Delivered: 1},
		}
	})
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if !strings.HasPrefix(family.GetName(), "pipelock_audit_sink_") {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "sink" && label.GetValue() != emit.SinkWebhook {
					t.Fatalf("%s accepted unbounded sink label value of %d bytes", family.GetName(), len(label.GetValue()))
				}
			}
		}
	}
}

func TestSetAuditSinkHealthSnapshotNilSafe(t *testing.T) {
	var nilMetrics *Metrics
	nilMetrics.SetAuditSinkHealthSnapshot(func() []emit.SinkHealth { return nil })
	New().SetAuditSinkHealthSnapshot(nil)
}
