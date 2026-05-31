package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

// adaptiveUpgradeCounterValue reads the pipelock_adaptive_upgrades_total counter
// for a specific (from_action, to_action, level) label set out of the metrics
// registry, without reaching into unexported fields. Returns 0 when no matching
// series is present.
func adaptiveUpgradeCounterValue(t *testing.T, m *metrics.Metrics, from, to, level string) float64 {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, fam := range families {
		if fam.GetName() != "pipelock_adaptive_upgrades_total" {
			continue
		}
		for _, mm := range fam.GetMetric() {
			labels := map[string]string{}
			for _, lp := range mm.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["from_action"] == from && labels["to_action"] == to && labels["level"] == level {
				return mm.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// TestRecordAdaptiveUpgrade_WiresLogAndMetric proves the helper drives the
// adaptive-upgrade Prometheus counter from the From/To/Level fields of the
// struct. The audit-log emission and the metric emission are fed from the same
// adaptiveUpgrade value, so they cannot disagree on those fields by
// construction; that is the property the helper exists to guarantee.
func TestRecordAdaptiveUpgrade_WiresLogAndMetric(t *testing.T) {
	m := metrics.New()
	logger := audit.NewNop()

	recordAdaptiveUpgrade(logger, m, adaptiveUpgrade{
		SessionKey: "agent-a|10.0.0.1",
		Level:      "L1",
		FromAction: config.ActionWarn,
		ToAction:   config.ActionBlock,
		Scanner:    "session_deny",
		ClientIP:   "10.0.0.1",
		RequestID:  "req-1",
	})

	if got := adaptiveUpgradeCounterValue(t, m, config.ActionWarn, config.ActionBlock, "L1"); got != 1 {
		t.Errorf("adaptive upgrade counter = %v, want 1 for from=warn to=block level=L1", got)
	}
}

// TestRecordAdaptiveUpgrade_NilMetricsSafe confirms the helper does not panic
// when metrics are nil, matching the TLS-intercept path where the proxy-level
// metrics handle can be absent. The audit log must still be emitted.
func TestRecordAdaptiveUpgrade_NilMetricsSafe(t *testing.T) {
	logger := audit.NewNop()
	// Must not panic with a nil *metrics.Metrics.
	recordAdaptiveUpgrade(logger, nil, adaptiveUpgrade{
		SessionKey: "10.0.0.1",
		Level:      "L2",
		FromAction: "",
		ToAction:   config.ActionBlock,
		Scanner:    "session_deny",
		ClientIP:   "10.0.0.1",
		RequestID:  "req-2",
	})
}
