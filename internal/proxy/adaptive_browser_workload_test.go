// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestAdaptiveDefaultsBrowserWorkloadRecoversButRotationEscalates(t *testing.T) {
	cfg := config.Defaults()
	cfg.SessionProfiling.Enabled = true
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.ApplyDefaults()

	runPages := func(repeatKnownDomains bool) *SessionState {
		t.Helper()
		sess := &SessionState{key: "browser"}
		for page := 0; page < 3; page++ {
			firstHost := fmt.Sprintf("asset-%d-0.example", page)
			for host := 0; host < 8; host++ {
				domain := fmt.Sprintf("asset-%d-%d.example", page, host)
				recordAdaptiveAnomalies(sess, sess.RecordRequest(domain, &cfg.SessionProfiling), &cfg.AdaptiveEnforcement)
			}
			if repeatKnownDomains {
				for range 100 {
					anomalies := sess.RecordRequest(firstHost, &cfg.SessionProfiling)
					if len(anomalies) == 0 {
						sess.RecordClean(cfg.AdaptiveEnforcement.DecayPerCleanRequest)
					}
				}
			}

			sess.mu.Lock()
			sess.domainWindows = nil
			sess.lastBurstAt = time.Now().Add(-time.Duration(cfg.SessionProfiling.WindowMinutes+1) * time.Minute)
			sess.mu.Unlock()
		}
		return sess
	}

	browser := runPages(true)
	if got := browser.EscalationLevel(); got != 0 {
		t.Fatalf("browser workload escalated to level %d with score %.2f", got, browser.ThreatScore())
	}
	if got := browser.ThreatScore(); got != 0 {
		t.Fatalf("browser workload score = %.2f, want clean-request decay to 0", got)
	}

	rotation := runPages(false)
	if got := rotation.EscalationLevel(); got == 0 {
		t.Fatalf("fresh-domain rotation stayed normal with score %.2f", rotation.ThreatScore())
	}
	if got := rotation.ThreatScore(); got != 6 {
		t.Fatalf("fresh-domain rotation score = %.2f, want 6.00", got)
	}
}

func recordAdaptiveAnomalies(sess *SessionState, anomalies []Anomaly, cfg *config.AdaptiveEnforcement) {
	for _, anomaly := range anomalies {
		if anomaly.Score <= 0 {
			continue
		}
		signal, ok := signalForSessionAnomaly(anomaly.Type, false)
		if ok {
			sess.RecordSignal(signal, cfg.EscalationThreshold)
		}
	}
}
