// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestRecordObservedCoreResponseMatchesLabelsItsOwnReason is the shared
// recorder every HTTP transport calls. The label matters: ordinary suppression
// cannot reach the immutable floor, so an auditor must be able to separate an
// operator-declared floor observation from a suppression without reading config.
func TestRecordObservedCoreResponseMatchesLabelsItsOwnReason(t *testing.T) {
	if ExemptReasonCoreObserved == ExemptReasonSuppress {
		t.Fatal("observed-core evidence is indistinguishable from ordinary suppression")
	}

	m := metrics.New()
	observed := []scanner.ObservedCoreMatch{
		{Match: scanner.ResponseMatch{PatternName: "Prompt Injection"}, Host: "docs.vendor.example", Owner: "security-team"},
		{Match: scanner.ResponseMatch{PatternName: "System Override"}, Host: "docs.vendor.example", Owner: "security-team"},
	}

	recordObservedCoreResponseMatches(m, nil, audit.LogContext{}, observed, TransportForward)

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var found int
	for _, f := range families {
		for _, metric := range f.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetValue() == ExemptReasonCoreObserved {
					found++
				}
			}
		}
	}
	if found == 0 {
		t.Fatalf("no metric carried the %q reason; observed findings would be invisible", ExemptReasonCoreObserved)
	}
}

// TestRecordObservedCoreResponseMatchesToleratesNilDependencies matches the
// suppression sibling's contract: evidence recording is observational and must
// never change a response verdict or panic an unconfigured deployment.
func TestRecordObservedCoreResponseMatchesToleratesNilDependencies(t *testing.T) {
	recordObservedCoreResponseMatches(nil, nil, audit.LogContext{}, []scanner.ObservedCoreMatch{
		{Match: scanner.ResponseMatch{PatternName: "Prompt Injection"}},
	}, TransportFetch)
	// An empty slice is the overwhelmingly common case and must be a no-op.
	recordObservedCoreResponseMatches(nil, nil, audit.LogContext{}, nil, TransportFetch)
}

// TestObservedCoreEvidenceNamesItsAuthorization is the point of the whole
// evidence path. A record saying only that something was observed cannot tell
// a later auditor which approval allowed it or when that approval ended, so
// the host, owner and expiry have to survive into the audit line.
func TestObservedCoreEvidenceNamesItsAuthorization(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	log, err := audit.New("json", "file", logPath, true, true)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}

	// Derived, never pinned: a literal date in a field that carries an expiry
	// turns the clock-literal policy red on a calendar date with no commit.
	wantExpires := time.Now().UTC().Add(72 * time.Hour).Format("2006-01-02")
	recordObservedCoreResponseMatches(metrics.New(), log, audit.LogContext{}, []scanner.ObservedCoreMatch{{
		Match:   scanner.ResponseMatch{PatternName: "Prompt Injection"},
		Host:    "docs.vendor.example",
		Reason:  "vendor security documentation",
		Owner:   "security-team",
		Expires: wantExpires,
	}}, TransportForward)
	log.Close()

	raw, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		if entry["reason"] != ExemptReasonCoreObserved {
			continue
		}
		found = true
		for field, want := range map[string]string{
			"observe_host":    "docs.vendor.example",
			"observe_owner":   "security-team",
			"observe_expires": wantExpires,
			"observe_reason":  "vendor security documentation",
			"pattern":         "Prompt Injection",
		} {
			if got, _ := entry[field].(string); got != want {
				t.Errorf("audit field %s = %q, want %q", field, got, want)
			}
		}
	}
	if !found {
		t.Fatalf("no audit record carried the %q reason; log was:\n%s", ExemptReasonCoreObserved, raw)
	}
}
