// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

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
