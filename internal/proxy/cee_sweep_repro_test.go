// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestRepro_EscapedSlashSplitsPositions reproduces the reviewer finding that a
// percent-encoded slash is treated as a separator. net/url has already decoded
// u.Path, so "/upload/value%2Ftail" arrives as three segments instead of the two
// the wire actually carried, shifting every later position.
func TestRepro_EscapedSlashSplitsPositions(t *testing.T) {
	u, err := url.Parse("http://example.com/upload/value%2Ftail")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := pathSegments(u)
	if got == nil {
		t.Fatal("no payload")
	}
	if len(got.segments) != 2 {
		t.Fatalf("segments = %d (%q), want 2: an encoded slash is data, not a separator",
			len(got.segments), got.segments)
	}
}

// TestRepro_OverDepthForwardsWhenReassemblyDisabled reproduces the fail-open:
// depth enforcement lives inside the fragment-reassembly gate, so an over-depth
// path is forwarded uninspected whenever reassembly is off.
func TestRepro_OverDepthForwardsWhenReassemblyDisabled(t *testing.T) {
	u, err := url.Parse("http://example.com/" + strings.Repeat("x/", scanner.MaxPathPositions+1))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	payload := pathSegments(u)
	if payload == nil || !payload.depthExceeded {
		t.Fatal("expected the parser to flag depth")
	}
	// Reassembly disabled: fb nil and FragmentReassembly.Enabled false. The
	// over-depth path must still be denied.
	cfg := config.Defaults().CrossRequestDetection
	cfg.Enabled = true
	cfg.Action = config.ActionBlock
	cfg.FragmentReassembly.Enabled = false
	res := ceeAdmit(t.Context(), ceeAdmitOptions{SessionKey: "k", PathPayload: payload, TargetURL: "http://example.com/x", Agent: "agent", ClientIP: "1.2.3.4", RequestID: "req", Config: cfg, Logger: audit.NewNop(), Metrics: metrics.New()})
	if !res.Blocked {
		t.Fatal("over-depth path forwarded when fragment reassembly is disabled")
	}
}
