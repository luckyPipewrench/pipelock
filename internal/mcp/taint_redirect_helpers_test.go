// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestRedactionBlockAttributionUsesTypedReason(t *testing.T) {
	t.Parallel()

	layer, pattern, severity := redactionBlockAttribution(errors.New("plain failure"))
	if layer != mcpReceiptLayerRedaction || pattern != string(redact.ReasonInternalError) || severity != config.SeverityHigh {
		t.Fatalf("plain err = %q %q %q", layer, pattern, severity)
	}

	layer, pattern, severity = redactionBlockAttribution(&redact.BlockError{Reason: redact.ReasonDuplicateKey})
	if layer != mcpReceiptLayerRedaction || pattern != string(redact.ReasonDuplicateKey) || severity != config.SeverityHigh {
		t.Fatalf("typed err = %q %q %q", layer, pattern, severity)
	}
}

func TestApproveTaintDecisionNilSafeAndSetsOverride(t *testing.T) {
	t.Parallel()

	approveTaintDecision(nil)

	d := &taintDecision{}
	approveTaintDecision(d)
	if d.Authority != session.AuthorityOperatorOverride || !d.RequiresReauth {
		t.Fatalf("approved = %+v", d)
	}
}

func TestBuildHITLRequestForTaintFallbackTarget(t *testing.T) {
	t.Parallel()

	req := buildHITLRequestForTaint("", "taint_block", "preview")
	if req.URL != "mcp-tools-call" {
		t.Fatalf("empty tool target = %q, want mcp-tools-call", req.URL)
	}
	if req.Reason != "taint_block" || req.Preview != "preview" {
		t.Fatalf("hitl request = %+v", req)
	}

	req = buildHITLRequestForTaint("fetch_url", "taint_block", "preview")
	if req.URL != "fetch_url" {
		t.Fatalf("named tool target = %q", req.URL)
	}
}

func TestTaintDecisionRequiresApprovalWithoutApprover(t *testing.T) {
	t.Parallel()

	allowed, asked := taintDecisionRequiresApproval(MCPProxyOpts{}, "write_file", "taint_block", "preview")
	if allowed || asked {
		t.Fatalf("nil approver = allowed=%t asked=%t, want false false", allowed, asked)
	}
}

func TestArgsDigestDoesNotEchoRawArgs(t *testing.T) {
	t.Parallel()

	secret := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	got := argsDigest(`{"token":"` + secret + `"}`)
	if !strings.HasPrefix(got, "sha256:") || !strings.Contains(got, "len=") {
		t.Fatalf("digest shape = %q", got)
	}
	if strings.Contains(got, secret) {
		t.Fatalf("raw args leaked into digest: %q", got)
	}
	if strings.Contains(got, "token") {
		t.Fatalf("arg keys leaked into digest: %q", got)
	}
}
