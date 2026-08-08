// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

type mcpCaptureMetadataObserver struct {
	got chan capture.DLPVerdictRecord
}

func (o *mcpCaptureMetadataObserver) ObserveURLVerdict(context.Context, *capture.URLVerdictRecord) {}

func (o *mcpCaptureMetadataObserver) ObserveResponseVerdict(context.Context, *capture.ResponseVerdictRecord) {
}
func (o *mcpCaptureMetadataObserver) ObserveCEEVerdict(context.Context, *capture.CEERecord) {}
func (o *mcpCaptureMetadataObserver) ObserveToolPolicyVerdict(context.Context, *capture.ToolPolicyRecord) {
}

func (o *mcpCaptureMetadataObserver) ObserveToolScanVerdict(context.Context, *capture.ToolScanRecord) {
}
func (o *mcpCaptureMetadataObserver) Close() error { return nil }

func (o *mcpCaptureMetadataObserver) ObserveDLPVerdict(_ context.Context, rec *capture.DLPVerdictRecord) {
	o.got <- *rec
}

type mcpResponseCaptureObserver struct {
	capture.NopObserver
	got chan capture.ResponseVerdictRecord
}

func (o *mcpResponseCaptureObserver) ObserveResponseVerdict(_ context.Context, rec *capture.ResponseVerdictRecord) {
	o.got <- *rec
}

func TestForwardScanned_CapturesInboundDLPWithEffectiveAction(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	obs := &mcpResponseCaptureObserver{got: make(chan capture.ResponseVerdictRecord, 1)}
	accessKey := "AKIA" + "IOSFODNN7EXAMPLE"
	response := makeResponse(1, "server credential: "+accessKey) + "\n"
	var out bytes.Buffer

	found, err := ForwardScanned(
		transport.NewStdioReader(strings.NewReader(response)),
		transport.NewStdioWriter(&out),
		io.Discard,
		nil,
		MCPProxyOpts{Scanner: sc, CaptureObs: obs, Transport: transportMCPStdio},
	)
	if err != nil {
		t.Fatalf("ForwardScanned: %v", err)
	}
	if !found || !strings.Contains(out.String(), accessKey) {
		t.Fatalf("warn action must forward the inbound DLP response: found=%v out=%q", found, out.String())
	}

	select {
	case rec := <-obs.got:
		if rec.EffectiveAction != config.ActionWarn {
			t.Fatalf("effective action = %q, want warn", rec.EffectiveAction)
		}
		if len(rec.RawFindings) == 0 {
			t.Fatal("expected DLP capture finding")
		}
		for _, finding := range rec.RawFindings {
			if finding.Kind != capture.KindDLP || finding.Action != config.ActionWarn {
				t.Fatalf("DLP capture finding = %+v, want kind=dlp action=warn", finding)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected inbound DLP response capture record")
	}
}

func TestCaptureMetadata_MCPHTTPInputTransport(t *testing.T) {
	t.Parallel()

	sc := testScannerForHTTP(t)
	obs := &mcpCaptureMetadataObserver{got: make(chan capture.DLPVerdictRecord, 1)}
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"api_key":"` +
		testSecretPrefix + `aaaaaaaaaaaaaaaaaaaaaaaaa"}}}`)

	decision := scanHTTPInputDecision(msg, io.Discard, "sess", "sess", MCPProxyOpts{
		Scanner:    sc,
		InputCfg:   &InputScanConfig{Enabled: true, Action: config.ActionBlock},
		CaptureObs: obs,
		ConfigHash: "sha256:test-config",
		Profile:    "mcp-profile",
		Transport:  transportMCPHTTP,
	})
	if decision.Blocked == nil {
		t.Fatal("expected MCP input DLP block")
	}

	select {
	case rec := <-obs.got:
		if rec.Subsurface != "dlp_mcp_input" {
			t.Fatalf("subsurface = %q, want dlp_mcp_input", rec.Subsurface)
		}
		if rec.Transport != transportMCPHTTP {
			t.Fatalf("transport = %q, want %q", rec.Transport, transportMCPHTTP)
		}
		if rec.SessionID == "" {
			t.Fatal("session_id is empty")
		}
		if rec.ConfigHash != "sha256:test-config" {
			t.Fatalf("config_hash = %q", rec.ConfigHash)
		}
		if rec.Profile != "mcp-profile" {
			t.Fatalf("profile = %q", rec.Profile)
		}
		if rec.ActionClass != "read" {
			t.Fatalf("action_class = %q, want read", rec.ActionClass)
		}
		if rec.EffectiveAction != config.ActionBlock {
			t.Fatalf("effective_action = %q, want block", rec.EffectiveAction)
		}
		if rec.Outcome != capture.OutcomeBlocked {
			t.Fatalf("outcome = %q, want blocked", rec.Outcome)
		}
		if string(rec.Request.RPCID) != "1" {
			t.Fatalf("rpc_id = %q, want %q (request-side join key from id=1)", string(rec.Request.RPCID), "1")
		}
	default:
		t.Fatal("expected DLP capture record")
	}
}

func TestCaptureMetadata_MCPStdioInputTransport(t *testing.T) {
	t.Parallel()

	sc := testScannerForHTTP(t)
	obs := &mcpCaptureMetadataObserver{got: make(chan capture.DLPVerdictRecord, 1)}

	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"api_key":"` +
		testSecretPrefix + `aaaaaaaaaaaaaaaaaaaaaaaaa"}}}` + "\n")

	opts := buildTestOpts(sc)
	opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock}
	opts.CaptureObs = obs
	opts.ConfigHash = "sha256:test-stdio-config"
	opts.Profile = "stdio-profile"
	opts.Transport = transportMCPStdio

	var serverBuf, logBuf bytes.Buffer
	blockedCh := make(chan BlockedRequest, 1)

	done := make(chan struct{})
	go func() {
		ForwardScannedInput(
			transport.NewStdioReader(strings.NewReader(string(msg))),
			transport.NewStdioWriter(&serverBuf),
			&logBuf,
			config.ActionBlock,
			config.ActionBlock,
			blockedCh,
			nil,
			nil,
			opts,
		)
		close(done)
	}()

	// Drain the blocked-request channel so ForwardScannedInput can return.
	select {
	case blocked := <-blockedCh:
		if blocked.ID == nil {
			t.Fatal("blocked request missing ID")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for blocked request")
	}
	<-done

	select {
	case rec := <-obs.got:
		if rec.Subsurface != "dlp_mcp_input" {
			t.Fatalf("subsurface = %q, want dlp_mcp_input", rec.Subsurface)
		}
		if rec.Transport != transportMCPStdio {
			t.Fatalf("transport = %q, want %q", rec.Transport, transportMCPStdio)
		}
		if rec.SessionID == "" {
			t.Fatal("session_id is empty — stdio capture metadata regressed")
		}
		if rec.ConfigHash != "sha256:test-stdio-config" {
			t.Fatalf("config_hash = %q, want sha256:test-stdio-config", rec.ConfigHash)
		}
		if rec.Profile != "stdio-profile" {
			t.Fatalf("profile = %q, want stdio-profile", rec.Profile)
		}
		if rec.ActionClass != "read" {
			t.Fatalf("action_class = %q, want read", rec.ActionClass)
		}
		if rec.EffectiveAction != config.ActionBlock {
			t.Fatalf("effective_action = %q, want block", rec.EffectiveAction)
		}
		if rec.Outcome != capture.OutcomeBlocked {
			t.Fatalf("outcome = %q, want blocked", rec.Outcome)
		}
		if string(rec.Request.RPCID) != "1" {
			t.Fatalf("rpc_id = %q, want %q (request-side join key from id=1)", string(rec.Request.RPCID), "1")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected DLP capture record on stdio block path")
	}
}
