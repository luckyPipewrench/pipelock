// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	testWarnHookPattern = "warnctx"
	testWarnHookToken   = "warnctx-ABCDEFGHIJ1234"
)

func testWarnScanner(t *testing.T) (*scanner.Scanner, *[]scanner.DLPWarnContext) {
	t.Helper()

	cfg := testScannerConfig()
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:     testWarnHookPattern,
		Regex:    `warnctx-[A-Za-z0-9]{10,}`,
		Severity: "high",
		Action:   config.ActionWarn,
	})

	sc := scanner.New(cfg)
	captured := []scanner.DLPWarnContext{}
	sc.SetDLPWarnHook(func(ctx context.Context, _, _ string) {
		captured = append(captured, scanner.DLPWarnContextFromCtx(ctx))
	})
	return sc, &captured
}

func TestScanRequestBody_PropagatesWarnContext(t *testing.T) {
	sc, captured := testWarnScanner(t)
	defer sc.Close()

	cfg := testScannerConfig()
	ctx := scanner.WithDLPWarnContext(context.Background(), scanner.DLPWarnContext{
		Method:    http.MethodPost,
		URL:       "https://example.com/upload",
		ClientIP:  "10.0.0.1",
		RequestID: "req-body",
		Transport: "forward",
	})

	body := `{"key":"` + fakeAPIKey() + ` ` + testWarnHookToken + `"}`
	_, result := scanRequestBody(ctx, BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/json",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match in request body")
	}
	if len(*captured) == 0 {
		t.Fatal("expected DLP warn hook to capture context")
	}
	got := (*captured)[0]
	if got.Transport != "forward" {
		t.Fatalf("transport = %q, want %q", got.Transport, "forward")
	}
	if got.URL != "https://example.com/upload" {
		t.Fatalf("url = %q, want %q", got.URL, "https://example.com/upload")
	}
}

func TestScanRequestHeaders_PropagatesWarnContext(t *testing.T) {
	sc, captured := testWarnScanner(t)
	defer sc.Close()

	ctx := scanner.WithDLPWarnContext(context.Background(), scanner.DLPWarnContext{
		Method:    http.MethodGet,
		URL:       "https://example.com/fetch",
		ClientIP:  "10.0.0.2",
		RequestID: "req-header",
		Transport: TransportFetch,
	})

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+fakeAPIKey()+" "+testWarnHookToken)
	result := scanRequestHeaders(ctx, headers, testScannerConfig(), sc)
	if result == nil || result.Clean {
		t.Fatal("expected DLP match in request headers")
	}
	if len(*captured) == 0 {
		t.Fatal("expected DLP warn hook to capture context")
	}
	got := (*captured)[0]
	if got.Transport != TransportFetch {
		t.Fatalf("transport = %q, want %q", got.Transport, TransportFetch)
	}
	if got.RequestID != "req-header" {
		t.Fatalf("requestID = %q, want %q", got.RequestID, "req-header")
	}
}

func TestDLPScanWSHeaders_PropagatesWarnContext(t *testing.T) {
	sc, captured := testWarnScanner(t)
	defer sc.Close()

	ctx := scanner.WithDLPWarnContext(context.Background(), scanner.DLPWarnContext{
		Method:    "WS",
		URL:       "https://ws.example.com/chat",
		ClientIP:  "10.0.0.3",
		RequestID: "req-ws-header",
		Transport: TransportWS,
	})

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+fakeAPIKey()+" "+testWarnHookToken)
	blocked, reason := (&Proxy{}).dlpScanWSHeaders(ctx, headers, sc)
	if !blocked {
		t.Fatal("expected DLP match in websocket headers")
	}
	if reason == "" {
		t.Fatal("expected non-empty block reason")
	}
	if len(*captured) == 0 {
		t.Fatal("expected DLP warn hook to capture context")
	}
	got := (*captured)[0]
	if got.Transport != TransportWS {
		t.Fatalf("transport = %q, want %q", got.Transport, TransportWS)
	}
	if got.URL != "https://ws.example.com/chat" {
		t.Fatalf("url = %q, want %q", got.URL, "https://ws.example.com/chat")
	}
}
