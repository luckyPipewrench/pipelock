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
	testUploadURL       = "https://example.com/upload"
	testFetchURL        = "https://example.com/fetch"
	testWSURL           = "https://ws.example.com/chat"
	testClientIPBody    = "10.0.0.1"
	testClientIPHeader  = "10.0.0.2"
	testClientIPWS      = "10.0.0.3"
	testReqIDBody       = "req-body"
	testReqIDHeader     = "req-header"
	testReqIDWS         = "req-ws-header"
)

func testWarnScanner(t *testing.T) (*scanner.Scanner, *[]scanner.DLPWarnContext) {
	t.Helper()

	cfg := testScannerConfig()
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:     testWarnHookPattern,
		Regex:    `warnctx-[A-Za-z0-9]{10,}`,
		Severity: config.SeverityHigh,
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
		URL:       testUploadURL,
		ClientIP:  testClientIPBody,
		RequestID: testReqIDBody,
		Transport: TransportForward,
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
	if got.Transport != TransportForward {
		t.Fatalf("transport = %q, want %q", got.Transport, TransportForward)
	}
	if got.URL != testUploadURL {
		t.Fatalf("url = %q, want %q", got.URL, testUploadURL)
	}
}

func TestScanRequestHeaders_PropagatesWarnContext(t *testing.T) {
	sc, captured := testWarnScanner(t)
	defer sc.Close()

	ctx := scanner.WithDLPWarnContext(context.Background(), scanner.DLPWarnContext{
		Method:    http.MethodGet,
		URL:       testFetchURL,
		ClientIP:  testClientIPHeader,
		RequestID: testReqIDHeader,
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
	if got.RequestID != testReqIDHeader {
		t.Fatalf("requestID = %q, want %q", got.RequestID, testReqIDHeader)
	}
}

func TestDLPScanWSHeaders_PropagatesWarnContext(t *testing.T) {
	sc, captured := testWarnScanner(t)
	defer sc.Close()

	ctx := scanner.WithDLPWarnContext(context.Background(), scanner.DLPWarnContext{
		Method:    "WS",
		URL:       testWSURL,
		ClientIP:  testClientIPWS,
		RequestID: testReqIDWS,
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
	if got.Method != "WS" {
		t.Fatalf("method = %q, want %q", got.Method, "WS")
	}
	if got.URL != testWSURL {
		t.Fatalf("url = %q, want %q", got.URL, testWSURL)
	}
}
