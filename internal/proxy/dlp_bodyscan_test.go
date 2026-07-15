// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func newBodyDLPScanner(t *testing.T) *scanner.Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	return sc
}

func bodyMatchesPattern(t *testing.T, sc *scanner.Scanner, body, patternName string) bool {
	t.Helper()
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/json",
		MaxBytes:    1024 * 1024,
		Scanner:     sc,
	})
	for _, m := range result.DLPMatches {
		if strings.Contains(m.PatternName, patternName) {
			return true
		}
	}
	return false
}

// TestScanRequestBody_TwilioMailgunBoundaries proves the Twilio/Mailgun
// boundary tightening holds on the request-body transport, matching the URL
// and text-DLP coverage. Asserting on DLPMatches (not Clean) isolates the
// regex from the warn-vs-block action.
func TestScanRequestBody_TwilioMailgunBoundaries(t *testing.T) {
	sc := newBodyDLPScanner(t)
	// Built at runtime to avoid gitleaks-style source scanning.
	hex32 := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"

	const (
		twilioName  = "Twilio API Key"
		mailgunName = "Mailgun API Key"
	)

	cases := []struct {
		name    string
		body    string
		pattern string
		want    bool // true = must match (no false-negative), false = FP fixed
	}{
		{"twilio real shape matches", `{"sid": "SK` + hex32 + `"}`, twilioName, true},
		{"mailgun real shape matches", `{"api_key": "key-` + hex32 + `"}`, mailgunName, true},
		{"twilio word-ending-sk clean", `{"id": "disk` + hex32 + `"}`, twilioName, false},
		{"twilio overlong hex clean", `{"id": "SK` + hex32 + hex32 + `"}`, twilioName, false},
		{"mailgun embedded clean", `{"id": "monkey-` + hex32 + `"}`, mailgunName, false},
		{"mailgun overlong clean", `{"id": "key-` + hex32 + `wxyzWXYZ"}`, mailgunName, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bodyMatchesPattern(t, sc, tc.body, tc.pattern)
			if got != tc.want {
				t.Errorf("body %q matched %s = %v, want %v", tc.body, tc.pattern, got, tc.want)
			}
		})
	}
}

func TestScanRequestBody_TwilioMailgunRedactionClasses(t *testing.T) {
	sc := newBodyDLPScanner(t)
	hex32 := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	twilioKey := "SK" + hex32
	mailgunKey := "key-" + hex32
	body := `{"sid":"` + twilioKey + `","api_key":"` + mailgunKey + `"}`

	buf, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:          strings.NewReader(body),
		ContentType:   "application/json",
		MaxBytes:      1024 * 1024,
		Scanner:       sc,
		RedactMatcher: redact.NewDefaultMatcher(),
	})
	got := string(buf)
	if strings.Contains(got, twilioKey) || strings.Contains(got, mailgunKey) {
		t.Fatalf("redacted body leaked raw Twilio/Mailgun key: %s", got)
	}
	if !strings.Contains(got, "<pl:twilio-api-key:1>") {
		t.Fatalf("redacted body missing Twilio placeholder: %s", got)
	}
	if !strings.Contains(got, "<pl:mailgun-api-key:1>") {
		t.Fatalf("redacted body missing Mailgun placeholder: %s", got)
	}
	if result.RedactionReport == nil || !result.RedactionReport.Applied {
		t.Fatalf("RedactionReport missing or not applied: %+v", result.RedactionReport)
	}
	if len(result.DLPMatches) == 0 {
		t.Fatal("expected pre-redaction DLP evidence to survive redaction")
	}
}
