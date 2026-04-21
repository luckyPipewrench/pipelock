// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestScanRequestBody_Redaction_BeforeDLPEarlyReturn is the load-bearing
// test for the v1b round-1 review finding (2026-04-19): in warn-mode
// DLP, the old code returned on the DLP match BEFORE redaction ran, so
// the caller forwarded the original unredacted buf. After the ordering
// fix, redaction always runs first; the buf returned to the caller —
// even when DLPMatches is non-empty — is the redacted version. Any
// warn-mode residual that DLP still flags is one redaction did not
// cover, not a raw secret the caller was about to forward.
func TestScanRequestBody_Redaction_BeforeDLPEarlyReturn(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	m := redact.NewDefaultMatcher()
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	body := `{"system":"use ` + awsKey + ` against 10.0.0.1"}`

	buf, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:          strings.NewReader(body),
		ContentType:   contentTypeJSON,
		MaxBytes:      len(body) * 2,
		Scanner:       sc,
		RedactMatcher: m,
	})

	// The returned buf is the scanner's view of the body after the
	// redaction step. Regardless of DLP verdict, the AWS key MUST NOT
	// appear in the buf the caller will forward.
	if strings.Contains(string(buf), awsKey) {
		t.Fatalf("AWS access key leaked through buf returned to caller: %s", buf)
	}
	if strings.Contains(string(buf), "10.0.0.1") {
		t.Fatalf("IPv4 leaked through buf: %s", buf)
	}
	if !strings.Contains(string(buf), "<pl:aws-access-key:1>") {
		t.Fatalf("placeholder missing from buf: %s", buf)
	}
	if result.RedactionReport == nil || !result.RedactionReport.Applied {
		t.Fatalf("RedactionReport missing or not applied: %+v", result.RedactionReport)
	}
}

// TestScanRequestBody_Redaction_NonJSONBlocked enforces fail-closed on
// non-JSON bodies when redaction is enabled and the host is not on the
// allowlist. Review §4.7 + round-1 #1.
func TestScanRequestBody_Redaction_NonJSONBlocked(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:          strings.NewReader(`any=binary&blob=here`),
		ContentType:   "application/x-www-form-urlencoded",
		MaxBytes:      1024,
		Scanner:       sc,
		RedactMatcher: redact.NewDefaultMatcher(),
		Host:          "api.anthropic.com",
	})
	if result.Clean {
		t.Fatal("expected block on non-JSON + not-allowlisted, got clean")
	}
	if result.RedactionBlockReason != redact.ReasonNonJSONBody {
		t.Fatalf("RedactionBlockReason = %q, want %q", result.RedactionBlockReason, redact.ReasonNonJSONBody)
	}
}

// TestScanRequestBody_Redaction_HostPortMatchesAllowlist guards the
// review finding that allowlist_unparseable entries are bare hostnames
// but r.Host carries :port on real proxy traffic. Must strip port
// before matching.
func TestScanRequestBody_Redaction_HostPortMatchesAllowlist(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:                       strings.NewReader(`bin payload`),
		ContentType:                "application/octet-stream",
		MaxBytes:                   1024,
		Scanner:                    sc,
		RedactMatcher:              redact.NewDefaultMatcher(),
		Host:                       "api.anthropic.com:443",
		RedactAllowlistUnparseable: []string{"api.anthropic.com"},
	})
	if !result.Clean {
		t.Fatalf("host:port should match allowlist entry, got block: reason=%q", result.RedactionBlockReason)
	}
}

// TestScanRequestBody_Redaction_NilMatcherIsNoop confirms the existing
// scan path is unaffected when redaction is not enabled (RedactMatcher
// is nil).
func TestScanRequestBody_Redaction_NilMatcherIsNoop(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	body := `{"msg":"hello"}`
	buf, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: contentTypeJSON,
		MaxBytes:    1024,
		Scanner:     sc,
	})
	if !result.Clean {
		t.Fatalf("nil matcher + clean body should be clean, got %+v", result)
	}
	if result.RedactionReport != nil {
		t.Fatalf("RedactionReport should be nil when matcher disabled, got %+v", result.RedactionReport)
	}
	if string(buf) != body {
		t.Fatalf("buf modified by disabled redaction: %s", buf)
	}
}
