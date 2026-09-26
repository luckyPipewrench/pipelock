// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestDoHPostBodyBlocksCredentialAndAllowsBenign(t *testing.T) {
	sc := newBodyDLPScanner(t)
	attack := dohQueryWire([]string{strings.ToLower(dohBase32(awsExampleAccessKeyID())), "x", "exfil", "test"})
	benign := dohQueryWire([]string{"cache", "example", "test"})
	notDNS := []byte("this body is not a dns message but it is long enough to be scanned as text")

	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			// The message's pieces go through ordinary body DLP, so the
			// result carries the configured body action (warn here) and the
			// critical match; the forward and intercept paths hard-block it
			// through shouldHardBlockRequestDLP, which is asserted directly.
			blocked := scanDoHBody(t, sc, scheme, attack)
			if blocked.Clean || !dohHasMatch(blocked, "AWS Access ID") {
				t.Fatalf("attack = clean %v matches %+v", blocked.Clean, blocked.DLPMatches)
			}
			if !shouldHardBlockRequestDLP(blocked.DLPMatches, config.Defaults()) {
				t.Fatalf("attack match does not hard-block: %+v", blocked.DLPMatches)
			}
			allowed := scanDoHBody(t, sc, scheme, benign)
			if !allowed.Clean {
				t.Fatalf("benign blocked: action %q reason %q", allowed.Action, allowed.Reason)
			}
			opaque := scanDoHBody(t, sc, scheme, notDNS)
			if opaque.Action == config.ActionBlock && strings.Contains(opaque.Reason, "DLP") {
				t.Fatalf("non-DNS body hard-blocked: %q", opaque.Reason)
			}
		})
	}
}

func TestDoHPostBodyCorePatternWithEmptyConfiguredList(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.IncludeDefaults = boolPtr(false)
	cfg.DLP.Patterns = nil
	cfg.RequestBodyScanning.Enabled = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	wire := dohTXTWire(awsExampleAccessKeyID())
	result := scanDoHBody(t, sc, "https", wire)
	if !dohHasMatch(result, "AWS Access ID") || !shouldHardBlockRequestDLP(result.DLPMatches, config.Defaults()) {
		t.Fatalf("core TXT = clean %v matches %+v", result.Clean, result.DLPMatches)
	}
}

// An operator suppression for a configured pattern now reaches a DNS
// message, because its pieces run through the ordinary body DLP pipeline.
// The same request without the suppression still matches.
func TestDoHPostBodyHonorsScopedSuppress(t *testing.T) {
	sc := newBodyDLPScanner(t)
	wire := dohTXTWire(fakeAnthropicKey())
	req := func(suppress []config.SuppressEntry) BodyScanResult {
		_, result := scanRequestBody(context.Background(), BodyScanRequest{
			Body:        bytes.NewReader(wire),
			Scheme:      "https",
			Method:      http.MethodPost,
			ContentType: dnsMessageMediaType,
			MaxBytes:    1024 * 1024,
			Scanner:     sc,
			Host:        "dns.vendor.example",
			Path:        "/dns-query",
			Target:      "https://dns.vendor.example/dns-query",
			Action:      config.ActionWarn,
			Suppress:    suppress,
		})
		return result
	}
	if r := req(nil); !dohHasMatch(r, "Anthropic API Key") {
		t.Fatalf("unsuppressed DoH body lost its match: %+v", r.DLPMatches)
	}
	suppressed := req([]config.SuppressEntry{{Rule: "Anthropic API Key", Path: "*dns.vendor.example*", Reason: "test suppression"}})
	if dohHasMatch(suppressed, "Anthropic API Key") {
		t.Fatalf("suppression ignored for DoH body: %+v", suppressed.DLPMatches)
	}
}

func dohHasMatch(result BodyScanResult, pattern string) bool {
	for _, m := range result.DLPMatches {
		if m.PatternName == pattern {
			return true
		}
	}
	return false
}

func TestDoHPostForwardAndIntercept(t *testing.T) {
	p, backend := setupTestProxy(t)
	t.Cleanup(p.Close)
	t.Cleanup(backend.Close)
	attack := dohQueryWire([]string{strings.ToLower(dohBase32(awsExampleAccessKeyID())), "x", "exfil", "test"})
	benign := dohQueryWire([]string{"cache", "example", "test"})

	forward := func(body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, backend.URL+"/dns-query", bytes.NewReader(body))
		req.Header.Set("Content-Type", dnsMessageMediaType)
		rec := httptest.NewRecorder()
		p.handleForwardHTTP(rec, req)
		return rec
	}
	if rec := forward(attack); rec.Code != http.StatusForbidden {
		t.Fatalf("forward attack status = %d body %s", rec.Code, rec.Body.String())
	}
	if rec := forward(benign); rec.Code == http.StatusForbidden {
		t.Fatalf("forward benign blocked: %s", rec.Body.String())
	}

	cfg := p.cfgPtr.Load()
	sc := p.scannerPtr.Load()
	handler := newInterceptHandler(&InterceptContext{
		TargetHost: "api.vendor.example",
		TargetPort: "443",
		Config:     cfg,
		Scanner:    sc,
		Logger:     p.logger,
		Metrics:    p.metrics,
		ClientIP:   "127.0.0.1",
		RequestID:  "doh-intercept",
		Agent:      "test-agent",
		Proxy:      p,
	}, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(strings.NewReader("ok")),
			ContentLength: 2,
			Header:        make(http.Header),
			Request:       r,
		}, nil
	}))
	intercept := func(body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://api.vendor.example/dns-query", bytes.NewReader(body))
		req.Header.Set("Content-Type", dnsMessageMediaType)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := intercept(attack); rec.Code != http.StatusForbidden {
		t.Fatalf("intercept attack status = %d body %s", rec.Code, rec.Body.String())
	}
	if rec := intercept(benign); rec.Code == http.StatusForbidden {
		t.Fatalf("intercept benign blocked: %s", rec.Body.String())
	}
}

func scanDoHBody(t *testing.T, sc *scanner.Scanner, scheme string, body []byte) BodyScanResult {
	t.Helper()
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:                    bytes.NewReader(body),
		Scheme:                  scheme,
		Method:                  http.MethodPost,
		ContentType:             dnsMessageMediaType,
		MaxBytes:                1024 * 1024,
		Scanner:                 sc,
		Host:                    "dns.vendor.example",
		Path:                    "/dns-query",
		ContentEntropyEnabled:   true,
		ContentEntropyAction:    config.ActionWarn,
		ContentEntropyThreshold: 4.5,
		ContentEntropyMinLength: 32,
		Action:                  config.ActionWarn,
	})
	return result
}

func awsExampleAccessKeyID() string {
	return "AKIA" + "IOSFODNN7EXAMPLE"
}

func dohBase32(s string) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString([]byte(s)), "=")
}

func dohQueryWire(labels []string) []byte {
	wire := make([]byte, 12)
	wire[5] = 1
	for _, label := range labels {
		wire = append(wire, byte(len(label))) // #nosec G115 -- DNS test lengths are small fixed values.
		wire = append(wire, label...)
	}
	wire = append(wire, 0, 0x00, 0x01, 0x00, 0x01)
	return wire
}

func dohTXTWire(secret string) []byte {
	wire := dohQueryWire([]string{"cache", "example", "test"})
	wire[11] = 1
	wire = append(wire, byte(len("txt")))
	wire = append(wire, "txt"...)
	wire = append(wire, byte(len("example")))
	wire = append(wire, "example"...)
	wire = append(wire, byte(len("test")))
	wire = append(wire, "test"...)
	wire = append(wire, 0)
	rdata := append([]byte{byte(len(secret))}, secret...)                        // #nosec G115 -- DNS test lengths are small fixed values.
	wire = append(wire, 0x00, 0x10, 0x00, 0x01, 0, 0, 0, 0, 0, byte(len(rdata))) // #nosec G115 -- DNS test lengths are small fixed values.
	return append(wire, rdata...)
}

func boolPtr(v bool) *bool { return &v }

// Data split into many labels, each shorter than the content-entropy minimum
// length, is still measured: every piece of the message goes to one
// ScanTexts call, whose joined check sees them together. Scored one piece at
// a time, no piece would reach the minimum length.
func TestDoHPostBodyJoinedEntropyCoversSplitLabels(t *testing.T) {
	sc := newBodyDLPScanner(t)
	const labelLen = 30 // under ContentEntropyMinLength (32)
	var labels []string
	seed := sha256.Sum256([]byte("split-labels"))
	for len(labels) < 8 {
		enc := base64.RawURLEncoding.EncodeToString(seed[:])
		labels = append(labels, enc[:labelLen])
		seed = sha256.Sum256(seed[:])
	}
	// Four labels per question keeps each name under the 255-byte RFC 1035
	// limit, so the body really is a strict DNS message.
	wire := make([]byte, 12)
	wire[5] = byte(len(labels) / 4) // #nosec G115 -- two questions
	for i := 0; i < len(labels); i += 4 {
		for _, label := range append(labels[i:i+4:i+4], "example", "test") {
			wire = append(wire, byte(len(label))) // #nosec G115 -- DNS test lengths are small fixed values.
			wire = append(wire, label...)
		}
		wire = append(wire, 0, 0x00, 0x01, 0x00, 0x01)
	}
	if !sc.InspectDNSPayload(wire).Parsed {
		t.Fatal("premise: the fixture must parse as a strict DNS message")
	}
	result := scanDoHBody(t, sc, "https", wire)
	if result.EntropyFinding == nil {
		t.Fatalf("split high-entropy labels produced no entropy finding: %+v", result)
	}
	benign := scanDoHBody(t, sc, "https", dohQueryWire([]string{"www", "example", "test"}))
	if benign.EntropyFinding != nil {
		t.Fatalf("ordinary query produced an entropy finding: %+v", benign.EntropyFinding)
	}
}

// A key split across two labels appears only in the parsed message's joined
// view, never in the raw body, so this proves the DNS pieces reach body DLP.
func TestDoHPostBodySplitLabelKeyReachesDLP(t *testing.T) {
	sc := newBodyDLPScanner(t)
	key := awsExampleAccessKeyID()
	half := len(key) / 2
	// Each label is 35 bytes, so the length octet between them is a printable
	// '#' that the raw-body views keep, splitting the key there. A '.' would
	// not do: the subdomain view drops dots and would rejoin the halves.
	pad := strings.Repeat("-", 35-half)
	wire := dohQueryWire([]string{pad + key[:half], key[half:] + pad, "exfil", "test"})
	if strings.Contains(string(wire), key) {
		t.Fatal("premise: the raw body must not carry the key contiguously")
	}
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			r := scanDoHBody(t, sc, scheme, wire)
			if r.Clean || !dohHasMatch(r, "AWS Access ID") {
				t.Fatalf("split key = clean %v matches %+v", r.Clean, r.DLPMatches)
			}
		})
	}
}
