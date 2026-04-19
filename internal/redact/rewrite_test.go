// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"errors"
	"strings"
	"testing"
)

func TestRewriteString_SingleMatch(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	// "connect to " is 11 chars; "192.0.2.104" occupies [11, 22).
	matches := []Match{
		{Class: ClassIPv4, Start: 11, End: 22, Original: "192.0.2.104"},
	}
	got := RewriteString("connect to 192.0.2.104 now", matches, r)
	want := "connect to <pl:ipv4:1> now"
	if got != want {
		t.Fatalf("RewriteString = %q, want %q", got, want)
	}
}

func TestRewriteString_MultipleMatches(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	in := "from 10.0.0.1 to 10.0.0.2 via dc01.corp.local"
	matches := []Match{
		{Class: ClassIPv4, Start: 5, End: 13, Original: "10.0.0.1"},
		{Class: ClassIPv4, Start: 17, End: 25, Original: "10.0.0.2"},
		{Class: ClassFQDN, Start: 30, End: 45, Original: "dc01.corp.local"},
	}
	got := RewriteString(in, matches, r)
	want := "from <pl:ipv4:1> to <pl:ipv4:2> via <pl:fqdn:1>"
	if got != want {
		t.Fatalf("RewriteString = %q, want %q", got, want)
	}
}

func TestRewriteString_EmptyNoop(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	if got := RewriteString("", nil, r); got != "" {
		t.Fatalf("empty input should return empty, got %q", got)
	}
	if got := RewriteString("unchanged", nil, r); got != "unchanged" {
		t.Fatalf("no matches should return input verbatim, got %q", got)
	}
}

func TestRewriteString_OverlappingSkipped(t *testing.T) {
	t.Parallel()
	// Malformed caller input: overlapping matches. Rewriter must defensively
	// skip the overlapper instead of producing garbled output.
	r := NewRedactor()
	in := "10.0.0.1"
	matches := []Match{
		{Class: ClassIPv4, Start: 0, End: 8, Original: "10.0.0.1"},
		{Class: ClassFQDN, Start: 3, End: 8, Original: "0.0.1"}, // overlaps with IPv4
	}
	got := RewriteString(in, matches, r)
	// First match applied; second skipped because Start < cursor.
	if got != "<pl:ipv4:1>" {
		t.Fatalf("RewriteString with overlapping = %q, want %q", got, "<pl:ipv4:1>")
	}
}

func TestRewriteJSON_WholeBodyScan(t *testing.T) {
	t.Parallel()
	body := []byte(`{
        "system": "Use AKIA` + `IOSFODNN7EXAMPLE against dc01.corp.local",
        "tools": [{"description": "call 10.0.0.5"}],
        "messages": [
          {"role": "user", "content": "please scan 192.168.1.1 for me"}
        ]
    }`)

	out, report, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{})
	if err != nil {
		t.Fatalf("RewriteJSON error: %v", err)
	}
	if report == nil || !report.Applied {
		t.Fatalf("report = %+v, want Applied=true", report)
	}
	if report.TotalRedactions < 4 {
		t.Fatalf("expected at least 4 redactions (system AWS key + system FQDN + tool IPv4 + message IPv4), got %d", report.TotalRedactions)
	}
	outStr := string(out)
	// Whole-body scan — the AWS key in `system` MUST be redacted (round-3
	// bypass fix).
	if strings.Contains(outStr, "AKIA"+"IOSFODNN7EXAMPLE") {
		t.Fatalf("AWS access key leaked through system field: %s", outStr)
	}
	// FQDN in system must be redacted too.
	if strings.Contains(outStr, "dc01.corp.local") {
		t.Fatalf("FQDN leaked through system field: %s", outStr)
	}
	// IPv4 in tools description must be redacted.
	if strings.Contains(outStr, "10.0.0.5") {
		t.Fatalf("IPv4 leaked through tools field: %s", outStr)
	}
	// IPv4 in user message must be redacted.
	if strings.Contains(outStr, "192.168.1.1") {
		t.Fatalf("IPv4 leaked through user message: %s", outStr)
	}
}

func TestRewriteJSON_DeepNestingRedacted(t *testing.T) {
	t.Parallel()
	// Secret buried several levels deep must still be scanned.
	body := []byte(`{
        "outer": {
            "middle": {
                "inner": [
                    {"deep": "hit AKIA` + `IOSFODNN7EXAMPLE now"}
                ]
            }
        }
    }`)
	out, report, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{})
	if err != nil {
		t.Fatalf("RewriteJSON error: %v", err)
	}
	if report.TotalRedactions != 1 {
		t.Fatalf("expected 1 redaction, got %d", report.TotalRedactions)
	}
	if strings.Contains(string(out), "AKIA"+"IOSFODNN7EXAMPLE") {
		t.Fatalf("deep-nested secret leaked: %s", out)
	}
}

func TestRewriteJSON_DedupAcrossFields(t *testing.T) {
	t.Parallel()
	// Same original value in two different fields must get the same
	// placeholder (per-request dedup).
	body := []byte(`{"a": "see 10.0.0.1 here", "b": "and 10.0.0.1 there"}`)
	out, report, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{})
	if err != nil {
		t.Fatalf("RewriteJSON error: %v", err)
	}
	if report.TotalRedactions != 1 {
		t.Fatalf("same value in two fields should dedup to 1, got %d", report.TotalRedactions)
	}
	// Both occurrences should become <pl:ipv4:1>.
	if c := strings.Count(string(out), "<pl:ipv4:1>"); c != 2 {
		t.Fatalf("expected 2 placeholder occurrences, got %d; out=%s", c, out)
	}
}

func TestRewriteJSON_OverflowDedupCountsUniquePairsOnly(t *testing.T) {
	t.Parallel()
	body := []byte(`{"a":"10.0.0.1 10.0.0.1","b":"10.0.0.1"}`)
	out, report, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{MaxRedactionsPerRequest: 1})
	if err != nil {
		t.Fatalf("duplicate values should fit under unique-count cap, got %v", err)
	}
	if report.TotalRedactions != 1 {
		t.Fatalf("expected 1 unique redaction, got %d", report.TotalRedactions)
	}
	if c := strings.Count(string(out), "<pl:ipv4:1>"); c != 3 {
		t.Fatalf("expected 3 placeholder occurrences, got %d; out=%s", c, out)
	}
}

func TestRewriteJSON_BodyTooLargeBlocks(t *testing.T) {
	t.Parallel()
	body := []byte(`{"x":"` + strings.Repeat("a", 2048) + `"}`)
	_, _, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{MaxBodyBytes: 512})
	be, ok := asBlockError(err)
	if !ok {
		t.Fatalf("expected BlockError, got %v", err)
	}
	if be.Reason != ReasonBodyTooLarge {
		t.Fatalf("reason = %q, want %q", be.Reason, ReasonBodyTooLarge)
	}
}

func TestRewriteJSON_UnparseableBodyBlocks(t *testing.T) {
	t.Parallel()
	_, _, err := RewriteJSON([]byte(`{not json`), NewDefaultMatcher(), NewRedactor(), Limits{})
	be, ok := asBlockError(err)
	if !ok {
		t.Fatalf("expected BlockError, got %v", err)
	}
	if be.Reason != ReasonBodyUnparseable {
		t.Fatalf("reason = %q, want %q", be.Reason, ReasonBodyUnparseable)
	}
}

func TestRewriteJSON_OverflowBlocks(t *testing.T) {
	t.Parallel()
	// Attacker crafts a body with many distinct IPs; cap at 3 forces
	// overflow on the fourth.
	body := []byte(`{"x":"10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4"}`)
	_, _, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{MaxRedactionsPerRequest: 3})
	be, ok := asBlockError(err)
	if !ok {
		t.Fatalf("expected BlockError, got %v", err)
	}
	if be.Reason != ReasonOverflow {
		t.Fatalf("reason = %q, want %q", be.Reason, ReasonOverflow)
	}
}

func TestRewriteJSON_DepthLimitBlocks(t *testing.T) {
	t.Parallel()
	// 6 levels of nesting, cap at 2 — should block.
	body := []byte(`{"a":{"b":{"c":{"d":{"e":{"f":"x"}}}}}}`)
	_, _, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{MaxDepth: 2})
	be, ok := asBlockError(err)
	if !ok {
		t.Fatalf("expected BlockError, got %v", err)
	}
	if be.Reason != ReasonDepthExceeded {
		t.Fatalf("reason = %q, want %q", be.Reason, ReasonDepthExceeded)
	}
}

func TestRewriteJSON_EmptyBodyClean(t *testing.T) {
	t.Parallel()
	out, report, err := RewriteJSON([]byte(`{}`), NewDefaultMatcher(), NewRedactor(), Limits{})
	if err != nil {
		t.Fatalf("empty object should not error: %v", err)
	}
	if string(out) != `{}` {
		t.Fatalf("empty object = %q, want %q", out, `{}`)
	}
	if report.TotalRedactions != 0 {
		t.Fatalf("no redactions expected, got %d", report.TotalRedactions)
	}
}

func TestRewriteJSON_PreservesNumbersAndBools(t *testing.T) {
	t.Parallel()
	body := []byte(`{"n": 42, "pi": 3.14, "ok": true, "v": null, "text": "10.0.0.1"}`)
	out, report, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{})
	if err != nil {
		t.Fatalf("RewriteJSON error: %v", err)
	}
	if report.TotalRedactions != 1 {
		t.Fatalf("expected 1 redaction, got %d", report.TotalRedactions)
	}
	outStr := string(out)
	for _, needle := range []string{`"n":42`, `"pi":3.14`, `"ok":true`, `"v":null`} {
		if !strings.Contains(outStr, needle) {
			t.Errorf("expected %s in output, got %s", needle, outStr)
		}
	}
}

// TestRewriteJSON_JSONKeyBypassClosed confirms that secrets placed in
// JSON object KEYS are scanned and redacted. Review finding #1
// (2026-04-19): an agent could stuff a secret into a key name and evade
// value-only scanning.
func TestRewriteJSON_JSONKeyBypassClosed(t *testing.T) {
	t.Parallel()
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	body := []byte(`{"` + awsKey + `": "value"}`)
	out, report, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{})
	if err != nil {
		t.Fatalf("RewriteJSON: %v", err)
	}
	if report.TotalRedactions != 1 {
		t.Fatalf("expected 1 redaction, got %d", report.TotalRedactions)
	}
	if strings.Contains(string(out), awsKey) {
		t.Fatalf("secret in JSON key leaked: %s", out)
	}
	if !strings.Contains(string(out), "<pl:aws-access-key:1>") {
		t.Fatalf("expected placeholder-as-key in output, got %s", out)
	}
}

// TestRewriteJSON_KeyCollisionBlocks guards against silent sibling-field
// drop when the rewritten version of one key equals the literal value of
// another key in the same object. GPT review #2 (2026-04-19).
func TestRewriteJSON_KeyCollisionBlocks(t *testing.T) {
	t.Parallel()
	// First key is a literal placeholder-shaped string (untouched).
	// Second key contains an IPv4 that rewrites to the same string.
	body := []byte(`{"<pl:ipv4:1>": "one", "10.0.0.1": "two"}`)
	_, _, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{})
	be, ok := asBlockError(err)
	if !ok {
		t.Fatalf("expected BlockError, got %v", err)
	}
	if be.Reason != ReasonKeyCollision {
		t.Fatalf("reason = %q, want %q", be.Reason, ReasonKeyCollision)
	}
}

func TestRewriteJSON_JSONKeyRedactionDedupesWithValue(t *testing.T) {
	t.Parallel()
	// Same secret appearing as both a key and a value should dedup to one
	// placeholder per the Redactor's (class, original) contract.
	ip := "10.0.0.1"
	body := []byte(`{"` + ip + `": "mirrored here: ` + ip + `"}`)
	_, report, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{})
	if err != nil {
		t.Fatalf("RewriteJSON: %v", err)
	}
	if report.TotalRedactions != 1 {
		t.Fatalf("key+value of same original should dedup to 1, got %d", report.TotalRedactions)
	}
}

func TestRewriteJSON_NonStringScalarsUntouched(t *testing.T) {
	t.Parallel()
	// A JSON array of numbers — no scalars to scan, no redactions.
	body := []byte(`[1, 2, 3, 4]`)
	out, report, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{})
	if err != nil {
		t.Fatalf("array input error: %v", err)
	}
	if report.TotalRedactions != 0 {
		t.Fatalf("expected no redactions, got %d", report.TotalRedactions)
	}
	if string(out) != `[1,2,3,4]` {
		t.Fatalf("array output = %q, want %q", out, `[1,2,3,4]`)
	}
}

func TestNormaliseLimits_DefaultsAndClamps(t *testing.T) {
	t.Parallel()
	// Zero input → defaults.
	l := normaliseLimits(Limits{})
	if l.MaxBodyBytes != DefaultMaxBodyBytes {
		t.Errorf("MaxBodyBytes default = %d, want %d", l.MaxBodyBytes, DefaultMaxBodyBytes)
	}
	if l.MaxRedactionsPerRequest != DefaultMaxRedactions {
		t.Errorf("MaxRedactions default = %d, want %d", l.MaxRedactionsPerRequest, DefaultMaxRedactions)
	}
	if l.MaxDepth != DefaultMaxDepth {
		t.Errorf("MaxDepth default = %d, want %d", l.MaxDepth, DefaultMaxDepth)
	}
	// Over-the-limit input → clamped.
	l = normaliseLimits(Limits{
		MaxBodyBytes:            absoluteBodyCapBytes * 10,
		MaxRedactionsPerRequest: absoluteRedactionCap * 10,
		MaxDepth:                absoluteDepthCap * 10,
	})
	if l.MaxBodyBytes != absoluteBodyCapBytes {
		t.Errorf("MaxBodyBytes clamp = %d, want %d", l.MaxBodyBytes, absoluteBodyCapBytes)
	}
	if l.MaxRedactionsPerRequest != absoluteRedactionCap {
		t.Errorf("MaxRedactions clamp = %d, want %d", l.MaxRedactionsPerRequest, absoluteRedactionCap)
	}
	if l.MaxDepth != absoluteDepthCap {
		t.Errorf("MaxDepth clamp = %d, want %d", l.MaxDepth, absoluteDepthCap)
	}
}

// asBlockError unwraps an error to a *BlockError if one is present.
func asBlockError(err error) (*BlockError, bool) {
	if err == nil {
		return nil, false
	}
	var be *BlockError
	if errors.As(err, &be) {
		return be, true
	}
	return nil, false
}
