// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"strings"
	"testing"
	"time"
)

func TestFormatCEFEvent(t *testing.T) {
	ts := time.Date(2026, 7, 5, 12, 34, 56, 789, time.UTC)
	event := Event{
		Severity:   SeverityWarn,
		Type:       EventBodyDLP,
		Timestamp:  ts,
		InstanceID: testInstanceName,
		Fields: map[string]any{
			"action":     conventionActionBlock,
			"agent":      "agent-a",
			"client_ip":  "203.0.113.10",
			"method":     "POST",
			"pattern":    "api-key",
			"request_id": "req-123",
			"scanner":    "dlp",
			"url":        "https://api.vendor.example/v1/chat",
			fieldReason:  "secret detected",
		},
	}

	got := FormatCEFEvent(event, "1.2.3")
	want := "CEF:0|Pipelock|Pipelock|1.2.3|body_dlp|body_dlp: secret detected|6|act=block cat=body_dlp cs1=dlp cs2=api-key externalId=req-123 msg=secret detected pipelockEvent=body_dlp pipelockInstance=test-instance pipelockSeverity=warn request=https://api.vendor.example/v1/chat requestMethod=POST rt=2026-07-05T12:34:56.000000789Z src=203.0.113.10 suser=agent-a"
	if got != want {
		t.Fatalf("FormatCEFEvent() =\n%s\nwant\n%s", got, want)
	}
}

func TestFormatCEFEventEscapesDelimiters(t *testing.T) {
	event := Event{
		Severity:   SeverityCritical,
		Type:       `blocked|event`,
		Timestamp:  time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		InstanceID: `node|a`,
		Fields: map[string]any{
			fieldReason: `bad|pipe=eq\slash` + "\nline",
			"agent":     `agent|one=two\three` + "\nnext",
		},
	}

	got := FormatCEFEvent(event, `2|x`)
	for _, want := range []string{
		`CEF:0|Pipelock|Pipelock|2\|x|blocked\|event|blocked\|event: bad\|pipe\=eq\\slash\nline|10|`,
		`msg=bad\|pipe\=eq\\slash\nline`,
		`suser=agent\|one\=two\\three\nnext`,
		`pipelockInstance=node\|a`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("CEF line missing %q:\n%s", want, got)
		}
	}
}

func TestFormatCEFEventEscapesLineForgeryPayloads(t *testing.T) {
	payload := "https://api.vendor.example/path|name=value\\trail\r\nCEF:0|Forged|Device|1|sig|name|10|act=allow"
	event := Event{
		Severity:   SeverityCritical,
		Type:       "body|dlp\r\nCEF:0|forged",
		Timestamp:  time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		InstanceID: "node\r\nforged",
		Fields: map[string]any{
			"action":            conventionActionBlock,
			"agent":             "agent|id=value\\x\r\nforged",
			"url":               payload,
			fieldReason:         "matched snippet | key=value\\x\r\nforged",
			"bad|key=\r\nforge": "value",
		},
	}

	got := FormatCEFEvent(event, "2|x\r\n3")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("CEF line contains raw CR/LF:\n%q", got)
	}
	if pipes := countUnescapedPipes(got); pipes != 7 {
		t.Fatalf("CEF line has %d unescaped pipes, want 7:\n%s", pipes, got)
	}
	for _, want := range []string{
		`request=https://api.vendor.example/path\|name\=value\\trail\r\nCEF:0\|Forged\|Device\|1\|sig\|name\|10\|act\=allow`,
		`suser=agent\|id\=value\\x\r\nforged`,
		`msg=matched snippet \| key\=value\\x\r\nforged`,
		`pipelockBadkeyForge=value`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("CEF line missing escaped payload %q:\n%s", want, got)
		}
	}
}

func countUnescapedPipes(s string) int {
	count := 0
	backslashes := 0
	for _, r := range s {
		switch r {
		case '\\':
			backslashes++
		case '|':
			if backslashes%2 == 0 {
				count++
			}
			backslashes = 0
		default:
			backslashes = 0
		}
	}
	return count
}

func TestFormatCEFEventEmptyFields(t *testing.T) {
	event := Event{
		Severity:  SeverityInfo,
		Type:      EventStartup,
		Timestamp: time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC),
	}

	got := FormatCEFEvent(event, "")
	want := "CEF:0|Pipelock|Pipelock|unknown|startup|startup|3|act=allow cat=startup pipelockEvent=startup pipelockSeverity=info rt=2026-07-05T00:00:00Z"
	if got != want {
		t.Fatalf("FormatCEFEvent() =\n%s\nwant\n%s", got, want)
	}
}

func TestFormatCEFEventSampleProof(t *testing.T) {
	event := Event{
		Severity:   SeverityWarn,
		Type:       EventBodyDLP,
		Timestamp:  time.Date(2026, 7, 5, 12, 34, 56, 0, time.UTC),
		InstanceID: "fedora-demo",
		Fields: map[string]any{
			"action":     conventionActionBlock,
			"agent":      "agent-a",
			"client_ip":  "203.0.113.10",
			"method":     "POST",
			"request_id": "req-123",
			"scanner":    "dlp",
			"url":        "https://api.vendor.example/v1/chat",
			fieldReason:  "secret detected",
		},
	}

	t.Log(FormatCEFEvent(event, "dev"))
}
