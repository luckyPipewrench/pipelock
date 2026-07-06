// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"fmt"
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

func TestFormatCEFEventRawFieldsCannotOverwriteCanonicalKeys(t *testing.T) {
	event := Event{
		Severity:   SeverityWarn,
		Type:       EventBlocked,
		Timestamp:  time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		InstanceID: testInstanceName,
		Fields: map[string]any{
			"action":        "allow",
			"agent":         "agent-a",
			"decision":      "allow",
			"decision_type": "spoofed",
			"event":         "spoofed-event",
			"identity":      "spoofed-agent",
			fieldReason:     "blocked by scanner",
			"type":          "spoofed-type",
		},
	}

	got := FormatCEFEvent(event, "dev")
	for _, want := range []string{
		`act=block`,
		`cat=blocked`,
		`pipelockEvent=blocked`,
		`pipelockInstance=test-instance`,
		`suser=agent-a`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("CEF line missing canonical field %q:\n%s", want, got)
		}
	}
	for _, forbidden := range []string{
		`act=allow`,
		`cat=spoofed`,
		`pipelockEvent=spoofed-event`,
		`suser=spoofed-agent`,
	} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("CEF line allowed raw field overwrite %q:\n%s", forbidden, got)
		}
	}
}

func TestFormatCEFEventRawFieldCollisionsAreDeterministic(t *testing.T) {
	event := Event{
		Severity:  SeverityInfo,
		Type:      "custom_event",
		Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		Fields: map[string]any{
			"resource":  "sorted-first-resource",
			"target":    "sorted-second-target",
			"team-name": "sorted-first-custom",
			"team_name": "sorted-second-custom",
		},
	}

	got := FormatCEFEvent(event, "dev")
	for _, want := range []string{
		`destinationServiceName=sorted-first-resource`,
		`pipelockTeamName=sorted-first-custom`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("CEF line missing deterministic collision winner %q:\n%s", want, got)
		}
	}
	for _, forbidden := range []string{
		`destinationServiceName=sorted-second-target`,
		`pipelockTeamName=sorted-second-custom`,
	} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("CEF line used nondeterministic collision value %q:\n%s", forbidden, got)
		}
	}
}

func TestFormatCEFEventEscapesControlCharacters(t *testing.T) {
	event := Event{
		Severity:   SeverityWarn,
		Type:       "blocked\x00event",
		Timestamp:  time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		InstanceID: "node\x07one",
		Fields: map[string]any{
			fieldReason: "bad\x1b[31mvalue\tend",
		},
	}

	got := FormatCEFEvent(event, "dev\x00")
	for _, raw := range []string{"\x00", "\x07", "\x1b", "\t"} {
		if strings.Contains(got, raw) {
			t.Fatalf("CEF line contains raw control %q:\n%q", raw, got)
		}
	}
	for _, want := range []string{
		`dev\u0000`,
		`blocked\u0000event`,
		`bad\u001B[31mvalue\u0009end`,
		`pipelockInstance=node\u0007one`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("CEF line missing escaped control %q:\n%s", want, got)
		}
	}
}

type cefStringer string

func (s cefStringer) String() string {
	return fmt.Sprintf("stringer:%s", string(s))
}

func TestFormatCEFEventRendersCustomFieldValues(t *testing.T) {
	event := Event{
		Severity:  SeverityInfo,
		Type:      EventResponseScan,
		Timestamp: time.Date(2026, 7, 5, 2, 3, 4, 0, time.UTC),
		Fields: map[string]any{
			"enabled":      true,
			"empty":        "",
			"items":        []any{"x", 2, true},
			"nil_value":    nil,
			"scanner":      "prompt",
			"stringer":     cefStringer("value"),
			"target.zone":  "prod",
			"tag-list":     []string{"alpha", "beta"},
			"unsafe@field": "sanitized",
		},
	}

	got := FormatCEFEvent(event, "dev")
	for _, want := range []string{
		`CEF:0|Pipelock|Pipelock|dev|response_scan|response_scan: prompt|3|`,
		`cs1=prompt`,
		`pipelockEnabled=true`,
		`pipelockItems=x,2,true`,
		`pipelockStringer=stringer:value`,
		`pipelockTagList=alpha,beta`,
		`pipelockTargetZone=prod`,
		`pipelockUnsafefield=sanitized`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("CEF line missing %q:\n%s", want, got)
		}
	}
	for _, forbidden := range []string{"pipelockEmpty=", "pipelockNilValue="} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("CEF line contains skipped field %q:\n%s", forbidden, got)
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

	got := FormatCEFEvent(event, "dev")
	want := "CEF:0|Pipelock|Pipelock|dev|body_dlp|body_dlp: secret detected|6|act=block cat=body_dlp cs1=dlp externalId=req-123 msg=secret detected pipelockEvent=body_dlp pipelockInstance=fedora-demo pipelockSeverity=warn request=https://api.vendor.example/v1/chat requestMethod=POST rt=2026-07-05T12:34:56Z src=203.0.113.10 suser=agent-a"
	if got != want {
		t.Fatalf("FormatCEFEvent() =\n%s\nwant\n%s", got, want)
	}
}
