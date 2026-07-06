// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/emitformat"
)

const (
	FormatJSON = emitformat.JSON
	FormatCEF  = emitformat.CEF

	cefVersion       = "0"
	cefDeviceVendor  = "Pipelock"
	cefDeviceProduct = "Pipelock"
	fieldReason      = "reason"
)

// FormatCEFEvent renders an event as one ArcSight Common Event Format line.
func FormatCEFEvent(event Event, deviceVersion string) string {
	if deviceVersion == "" {
		deviceVersion = "unknown"
	}

	extension := cefExtension(event)

	header := []string{
		"CEF:" + cefVersion,
		cefEscapeHeader(cefDeviceVendor),
		cefEscapeHeader(cefDeviceProduct),
		cefEscapeHeader(deviceVersion),
		cefEscapeHeader(event.Type),
		cefEscapeHeader(cefName(event)),
		fmt.Sprintf("%d", cefSeverity(event.Severity)),
	}
	return strings.Join(header, "|") + "|" + extension
}

func cefName(event Event) string {
	if reason, ok := event.Fields[fieldReason].(string); ok && reason != "" {
		return event.Type + ": " + reason
	}
	if scanner, ok := event.Fields[fieldScanner].(string); ok && scanner != "" {
		return event.Type + ": " + scanner
	}
	return event.Type
}

func cefSeverity(sev Severity) int {
	switch sev {
	case SeverityCritical:
		return 10
	case SeverityWarn:
		return 6
	default:
		return 3
	}
}

func cefExtension(event Event) string {
	values := map[string]string{
		"rt":               event.Timestamp.UTC().Format(time.RFC3339Nano),
		"pipelockEvent":    event.Type,
		"pipelockSeverity": event.Severity.String(),
	}
	if event.InstanceID != "" {
		values["pipelockInstance"] = event.InstanceID
	}
	if action := eventAction(event); action != "" {
		values["act"] = action
	}
	if decisionType := eventDecisionType(event); decisionType != "" {
		values["cat"] = decisionType
	}
	if agent := eventAgent(event); agent != "" {
		values["suser"] = agent
	}

	for _, key := range sortedKeys(event.Fields) {
		value := event.Fields[key]
		cefKey, ok := cefFieldKey(key)
		if !ok {
			continue
		}
		if _, exists := values[cefKey]; exists {
			continue
		}
		rendered := cefFieldValue(value)
		if rendered == "" {
			continue
		}
		values[cefKey] = rendered
	}

	keys := sortedKeys(values)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+cefEscapeExtension(values[key]))
	}
	return strings.Join(parts, " ")
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cefFieldKey(key string) (string, bool) {
	switch key {
	case "action", "decision":
		return "act", true
	case "agent", "identity", "actor", "principal":
		return "suser", true
	case "client_ip":
		return "src", true
	case "method":
		return "requestMethod", true
	case "request_id":
		return "externalId", true
	case "url":
		return "request", true
	case "target", "resource":
		return "destinationServiceName", true
	case fieldReason, "error":
		return "msg", true
	case "scanner":
		return "cs1", true
	case "pattern":
		return "cs2", true
	case "decision_type":
		return "cat", true
	default:
		safe := cefCustomKey(key)
		return safe, safe != ""
	}
}

func cefCustomKey(key string) string {
	var b strings.Builder
	b.WriteString("pipelock")
	upperNext := true
	for _, r := range key {
		if r == '_' || r == '-' || r == '.' || unicode.IsSpace(r) {
			upperNext = true
			continue
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			continue
		}
		if upperNext {
			b.WriteRune(unicode.ToUpper(r))
			upperNext = false
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() == len("pipelock") {
		return ""
	}
	return b.String()
}

func cefFieldValue(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case []string:
		return strings.Join(v, ",")
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, fmt.Sprint(item))
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprint(v)
	}
}

func cefEscapeHeader(s string) string {
	return cefEscape(s)
}

func cefEscapeExtension(s string) string {
	return cefEscape(s)
}

func cefEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '|':
			b.WriteString(`\|`)
		case '=':
			b.WriteString(`\=`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if unicode.IsControl(r) {
				_, _ = fmt.Fprintf(&b, `\u%04X`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}
