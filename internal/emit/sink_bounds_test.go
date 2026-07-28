// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"strings"
	"testing"
	"time"
)

// TestEverySinkFormatBoundsHostileFields is the class-level guard for audit-sink
// amplification. A hostile oversized event field must not turn one audit event
// into a multi-megabyte record on ANY sink format. OCSF was capped first; CEF
// and OTLP carried the identical hole, because all three copy attacker-
// influenced event fields into their output with no byte cap of their own.
//
// This asserts the property once, per format, so a format added later is
// covered by adding a case here rather than by remembering the class exists.
func TestEverySinkFormatBoundsHostileFields(t *testing.T) {
	t.Parallel()

	const hostileBytes = 1 << 20 // 1 MiB
	hostile := strings.Repeat("C", hostileBytes)

	event := Event{
		Severity:   SeverityCritical,
		Type:       EventBodyDLP,
		Timestamp:  time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		InstanceID: hostile,
		Fields: map[string]any{
			"action":    conventionActionBlock,
			"agent":     hostile,
			"client_ip": hostile,
			"scanner":   hostile,
			"url":       "https://" + hostile + ".example/" + hostile,
			fieldReason: hostile,
		},
	}

	// A bounded record is allowed to be a multiple of the cap (several capped
	// fields), but it must not scale with the hostile input. Anything at or
	// above the input size means the field rode through untruncated.
	tests := []struct {
		name   string
		encode func() string
	}{
		{name: "OCSF", encode: func() string { return FormatOCSFEvent(event, "1.2.3") }},
		{name: "CEF", encode: func() string { return FormatCEFEvent(event, "1.2.3") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.encode()
			if len(got) >= hostileBytes {
				t.Errorf("%s record is %d bytes for a %d-byte hostile field: "+
					"a bounded record must not scale with its input",
					tt.name, len(got), hostileBytes)
			}
		})
	}

	// OTLP emits protobuf rather than a string, so it is asserted on the
	// attribute values it would export.
	t.Run("OTLP", func(t *testing.T) {
		t.Parallel()
		maxLen := emitMaxStringBytes + len(emitTruncationMarker)
		sink := &OTLPSink{}
		record := sink.eventToLogRecord(event)
		for _, attr := range record.GetAttributes() {
			if got := len(attr.GetKey()); got > maxLen {
				t.Errorf("OTLP attribute key is %d bytes, exceeds the %d-byte bound", got, maxLen)
			}
			if got := len(attr.GetValue().GetStringValue()); got > maxLen {
				t.Errorf("OTLP attribute %q is %d bytes, exceeds the %d-byte bound",
					attr.GetKey(), got, maxLen)
			}
		}
	})
}
