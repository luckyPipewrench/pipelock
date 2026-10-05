// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	testCorrelationValue = "case-0042"
	testCorrelationReqID = "req-77"
)

func correlationTestEvent(withCorrelation bool) Event {
	fields := map[string]any{
		"request_id": testCorrelationReqID,
		"method":     "GET",
		"url":        "https://api.vendor.example/v1",
		"scanner":    "dlp",
		"reason":     "test block",
	}
	if withCorrelation {
		fields[FieldCorrelationID] = testCorrelationValue
	}
	return Event{
		Severity:   SeverityWarn,
		Type:       EventBlocked,
		Timestamp:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		InstanceID: "test-instance",
		Fields:     fields,
	}
}

// JSON is the shared body for the webhook and syslog json formats.
func TestCorrelation_JSONFormat(t *testing.T) {
	t.Parallel()
	body, _, err := formatEvent(correlationTestEvent(true), FormatJSON, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Fields map[string]any `json:"fields"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Fields[FieldCorrelationID] != testCorrelationValue {
		t.Fatalf("fields.correlation_id = %v, want %q", payload.Fields[FieldCorrelationID], testCorrelationValue)
	}
	if payload.Fields["request_id"] != testCorrelationReqID {
		t.Fatalf("request_id changed: %v", payload.Fields["request_id"])
	}

	body, _, err = formatEvent(correlationTestEvent(false), FormatJSON, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), FieldCorrelationID) {
		t.Fatalf("correlation_id present without a tag: %s", body)
	}
}

func TestCorrelation_CEFFormat(t *testing.T) {
	t.Parallel()
	line := FormatCEFEvent(correlationTestEvent(true), "1.0.0")
	for _, want := range []string{
		"cs3=" + testCorrelationValue,
		"cs3Label=correlationId",
		"externalId=" + testCorrelationReqID,
		"cs1=dlp",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("CEF line missing %q:\n%s", want, line)
		}
	}
	if strings.Contains(line, "pipelockCorrelationId") {
		t.Errorf("correlation_id fell through to the generic custom key:\n%s", line)
	}

	plain := FormatCEFEvent(correlationTestEvent(false), "1.0.0")
	if strings.Contains(plain, "cs3") {
		t.Errorf("cs3/cs3Label emitted without a tag:\n%s", plain)
	}
}

// CEF extension values are escaped by the shared encoder; a tag containing
// CEF metacharacters must not break the key=value structure.
func TestCorrelation_CEFEscapesValue(t *testing.T) {
	t.Parallel()
	ev := correlationTestEvent(true)
	ev.Fields[FieldCorrelationID] = `a=b\c`
	line := FormatCEFEvent(ev, "1.0.0")
	if !strings.Contains(line, `cs3=a\=b\\c`) {
		t.Fatalf("CEF value not escaped:\n%s", line)
	}
}

func TestCorrelation_OCSFFormat(t *testing.T) {
	t.Parallel()
	var record struct {
		Metadata struct {
			CorrelationUID *string `json:"correlation_uid"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(FormatOCSFEvent(correlationTestEvent(true), "1.0.0")), &record); err != nil {
		t.Fatal(err)
	}
	if record.Metadata.CorrelationUID == nil || *record.Metadata.CorrelationUID != testCorrelationValue {
		t.Fatalf("metadata.correlation_uid = %v, want %q", record.Metadata.CorrelationUID, testCorrelationValue)
	}

	record.Metadata.CorrelationUID = nil
	if err := json.Unmarshal([]byte(FormatOCSFEvent(correlationTestEvent(false), "1.0.0")), &record); err != nil {
		t.Fatal(err)
	}
	if record.Metadata.CorrelationUID != nil {
		t.Fatalf("metadata.correlation_uid present without a tag: %q", *record.Metadata.CorrelationUID)
	}
}

func TestCorrelation_OTLPAttribute(t *testing.T) {
	t.Parallel()
	s := &OTLPSink{version: "1.0.0"}
	rec := s.eventToLogRecord(correlationTestEvent(true))
	var got string
	for _, kv := range rec.Attributes {
		if kv.Key == FieldCorrelationID {
			got = kv.GetValue().GetStringValue()
		}
	}
	if got != testCorrelationValue {
		t.Fatalf("OTLP attribute %s = %q, want %q", FieldCorrelationID, got, testCorrelationValue)
	}

	rec = s.eventToLogRecord(correlationTestEvent(false))
	for _, kv := range rec.Attributes {
		if kv.Key == FieldCorrelationID {
			t.Fatalf("OTLP correlation_id present without a tag: %v", kv)
		}
	}
}

// The convention attribute agent.threat.detection.correlation_id keeps its
// shipped meaning (Pipelock's request_id). The client tag must not replace it.
func TestCorrelation_OTLPConventionAttributeUnchanged(t *testing.T) {
	t.Parallel()
	ev := correlationTestEvent(true)
	ev.Fields[fieldAction] = verdictBlockedShort
	attrs := agentThreatDetectionAttrs(ev, "1.0.0")
	var got string
	for _, kv := range attrs {
		if kv.Key == attrAgentThreatCorrelationID {
			got = kv.GetValue().GetStringValue()
		}
	}
	if got != testCorrelationReqID {
		t.Fatalf("%s = %q, want request_id %q", attrAgentThreatCorrelationID, got, testCorrelationReqID)
	}
}
