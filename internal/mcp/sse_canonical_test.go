// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestCanonicalSSEEventText_MultilineDataUsesPerLineDataFields(t *testing.T) {
	reader := transport.NewSSEReader(strings.NewReader(strings.Join([]string{
		"event: message_delta",
		"id: evt-1",
		"retry: 2500",
		"data: first",
		"data: ",
		"data: third",
		"",
	}, "\n")))

	event, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	got := canonicalSSEEventText(event, reader)
	want := strings.Join([]string{
		"event: message_delta",
		"id: evt-1",
		"retry: 2500",
		"data: first",
		"data: ",
		"data: third",
		"",
		"",
	}, "\n")

	if got != want {
		t.Fatalf("canonicalSSEEventText() mismatch\nwant:\n%q\ngot:\n%q", want, got)
	}

	if _, err := reader.ReadMessage(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after one event, got %v", err)
	}
}
