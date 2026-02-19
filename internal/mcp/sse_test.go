package mcp

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSSEReader_SingleEvent(t *testing.T) {
	input := "event: message\ndata: {\"id\":1}\n\n"
	r := NewSSEReader(strings.NewReader(input))

	msg, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(msg) != `{"id":1}` { //nolint:goconst // test value
		t.Errorf("got %q, want %q", string(msg), `{"id":1}`)
	}

	// Next read should return io.EOF.
	_, err = r.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF after single event, got %v", err)
	}
}

func TestSSEReader_MultipleEvents(t *testing.T) {
	input := "data: {\"id\":1}\n\ndata: {\"id\":2}\n\n"
	r := NewSSEReader(strings.NewReader(input))

	msg1, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("msg1: unexpected error: %v", err)
	}
	if string(msg1) != `{"id":1}` { //nolint:goconst // test value
		t.Errorf("msg1 = %q, want %q", string(msg1), `{"id":1}`)
	}

	msg2, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("msg2: unexpected error: %v", err)
	}
	if string(msg2) != `{"id":2}` { //nolint:goconst // test value
		t.Errorf("msg2 = %q, want %q", string(msg2), `{"id":2}`)
	}

	_, err = r.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF after all events, got %v", err)
	}
}

func TestSSEReader_MultiLineData(t *testing.T) {
	// Multiple data: lines in one event are concatenated with \n per SSE spec.
	input := "data: {\"part\":\ndata: \"one\"}\n\n"
	r := NewSSEReader(strings.NewReader(input))

	msg, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "{\"part\":\n\"one\"}"
	if string(msg) != want {
		t.Errorf("got %q, want %q", string(msg), want)
	}
}

func TestSSEReader_IgnoresNonDataFields(t *testing.T) {
	// event:, id:, retry: fields should not appear in the data payload.
	input := "event: message\nid: 42\nretry: 3000\ndata: hello\n\n"
	r := NewSSEReader(strings.NewReader(input))

	msg, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(msg) != "hello" {
		t.Errorf("got %q, want %q", string(msg), "hello")
	}
}

func TestSSEReader_TracksLastEventID(t *testing.T) {
	input := "id: evt-42\ndata: payload\n\n"
	r := NewSSEReader(strings.NewReader(input))

	_, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.LastEventID() != "evt-42" {
		t.Errorf("LastEventID() = %q, want %q", r.LastEventID(), "evt-42")
	}
}

func TestSSEReader_SkipsEmptyData(t *testing.T) {
	// Comment lines (:keep-alive) and events with no data: lines should be skipped.
	input := ":keep-alive\n\n:another comment\n\ndata: real\n\n"
	r := NewSSEReader(strings.NewReader(input))

	msg, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(msg) != "real" {
		t.Errorf("got %q, want %q", string(msg), "real")
	}
}

func TestSSEReader_EmptyInput(t *testing.T) {
	r := NewSSEReader(strings.NewReader(""))

	_, err := r.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF for empty input, got %v", err)
	}
}

func TestSSEReader_IDWithNULLIgnored(t *testing.T) {
	// Per SSE spec: if the id field value contains U+0000 NULL, ignore it.
	input := "id: valid-id\ndata: first\n\nid: has\x00null\ndata: second\n\n"
	r := NewSSEReader(strings.NewReader(input))

	// First event: id is valid.
	msg1, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("msg1: unexpected error: %v", err)
	}
	if string(msg1) != "first" {
		t.Errorf("msg1 = %q, want %q", string(msg1), "first")
	}
	if r.LastEventID() != "valid-id" {
		t.Errorf("after first event: LastEventID() = %q, want %q", r.LastEventID(), "valid-id")
	}

	// Second event: id contains NULL — should be ignored, keeping previous id.
	msg2, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("msg2: unexpected error: %v", err)
	}
	if string(msg2) != "second" {
		t.Errorf("msg2 = %q, want %q", string(msg2), "second")
	}
	// LastEventID should still be "valid-id" since the NULL id was ignored.
	if r.LastEventID() != "valid-id" {
		t.Errorf("after second event: LastEventID() = %q, want %q (NULL id should be ignored)", r.LastEventID(), "valid-id")
	}
}

func TestSSEReader_DataWithoutNewlineTerminator(t *testing.T) {
	// Stream ends without a final blank line but has accumulated data.
	// Should still return the event.
	input := "data: final"
	r := NewSSEReader(strings.NewReader(input))

	msg, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(msg) != "final" {
		t.Errorf("got %q, want %q", string(msg), "final")
	}

	// Next read should return io.EOF.
	_, err = r.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF after unterminated event, got %v", err)
	}
}
