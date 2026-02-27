package transport

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// errWriter returns an error after limit writes.
// Mirrors the same helper in proxy_test.go; duplicated because different packages.
type errWriter struct {
	n     int
	limit int
}

func (w *errWriter) Write(p []byte) (int, error) {
	w.n++
	if w.n > w.limit {
		return 0, errors.New("simulated write error")
	}
	return len(p), nil
}

func TestStdioReader_SingleMessage(t *testing.T) {
	r := NewStdioReader(strings.NewReader(`{"jsonrpc":"2.0","id":1}` + "\n"))
	msg, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(msg) != `{"jsonrpc":"2.0","id":1}` { //nolint:goconst // test value
		t.Errorf("got %q", string(msg))
	}
}

func TestStdioReader_MultipleMessages(t *testing.T) {
	input := `{"id":1}` + "\n" + `{"id":2}` + "\n" //nolint:goconst // test value
	r := NewStdioReader(strings.NewReader(input))

	msg1, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("msg1: %v", err)
	}
	if string(msg1) != `{"id":1}` { //nolint:goconst // test value
		t.Errorf("msg1 = %q", string(msg1))
	}

	msg2, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("msg2: %v", err)
	}
	if string(msg2) != `{"id":2}` { //nolint:goconst // test value
		t.Errorf("msg2 = %q", string(msg2))
	}

	_, err = r.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestStdioReader_SkipsEmptyLines(t *testing.T) {
	input := "\n\n" + `{"id":1}` + "\n\n\n" + `{"id":2}` + "\n"
	r := NewStdioReader(strings.NewReader(input))

	msg1, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("msg1: %v", err)
	}
	if string(msg1) != `{"id":1}` { //nolint:goconst // test value
		t.Errorf("msg1 = %q", string(msg1))
	}

	msg2, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("msg2: %v", err)
	}
	if string(msg2) != `{"id":2}` { //nolint:goconst // test value
		t.Errorf("msg2 = %q", string(msg2))
	}
}

func TestStdioReader_TrimsWhitespace(t *testing.T) {
	r := NewStdioReader(strings.NewReader("  {\"id\":1}  \n"))
	msg, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(msg) != `{"id":1}` {
		t.Errorf("got %q, want trimmed", string(msg))
	}
}

func TestStdioReader_EmptyInput(t *testing.T) {
	r := NewStdioReader(strings.NewReader(""))
	_, err := r.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF for empty input, got %v", err)
	}
}

func TestStdioReader_OnlyEmptyLines(t *testing.T) {
	r := NewStdioReader(strings.NewReader("\n\n\n"))
	_, err := r.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF for whitespace-only input, got %v", err)
	}
}

func TestStdioReader_ReturnsCopy(t *testing.T) {
	input := `{"id":1}` + "\n" + `{"id":2}` + "\n"
	r := NewStdioReader(strings.NewReader(input))

	msg1, _ := r.ReadMessage()
	snapshot := string(msg1)

	// Read next message - should not clobber msg1.
	_, _ = r.ReadMessage()
	if string(msg1) != snapshot {
		t.Errorf("msg1 was mutated: got %q, want %q", string(msg1), snapshot)
	}
}

func TestStdioWriter_SingleMessage(t *testing.T) {
	var buf bytes.Buffer
	w := NewStdioWriter(&buf)

	if err := w.WriteMessage([]byte(`{"id":1}`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != "{\"id\":1}\n" {
		t.Errorf("got %q", buf.String())
	}
}

func TestStdioWriter_MultipleMessages(t *testing.T) {
	var buf bytes.Buffer
	w := NewStdioWriter(&buf)

	_ = w.WriteMessage([]byte(`{"id":1}`))
	_ = w.WriteMessage([]byte(`{"id":2}`))

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), buf.String())
	}
	if lines[0] != `{"id":1}` {
		t.Errorf("line 0 = %q", lines[0])
	}
	if lines[1] != `{"id":2}` {
		t.Errorf("line 1 = %q", lines[1])
	}
}

func TestStdioWriter_PropagatesError(t *testing.T) {
	w := NewStdioWriter(&errWriter{limit: 0})
	err := w.WriteMessage([]byte(`{"id":1}`))
	if err == nil {
		t.Error("expected error from failing writer")
	}
}

func TestStdioRoundTrip(t *testing.T) {
	// Write messages via StdioWriter, read them back via StdioReader.
	var buf bytes.Buffer
	w := NewStdioWriter(&buf)

	messages := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"test"}}`,
	}
	for _, m := range messages {
		if err := w.WriteMessage([]byte(m)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	r := NewStdioReader(&buf)
	for i, want := range messages {
		got, err := r.ReadMessage()
		if err != nil {
			t.Fatalf("msg %d: %v", i, err)
		}
		if string(got) != want {
			t.Errorf("msg %d = %q, want %q", i, string(got), want)
		}
	}

	_, err := r.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected EOF after all messages, got %v", err)
	}
}

func TestStdioWriter_TooLarge(t *testing.T) {
	var buf bytes.Buffer
	w := NewStdioWriter(&buf)

	huge := make([]byte, MaxLineSize+1)
	err := w.WriteMessage(huge)
	if err == nil {
		t.Fatal("expected error for oversized message")
	}
	if !strings.Contains(err.Error(), "message too large") {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Error("oversized message should not have been written")
	}
}

func TestStdioReader_OversizedMessage(t *testing.T) {
	// A line exceeding MaxLineSize should return bufio.ErrTooLong, not EOF.
	huge := strings.Repeat("x", MaxLineSize+1) + "\n"
	r := NewStdioReader(strings.NewReader(huge))
	_, err := r.ReadMessage()
	if err == nil {
		t.Fatal("expected error for oversized message")
	}
	if errors.Is(err, io.EOF) {
		t.Error("oversized message should return a read error, not EOF")
	}
}
