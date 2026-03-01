package wsutil

import (
	"errors"
	"io"
	"testing"
)

func TestIsExpectedCloseErr(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"EOF", io.EOF, true},
		{"closed connection", errors.New("use of closed network connection"), true},
		{"connection reset", errors.New("connection reset by peer"), true},
		{"broken pipe", errors.New("broken pipe"), true},
		{"unrelated error", errors.New("something else"), false},
		{"timeout", errors.New("i/o timeout"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsExpectedCloseErr(tt.err); got != tt.expected {
				t.Errorf("IsExpectedCloseErr(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}
