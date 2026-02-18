package cli

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitError_Error(t *testing.T) {
	inner := fmt.Errorf("config load error: file not found")
	ee := &ExitError{Err: inner, Code: 2}

	if ee.Error() != inner.Error() {
		t.Errorf("Error() = %q, want %q", ee.Error(), inner.Error())
	}
}

func TestExitError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("wrapped: %w", errors.New("root cause"))
	ee := &ExitError{Err: inner, Code: 2}

	if !errors.Is(ee.Unwrap(), inner) {
		t.Error("Unwrap() should return the inner error")
	}

	// errors.Is should see through the ExitError wrapper.
	root := errors.New("sentinel")
	ee2 := &ExitError{Err: fmt.Errorf("wrap: %w", root), Code: 3}
	if !errors.Is(ee2, root) {
		t.Error("errors.Is should find sentinel through ExitError")
	}
}

func TestExitCodeError(t *testing.T) {
	inner := errors.New("bad config")
	wrapped := ExitCodeError(2, inner)

	var ee *ExitError
	if !errors.As(wrapped, &ee) {
		t.Fatal("ExitCodeError should produce an *ExitError")
	}
	if ee.Code != 2 {
		t.Errorf("Code = %d, want 2", ee.Code)
	}
	if !errors.Is(ee.Err, inner) {
		t.Error("Err should be the original error")
	}
}

func TestExitCodeError_NilErr(t *testing.T) {
	if got := ExitCodeError(2, nil); got != nil {
		t.Errorf("ExitCodeError(2, nil) = %v, want nil", got)
	}
}

func TestExitCodeOf(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{
			name: "ExitError with code 2",
			err:  ExitCodeError(2, errors.New("config error")),
			want: 2,
		},
		{
			name: "ExitError with code 42",
			err:  ExitCodeError(42, errors.New("custom")),
			want: 42,
		},
		{
			name: "plain error defaults to 1",
			err:  errors.New("generic failure"),
			want: 1,
		},
		{
			name: "wrapped ExitError",
			err:  fmt.Errorf("outer: %w", ExitCodeError(2, errors.New("inner"))),
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExitCodeOf(tt.err)
			if got != tt.want {
				t.Errorf("ExitCodeOf() = %d, want %d", got, tt.want)
			}
		})
	}
}
