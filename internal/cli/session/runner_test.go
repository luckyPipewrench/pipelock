// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestMapClientError_NilIsNil(t *testing.T) {
	if err := mapClientError(nil); err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestMapClientError_APIErrorClasses(t *testing.T) {
	tests := []struct {
		name       string
		apiErr     *APIError
		wantExit   int
		wantSubstr string
	}{
		{"401 unauthorized", &APIError{StatusCode: http.StatusUnauthorized, Body: "nope"}, 2, "unauthorized"},
		{"404 not found", &APIError{StatusCode: http.StatusNotFound}, 1, "not found"},
		{"429 rate limited", &APIError{StatusCode: http.StatusTooManyRequests, RetryAfter: "60"}, 1, "rate limited"},
		{"400 bad request", &APIError{StatusCode: http.StatusBadRequest, Body: "bad"}, 2, "bad request"},
		{"500 server error", &APIError{StatusCode: http.StatusInternalServerError, Body: "oops"}, 1, "server error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapped := mapClientError(tt.apiErr)
			if mapped == nil {
				t.Fatal("expected error")
			}
			if code := cliutil.ExitCodeOf(mapped); code != tt.wantExit {
				t.Errorf("exit code: got %d, want %d", code, tt.wantExit)
			}
			if !strings.Contains(mapped.Error(), tt.wantSubstr) {
				t.Errorf("error text %q missing %q", mapped.Error(), tt.wantSubstr)
			}
		})
	}
}

func TestMapClientError_NonAPIErrorIsExit1(t *testing.T) {
	err := mapClientError(errors.New("boom"))
	if code := cliutil.ExitCodeOf(err); code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
}

// TestRunClientCmd_PreservesExitCodeError guards against regression of a
// bug where runClientCmd remapped every executor error through
// mapClientError, stripping any pre-wrapped cliutil.ExitCodeError. The
// interactive recover path relies on ExitConfig (2) for invalid-input
// errors; without this passthrough those become ExitGeneral (1).
func TestRunClientCmd_PreservesExitCodeError(t *testing.T) {
	origFactory := newClientFn
	t.Cleanup(func() { newClientFn = origFactory })
	newClientFn = func(*rootFlags) (*Client, error) {
		return newClient(endpoint{URL: "http://stub:0", Token: "t"}), nil
	}

	wrapped := cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("invalid input"))
	err := runClientCmd(&rootFlags{}, context.Background(), io.Discard, func(context.Context, *Client, io.Writer) error {
		return wrapped
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if code := cliutil.ExitCodeOf(err); code != cliutil.ExitConfig {
		t.Errorf("exit code: got %d, want %d (original classification must survive)", code, cliutil.ExitConfig)
	}
}

// TestRunClientCmd_UnclassifiedErrorsStillMapped keeps the default path
// working: bare errors without ExitCodeError wrapping still get routed
// through mapClientError.
func TestRunClientCmd_UnclassifiedErrorsStillMapped(t *testing.T) {
	origFactory := newClientFn
	t.Cleanup(func() { newClientFn = origFactory })
	newClientFn = func(*rootFlags) (*Client, error) {
		return newClient(endpoint{URL: "http://stub:0", Token: "t"}), nil
	}

	err := runClientCmd(&rootFlags{}, context.Background(), io.Discard, func(context.Context, *Client, io.Writer) error {
		return errors.New("bare error")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if code := cliutil.ExitCodeOf(err); code != cliutil.ExitGeneral {
		t.Errorf("bare error should map to ExitGeneral, got %d", code)
	}
}

func TestWriteJSON_Roundtrip(t *testing.T) {
	var buf bytes.Buffer
	data := map[string]any{"foo": "bar", "num": 42}
	if err := writeJSON(&buf, data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"foo": "bar"`) {
		t.Errorf("json output: %s", buf.String())
	}
}
