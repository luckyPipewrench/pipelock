// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"errors"
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
