// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package authority

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type verifierFunc func(context.Context, Request) Result

func (f verifierFunc) Verify(ctx context.Context, request Request) Result {
	return f(ctx, request)
}

func TestExtractHTTPReference(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		header  http.Header
		want    string
		wantErr error
	}{
		{name: "nil headers", wantErr: ErrMissingReference},
		{name: "one value", header: http.Header{HTTPHeader: {" grant "}}, want: "grant"},
		{name: "unrelated and ordinary connection headers", header: http.Header{HTTPHeader: {"grant"}, "X-Test": {"keep"}, "Connection": {"keep-alive"}}, want: "grant"},
		{name: "missing", header: http.Header{}, wantErr: ErrMissingReference},
		{name: "empty", header: http.Header{HTTPHeader: {" "}}, wantErr: ErrMalformedReference},
		{name: "duplicate", header: http.Header{HTTPHeader: {"one", "two"}}, wantErr: ErrDuplicateReference},
		{name: "mixed case duplicate", header: http.Header{HTTPHeader: {"one"}, "pIpElOcK-aUtHoRiTy": {"two"}}, wantErr: ErrDuplicateReference},
		{name: "comma joined", header: http.Header{HTTPHeader: {"one,two"}}, wantErr: ErrMalformedReference},
		{name: "connection nomination", header: http.Header{HTTPHeader: {"one"}, "Connection": {"keep-alive, Pipelock-Authority"}}, wantErr: ErrNominatedByConnection},
		{name: "oversize", header: http.Header{HTTPHeader: {strings.Repeat("x", MaxReferenceBytes+1)}}, wantErr: ErrMalformedReference},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExtractHTTPReference(tc.header)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("reference = %q, want %q", got, tc.want)
			}
			for name := range tc.header {
				if strings.EqualFold(name, HTTPHeader) {
					t.Fatalf("reserved header survived extraction as %q", name)
				}
			}
		})
	}
}

func TestEvaluateFailsClosed(t *testing.T) {
	t.Parallel()
	request := Request{Actor: "agent-a", Action: "read", Destination: "https://service.example", AuthorityRef: "grant"}

	if _, err := Evaluate(t.Context(), nil, Request{}, ErrMissingReference); err != nil {
		t.Fatalf("nil verifier changed existing behavior: %v", err)
	}
	allow := verifierFunc(func(context.Context, Request) Result {
		return Result{Decision: DecisionAllow, Reason: ReasonMatched}
	})
	if _, err := Evaluate(t.Context(), allow, request, nil); err != nil {
		t.Fatalf("allow result blocked: %v", err)
	}

	for _, result := range []Result{
		{Decision: DecisionDeny, Reason: ReasonActionMismatch},
		{Decision: DecisionIndeterminate, Reason: ReasonTimeout},
		{Decision: Decision(255)},
	} {
		verifier := verifierFunc(func(context.Context, Request) Result { return result })
		if _, err := Evaluate(t.Context(), verifier, request, nil); err == nil {
			t.Fatalf("result %+v did not fail closed", result)
		}
	}
	if _, err := Evaluate(t.Context(), allow, request, ErrMalformedReference); !errors.Is(err, ErrMalformedReference) {
		t.Fatalf("carrier error = %v, want malformed reference", err)
	}
	if _, err := Evaluate(t.Context(), allow, Request{Actor: "agent-a", Action: "read", AuthorityRef: "grant"}, nil); !errors.Is(err, ErrMalformedReference) {
		t.Fatalf("incomplete request error = %v, want malformed reference", err)
	}
}
