// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type redirectFailureReadCloser struct {
	closed atomic.Bool
}

func (r *redirectFailureReadCloser) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func (r *redirectFailureReadCloser) Close() error {
	r.closed.Store(true)
	return nil
}

func TestConnectAdmissionRejectsMissingTarget(t *testing.T) {
	p := newTestProxy(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "http://proxy.invalid", nil)
	req.Host = ""
	rec := httptest.NewRecorder()

	p.handleConnect(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "missing target host") {
		t.Fatalf("response body = %q, want missing target host", rec.Body.String())
	}
	if got := rec.Header().Get("X-Pipelock-Block-Reason"); got != "bad_request" {
		t.Fatalf("block reason = %q, want bad_request", got)
	}
}

func TestRedirectBodyReplayFailuresBlockAndCleanUp(t *testing.T) {
	tests := []struct {
		name           string
		openErr        error
		wantCause      string
		wantBodyClosed bool
	}{
		{
			name:      "open failure",
			openErr:   errors.New("replay unavailable"),
			wantCause: "opening redirect GetBody",
		},
		{
			name:           "read failure closes body",
			wantCause:      "draining redirect GetBody",
			wantBodyClosed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newSigningProxyForTest(t)
			t.Cleanup(p.Close)

			var body *redirectFailureReadCloser
			getBody := func() (io.ReadCloser, error) {
				return nil, tt.openErr
			}
			if tt.wantBodyClosed {
				body = &redirectFailureReadCloser{}
				getBody = func() (io.ReadCloser, error) {
					return body, nil
				}
			}

			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
				"https://redirected.example/upload", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.GetBody = getBody

			err = p.refreshEnvelopeForRedirect(req, nil, p.cfgPtr.Load())
			if err == nil {
				t.Fatal("redirect body replay failure was allowed")
			}
			blockedErr, ok := blockedRequestErrorFrom(err)
			if !ok {
				t.Fatalf("error type = %T, want *blockedRequestError", err)
			}
			if blockedErr.layer != blockLayerMediationEnvelope {
				t.Fatalf("blocked layer = %q, want %q", blockedErr.layer, blockLayerMediationEnvelope)
			}
			if blockedErr.reason != "redirect blocked: "+mediationEnvelopeBlockReason {
				t.Fatalf("blocked reason = %q", blockedErr.reason)
			}
			if !strings.Contains(blockedErr.detail, tt.wantCause) {
				t.Fatalf("blocked detail = %q, want cause %q", blockedErr.detail, tt.wantCause)
			}
			if tt.wantBodyClosed && !body.closed.Load() {
				t.Fatal("redirect replay body was not closed after read failure")
			}
		})
	}
}
