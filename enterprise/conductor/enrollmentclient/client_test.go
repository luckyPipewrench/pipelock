//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enrollmentclient

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type stubDoer struct {
	req    *http.Request
	status int
	body   string
}

func (d *stubDoer) Do(req *http.Request) (*http.Response, error) {
	d.req = req
	status := d.status
	if status == 0 {
		status = http.StatusCreated
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(d.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestNewRejectsBadBaseURL(t *testing.T) {
	for name, tc := range map[string]struct{ url, want string }{
		"plain http":      {"http://conductor.example:8895", "must be https"},
		"userinfo":        {"https://user@conductor.example:8895", "userinfo"},
		"query":           {"https://conductor.example:8895?x=1", "userinfo, query, or fragment"},
		"bare query mark": {"https://conductor.example:8895?", "userinfo, query, or fragment"},
		"fragment":        {"https://conductor.example:8895#frag", "userinfo, query, or fragment"},
		"path":            {"https://conductor.example:8895/api", "path component"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(Config{BaseURL: tc.url, Client: &stubDoer{}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New(%q) error = %v, want %q", tc.url, err, tc.want)
			}
		})
	}
}

func TestEnrollValidatesSuccessResponse(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "empty object",
			body: `{}`,
			want: "missing org_id",
		},
		{
			name: "audit key mismatch",
			body: `{"org_id":"org-main","fleet_id":"prod","instance_id":"edge-01","environment":"prod","audit_key_id":"other-key","enrolled_at":"2026-06-11T12:00:00Z"}`,
			want: "audit_key_id does not match",
		},
		{
			name: "missing enrolled_at",
			body: `{"org_id":"org-main","fleet_id":"prod","instance_id":"edge-01","environment":"prod","audit_key_id":"audit-key-1"}`,
			want: "missing enrolled_at",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(Config{BaseURL: "https://conductor.example:8895", Client: &stubDoer{body: tc.body}})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			_, err = c.Enroll(context.Background(), Request{
				Token:          "pl_" + "enroll_test",
				AuditKeyID:     "audit-key-1",
				AuditPublicKey: strings.Repeat("a", 64),
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Enroll() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestEnrollHappyPathUsesEnrollEndpoint(t *testing.T) {
	doer := &stubDoer{body: `{"org_id":"org-main","fleet_id":"prod","instance_id":"edge-01","environment":"prod","audit_key_id":"audit-key-1","enrolled_at":"2026-06-11T12:00:00Z"}`}
	c, err := New(Config{BaseURL: "https://conductor.example:8895", Client: doer})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	resp, err := c.Enroll(context.Background(), Request{
		Token:          "pl_" + "enroll_test",
		AuditKeyID:     "audit-key-1",
		AuditPublicKey: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}
	if resp.AuditKeyID != "audit-key-1" {
		t.Fatalf("AuditKeyID = %q, want audit-key-1", resp.AuditKeyID)
	}
	if doer.req == nil || doer.req.URL.Scheme != "https" || doer.req.URL.Path != "/api/v1/conductor/enroll" {
		t.Fatalf("request URL = %v, want https enroll endpoint", doer.req.URL)
	}
}
