//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enrollmentclient

import (
	"context"
	"errors"
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

// TestValidateResponseMissingFields covers each per-field guard in
// validateResponse so a malformed conductor response fails closed with a
// specific diagnostic instead of accepting a partial enrollment.
func TestValidateResponseMissingFields(t *testing.T) {
	const enrolledAt = `"enrolled_at":"2026-06-11T12:00:00Z"`
	full := map[string]string{
		"org_id":       `"org_id":"org-main"`,
		"fleet_id":     `"fleet_id":"prod"`,
		"instance_id":  `"instance_id":"edge-01"`,
		"environment":  `"environment":"prod"`,
		"audit_key_id": `"audit_key_id":"audit-key-1"`,
	}
	order := []string{"org_id", "fleet_id", "instance_id", "environment", "audit_key_id"}
	wantByMissing := map[string]string{
		"org_id":       "missing org_id",
		"fleet_id":     "missing fleet_id",
		"instance_id":  "missing instance_id",
		"environment":  "missing environment",
		"audit_key_id": "missing audit_key_id",
	}
	for _, missing := range order {
		t.Run("missing "+missing, func(t *testing.T) {
			fields := []string{}
			for _, key := range order {
				if key == missing {
					continue
				}
				fields = append(fields, full[key])
			}
			fields = append(fields, enrolledAt)
			body := "{" + strings.Join(fields, ",") + "}"
			c, err := New(Config{BaseURL: "https://conductor.example:8895", Client: &stubDoer{body: body}})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			_, err = c.Enroll(context.Background(), Request{
				Token:          "pl_" + "enroll_test",
				AuditKeyID:     "audit-key-1",
				AuditPublicKey: strings.Repeat("a", 64),
			})
			if err == nil || !strings.Contains(err.Error(), wantByMissing[missing]) {
				t.Fatalf("Enroll(missing %s) error = %v, want %q", missing, err, wantByMissing[missing])
			}
		})
	}
}

// errDoer simulates a transport-level failure (DNS/TCP/TLS) from the HTTP client.
type errDoer struct{}

func (errDoer) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: connection refused")
}

// readErrDoer returns a response body that errors mid-read so the io.ReadAll
// path is exercised.
type readErrDoer struct{}

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("body read failed") }
func (errReadCloser) Close() error             { return nil }

func (readErrDoer) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusCreated,
		Body:       errReadCloser{},
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestEnrollTransportAndDecodeErrors(t *testing.T) {
	const token = "pl_" + "enroll_test"
	t.Run("transport error", func(t *testing.T) {
		c, err := New(Config{BaseURL: "https://conductor.example:8895", Client: errDoer{}})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := c.Enroll(context.Background(), Request{Token: token, AuditKeyID: "audit-key-1"}); err == nil ||
			!strings.Contains(err.Error(), "enroll request") {
			t.Fatalf("Enroll(transport error) error = %v, want enroll request wrapped", err)
		}
	})

	t.Run("body read error", func(t *testing.T) {
		c, err := New(Config{BaseURL: "https://conductor.example:8895", Client: readErrDoer{}})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := c.Enroll(context.Background(), Request{Token: token, AuditKeyID: "audit-key-1"}); err == nil ||
			!strings.Contains(err.Error(), "read enroll response") {
			t.Fatalf("Enroll(body read error) error = %v, want read enroll response wrapped", err)
		}
	})

	t.Run("non-2xx status redacts token in snippet", func(t *testing.T) {
		// The error body echoes the token; the snippet must redact it so the
		// secret never lands in logs.
		doer := &stubDoer{status: http.StatusForbidden, body: "denied for token " + token}
		c, err := New(Config{BaseURL: "https://conductor.example:8895", Client: doer})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		_, err = c.Enroll(context.Background(), Request{Token: token, AuditKeyID: "audit-key-1"})
		if err == nil || !strings.Contains(err.Error(), "status=403") {
			t.Fatalf("Enroll(403) error = %v, want status=403", err)
		}
		if strings.Contains(err.Error(), token) {
			t.Fatalf("Enroll(403) error leaked token: %v", err)
		}
		if !strings.Contains(err.Error(), "[redacted]") {
			t.Fatalf("Enroll(403) error = %v, want [redacted] token", err)
		}
	})

	t.Run("invalid json decode error", func(t *testing.T) {
		doer := &stubDoer{body: "{not json"}
		c, err := New(Config{BaseURL: "https://conductor.example:8895", Client: doer})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := c.Enroll(context.Background(), Request{Token: token, AuditKeyID: "audit-key-1"}); err == nil ||
			!strings.Contains(err.Error(), "decode enroll response") {
			t.Fatalf("Enroll(bad json) error = %v, want decode enroll response wrapped", err)
		}
	})
}

func TestEnrollNilClient(t *testing.T) {
	var c *Client
	if _, err := c.Enroll(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), "nil client") {
		t.Fatalf("Enroll(nil client) error = %v, want nil client", err)
	}
}

func TestSnippetRedactsAndSanitizes(t *testing.T) {
	t.Run("redacts secrets and strips control chars", func(t *testing.T) {
		secret := "pl_" + "snippet_secret"
		raw := "  error with \x00\x07control " + secret + " and \x7f trailing  "
		got := snippet([]byte(raw), secret, "", "   ")
		if strings.Contains(got, secret) {
			t.Fatalf("snippet leaked secret: %q", got)
		}
		if !strings.Contains(got, "[redacted]") {
			t.Fatalf("snippet missing [redacted]: %q", got)
		}
		if strings.ContainsRune(got, 0x00) || strings.ContainsRune(got, 0x07) || strings.ContainsRune(got, 0x7f) {
			t.Fatalf("snippet retained control chars: %q", got)
		}
		// Leading/trailing whitespace is trimmed before mapping.
		if strings.HasPrefix(got, " ") || strings.HasSuffix(got, " ") {
			t.Fatalf("snippet not trimmed: %q", got)
		}
	})

	t.Run("truncates beyond 512 bytes", func(t *testing.T) {
		raw := strings.Repeat("a", 600)
		got := snippet([]byte(raw))
		if !strings.HasSuffix(got, "...") {
			t.Fatalf("snippet(>512) missing ellipsis suffix: len=%d", len(got))
		}
		if len(got) != 512+len("...") {
			t.Fatalf("snippet(>512) len=%d, want %d", len(got), 512+len("..."))
		}
	})
}
