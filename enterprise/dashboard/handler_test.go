//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	hostileScript = "<script>alert(1)</script>"
	hostileImage  = "\"><img src=x onerror=alert(1)>"
	hostileJSURL  = "javascript:alert(1)"
	hostileJSON   = `</script><script>alert("json")</script>`
)

func TestHandler_Gating(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	handler := New(Options{ReceiptDir: dir})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("nil HasFeature status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if strings.Contains(rec.Body.String(), "Scorecard") {
		t.Fatal("forbidden response should not contain evidence body")
	}

	handler = New(Options{
		ReceiptDir: dir,
		HasFeature: func(string) bool {
			return false
		},
	})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("false HasFeature status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("false HasFeature /session status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestHandler_AllowedRendersScorecard(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		ReceiptDir:  dir,
		TrustedKeys: trusted,
		HasFeature:  allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Scorecard") {
		t.Fatal("allowed response should render scorecard")
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != contentSecurityPolicy {
		t.Fatalf("CSP = %q, want %q", got, contentSecurityPolicy)
	}
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestHandler_HostileEvidenceRenderEscapesReceiptFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	r := signDashboardReceipt(t, priv, 0, receipt.GenesisHash, time.Date(2026, 7, 3, 13, 0, 0, 0, time.UTC))
	r.ActionRecord.Target = hostileScript
	r.ActionRecord.Pattern = hostileImage
	r.ActionRecord.Verdict = hostileScript
	r.ActionRecord.Intent = hostileJSON
	r.ActionRecord.RequestID = hostileJSURL
	resigned, err := signAlteredReceipt(r, priv)
	if err != nil {
		t.Fatalf("signAlteredReceipt: %v", err)
	}
	writeReceiptsToDir(t, dir, []receipt.Receipt{resigned})

	handler := New(Options{
		ReceiptDir: dir,
		TrustedKeys: map[string]TrustedKey{
			keyHex: {Source: trustedKeySource},
		},
		HasFeature: allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body := rec.Body.String()
	if strings.Contains(body, hostileScript) {
		t.Fatal("response contains raw script tag")
	}
	if strings.Contains(body, hostileImage) {
		t.Fatal("response contains raw image injection")
	}
	if strings.Contains(body, hostileJSON) {
		t.Fatal("response contains raw script-breaking JSON payload")
	}
	if strings.Contains(body, `href="javascript:`) {
		t.Fatal("response contains javascript URL in href attribute")
	}
	for _, rawAttr := range []string{
		`="` + hostileJSURL + `"`,
		`='` + hostileJSURL + `'`,
		`=` + hostileJSURL,
	} {
		if strings.Contains(body, rawAttr) {
			t.Fatalf("response contains raw javascript URL in attribute context: %q", rawAttr)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("response should contain HTML-escaped script text")
	}
	if !strings.Contains(body, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Fatal("response should contain HTML-escaped image injection text")
	}
	if !strings.Contains(body, "\\u003c/script\\u003e") {
		t.Fatal("response should contain JSON-escaped closing script token in signed payload")
	}
	escapedRequestID := "&#34;request_id&#34;: &#34;" + hostileJSURL + "&#34;"
	if !strings.Contains(body, escapedRequestID) {
		t.Fatal("javascript URL field should render only as escaped text in the signed payload")
	}
}

func TestHandler_MethodAndPathRejection(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	handler := New(Options{
		ReceiptDir: dir,
		HasFeature: allowAgentsFeature,
	})

	tests := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{name: "post index", method: http.MethodPost, path: "/", want: http.StatusMethodNotAllowed},
		{name: "nested session path", method: http.MethodGet, path: "/session/foo/bar", want: http.StatusNotFound},
		{name: "unknown path", method: http.MethodGet, path: "/nope", want: http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, nil)
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("%s %s status = %d, want %d; body=%s", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestHandler_ReadLimitWarning(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	writeReceiptsToDir(t, dir, buildDashboardChain(t, priv, 4))

	handler := New(Options{
		ReceiptDir:       dir,
		ReceiptReadLimit: 2,
		TimelineLimit:    1,
		TrustedKeys: map[string]TrustedKey{
			keyHex: {Source: trustedKeySource},
		},
		HasFeature: allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Dashboard read limit reached",
		"2+ receipts",
		"Showing first 1 of 2+ loaded receipts.",
		"Partial",
		"Prefix only",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
}

func TestHandler_AbsenceRender(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeZeroReceiptSessionFile(t, dir, zeroSessionID)
	handler := New(Options{
		ReceiptDir: dir,
		HasFeature: allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/session/"+zeroSessionID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{"No receipts", "NO independent evidence", "ABSENT"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
}

func TestHandler_AuthorizeFailsClosed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)

	// A rejecting authorizer must fail closed even when the feature is present.
	denied := New(Options{
		ReceiptDir: dir,
		HasFeature: allowAgentsFeature,
		Authorize:  func(*http.Request) error { return errors.New("no principal") },
	})
	rec := httptest.NewRecorder()
	denied.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rejecting Authorize status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if strings.Contains(rec.Body.String(), "Scorecard") {
		t.Fatal("forbidden response must not contain evidence body")
	}

	// An accepting authorizer reaches the handler.
	allowed := New(Options{
		ReceiptDir: dir,
		HasFeature: allowAgentsFeature,
		Authorize:  func(*http.Request) error { return nil },
	})
	rec = httptest.NewRecorder()
	allowed.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("accepting Authorize status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func allowAgentsFeature(feature string) bool {
	return feature == license.FeatureAgents
}

func signAlteredReceipt(r receipt.Receipt, priv ed25519.PrivateKey) (receipt.Receipt, error) {
	return receipt.Sign(r.ActionRecord, priv)
}

func writeTrustedHandlerSession(t *testing.T) (string, map[string]TrustedKey) {
	t.Helper()
	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	writeReceiptsToDir(t, dir, buildDashboardChain(t, priv, 2))
	return dir, map[string]TrustedKey{
		keyHex: {Source: trustedKeySource},
	}
}
