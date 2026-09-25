//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// recordedEmail is one message the fake mail provider received.
type recordedEmail struct {
	To   []string
	HTML string
}

type emailRecorder struct {
	mu   sync.Mutex
	msgs []recordedEmail
}

func (r *emailRecorder) all() []recordedEmail {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedEmail(nil), r.msgs...)
}

// recordEmails swaps the handler's mail provider for one that records every
// message and always succeeds.
func recordEmails(t *testing.T, h *WebhookHandler) *emailRecorder {
	t.Helper()
	rec := &emailRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req resendRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode email request: %v", err)
		}
		rec.mu.Lock()
		rec.msgs = append(rec.msgs, recordedEmail{To: req.To, HTML: req.HTML})
		rec.mu.Unlock()
		w.Header().Set("Content-Type", testContentTypeJSON)
		_, _ = w.Write([]byte(`{"id":"msg_resend_test"}`))
	}))
	t.Cleanup(srv.Close)
	h.email = &EmailSender{apiKey: "re_test", fromEmail: "test@pipelock.dev", client: srv.Client(), apiURL: srv.URL}
	return rec
}

// issueTrial issues a zero-dollar trial to email and returns the token from
// the original delivery.
func issueResendTrial(t *testing.T, ts *testSetup, orderID, email string) string {
	t.Helper()
	rec := recordEmails(t, ts.handler)
	if err := ts.handler.HandleOrderEvent(t.Context(), zeroTrialOrderEvent(t, orderID, email)); err != nil {
		t.Fatalf("issue trial %s: %v", orderID, err)
	}
	msgs := rec.all()
	if len(msgs) != 1 {
		t.Fatalf("original delivery sent %d emails, want 1", len(msgs))
	}
	return msgs[0].HTML
}

func TestResendLicensesForEmailSendsExistingTokenToAddressOnRecord(t *testing.T) {
	ts := newTestSetup(t)
	const orderID = "order_free_1_alphaupper"
	original := issueResendTrial(t, ts, orderID, "ALPHA@Example.com")
	rec := recordEmails(t, ts.handler)

	// The caller's spelling differs from the stored one; delivery still goes
	// to the stored address, not to whatever the caller typed.
	sent, err := ts.handler.ResendLicensesForEmail(t.Context(), "  alpha@EXAMPLE.com ", time.Now())
	if err != nil {
		t.Fatalf("resend: %v", err)
	}
	if sent != 1 {
		t.Fatalf("sent = %d, want 1", sent)
	}
	msgs := rec.all()
	if len(msgs) != 1 {
		t.Fatalf("resend sent %d emails, want 1", len(msgs))
	}
	stored, err := ts.db.GetBySubscriptionID(t.Context(), orderID)
	if err != nil || stored == nil {
		t.Fatalf("load stored entitlement: %v", err)
	}
	if len(msgs[0].To) != 1 || msgs[0].To[0] != stored.CustomerEmail || msgs[0].To[0] == "  alpha@EXAMPLE.com " {
		t.Fatalf("resend went to %v, want the stored address %q", msgs[0].To, stored.CustomerEmail)
	}
	// Same deterministic token: nothing was minted and no expiry moved.
	if msgs[0].HTML != original {
		t.Fatal("resend delivered a different license than the original email")
	}
	ent, err := ts.db.GetBySubscriptionID(t.Context(), orderID)
	if err != nil || ent == nil {
		t.Fatalf("reload entitlement: %v", err)
	}
	if ent.LastDeliveryStatus != "sent" {
		t.Fatalf("delivery status = %q, want sent", ent.LastDeliveryStatus)
	}
}

func TestResendLicensesForEmailIgnoresUnknownAndMalformedAddresses(t *testing.T) {
	ts := newTestSetup(t)
	issueResendTrial(t, ts, "order_free_resend_known", "known@example.com")
	rec := recordEmails(t, ts.handler)

	for _, email := range []string{"stranger@example.com", "not an email", "", "a@example.com, known@example.com"} {
		sent, err := ts.handler.ResendLicensesForEmail(t.Context(), email, time.Now())
		if err != nil || sent != 0 {
			t.Fatalf("ResendLicensesForEmail(%q) = %d, %v; want 0, nil", email, sent, err)
		}
	}
	if got := len(rec.all()); got != 0 {
		t.Fatalf("unknown addresses caused %d emails", got)
	}
	var rows int
	if err := ts.db.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM license_resend_requests`).Scan(&rows); err != nil {
		t.Fatalf("count limiter rows: %v", err)
	}
	if rows != 0 {
		t.Fatalf("non-matching requests left %d limiter rows, want 0", rows)
	}
}

func TestResendLicensesForEmailRefusesIneligibleLicenses(t *testing.T) {
	cases := []struct {
		name    string
		breakFn func(t *testing.T, ts *testSetup, orderID string)
	}{
		{"expired", func(t *testing.T, ts *testSetup, orderID string) {
			if _, err := ts.db.db.ExecContext(t.Context(),
				`UPDATE entitlements SET last_license_expires_at = ? WHERE subscription_id = ?`, time.Now().Add(-time.Minute), orderID); err != nil {
				t.Fatal(err)
			}
		}},
		{"revoked", func(t *testing.T, ts *testSetup, orderID string) {
			if err := ts.handler.RevokeTrialAccess(t.Context(), orderID, "test revoke", time.Now()); err != nil {
				t.Fatal(err)
			}
		}},
		{"revoked license on active row", func(t *testing.T, ts *testSetup, orderID string) {
			ent, err := ts.db.GetBySubscriptionID(t.Context(), orderID)
			if err != nil || ent == nil {
				t.Fatal(err)
			}
			if _, err := ts.db.db.ExecContext(t.Context(),
				`INSERT INTO license_revocations (license_id, subscription_id, reason, revoked_at) VALUES (?, ?, 'test', ?)`,
				ent.LastLicenseID, orderID, time.Now()); err != nil {
				t.Fatal(err)
			}
		}},
		{"no persisted issuance", func(t *testing.T, ts *testSetup, orderID string) {
			if _, err := ts.db.db.ExecContext(t.Context(), `DELETE FROM license_issuances WHERE subscription_id = ?`, orderID); err != nil {
				t.Fatal(err)
			}
		}},
		{"canceled", func(t *testing.T, ts *testSetup, orderID string) {
			if _, err := ts.db.db.ExecContext(t.Context(),
				`UPDATE entitlements SET status = 'canceled' WHERE subscription_id = ?`, orderID); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestSetup(t)
			const orderID = "order_free_resend_ineligible"
			issueResendTrial(t, ts, orderID, "ineligible@example.com")
			tc.breakFn(t, ts, orderID)
			rec := recordEmails(t, ts.handler)
			sent, err := ts.handler.ResendLicensesForEmail(t.Context(), "ineligible@example.com", time.Now())
			if err != nil {
				t.Fatalf("resend: %v", err)
			}
			if sent != 0 || len(rec.all()) != 0 {
				t.Fatalf("ineligible license was re-sent (sent=%d emails=%d)", sent, len(rec.all()))
			}
		})
	}
}

func TestResendLicensesForEmailRateLimitsPerAddress(t *testing.T) {
	ts := newTestSetup(t)
	issueResendTrial(t, ts, "order_free_resend_limit", "limit@example.com")
	rec := recordEmails(t, ts.handler)
	start := time.Now()

	if sent, err := ts.handler.ResendLicensesForEmail(t.Context(), "limit@example.com", start); err != nil || sent != 1 {
		t.Fatalf("first resend = %d, %v", sent, err)
	}
	// Inside the spacing interval.
	if _, err := ts.handler.ResendLicensesForEmail(t.Context(), "limit@example.com", start.Add(time.Minute)); !errors.Is(err, ErrResendThrottled) {
		t.Fatalf("second resend err = %v, want throttled", err)
	}
	if sent, err := ts.handler.ResendLicensesForEmail(t.Context(), "limit@example.com", start.Add(resendAddressInterval+time.Second)); err != nil || sent != 1 {
		t.Fatalf("spaced resend = %d, %v", sent, err)
	}
	if sent, err := ts.handler.ResendLicensesForEmail(t.Context(), "limit@example.com", start.Add(2*resendAddressInterval+2*time.Second)); err != nil || sent != 1 {
		t.Fatalf("third resend = %d, %v", sent, err)
	}
	// Daily cap reached even though the spacing interval has passed.
	if _, err := ts.handler.ResendLicensesForEmail(t.Context(), "limit@example.com", start.Add(3*resendAddressInterval+3*time.Second)); !errors.Is(err, ErrResendThrottled) {
		t.Fatalf("fourth resend err = %v, want throttled", err)
	}
	if got := len(rec.all()); got != resendAddressDailyMax {
		t.Fatalf("emails sent = %d, want %d", got, resendAddressDailyMax)
	}
	// The window rolls over.
	if sent, err := ts.handler.ResendLicensesForEmail(t.Context(), "limit@example.com", start.Add(resendWindow+time.Hour)); err != nil || sent != 1 {
		t.Fatalf("next-day resend = %d, %v", sent, err)
	}
}

func TestAdmitLicenseResendGlobalCap(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	for i := 0; i < resendGlobalHourlyMax; i++ {
		if err := db.AdmitLicenseResend(t.Context(), strings.Repeat("x", i+1)+"@example.com", 1, now); err != nil {
			t.Fatalf("admit %d: %v", i, err)
		}
	}
	if err := db.AdmitLicenseResend(t.Context(), "fresh@example.com", 1, now); !errors.Is(err, ErrResendThrottled) {
		t.Fatalf("admit over global cap err = %v, want throttled", err)
	}
	if err := db.AdmitLicenseResend(t.Context(), "fresh@example.com", 1, now.Add(time.Hour+time.Second)); err != nil {
		t.Fatalf("admit after the hour: %v", err)
	}
}

// A second service process on the same database must see the first one's
// admissions, which is also what a restart looks like.
func TestResendLimitSharedAcrossProcesses(t *testing.T) {
	first, second, db := newFileBackedTrialSupportHandlers(t)
	if err := first.HandleOrderEvent(t.Context(), zeroTrialOrderEvent(t, "order_free_resend_shared", "shared@example.com")); err != nil {
		t.Fatalf("issue trial: %v", err)
	}
	recordEmails(t, first)
	recordEmails(t, second)
	now := time.Now()
	if sent, err := first.ResendLicensesForEmail(t.Context(), "shared@example.com", now); err != nil || sent != 1 {
		t.Fatalf("first process resend = %d, %v", sent, err)
	}
	if _, err := second.ResendLicensesForEmail(t.Context(), "shared@example.com", now.Add(time.Second)); !errors.Is(err, ErrResendThrottled) {
		t.Fatalf("second process err = %v, want throttled", err)
	}
	var rows int
	if err := db.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM license_resend_requests`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("shared limiter rows = %d, %v; want 1", rows, err)
	}
}

func newResendTestServer(t *testing.T, returnURL string) (*Server, *testSetup) {
	t.Helper()
	ts := newTestSetup(t)
	cfg := *ts.cfg
	cfg.SelfServeResendEnabled = true
	cfg.SelfServeResendReturnURL = returnURL
	s := NewServer(&cfg, ts.handler, ts.ledger, zerolog.New(zerolog.NewTestWriter(t)))
	t.Cleanup(func() { s.stopResendWorker(context.Background()) })
	return s, ts
}

func postResend(t *testing.T, s *Server, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/license/resend", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	s.mux.ServeHTTP(rr, req)
	return rr
}

func TestHandleLicenseResendResponseDoesNotRevealCustomers(t *testing.T) {
	s, ts := newResendTestServer(t, "")
	issueResendTrial(t, ts, "order_free_resend_httpowner", "httpowner@example.com")
	rec := recordEmails(t, ts.handler)

	known := postResend(t, s, "application/json", `{"email":"httpowner@example.com"}`)
	unknown := postResend(t, s, "application/json", `{"email":"nobody@example.com"}`)
	malformed := postResend(t, s, "application/json", `{"email":"not an address"}`)
	for name, rr := range map[string]*httptest.ResponseRecorder{"unknown": unknown, "malformed": malformed} {
		if rr.Code != known.Code || rr.Body.String() != known.Body.String() {
			t.Fatalf("%s response %d %q differs from known %d %q", name, rr.Code, rr.Body.String(), known.Code, known.Body.String())
		}
	}
	if known.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", known.Code)
	}
	if known.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("resend response must not be cached")
	}

	testwait.For(t, 5*time.Second, func() bool { return len(rec.all()) > 0 }, "background resend never delivered")
	msgs := rec.all()
	if len(msgs) != 1 || msgs[0].To[0] != "httpowner@example.com" {
		t.Fatalf("background resend emails = %+v, want one to the owner", msgs)
	}
}

func TestHandleLicenseResendForm(t *testing.T) {
	t.Run("redirects to return URL", func(t *testing.T) {
		s, _ := newResendTestServer(t, "https://pipelab.example/license/resend-sent/")
		rr := postResend(t, s, "application/x-www-form-urlencoded", "email=someone%40example.com")
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "https://pipelab.example/license/resend-sent/" {
			t.Fatalf("form response = %d %q", rr.Code, rr.Header().Get("Location"))
		}
	})
	t.Run("plain text without return URL", func(t *testing.T) {
		s, _ := newResendTestServer(t, "")
		rr := postResend(t, s, "application/x-www-form-urlencoded", "email=someone%40example.com")
		if rr.Code != http.StatusAccepted || !strings.Contains(rr.Body.String(), "active Pipelock license") {
			t.Fatalf("form response = %d %q", rr.Code, rr.Body.String())
		}
	})
}

func TestHandleLicenseResendRejectsBadRequests(t *testing.T) {
	s, _ := newResendTestServer(t, "")
	cases := []struct {
		name, contentType, body string
		want                    int
	}{
		{"oversized", "application/json", `{"email":"` + strings.Repeat("a", maxResendBody) + `"}`, http.StatusRequestEntityTooLarge},
		{"bad json", "application/json", `{`, http.StatusBadRequest},
		{"unsupported type", "text/plain", "someone@example.com", http.StatusUnsupportedMediaType},
		{"bad form", "application/x-www-form-urlencoded", "email=%zz", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rr := postResend(t, s, tc.contentType, tc.body); rr.Code != tc.want {
				t.Fatalf("status = %d, want %d", rr.Code, tc.want)
			}
		})
	}
}

func TestHandleLicenseResendDisabledByDefault(t *testing.T) {
	ts := newTestSetup(t)
	s := NewServer(ts.cfg, ts.handler, ts.ledger, zerolog.Nop())
	rr := postResend(t, s, "application/json", `{"email":"someone@example.com"}`)
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("disabled endpoint status = %d, want not routed", rr.Code)
	}
	if s.resend != nil {
		t.Fatal("disabled endpoint started a worker")
	}
	s.stopResendWorker(t.Context()) // nil worker is a no-op
}

func TestHandleLicenseResendRefusesWhenQueueFull(t *testing.T) {
	s, _ := newResendTestServer(t, "")
	// Stop the worker so nothing drains the queue, then fill it.
	s.stopResendWorker(t.Context())
	for i := 0; i < resendQueueSize; i++ {
		s.resend.queue <- "filler@example.com"
	}
	// Busy depends on load only, so a known and an unknown address get the
	// same refusal, and the caller learns it was not accepted.
	rr := postResend(t, s, "application/json", `{"email":"overflow@example.com"}`)
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("overflow status = %d retry-after=%q, want 503 with Retry-After", rr.Code, rr.Header().Get("Retry-After"))
	}
	if got := len(s.resend.queue); got != resendQueueSize {
		t.Fatalf("queue length = %d, want %d", got, resendQueueSize)
	}
}

func TestLoadConfigSelfServeResend(t *testing.T) {
	setRequiredConfigEnv(t)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig default: %v", err)
	}
	if cfg.SelfServeResendEnabled || cfg.SelfServeResendReturnURL != "" {
		t.Fatal("self-serve resend must default off")
	}

	t.Setenv("SELF_SERVE_RESEND_ENABLED", "true")
	t.Setenv("SELF_SERVE_RESEND_RETURN_URL", "https://pipelab.example/license/sent/")
	cfg, err = LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig enabled: %v", err)
	}
	if !cfg.SelfServeResendEnabled || cfg.SelfServeResendReturnURL != "https://pipelab.example/license/sent/" {
		t.Fatalf("enabled config = %+v", cfg)
	}

	for _, bad := range []struct{ key, value string }{
		{"SELF_SERVE_RESEND_ENABLED", "maybe"},
		{"SELF_SERVE_RESEND_RETURN_URL", "http://pipelab.example/sent"},
		{"SELF_SERVE_RESEND_RETURN_URL", "/relative"},
		{"SELF_SERVE_RESEND_RETURN_URL", "https://user:pw@pipelab.example/"},
	} {
		t.Run(bad.key+"="+bad.value, func(t *testing.T) {
			t.Setenv("SELF_SERVE_RESEND_ENABLED", "true")
			t.Setenv("SELF_SERVE_RESEND_RETURN_URL", "")
			t.Setenv(bad.key, bad.value)
			if _, err := LoadConfig(); err == nil {
				t.Fatalf("LoadConfig accepted %s=%q", bad.key, bad.value)
			}
		})
	}
}

func TestResendLicensesForEmailCoversPaidSubscription(t *testing.T) {
	ts := newTestSetup(t)
	recordEmails(t, ts.handler)
	if err := ts.handler.HandleEvent(t.Context(), &PolarWebhookEvent{
		Type: EventSubscriptionCreated,
		Data: json.RawMessage(testSubscriptionJSON),
	}); err != nil {
		t.Fatalf("issue subscription license: %v", err)
	}
	rec := recordEmails(t, ts.handler)
	sent, err := ts.handler.ResendLicensesForEmail(t.Context(), testCustomerEmail, time.Now())
	if err != nil || sent != 1 {
		t.Fatalf("subscription resend = %d, %v; want 1, nil", sent, err)
	}
	if msgs := rec.all(); len(msgs) != 1 || msgs[0].To[0] != testCustomerEmail {
		t.Fatalf("subscription resend emails = %+v", msgs)
	}
}

func TestResendLicensesForEmailCoversEnterpriseEval(t *testing.T) {
	es := newEvalTestSetup(t)
	if err := es.handler.HandleOrderPaidEvent(t.Context(), evalPaidEvent(), "msg_resend_eval"); err != nil {
		t.Fatalf("mint eval: %v", err)
	}
	before := es.emailHits.Load()
	sent, err := es.handler.ResendLicensesForEmail(t.Context(), testEvalEmail, time.Now())
	if err != nil || sent != 1 {
		t.Fatalf("eval resend = %d, %v; want 1, nil", sent, err)
	}
	if got := es.emailHits.Load() - before; got != 1 {
		t.Fatalf("eval resend sent %d emails, want 1", got)
	}
}

func TestResendLicensesForEmailReportsDeliveryFailure(t *testing.T) {
	ts := newTestSetup(t)
	issueResendTrial(t, ts, "order_free_resend_bounce", "bounce@example.com")
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider down", http.StatusInternalServerError)
	}))
	t.Cleanup(failing.Close)
	ts.handler.email = &EmailSender{apiKey: "re_test", fromEmail: "test@pipelock.dev", client: failing.Client(), apiURL: failing.URL}

	sent, err := ts.handler.ResendLicensesForEmail(t.Context(), "bounce@example.com", time.Now())
	if err == nil || sent != 0 {
		t.Fatalf("failed delivery = %d, %v; want 0 and an error", sent, err)
	}
	ent, lerr := ts.db.GetBySubscriptionID(t.Context(), "order_free_resend_bounce")
	if lerr != nil || ent == nil || ent.LastDeliveryStatus != "failed" {
		t.Fatalf("delivery status after failure = %+v, %v; want failed", ent, lerr)
	}
}

func TestResendOneLicenseRechecksTheReloadedRow(t *testing.T) {
	ts := newTestSetup(t)
	const orderID = "order_free_resend_moved"
	issueResendTrial(t, ts, orderID, "moved@example.com")
	rec := recordEmails(t, ts.handler)
	now := time.Now()

	// A webhook rewrote the address between the lookup and the reload.
	if ok, err := ts.handler.resendOneLicense(t.Context(), orderID, "someone-else@example.com", map[string]bool{}, now); err != nil || ok {
		t.Fatalf("changed address = %v, %v; want refused", ok, err)
	}
	// The row disappeared.
	if ok, err := ts.handler.resendOneLicense(t.Context(), "order_missing", "moved@example.com", map[string]bool{}, now); err != nil || ok {
		t.Fatalf("missing row = %v, %v; want refused", ok, err)
	}
	if got := len(rec.all()); got != 0 {
		t.Fatalf("refused resends sent %d emails", got)
	}
}

func TestResendableSubscriptionIDsSkipsUnparseableStoredAddress(t *testing.T) {
	ts := newTestSetup(t)
	const orderID = "order_free_resend_garbled"
	issueResendTrial(t, ts, orderID, "garbled@example.com")
	if _, err := ts.db.db.ExecContext(t.Context(),
		`UPDATE entitlements SET customer_email = 'not an address' WHERE subscription_id = ?`, orderID); err != nil {
		t.Fatal(err)
	}
	ids, err := ts.db.ResendableSubscriptionIDsForEmail(t.Context(), "garbled@example.com", time.Now())
	if err != nil || len(ids) != 0 {
		t.Fatalf("ids = %v, %v; want none", ids, err)
	}
}

func TestResendFailsClosedOnDatabaseErrors(t *testing.T) {
	ts := newTestSetup(t)
	const orderID = "order_free_resend_dberr"
	issueResendTrial(t, ts, orderID, "dberr@example.com")
	rec := recordEmails(t, ts.handler)
	if err := ts.db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	now := time.Now()
	if _, err := ts.handler.ResendLicensesForEmail(t.Context(), "dberr@example.com", now); err == nil {
		t.Fatal("resend with an unreadable database must fail")
	}
	if err := ts.db.AdmitLicenseResend(t.Context(), "dberr@example.com", 1, now); err == nil || errors.Is(err, ErrResendThrottled) {
		t.Fatalf("admission with an unreadable database = %v; want a storage error", err)
	}
	if _, err := ts.handler.revokedLicenseIDs(t.Context()); err == nil {
		t.Fatal("revocation list with an unreadable database must fail")
	}
	if ok, err := ts.handler.resendOneLicense(t.Context(), orderID, "dberr@example.com", map[string]bool{}, now); err == nil || ok {
		t.Fatalf("reload with an unreadable database = %v, %v; want an error", ok, err)
	}
	if got := len(rec.all()); got != 0 {
		t.Fatalf("database failure still sent %d emails", got)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestHandleLicenseResendBodyReadError(t *testing.T) {
	s, _ := newResendTestServer(t, "")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/license/resend", failingReader{})
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestResendEnterpriseEvalDeliveryFailure(t *testing.T) {
	es := newEvalTestSetup(t)
	if err := es.handler.HandleOrderPaidEvent(t.Context(), evalPaidEvent(), "msg_resend_eval_fail"); err != nil {
		t.Fatalf("mint eval: %v", err)
	}
	es.emailFail.Store(true)
	sent, err := es.handler.ResendLicensesForEmail(t.Context(), testEvalEmail, time.Now())
	if err == nil || sent != 0 {
		t.Fatalf("eval resend with failing provider = %d, %v; want 0 and an error", sent, err)
	}
}

// A resend that cannot be attributed in the audit ledger is not sent.
func TestResendRefusesToSendWithoutRequestAudit(t *testing.T) {
	ts := newTestSetup(t)
	issueResendTrial(t, ts, "order_free_resend_auditfail", "auditfail@example.com")
	rec := recordEmails(t, ts.handler)
	if err := ts.ledger.Close(); err != nil {
		t.Fatalf("close ledger: %v", err)
	}
	sent, err := ts.handler.ResendLicensesForEmail(t.Context(), "auditfail@example.com", time.Now())
	if err == nil || sent != 0 || len(rec.all()) != 0 {
		t.Fatalf("resend with closed ledger = %d, %v, emails=%d; want 0, error, 0", sent, err, len(rec.all()))
	}
}

func TestResendWritesRequestAuditBeforeCompletion(t *testing.T) {
	ts := newTestSetup(t)
	issueResendTrial(t, ts, "order_free_resend_auditorder", "auditorder@example.com")
	recordEmails(t, ts.handler)
	if sent, err := ts.handler.ResendLicensesForEmail(t.Context(), "auditorder@example.com", time.Now()); err != nil || sent != 1 {
		t.Fatalf("resend = %d, %v", sent, err)
	}
	data, err := os.ReadFile(ts.ledger.path)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	text := string(data)
	req := strings.Index(text, `"event":"`+AuditLicenseResendRequested+`"`)
	done := strings.Index(text, `"event":"`+AuditLicenseResent+`"`)
	if req < 0 || done < 0 || req > done {
		t.Fatalf("ledger order: requested at %d, resent at %d; want request first", req, done)
	}
}

func TestAdmitLicenseResendCountsEmailsAgainstGlobalBudget(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	if err := db.AdmitLicenseResend(t.Context(), "many@example.com", resendGlobalHourlyMax-2, now); err != nil {
		t.Fatalf("admit large batch: %v", err)
	}
	if err := db.AdmitLicenseResend(t.Context(), "three@example.com", 3, now); !errors.Is(err, ErrResendThrottled) {
		t.Fatalf("batch over the email budget err = %v, want throttled", err)
	}
	if err := db.AdmitLicenseResend(t.Context(), "two@example.com", 2, now); err != nil {
		t.Fatalf("batch that fits the email budget: %v", err)
	}
	if err := db.AdmitLicenseResend(t.Context(), "zero@example.com", 0, now); err == nil || errors.Is(err, ErrResendThrottled) {
		t.Fatalf("zero-send admission = %v, want an argument error", err)
	}
	if err := db.AdmitLicenseResend(t.Context(), "huge@example.com", math.MaxInt, now); err == nil || errors.Is(err, ErrResendThrottled) {
		t.Fatalf("oversized admission = %v, want an argument error", err)
	}
}

// Requests already accepted when the service shuts down are still delivered.
func TestStopResendWorkerDrainsAcceptedRequests(t *testing.T) {
	s, ts := newResendTestServer(t, "")
	issueResendTrial(t, ts, "order_free_resend_drainone", "drainone@example.com")
	rec := recordEmails(t, ts.handler)
	// Park the worker inside the first job so the second stays queued.
	ts.handler.processMu.Lock()
	s.resend.queue <- "drainone@example.com"
	testwait.For(t, 5*time.Second, func() bool { return len(s.resend.queue) == 0 }, "worker never took the first job")
	s.resend.queue <- "drainone@example.com"
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		s.stopResendWorker(context.Background())
	}()
	ts.handler.processMu.Unlock()
	testwait.For(t, 10*time.Second, func() bool {
		select {
		case <-stopped:
			return true
		default:
			return false
		}
	}, "worker did not stop")
	if got := len(s.resend.queue); got != 0 {
		t.Fatalf("queue after stop = %d, want drained", got)
	}
	// The first job sent; the drained second job ran and was throttled by the
	// per-address spacing, which proves it was processed rather than dropped.
	if got := len(rec.all()); got != 1 {
		t.Fatalf("emails = %d, want 1", got)
	}
	var rows int
	if err := ts.db.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM license_resend_requests`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("limiter rows = %d, %v", rows, err)
	}
}

// An address with no license must not wait on, or hold, the lock that webhook
// processing uses, because any caller can submit one.
func TestResendLookupForUnknownAddressDoesNotTakeWebhookLock(t *testing.T) {
	ts := newTestSetup(t)
	issueResendTrial(t, ts, "order_free_resend_lockfree", "lockfree@example.com")
	ts.handler.processMu.Lock()
	unlocked := false
	t.Cleanup(func() {
		if !unlocked {
			ts.handler.processMu.Unlock()
		}
	})
	done := make(chan error, 1)
	go func() {
		_, err := ts.handler.ResendLicensesForEmail(t.Context(), "stranger@example.com", time.Now())
		done <- err
	}()
	var lookupErr error
	testwait.For(t, 5*time.Second, func() bool {
		select {
		case lookupErr = <-done:
			return true
		default:
			return false
		}
	}, "unknown-address resend blocked on the webhook lock")
	if lookupErr != nil {
		t.Fatalf("unknown-address lookup failed: %v", lookupErr)
	}
	ts.handler.processMu.Unlock()
	unlocked = true
}

// One request re-sends at most resendMaxLicensesPerRequest licenses however
// many an address holds.
func TestResendCapsLicensesPerRequest(t *testing.T) {
	ts := newTestSetup(t)
	const base = "order_free_resend_fanout"
	issueResendTrial(t, ts, base, "fanout@example.com")
	for i := 0; i < resendMaxLicensesPerRequest+2; i++ {
		clone := fmt.Sprintf("%s_clone_%02d", base, i)
		if _, err := ts.db.db.ExecContext(t.Context(), `
			INSERT INTO entitlements SELECT ?, customer_email, product_id, tier, billing_interval, status,
				current_period_end, founding, founding_reserved_at, org, features, ? || last_license_id,
				last_license_issued_at, last_license_expires_at, last_license_period_end, last_license_tier,
				last_license_interval, last_license_product_id, last_delivery_status, last_delivery_attempt_at,
				next_refresh_at, created_at, updated_at
			FROM entitlements WHERE subscription_id = ?`, clone, clone, base); err != nil {
			t.Fatalf("clone entitlement: %v", err)
		}
		if _, err := ts.db.db.ExecContext(t.Context(), `
			INSERT INTO license_issuances (license_id, subscription_id, expires_at, issued_at)
			SELECT ? || license_id, ?, expires_at, issued_at FROM license_issuances WHERE subscription_id = ?`,
			clone, clone, base); err != nil {
			t.Fatalf("clone issuance: %v", err)
		}
	}
	rec := recordEmails(t, ts.handler)
	sent, err := ts.handler.ResendLicensesForEmail(t.Context(), "fanout@example.com", time.Now())
	if err != nil || sent != resendMaxLicensesPerRequest {
		t.Fatalf("fan-out resend = %d, %v; want %d", sent, err, resendMaxLicensesPerRequest)
	}
	if got := len(rec.all()); got != resendMaxLicensesPerRequest {
		t.Fatalf("emails = %d, want %d", got, resendMaxLicensesPerRequest)
	}
}

func TestResendThrottleStillRefusesWhenAuditUnavailable(t *testing.T) {
	ts := newTestSetup(t)
	issueResendTrial(t, ts, "order_free_resend_throttleaudit", "throttleaudit@example.com")
	rec := recordEmails(t, ts.handler)
	now := time.Now()
	if sent, err := ts.handler.ResendLicensesForEmail(t.Context(), "throttleaudit@example.com", now); err != nil || sent != 1 {
		t.Fatalf("first resend = %d, %v", sent, err)
	}
	if err := ts.ledger.Close(); err != nil {
		t.Fatalf("close ledger: %v", err)
	}
	if _, err := ts.handler.ResendLicensesForEmail(t.Context(), "throttleaudit@example.com", now.Add(time.Minute)); !errors.Is(err, ErrResendThrottled) {
		t.Fatalf("second resend err = %v, want throttled", err)
	}
	if got := len(rec.all()); got != 1 {
		t.Fatalf("emails = %d, want 1", got)
	}
}

// A shutdown whose deadline has passed abandons queued work instead of
// waiting for it.
func TestStopResendWorkerHonorsDeadline(t *testing.T) {
	s, ts := newResendTestServer(t, "")
	issueResendTrial(t, ts, "order_free_resend_deadline", "deadline@example.com")
	recordEmails(t, ts.handler)
	ts.handler.processMu.Lock()
	s.resend.queue <- "deadline@example.com"
	testwait.For(t, 5*time.Second, func() bool { return len(s.resend.queue) == 0 }, "worker never took the job")
	s.resend.queue <- "deadline@example.com"
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		s.stopResendWorker(ctx)
	}()
	// The worker is still parked on the lock; stop must return anyway.
	testwait.For(t, 10*time.Second, func() bool {
		select {
		case <-stopped:
			return true
		default:
			return false
		}
	}, "shutdown waited past its deadline for a blocked job")
	ts.handler.processMu.Unlock()
	testwait.For(t, 10*time.Second, func() bool {
		select {
		case <-s.resend.done:
			return true
		default:
			return false
		}
	}, "abandoned worker never exited after the lock released")
}

// A database created by an earlier build has the requests table without the
// sends column; opening it must add the column rather than break admission.
func TestOpenEntitlementDBAddsResendSendsColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old-resend.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	if _, err := old.ExecContext(t.Context(),
		`CREATE TABLE license_resend_requests (email_sha256 TEXT NOT NULL, requested_at DATETIME NOT NULL)`); err != nil {
		t.Fatalf("create old table: %v", err)
	}
	_ = old.Close()
	for i := 0; i < 2; i++ { // the second open is the ordinary restart
		db, err := OpenEntitlementDB(t.Context(), path)
		if err != nil {
			t.Fatalf("open upgraded db (pass %d): %v", i, err)
		}
		if err := db.AdmitLicenseResend(t.Context(), fmt.Sprintf("upgrade%d@example.com", i), 2, time.Now()); err != nil {
			t.Fatalf("admission after upgrade (pass %d): %v", i, err)
		}
		_ = db.Close()
	}
}

// Once shutdown has begun, a request that arrives late is refused rather than
// accepted into a queue nothing will drain.
func TestHandleLicenseResendRefusesAfterShutdown(t *testing.T) {
	s, _ := newResendTestServer(t, "")
	s.stopResendWorker(t.Context())
	rr := postResend(t, s, "application/json", `{"email":"late@example.com"}`)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("post-shutdown status = %d, want 503", rr.Code)
	}
	if got := len(s.resend.queue); got != 0 {
		t.Fatalf("post-shutdown request was queued (%d)", got)
	}
}
