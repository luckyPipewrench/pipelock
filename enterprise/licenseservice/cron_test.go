//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func newTestCron(t *testing.T) (*RefreshCron, *testSetup) {
	t.Helper()
	ts := newTestSetup(t)
	cron := NewRefreshCron(ts.handler, ts.db, ts.ledger, zerolog.Nop())
	return cron, ts
}

func TestNewRefreshCron(t *testing.T) {
	cron, _ := newTestCron(t)
	if cron.handler == nil {
		t.Error("handler is nil")
	}
	if cron.db == nil {
		t.Error("db is nil")
	}
	if cron.ledger == nil {
		t.Error("ledger is nil")
	}
}

func TestRefreshCron_Tick_NoDueEntitlements(t *testing.T) {
	cron, _ := newTestCron(t)
	ctx := t.Context()

	// tick with no due entitlements should complete without error.
	cron.tick(ctx)
}

func TestRefreshCron_Tick_RefreshesActiveSubscription(t *testing.T) {
	cron, ts := newTestCron(t)
	ctx := t.Context()

	// Point email sender at mock.
	ts.handler.email = &EmailSender{
		apiKey:    "re_" + "test_key",
		fromEmail: "test@pipelock.dev",
		client:    ts.emailSrv.Client(),
		apiURL:    ts.emailSrv.URL,
	}

	// Insert an entitlement due for refresh.
	past := time.Now().Add(-1 * time.Hour)
	ent := testEntitlement(testSubscriptionID)
	ent.NextRefreshAt = &past
	ent.LastLicenseID = testLicenseIDOld
	if err := ts.db.Upsert(ctx, ent); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	cron.tick(ctx)

	// Verify the entitlement was refreshed (new license issued).
	got, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if got.LastLicenseID == testLicenseIDOld {
		t.Error("license should have been refreshed but still has old ID")
	}
}

func TestRefreshCron_Tick_SkipsCanceledSubscription(t *testing.T) {
	cron, ts := newTestCron(t)
	ctx := t.Context()

	// Set up Polar mock to return canceled status.
	canceledPolar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testContentTypeJSON)
		_, _ = fmt.Fprintf(w, `{
			"id": "%s",
			"status": "canceled",
			"customer": {"email": "%s", "metadata": {}},
			"product": {"id": "%s", "name": "%s", "metadata": {"pipelock_tier": "pro"}},
			"recurring_interval": "month",
			"current_period_end": "2026-04-12T00:00:00Z"
		}`, testSubscriptionID, testCustomerEmail, testProductID, testProductName)
	}))
	defer canceledPolar.Close()
	ts.handler.polar = NewPolarClient(testPolarAPIToken, canceledPolar.URL)

	// Insert an entitlement due for refresh.
	past := time.Now().Add(-1 * time.Hour)
	ent := testEntitlement(testSubscriptionID)
	ent.NextRefreshAt = &past
	if err := ts.db.Upsert(ctx, ent); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	cron.tick(ctx)

	// Verify the entitlement was updated to canceled and refresh cleared.
	got, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if got.Status != testStatusCanceled {
		t.Errorf("Status = %q, want %q", got.Status, testStatusCanceled)
	}
	if got.NextRefreshAt != nil {
		t.Error("NextRefreshAt should be nil after canceled refresh")
	}
}

func TestRefreshCron_Run_StopsOnCancel(t *testing.T) {
	cron, _ := newTestCron(t)

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan struct{})
	go func() {
		cron.Run(ctx)
		close(done)
	}()

	// Cancel immediately.
	cancel()

	select {
	case <-done:
		// Run stopped as expected.
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop within timeout after context cancel")
	}
}

func TestRefreshCron_RefreshOne_PolarError(t *testing.T) {
	db := openTestDB(t)
	ledger, _ := openTestLedger(t)

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Polar mock that always returns 500.
	errorPolar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal"}`))
	}))
	defer errorPolar.Close()

	cfg := &Config{
		FoundingProCap:      50,
		FoundingProDeadline: time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
	}
	polar := NewPolarClient(testPolarAPIToken, errorPolar.URL)
	email := NewEmailSender("re_"+"key", "from@test.com")

	handler, err := NewWebhookHandler(cfg, db, polar, email, ledger, priv, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewWebhookHandler: %v", err)
	}

	cron := NewRefreshCron(handler, db, ledger, zerolog.Nop())
	ctx := t.Context()

	// Insert a due entitlement.
	past := time.Now().Add(-1 * time.Hour)
	ent := testEntitlement(testSubscriptionID)
	ent.NextRefreshAt = &past
	if err := db.Upsert(ctx, ent); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// tick should log the error but not panic.
	cron.tick(ctx)
}

func TestRefreshCron_RefreshOne_DirectCall(t *testing.T) {
	cron, ts := newTestCron(t)
	ctx := t.Context()

	// Point email sender at mock.
	ts.handler.email = &EmailSender{
		apiKey:    "re_" + "test_key",
		fromEmail: "test@pipelock.dev",
		client:    ts.emailSrv.Client(),
		apiURL:    ts.emailSrv.URL,
	}

	ent := testEntitlement(testSubscriptionID)
	if err := ts.db.Upsert(ctx, ent); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := cron.refreshOne(ctx, ent); err != nil {
		t.Fatalf("refreshOne: %v", err)
	}

	got, err := ts.db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if got.LastLicenseID == "" {
		t.Error("license should have been issued by refreshOne")
	}
}

func TestRefreshCron_RefreshOne_CanceledSub(t *testing.T) {
	db := openTestDB(t)
	ledger, _ := openTestLedger(t)

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	canceledPolar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testContentTypeJSON)
		_, _ = fmt.Fprintf(w, `{
			"id": "%s",
			"status": "canceled",
			"customer": {"email": "%s", "metadata": {}},
			"product": {"id": "%s", "name": "%s", "metadata": {"pipelock_tier": "pro"}},
			"recurring_interval": "month",
			"current_period_end": "2026-04-12T00:00:00Z"
		}`, testSubscriptionID, testCustomerEmail, testProductID, testProductName)
	}))
	defer canceledPolar.Close()

	cfg := &Config{
		FoundingProCap:      50,
		FoundingProDeadline: time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
	}
	polar := NewPolarClient(testPolarAPIToken, canceledPolar.URL)
	email := NewEmailSender("re_"+"key", "from@test.com")

	handler, err := NewWebhookHandler(cfg, db, polar, email, ledger, priv, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewWebhookHandler: %v", err)
	}

	cron := NewRefreshCron(handler, db, ledger, zerolog.Nop())
	ctx := t.Context()

	ent := testEntitlement(testSubscriptionID)
	if err := db.Upsert(ctx, ent); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := cron.refreshOne(ctx, ent); err != nil {
		t.Fatalf("refreshOne: %v", err)
	}

	got, err := db.GetBySubscriptionID(ctx, testSubscriptionID)
	if err != nil {
		t.Fatalf("GetBySubscriptionID: %v", err)
	}
	if got.Status != testStatusCanceled {
		t.Errorf("Status = %q, want %q", got.Status, testStatusCanceled)
	}
	if got.NextRefreshAt != nil {
		t.Error("NextRefreshAt should be nil for canceled sub")
	}
}
