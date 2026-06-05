//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/rs/zerolog"
)

const (
	testEvalProductID = "prod_eval"
	testEvalOrderID   = "order_eval_1"
	testEvalEmail     = "buyer@example.com"
	testEvalAmount    = 500000
)

// evalTestSetup wires a handler whose Polar mock serves a controllable ORDER
// (GET /v1/orders/{id}) and whose email mock can be toggled to fail.
type evalTestSetup struct {
	handler   *WebhookHandler
	db        *EntitlementDB
	publicKey ed25519.PublicKey
	orderJSON *atomic.Pointer[string]
	emailFail *atomic.Bool
	emailHits *atomic.Int32
}

func newEvalTestSetup(t *testing.T) *evalTestSetup {
	t.Helper()

	db := openTestDB(t)
	ledger, _ := openTestLedger(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	orderJSON := &atomic.Pointer[string]{}
	def := defaultEvalOrderJSON(orderStatusPaidJSON())
	orderJSON.Store(&def)

	polarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(*orderJSON.Load()))
	}))
	t.Cleanup(polarSrv.Close)

	emailFail := &atomic.Bool{}
	emailHits := &atomic.Int32{}
	emailSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		emailHits.Add(1)
		if emailFail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"boom"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_eval"}`))
	}))
	t.Cleanup(emailSrv.Close)

	cfg := &Config{
		PolarWebhookSecret:  "whsec_" + "dGVzdA==",
		PolarAPIToken:       testPolarAPIToken,
		PrivateKeyPath:      filepath.Join(t.TempDir(), "k"),
		ResendAPIKey:        "re_" + "test",
		DBPath:              ":memory:",
		LedgerPath:          filepath.Join(t.TempDir(), "l.jsonl"),
		FoundingProCap:      50,
		FoundingProDeadline: time.Date(2099, 6, 30, 0, 0, 0, 0, time.UTC),
		ListenAddr:          ":0",
		FromEmail:           "test@pipelock.dev",
		PolarAPIBase:        polarSrv.URL,
		EvalProductIDs:      []string{testEvalProductID},
		EvalAmountCents:     testEvalAmount,
		EvalCurrency:        "usd",
	}
	email := &EmailSender{apiKey: cfg.ResendAPIKey, fromEmail: cfg.FromEmail, client: emailSrv.Client(), apiURL: emailSrv.URL}
	polar := NewPolarClient(cfg.PolarAPIToken, cfg.PolarAPIBase)
	handler, err := NewWebhookHandler(cfg, db, polar, email, ledger, priv, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewWebhookHandler: %v", err)
	}

	return &evalTestSetup{handler: handler, db: db, publicKey: pub, orderJSON: orderJSON, emailFail: emailFail, emailHits: emailHits}
}

func orderStatusPaidJSON() string { return orderStatusPaid }

// defaultEvalOrderJSON builds an order body with the given status, all other
// fields valid for the configured eval product.
func defaultEvalOrderJSON(status string) string {
	paid := "true"
	refunded := 0
	if status == orderStatusRefunded {
		refunded = testEvalAmount
	}
	if status == orderStatusPartiallyRefunded {
		refunded = testEvalAmount / 5
	}
	return fmt.Sprintf(`{
		"id": "%s",
		"status": "%s",
		"paid": %s,
		"billing_reason": "purchase",
		"total_amount": %d,
		"refunded_amount": %d,
		"currency": "usd",
		"customer": {"email": "%s", "metadata": {"org": "buyercorp"}},
		"product": {"id": "%s", "name": "Enterprise Eval", "metadata": {"pipelock_tier": "enterprise_eval"}}
	}`, testEvalOrderID, status, paid, testEvalAmount, refunded, testEvalEmail, testEvalProductID)
}

func evalPaidEvent() *PolarWebhookEvent {
	return &PolarWebhookEvent{Type: EventOrderPaid, Data: json.RawMessage(fmt.Sprintf(`{"id":%q}`, testEvalOrderID))}
}

func evalRefundEvent() *PolarWebhookEvent {
	return &PolarWebhookEvent{Type: EventOrderRefunded, Data: json.RawMessage(fmt.Sprintf(`{"id":%q}`, testEvalOrderID))}
}

func TestHandleOrderPaid_MintsEvalToken(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()

	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_1"); err != nil {
		t.Fatalf("HandleOrderPaidEvent: %v", err)
	}

	ent, err := s.db.GetBySubscriptionID(ctx, testEvalOrderID)
	if err != nil || ent == nil {
		t.Fatalf("entitlement not created: %v", err)
	}
	if ent.Tier != tierEnterpriseEval || ent.CustomerEmail != testEvalEmail {
		t.Errorf("entitlement wrong: %+v", ent)
	}
	if ent.LastDeliveryStatus != testDeliveryStatusSent {
		t.Errorf("delivery status = %q, want sent", ent.LastDeliveryStatus)
	}
	// 60-day expiry (now-relative; tolerate a small window).
	wantExp := time.Now().Add(evalTokenLifetime)
	if ent.LastLicenseExpiresAt == nil || ent.LastLicenseExpiresAt.Sub(wantExp).Abs() > time.Hour {
		t.Errorf("expiry = %v, want ~%v", ent.LastLicenseExpiresAt, wantExp)
	}

	eo, err := s.db.GetEvalOrder(ctx, testEvalOrderID)
	if err != nil || eo == nil {
		t.Fatalf("eval order not recorded: %v", err)
	}
	if eo.FulfillmentState != fulfillmentMinted || eo.LicenseID == "" {
		t.Errorf("eval order = %+v, want minted with license id", eo)
	}
	if s.emailHits.Load() != 1 {
		t.Errorf("email hits = %d, want 1", s.emailHits.Load())
	}
}

func TestHandleOrderPaid_DuplicateDoesNotRemint(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()

	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_1"); err != nil {
		t.Fatalf("first: %v", err)
	}
	first, _ := s.db.GetBySubscriptionID(ctx, testEvalOrderID)

	// Same delivery id replayed: must not mint a new license or restart expiry.
	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_1"); err != nil {
		t.Fatalf("replay: %v", err)
	}
	second, _ := s.db.GetBySubscriptionID(ctx, testEvalOrderID)
	if first.LastLicenseID != second.LastLicenseID {
		t.Errorf("license id changed on replay: %q -> %q", first.LastLicenseID, second.LastLicenseID)
	}
	if !first.LastLicenseExpiresAt.Equal(*second.LastLicenseExpiresAt) {
		t.Errorf("expiry restarted on replay: %v -> %v", first.LastLicenseExpiresAt, second.LastLicenseExpiresAt)
	}
}

func TestHandleOrderPaid_RejectsInvalidOrders(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "unpaid", body: strings.ReplaceAll(defaultEvalOrderJSON(orderStatusPaid), `"paid": true`, `"paid": false`)},
		{name: "wrong amount", body: strings.ReplaceAll(defaultEvalOrderJSON(orderStatusPaid), `"total_amount": 500000`, `"total_amount": 100`)},
		{name: "wrong currency", body: strings.ReplaceAll(defaultEvalOrderJSON(orderStatusPaid), `"currency": "usd"`, `"currency": "eur"`)},
		{name: "wrong product", body: strings.ReplaceAll(defaultEvalOrderJSON(orderStatusPaid), testEvalProductID, "prod_not_allowlisted")},
		{name: "fully refunded", body: defaultEvalOrderJSON(orderStatusRefunded)},
		{name: "not a purchase", body: strings.ReplaceAll(defaultEvalOrderJSON(orderStatusPaid), `"billing_reason": "purchase"`, `"billing_reason": "subscription_cycle"`)},
		{name: "wrong tier metadata", body: strings.ReplaceAll(defaultEvalOrderJSON(orderStatusPaid), `"pipelock_tier": "enterprise_eval"`, `"pipelock_tier": "pro"`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newEvalTestSetup(t)
			ctx := t.Context()
			b := tt.body
			s.orderJSON.Store(&b)

			if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_1"); err != nil {
				t.Fatalf("HandleOrderPaidEvent should not hard-error on a denied order: %v", err)
			}
			ent, _ := s.db.GetBySubscriptionID(ctx, testEvalOrderID)
			if ent != nil {
				t.Errorf("entitlement minted for invalid order %q: %+v", tt.name, ent)
			}
		})
	}
}

func TestHandleOrderPaid_RefundBeforePaidRefusesMint(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()

	// Refund lands first: the order shows refunded at fetch time.
	refundBody := defaultEvalOrderJSON(orderStatusRefunded)
	s.orderJSON.Store(&refundBody)
	if err := s.handler.HandleOrderRefundEvent(ctx, evalRefundEvent(), "msg_refund"); err != nil {
		t.Fatalf("refund first: %v", err)
	}
	// Then a stale paid event arrives whose fetch shows the order paid (the race
	// the eval_order refund-before-paid guard exists for).
	paidBody := defaultEvalOrderJSON(orderStatusPaid)
	s.orderJSON.Store(&paidBody)
	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_paid"); err != nil {
		t.Fatalf("paid after refund: %v", err)
	}
	ent, _ := s.db.GetBySubscriptionID(ctx, testEvalOrderID)
	if ent != nil {
		t.Errorf("minted despite refund-before-paid: %+v", ent)
	}
}

func TestHandleOrderRefund_RevokesMintedEval(t *testing.T) {
	for _, status := range []string{orderStatusRefunded, orderStatusPartiallyRefunded} {
		t.Run(status, func(t *testing.T) {
			s := newEvalTestSetup(t)
			ctx := t.Context()

			if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_paid"); err != nil {
				t.Fatalf("mint: %v", err)
			}
			ent, _ := s.db.GetBySubscriptionID(ctx, testEvalOrderID)
			licID := ent.LastLicenseID

			refundBody := defaultEvalOrderJSON(status)
			s.orderJSON.Store(&refundBody)
			if err := s.handler.HandleOrderRefundEvent(ctx, evalRefundEvent(), "msg_refund"); err != nil {
				t.Fatalf("refund: %v", err)
			}

			revs, err := s.db.ListLicenseRevocations(ctx)
			if err != nil {
				t.Fatalf("ListLicenseRevocations: %v", err)
			}
			found := false
			for _, r := range revs {
				if r.LicenseID == licID {
					found = true
				}
			}
			if !found {
				t.Errorf("license %q not revoked after %s refund", licID, status)
			}
		})
	}
}

func TestHandleOrderPaid_EmailFailureDoesNotRemintOrExtend(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()

	s.emailFail.Store(true)
	// First attempt: business commits, email fails → expect an error (500 to Polar).
	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_1"); err == nil {
		t.Fatal("expected error on email failure so Polar retries")
	}
	ent1, _ := s.db.GetBySubscriptionID(ctx, testEvalOrderID)
	if ent1 == nil {
		t.Fatal("entitlement should exist after committed mint even when email failed")
	}

	// Retry with email working: must resend the SAME token, not re-mint.
	s.emailFail.Store(false)
	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_1"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	ent2, _ := s.db.GetBySubscriptionID(ctx, testEvalOrderID)
	if ent1.LastLicenseID != ent2.LastLicenseID {
		t.Errorf("re-minted on retry: %q -> %q", ent1.LastLicenseID, ent2.LastLicenseID)
	}
	if !ent1.LastLicenseExpiresAt.Equal(*ent2.LastLicenseExpiresAt) {
		t.Errorf("expiry changed on retry: %v -> %v", ent1.LastLicenseExpiresAt, ent2.LastLicenseExpiresAt)
	}
	if ent2.LastDeliveryStatus != testDeliveryStatusSent {
		t.Errorf("delivery status = %q, want sent after retry", ent2.LastDeliveryStatus)
	}
}

func TestHandleOrderPaid_SecondActiveEvalSameEmailDenied(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()

	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_1"); err != nil {
		t.Fatalf("first eval: %v", err)
	}

	// A different order, same email, while the first is still active.
	const order2 = "order_eval_2"
	body := strings.ReplaceAll(defaultEvalOrderJSON(orderStatusPaid), testEvalOrderID, order2)
	s.orderJSON.Store(&body)
	ev2 := &PolarWebhookEvent{Type: EventOrderPaid, Data: json.RawMessage(fmt.Sprintf(`{"id":%q}`, order2))}
	if err := s.handler.HandleOrderPaidEvent(ctx, ev2, "msg_2"); err != nil {
		t.Fatalf("second eval: %v", err)
	}
	ent2, _ := s.db.GetBySubscriptionID(ctx, order2)
	if ent2 != nil {
		t.Errorf("second active eval for same email should be denied, got %+v", ent2)
	}
}

// TestHandleOrderPaid_MintedTokenVerifies proves the minted token verifies with
// the service public key and carries the fleet feature + eval tier.
func TestHandleOrderPaid_MintedTokenVerifies(t *testing.T) {
	s := newEvalTestSetup(t)
	ctx := t.Context()
	if err := s.handler.HandleOrderPaidEvent(ctx, evalPaidEvent(), "msg_1"); err != nil {
		t.Fatalf("mint: %v", err)
	}
	// Regenerate the deterministic token from persisted claims and verify it.
	ent, _ := s.db.GetBySubscriptionID(ctx, testEvalOrderID)
	tok := s.handler.regenerateEvalToken(ent)
	lic, err := license.Verify(tok, s.publicKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if lic.Tier != tierEnterpriseEval || !lic.HasFeature(license.FeatureFleet) {
		t.Errorf("license = %+v, want eval tier + fleet feature", lic)
	}
}
