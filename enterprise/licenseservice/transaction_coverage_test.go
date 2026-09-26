//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEndWithWebhookFailurePaths(t *testing.T) {
	now := time.Now().UTC()
	for _, tt := range []struct {
		name  string
		setup func(*testing.T, *EntitlementDB)
		msgID string
		want  string
	}{
		{"admission storage failure", func(t *testing.T, db *EntitlementDB) { createFaultTrigger(t, db, "fail_trial_commit") }, "msg_fail", "admit terminal webhook"},
		{"duplicate delivery", func(t *testing.T, db *EntitlementDB) {
			if err := db.UpsertWithWebhook(t.Context(), testEntitlement(testSubscriptionID), "msg_duplicate", EventSubscriptionUpdated); err != nil {
				t.Fatal(err)
			}
		}, "msg_duplicate", ""},
		{"issuance lookup failure", func(t *testing.T, db *EntitlementDB) {
			renameTable(t, db, "license_issuances", "license_issuances_fault")
		}, "msg_lookup", "list license issuances"},
		{"entitlement storage failure", func(t *testing.T, db *EntitlementDB) {
			if _, err := db.db.ExecContext(t.Context(), `CREATE TRIGGER fail_terminal_entitlement BEFORE INSERT ON entitlements BEGIN SELECT RAISE(ABORT, 'forced storage failure'); END`); err != nil {
				t.Fatal(err)
			}
		}, "msg_entitlement", "persist ended entitlement"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db := openTestDB(t)
			tt.setup(t, db)
			ended := testEntitlement(testSubscriptionID)
			ended.Status = statusCanceled
			_, err := db.endWithWebhook(t.Context(), ended, tt.msgID, EventSubscriptionCanceled, "lic_last", now)
			if tt.want == "" {
				if !errors.Is(err, ErrWebhookAlreadyCommitted) {
					t.Fatalf("error = %v, want duplicate", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
			if tt.name != "duplicate delivery" {
				assertWebhookUncommitted(t, db, tt.msgID)
			} else {
				// A rejected duplicate must leave the committed state untouched.
				got, err := db.GetBySubscriptionID(t.Context(), testSubscriptionID)
				if err != nil || got == nil || got.Status != statusActive {
					t.Fatalf("entitlement after duplicate = %+v, %v; want still active", got, err)
				}
				var revoked int
				if err := db.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM license_revocations WHERE license_id = ?`, "lic_last").Scan(&revoked); err != nil {
					t.Fatal(err)
				}
				if revoked != 0 {
					t.Fatalf("duplicate delivery recorded %d lic_last revocations, want 0", revoked)
				}
			}
		})
	}
	t.Run("nil entitlement", func(t *testing.T) {
		db := openTestDB(t)
		if _, err := db.endWithWebhook(t.Context(), nil, "msg_nil", EventSubscriptionCanceled, "", now); err == nil {
			t.Fatal("nil entitlement accepted")
		}
	})
	t.Run("closed database", func(t *testing.T) {
		db := openTestDB(t)
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := db.endWithWebhook(t.Context(), testEntitlement(testSubscriptionID), "msg_closed", EventSubscriptionCanceled, "", now); err == nil {
			t.Fatal("closed database accepted")
		}
	})
}

func TestFulfillEvalMintActiveLookupFailure(t *testing.T) {
	db := openTestDB(t)
	renameTable(t, db, "entitlements", "entitlements_fault")
	err := db.FulfillEvalMint(t.Context(), mintParams("order_lookup_failure", "buyer@example.com"))
	if err == nil || !strings.Contains(err.Error(), "check active eval at mint") {
		t.Fatalf("error = %v, want active eval lookup failure", err)
	}
	assertWebhookUncommitted(t, db, "msg_order_lookup_failure")
}

func TestHandleOrderPaidEvalMintStoreFailure(t *testing.T) {
	s := newEvalTestSetup(t)
	if _, err := s.db.db.ExecContext(t.Context(), `CREATE TRIGGER fail_eval_entitlement BEFORE INSERT ON entitlements BEGIN SELECT RAISE(ABORT, 'forced storage failure'); END`); err != nil {
		t.Fatal(err)
	}
	err := s.handler.HandleOrderPaidEvent(t.Context(), evalPaidEvent(), "msg_eval_store_failure")
	if err == nil || !strings.Contains(err.Error(), "fulfill eval mint") {
		t.Fatalf("error = %v, want mint storage failure", err)
	}
	assertWebhookUncommitted(t, s.db, "msg_eval_store_failure")
}

// The active-eval check reads the order's normalized email, so a caller that
// passes a different entitlement email must be refused before any write.
func TestFulfillEvalMintRejectsMismatchedEmails(t *testing.T) {
	db := openTestDB(t)
	ent := testEntitlement(testSubscriptionID)
	ent.CustomerEmail = "first@vendor.example"
	err := db.FulfillEvalMint(t.Context(), EvalMintParams{
		Entitlement:  ent,
		EvalOrder:    &EvalOrder{OrderID: "ord_mismatch", NormalizedEmail: "second@vendor.example"},
		WebhookMsgID: "msg_mismatch",
		EventType:    "order.paid",
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want email mismatch refusal", err)
	}
	if got, err := db.GetBySubscriptionID(t.Context(), testSubscriptionID); err != nil || got != nil {
		t.Fatalf("entitlement written despite refusal: %+v, %v", got, err)
	}
}
