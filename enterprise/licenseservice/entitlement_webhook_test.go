//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"errors"
	"testing"
	"time"
)

func TestTerminalWebhookRevocationFailureLeavesDeliveryRetryable(t *testing.T) {
	ts := newTestSetup(t)
	existing := testEntitlement(testSubscriptionID)
	existing.LastLicenseID = "lic_terminal_test"
	expires := time.Now().Add(time.Hour)
	existing.LastLicenseExpiresAt = &expires
	if err := ts.db.Upsert(t.Context(), existing); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.db.db.ExecContext(t.Context(), "CREATE TRIGGER fail_terminal_revocation BEFORE INSERT ON license_revocations BEGIN SELECT RAISE(ABORT, 'forced storage failure'); END"); err != nil {
		t.Fatal(err)
	}
	ended := *existing
	ended.Status = statusCanceled
	const msgID = "msg_terminal_revocation_failure"
	if err := ts.handler.handleEnded(t.Context(), &ended, existing, EventSubscriptionCanceled, msgID); err == nil {
		t.Fatal("terminal webhook accepted failed revocation")
	}
	committed, err := ts.db.WebhookCommitted(t.Context(), msgID)
	if err != nil {
		t.Fatal(err)
	}
	if committed {
		t.Fatal("delivery committed before revocation")
	}
	got, err := ts.db.GetBySubscriptionID(t.Context(), testSubscriptionID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != statusActive {
		t.Fatalf("status = %q after failed revocation, want active", got.Status)
	}
}

// UpsertWithWebhook is the atomic path for subscription events that change
// entitlement state without minting a token. The entitlement row and the
// webhook commit marker must land in one transaction, or a crash between them
// leaves a processed webhook that a replay would process again.
func TestEntitlementDB_UpsertWithWebhook(t *testing.T) {
	t.Run("nil entitlement is rejected", func(t *testing.T) {
		db := openTestDB(t)
		if err := db.UpsertWithWebhook(t.Context(), nil, "msg_nil", EventSubscriptionUpdated); err == nil {
			t.Fatal("UpsertWithWebhook(nil) = nil error, want rejection")
		}
	})

	t.Run("empty msgID upserts without a marker", func(t *testing.T) {
		db := openTestDB(t)
		ctx := t.Context()
		ent := testEntitlement(testSubscriptionID)

		if err := db.UpsertWithWebhook(ctx, ent, "", EventSubscriptionUpdated); err != nil {
			t.Fatalf("UpsertWithWebhook(empty msgID): %v", err)
		}
		got, err := db.GetBySubscriptionID(ctx, testSubscriptionID)
		if err != nil {
			t.Fatalf("GetBySubscriptionID: %v", err)
		}
		if got == nil {
			t.Fatal("entitlement was not written")
		}
		// No msgID means nothing to dedupe on later.
		committed, err := db.WebhookCommitted(ctx, "")
		if err != nil {
			t.Fatalf("WebhookCommitted(empty): %v", err)
		}
		if committed {
			t.Error("WebhookCommitted(empty) = true, want false")
		}
	})

	t.Run("entitlement and marker commit together", func(t *testing.T) {
		db := openTestDB(t)
		ctx := t.Context()
		ent := testEntitlement(testSubscriptionID)
		const msgID = "msg_upsert_webhook"

		if err := db.UpsertWithWebhook(ctx, ent, msgID, EventSubscriptionUpdated); err != nil {
			t.Fatalf("UpsertWithWebhook: %v", err)
		}

		got, err := db.GetBySubscriptionID(ctx, testSubscriptionID)
		if err != nil {
			t.Fatalf("GetBySubscriptionID: %v", err)
		}
		if got == nil {
			t.Fatal("entitlement was not written")
		}
		if got.CustomerEmail != testCustomerEmail {
			t.Errorf("CustomerEmail = %q, want %q", got.CustomerEmail, testCustomerEmail)
		}
		committed, err := db.WebhookCommitted(ctx, msgID)
		if err != nil {
			t.Fatalf("WebhookCommitted: %v", err)
		}
		if !committed {
			t.Error("WebhookCommitted = false, want true: the marker must land with the entitlement")
		}
	})

	t.Run("marker failure rolls back without mutating entitlement", func(t *testing.T) {
		db := openTestDB(t)
		ctx := t.Context()
		const msgID = "msg_abort_marker"
		if _, err := db.db.ExecContext(ctx, `
			CREATE TRIGGER abort_selected_webhook
			BEFORE INSERT ON webhook_deliveries
			WHEN NEW.msg_id = 'msg_abort_marker'
			BEGIN
				SELECT RAISE(ABORT, 'forced marker failure');
			END
		`); err != nil {
			t.Fatalf("create trigger: %v", err)
		}

		if err := db.UpsertWithWebhook(ctx, testEntitlement(testSubscriptionID), msgID, EventSubscriptionUpdated); err == nil {
			t.Fatal("UpsertWithWebhook = nil error, want forced marker failure")
		}
		got, err := db.GetBySubscriptionID(ctx, testSubscriptionID)
		if err != nil {
			t.Fatalf("GetBySubscriptionID: %v", err)
		}
		if got != nil {
			t.Fatalf("entitlement persisted after marker failure: %+v", got)
		}
		committed, err := db.WebhookCommitted(ctx, msgID)
		if err != nil {
			t.Fatalf("WebhookCommitted: %v", err)
		}
		if committed {
			t.Fatal("webhook marker persisted after failed transaction")
		}
	})

	t.Run("replaying the same msgID stays committed without updating state", func(t *testing.T) {
		db := openTestDB(t)
		ctx := t.Context()
		ent := testEntitlement(testSubscriptionID)
		const msgID = "msg_upsert_webhook_replay"

		if err := db.UpsertWithWebhook(ctx, ent, msgID, EventSubscriptionUpdated); err != nil {
			t.Fatalf("UpsertWithWebhook(first): %v", err)
		}
		ent.CustomerEmail = "changed@example.com"
		if err := db.UpsertWithWebhook(ctx, ent, msgID, EventSubscriptionUpdated); !errors.Is(err, ErrWebhookAlreadyCommitted) {
			t.Fatalf("UpsertWithWebhook(replay) err = %v, want ErrWebhookAlreadyCommitted", err)
		}

		committed, err := db.WebhookCommitted(ctx, msgID)
		if err != nil {
			t.Fatalf("WebhookCommitted: %v", err)
		}
		if !committed {
			t.Error("WebhookCommitted after replay = false, want true")
		}
		got, err := db.GetBySubscriptionID(ctx, testSubscriptionID)
		if err != nil {
			t.Fatalf("GetBySubscriptionID: %v", err)
		}
		if got.CustomerEmail != testCustomerEmail {
			t.Errorf("CustomerEmail = %q, want original %q", got.CustomerEmail, testCustomerEmail)
		}
	})

	t.Run("a closed database fails closed", func(t *testing.T) {
		db := openTestDB(t)
		ctx := t.Context()
		ent := testEntitlement(testSubscriptionID)
		if err := db.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := db.UpsertWithWebhook(ctx, ent, "msg_closed", EventSubscriptionUpdated); err == nil {
			t.Fatal("UpsertWithWebhook on a closed DB = nil error, want failure")
		}
	})
}
