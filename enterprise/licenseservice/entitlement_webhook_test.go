//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"errors"
	"testing"
)

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
