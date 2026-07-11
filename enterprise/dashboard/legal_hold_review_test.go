//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLegalHoldStore_ReleaseErrorPaths(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)

	newStore := func(t *testing.T) *LegalHoldStore {
		t.Helper()
		store, err := OpenLegalHoldStore(filepath.Join(t.TempDir(), "holds.json"))
		if err != nil {
			t.Fatalf("OpenLegalHoldStore: %v", err)
		}
		return store
	}

	t.Run("already released", func(t *testing.T) {
		store := newStore(t)
		if err := store.Add(LegalHold{ID: "hold-a", Scope: "agent-a", Reason: "review", Created: created}); err != nil {
			t.Fatalf("Add: %v", err)
		}
		if err := store.Release("hold-a", created.Add(time.Hour)); err != nil {
			t.Fatalf("Release: %v", err)
		}
		err := store.Release("hold-a", created.Add(2*time.Hour))
		if err == nil || !strings.Contains(err.Error(), "already released") {
			t.Fatalf("second release = %v, want already-released error", err)
		}
	})

	t.Run("released before created", func(t *testing.T) {
		store := newStore(t)
		if err := store.Add(LegalHold{ID: "hold-b", Scope: "agent-b", Reason: "review", Created: created}); err != nil {
			t.Fatalf("Add: %v", err)
		}
		err := store.Release("hold-b", created.Add(-time.Hour))
		if err == nil || !strings.Contains(err.Error(), "must not precede created") {
			t.Fatalf("release-before-created = %v, want precedence error", err)
		}
	})

	t.Run("missing hold", func(t *testing.T) {
		store := newStore(t)
		err := store.Release("nope", created)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("release of missing hold = %v, want not-found error", err)
		}
	})
}
