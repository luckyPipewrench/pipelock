//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestExemptionStore_AddListRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(90 * 24 * time.Hour)

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}
	rec := ExemptionRecord{
		ID:        "exm_test001",
		Scope:     "api.vendor.example",
		Owner:     "ops-team",
		Reason:    "provider-bound credential",
		CreatedBy: "operator-a",
		Created:   now,
		Expiry:    expiry,
	}
	if err := store.Add(rec, now); err != nil {
		t.Fatalf("Add: %v", err)
	}

	records := store.List()
	if len(records) != 1 {
		t.Fatalf("List() = %d records, want 1", len(records))
	}
	got := records[0]
	if got.ID != rec.ID || got.Scope != rec.Scope || got.Owner != rec.Owner {
		t.Fatalf("round-trip mismatch: got=%+v, want=%+v", got, rec)
	}
}

func TestExemptionStore_AtomicWriteAndReopen(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	expiry := now.Add(30 * 24 * time.Hour)

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}
	rec := ExemptionRecord{
		ID:      "exm_persist",
		Scope:   "internal.vendor.example",
		Owner:   "sec-team",
		Reason:  "reviewed exemption",
		Created: now,
		Expiry:  expiry,
	}
	if err := store.Add(rec, now); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Reopen the store from disk and verify the record persisted.
	store2, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore (reopen): %v", err)
	}
	records := store2.List()
	if len(records) != 1 {
		t.Fatalf("reopen List() = %d records, want 1", len(records))
	}
	if records[0].ID != "exm_persist" {
		t.Fatalf("reopen record ID = %q, want %q", records[0].ID, "exm_persist")
	}
}

func TestExemptionStore_MissingFileIsEmpty(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "nonexistent.json")

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}
	if records := store.List(); len(records) != 0 {
		t.Fatalf("List() = %d records, want 0", len(records))
	}
}

func TestExemptionStore_CorruptedJSONReturnsError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	if err := os.WriteFile(storePath, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := OpenExemptionStore(storePath); err == nil {
		t.Fatal("OpenExemptionStore should fail on corrupted JSON")
	} else if !strings.Contains(err.Error(), "parse") {
		t.Fatalf("OpenExemptionStore error = %q, want containing %q", err.Error(), "parse")
	}
}

func TestOpenExemptionStoreRejectsAmbiguousOrInvalidDirectLoad(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	base := `{"id":"exm-a","scope":"api.vendor.example","owner":"ops-team","reason":"reviewed exemption","created":"` + now.Format(time.RFC3339) + `","expiry":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}`
	tests := []struct {
		name string
		data string
	}{
		{name: "duplicate json key", data: `[` + strings.Replace(base, `"id":"exm-a"`, `"id":"exm-a","id":"exm-b"`, 1) + `]`},
		{name: "unknown field", data: `[` + strings.Replace(base, `"scope":`, `"future":true,"scope":`, 1) + `]`},
		{name: "invalid record", data: `[` + strings.Replace(base, `"owner":"ops-team"`, `"owner":""`, 1) + `]`},
		{name: "duplicate id", data: `[` + base + `,` + base + `]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "exemptions.json")
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenExemptionStore(path); err == nil {
				t.Fatal("OpenExemptionStore accepted invalid direct-load JSON")
			}
		})
	}
}

func TestOpenExemptionStoreRejectsOversizedDirectLoad(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "exemptions.json")
	file, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- test file under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxExemptionStoreFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExemptionStore(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("OpenExemptionStore oversized error = %v", err)
	}
}

func TestOpenExemptionStoreRejectsSymlinkDirectLoad(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "exemptions.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExemptionStore(link); err == nil {
		t.Fatal("OpenExemptionStore accepted a symlink")
	}
}

func TestExemptionStore_ValidationRejects(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(30 * 24 * time.Hour)

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}

	tests := []struct {
		name string
		rec  ExemptionRecord
		want string
	}{
		{
			name: "empty owner",
			rec:  ExemptionRecord{ID: "exm_1", Scope: "a", Owner: "", Reason: "r", Created: now, Expiry: expiry},
			want: "owner is required",
		},
		{
			name: "empty reason",
			rec:  ExemptionRecord{ID: "exm_2", Scope: "a", Owner: "o", Reason: "", Created: now, Expiry: expiry},
			want: "reason is required",
		},
		{
			name: "empty scope",
			rec:  ExemptionRecord{ID: "exm_3", Scope: "", Owner: "o", Reason: "r", Created: now, Expiry: expiry},
			want: "scope is required",
		},
		{
			name: "expiry not after created",
			rec:  ExemptionRecord{ID: "exm_4", Scope: "a", Owner: "o", Reason: "r", Created: now, Expiry: now},
			want: "expiry must be after created",
		},
		{
			name: "expiry before created",
			rec:  ExemptionRecord{ID: "exm_5", Scope: "a", Owner: "o", Reason: "r", Created: now, Expiry: now.Add(-time.Hour)},
			want: "expiry must be after created",
		},
		{
			name: "empty id",
			rec:  ExemptionRecord{ID: "", Scope: "a", Owner: "o", Reason: "r", Created: now, Expiry: expiry},
			want: "id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Add(tt.rec, now)
			if err == nil {
				t.Fatal("Add should have failed")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Add error = %q, want containing %q", err.Error(), tt.want)
			}
		})
	}
}

func TestExemptionStore_DuplicateIDRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(30 * 24 * time.Hour)

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}

	rec := ExemptionRecord{ID: "exm_dup", Scope: "a.example", Owner: "o", Reason: "r", Created: now, Expiry: expiry}
	if err := store.Add(rec, now); err != nil {
		t.Fatalf("Add first: %v", err)
	}
	rec2 := ExemptionRecord{ID: "exm_dup", Scope: "b.example", Owner: "o", Reason: "r", Created: now, Expiry: expiry}
	if err := store.Add(rec2, now); err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("Add duplicate ID: got %v, want duplicate id error", err)
	}
}

func TestExemptionStore_DuplicateActiveScopeRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(30 * 24 * time.Hour)

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}

	rec := ExemptionRecord{ID: "exm_s1", Scope: "same.example", Owner: "o", Reason: "r", Created: now, Expiry: expiry}
	if err := store.Add(rec, now); err != nil {
		t.Fatalf("Add first: %v", err)
	}
	rec2 := ExemptionRecord{ID: "exm_s2", Scope: "same.example", Owner: "o2", Reason: "r2", Created: now, Expiry: expiry}
	if err := store.Add(rec2, now); err == nil || !strings.Contains(err.Error(), "active record already exists") {
		t.Fatalf("Add duplicate scope: got %v, want active record error", err)
	}
}

func TestExemptionStore_DuplicateActiveScopeRejectedAcrossHandles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(30 * 24 * time.Hour)

	store1, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore store1: %v", err)
	}
	store2, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore store2: %v", err)
	}

	rec1 := ExemptionRecord{ID: "exm_s1", Scope: "same.example", Owner: "o", Reason: "r", Created: now, Expiry: expiry}
	if err := store1.Add(rec1, now); err != nil {
		t.Fatalf("Add first: %v", err)
	}
	rec2 := ExemptionRecord{ID: "exm_s2", Scope: "same.example", Owner: "o2", Reason: "r2", Created: now, Expiry: expiry}
	if err := store2.Add(rec2, now); err == nil || !strings.Contains(err.Error(), "active record already exists") {
		t.Fatalf("Add duplicate scope from stale handle: got %v, want active record error", err)
	}
}

func TestExemptionStore_StaleHandleDoesNotOverwriteCurrentFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(30 * 24 * time.Hour)

	store1, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore store1: %v", err)
	}
	store2, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore store2: %v", err)
	}

	rec1 := ExemptionRecord{ID: "exm_a", Scope: "a.example", Owner: "o", Reason: "r", Created: now, Expiry: expiry}
	if err := store1.Add(rec1, now); err != nil {
		t.Fatalf("Add first: %v", err)
	}
	rec2 := ExemptionRecord{ID: "exm_b", Scope: "b.example", Owner: "o2", Reason: "r2", Created: now, Expiry: expiry}
	if err := store2.Add(rec2, now); err != nil {
		t.Fatalf("Add from stale handle: %v", err)
	}

	reopened, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore reopen: %v", err)
	}
	records := reopened.List()
	if len(records) != 2 {
		t.Fatalf("records after stale-handle writes = %d, want 2: %+v", len(records), records)
	}
}

func TestExemptionStore_DuplicateScopeAllowedWhenExpired(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(-time.Hour) // already expired

	// First record: created in the past, already expired at "now".
	rec := ExemptionRecord{
		ID:      "exm_old",
		Scope:   "same.example",
		Owner:   "o",
		Reason:  "r",
		Created: now.Add(-48 * time.Hour),
		Expiry:  expiry,
	}
	// Write directly to avoid validation issues with expiry <= created.
	data, _ := json.MarshalIndent([]ExemptionRecord{rec}, "", "  ")
	if err := os.WriteFile(storePath, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}

	newExpiry := now.Add(90 * 24 * time.Hour)
	rec2 := ExemptionRecord{ID: "exm_new", Scope: "same.example", Owner: "o2", Reason: "renewal", Created: now, Expiry: newExpiry}
	if err := store.Add(rec2, now); err != nil {
		t.Fatalf("Add after expired: %v", err)
	}
}

func TestExemptionStore_ExpireRenewTouchRemove(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(90 * 24 * time.Hour)

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}

	rec := ExemptionRecord{ID: "exm_lifecycle", Scope: "lc.example", Owner: "owner", Reason: "test", Created: now, Expiry: expiry}
	if err := store.Add(rec, now); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Touch
	touchTime := now.Add(5 * 24 * time.Hour)
	if err := store.Touch("exm_lifecycle", touchTime); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	records := store.List()
	if records[0].LastMatched == nil || !records[0].LastMatched.Equal(touchTime) {
		t.Fatalf("Touch: LastMatched = %v, want %v", records[0].LastMatched, touchTime)
	}

	// Renew
	newExpiry := now.Add(180 * 24 * time.Hour)
	if err := store.Renew("exm_lifecycle", newExpiry); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	records = store.List()
	if !records[0].Expiry.Equal(newExpiry) {
		t.Fatalf("Renew: Expiry = %v, want %v", records[0].Expiry, newExpiry)
	}

	// Expire
	expireTime := now.Add(10 * 24 * time.Hour)
	if err := store.Expire("exm_lifecycle", expireTime); err != nil {
		t.Fatalf("Expire: %v", err)
	}
	records = store.List()
	if !records[0].Expiry.Equal(expireTime) {
		t.Fatalf("Expire: Expiry = %v, want %v", records[0].Expiry, expireTime)
	}

	// Remove
	if err := store.Remove("exm_lifecycle"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	records = store.List()
	if len(records) != 0 {
		t.Fatalf("Remove: List() = %d records, want 0", len(records))
	}
}

func TestExemptionStore_MutateNotFoundErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		fn   func() error
	}{
		{"Expire", func() error { return store.Expire("nonexistent", now) }},
		{"Renew", func() error { return store.Renew("nonexistent", now.Add(time.Hour)) }},
		{"Touch", func() error { return store.Touch("nonexistent", now) }},
		{"Remove", func() error { return store.Remove("nonexistent") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil || !strings.Contains(err.Error(), "not found") {
				t.Fatalf("%s: got %v, want not found error", tc.name, err)
			}
		})
	}
}

func TestExemptionRecord_Status(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	recentMatch := now.Add(-7 * 24 * time.Hour) // 7 days ago
	staleMatch := now.Add(-60 * 24 * time.Hour) // 60 days ago

	tests := []struct {
		name string
		rec  ExemptionRecord
		want string
	}{
		{
			name: "active with recent match",
			rec: ExemptionRecord{
				Created:     now.Add(-30 * 24 * time.Hour),
				Expiry:      now.Add(60 * 24 * time.Hour),
				LastMatched: &recentMatch,
			},
			want: lifecycleActive,
		},
		{
			name: "expired",
			rec: ExemptionRecord{
				Created: now.Add(-90 * 24 * time.Hour),
				Expiry:  now.Add(-1 * time.Hour),
			},
			want: lifecycleExpired,
		},
		{
			name: "expired at exact now",
			rec: ExemptionRecord{
				Created: now.Add(-90 * 24 * time.Hour),
				Expiry:  now,
			},
			want: lifecycleExpired,
		},
		{
			name: "stale - old last match",
			rec: ExemptionRecord{
				Created:     now.Add(-90 * 24 * time.Hour),
				Expiry:      now.Add(60 * 24 * time.Hour),
				LastMatched: &staleMatch,
			},
			want: lifecycleStale,
		},
		{
			name: "not observed - nil last match",
			rec: ExemptionRecord{
				Created:     now.Add(-30 * 24 * time.Hour),
				Expiry:      now.Add(60 * 24 * time.Hour),
				LastMatched: nil,
			},
			want: lifecycleUnobserved,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rec.Status(now)
			if got != tt.want {
				t.Fatalf("Status() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExemptionStore_FindByScope(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(90 * 24 * time.Hour)

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}

	rec := ExemptionRecord{
		ID:      "exm_find",
		Scope:   "find-me.example",
		Owner:   "ops",
		Reason:  "test find",
		Created: now,
		Expiry:  expiry,
	}
	if err := store.Add(rec, now); err != nil {
		t.Fatalf("Add: %v", err)
	}

	found, ok := store.Find("find-me.example", now)
	if !ok {
		t.Fatal("Find: not found")
	}
	if found.ID != "exm_find" {
		t.Fatalf("Find: ID = %q, want %q", found.ID, "exm_find")
	}

	_, ok = store.Find("not-there.example", now)
	if ok {
		t.Fatal("Find: should not find nonexistent scope")
	}
}

func TestExemptionStore_FindPrefersActiveRenewal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}

	expired := ExemptionRecord{
		ID:      "exm_old",
		Scope:   "renewed.example",
		Owner:   "old-owner",
		Reason:  "old reason",
		Created: now.Add(-60 * 24 * time.Hour),
		Expiry:  now.Add(-24 * time.Hour),
	}
	if err := store.Add(expired, now); err != nil {
		t.Fatalf("Add expired: %v", err)
	}
	renewed := ExemptionRecord{
		ID:      "exm_new",
		Scope:   "renewed.example",
		Owner:   "new-owner",
		Reason:  "renewed reason",
		Created: now.Add(-time.Hour),
		Expiry:  now.Add(30 * 24 * time.Hour),
	}
	if err := store.Add(renewed, now); err != nil {
		t.Fatalf("Add renewed: %v", err)
	}

	found, ok := store.Find("renewed.example", now)
	if !ok {
		t.Fatal("Find: not found")
	}
	if found.ID != renewed.ID {
		t.Fatalf("Find ID = %q, want active renewal %q", found.ID, renewed.ID)
	}
}

func TestExemptionStore_ListDeterministicSort(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(90 * 24 * time.Hour)

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}

	// Add in reverse order.
	for _, id := range []string{"exm_c", "exm_a", "exm_b"} {
		rec := ExemptionRecord{
			ID:      id,
			Scope:   id + ".example",
			Owner:   "o",
			Reason:  "r",
			Created: now,
			Expiry:  expiry,
		}
		if err := store.Add(rec, now); err != nil {
			t.Fatalf("Add %s: %v", id, err)
		}
	}

	records := store.List()
	if len(records) != 3 {
		t.Fatalf("List() = %d, want 3", len(records))
	}
	if records[0].ID != "exm_a" || records[1].ID != "exm_b" || records[2].ID != "exm_c" {
		t.Fatalf("List() not sorted: %v", []string{records[0].ID, records[1].ID, records[2].ID})
	}
}

func TestExemptionStore_RenewValidatesExpiry(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(30 * 24 * time.Hour)

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}
	rec := ExemptionRecord{ID: "exm_renew", Scope: "r.example", Owner: "o", Reason: "r", Created: now, Expiry: expiry}
	if err := store.Add(rec, now); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Renew to before Created should fail.
	badExpiry := now.Add(-time.Hour)
	if err := store.Renew("exm_renew", badExpiry); err == nil || !strings.Contains(err.Error(), "must be after created") {
		t.Fatalf("Renew with bad expiry: got %v, want must be after created", err)
	}
}

func TestExemptions_OverlayJoinsStoreRecords(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(90 * 24 * time.Hour)
	matched := now.Add(-5 * 24 * time.Hour)

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}

	rec := ExemptionRecord{
		ID:          "exm_overlay",
		Scope:       "internal.vendor.example",
		Owner:       "ops-team",
		Reason:      "vendor integration",
		Created:     now.Add(-30 * 24 * time.Hour),
		Expiry:      expiry,
		LastMatched: &matched,
	}
	if err := store.Add(rec, now); err != nil {
		t.Fatalf("Add: %v", err)
	}

	cfg := &config.Config{
		TrustedDomains: []string{"internal.vendor.example"},
	}

	inventory := NewReadModel(Options{Config: cfg, ExemptionStore: store}).Exemptions()
	if !inventory.ConfigLoaded {
		t.Fatal("ConfigLoaded = false, want true")
	}

	// Find the overlaid entry.
	var found *ExemptionEntry
	for i, e := range inventory.Entries {
		if e.Scope == "internal.vendor.example" {
			found = &inventory.Entries[i]
			break
		}
	}
	if found == nil {
		t.Fatal("missing entry for internal.vendor.example")
	}
	if found.Owner != "ops-team" {
		t.Fatalf("Owner = %q, want %q", found.Owner, "ops-team")
	}
	if found.Reason != "vendor integration" {
		t.Fatalf("Reason = %q, want %q", found.Reason, "vendor integration")
	}
	if found.Lifecycle != lifecycleActive {
		t.Fatalf("Lifecycle = %q, want %q", found.Lifecycle, lifecycleActive)
	}
}

func TestExemptions_OverlayUsesInjectedClock(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(24 * time.Hour)
	matched := now.Add(-time.Hour)

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}
	rec := ExemptionRecord{
		ID:          "exm_clock",
		Scope:       "clock.vendor.example",
		Owner:       "ops-team",
		Reason:      "bounded test clock",
		Created:     now.Add(-time.Hour),
		Expiry:      expiry,
		LastMatched: &matched,
	}
	if err := store.Add(rec, now); err != nil {
		t.Fatalf("Add: %v", err)
	}
	cfg := &config.Config{TrustedDomains: []string{"clock.vendor.example"}}

	inventory := NewReadModel(Options{
		Config:         cfg,
		ExemptionStore: store,
		Now:            func() time.Time { return now },
	}).Exemptions()
	var found *ExemptionEntry
	for i := range inventory.Entries {
		if inventory.Entries[i].Scope == "clock.vendor.example" {
			found = &inventory.Entries[i]
			break
		}
	}
	if found == nil {
		t.Fatal("missing clock.vendor.example entry")
	}
	if found.Lifecycle != lifecycleActive {
		t.Fatalf("Lifecycle = %q, want %q with injected now %s", found.Lifecycle, lifecycleActive, now.Format(time.RFC3339))
	}
}

func TestExemptions_OverlayNotTrackedWithoutRecord(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}

	cfg := &config.Config{
		TrustedDomains: []string{"unmatched.vendor.example"},
	}

	inventory := NewReadModel(Options{Config: cfg, ExemptionStore: store}).Exemptions()

	var found *ExemptionEntry
	for i, e := range inventory.Entries {
		if e.Scope == "unmatched.vendor.example" {
			found = &inventory.Entries[i]
			break
		}
	}
	if found == nil {
		t.Fatal("missing entry for unmatched.vendor.example")
	}
	if found.Owner != notTracked {
		t.Fatalf("Owner = %q, want %q", found.Owner, notTracked)
	}
	if found.Lifecycle != notTracked {
		t.Fatalf("Lifecycle = %q, want %q", found.Lifecycle, notTracked)
	}
}

func TestExemptions_OverlayMetadataRedactsOwnerReason(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(90 * 24 * time.Hour)

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}

	rec := ExemptionRecord{
		ID:      "exm_redact",
		Scope:   "internal.vendor.example",
		Owner:   "secret-internal-team",
		Reason:  "confidential-integration-reason",
		Created: now.Add(-30 * 24 * time.Hour),
		Expiry:  expiry,
	}
	if err := store.Add(rec, now); err != nil {
		t.Fatalf("Add: %v", err)
	}

	cfg := &config.Config{
		TrustedDomains: []string{"internal.vendor.example"},
	}

	// Metadata (non-raw) view: owner and reason must be redacted.
	metaBody := serveExemptionsBodyWithStore(t, cfg, store, false)
	if strings.Contains(metaBody, "secret-internal-team") {
		t.Fatal("metadata view leaked owner value")
	}
	if strings.Contains(metaBody, "confidential-integration-reason") {
		t.Fatal("metadata view leaked reason value")
	}

	// Raw view: owner and reason must be visible.
	rawBody := serveExemptionsBodyWithStore(t, cfg, store, true)
	if !strings.Contains(rawBody, "secret-internal-team") {
		t.Fatal("raw view missing owner value")
	}
	if !strings.Contains(rawBody, "confidential-integration-reason") {
		t.Fatal("raw view missing reason value")
	}
}

func serveExemptionsBodyWithStore(t *testing.T, cfg *config.Config, store *ExemptionStore, raw bool) string {
	t.Helper()
	opts := Options{
		ReceiptDir:     t.TempDir(),
		Config:         cfg,
		HasFeature:     allowAgentsFeature,
		Authorize:      func(*http.Request) error { return nil },
		ExemptionStore: store,
	}
	if raw {
		opts.AuthorizeRaw = allowRawAccess
	}
	handler := New(opts)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/exemptions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	return rec.Body.String()
}

func TestExemptions_PristineDefaultsStillZeroAttentionWithStore(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}

	cfg := config.Defaults()
	cfg.ApplyDefaults()
	inventory := NewReadModel(Options{Config: cfg, ExemptionStore: store}).Exemptions()
	if !inventory.ConfigLoaded {
		t.Fatal("ConfigLoaded = false, want true")
	}
	if inventory.InertCount != 0 || inventory.MisdirectedCount != 0 {
		t.Fatalf("pristine default attention counts: inert=%d misdirected=%d, want 0/0",
			inventory.InertCount, inventory.MisdirectedCount)
	}
}

func TestExemptions_FilePermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "exemptions.json")
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(30 * 24 * time.Hour)

	store, err := OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}
	rec := ExemptionRecord{ID: "exm_perms", Scope: "p.example", Owner: "o", Reason: "r", Created: now, Expiry: expiry}
	if err := store.Add(rec, now); err != nil {
		t.Fatalf("Add: %v", err)
	}

	info, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// The atomicfile.Write creates with 0o600; the exact mode depends on
	// umask, but the owner-only bits should be set.
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		t.Fatalf("file permissions = %04o, want no group/other access", mode)
	}
}
