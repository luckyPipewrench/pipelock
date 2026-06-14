//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestNextCRLGenerationMonotonic verifies the issuer counter strictly increases.
func TestNextCRLGenerationMonotonic(t *testing.T) {
	db := openTestDB(t)
	var prev uint64
	for i := 0; i < 5; i++ {
		gen, err := db.NextCRLGeneration(t.Context())
		if err != nil {
			t.Fatalf("NextCRLGeneration: %v", err)
		}
		if gen <= prev && i > 0 {
			t.Fatalf("generation %d not strictly greater than prior %d", gen, prev)
		}
		if i == 0 && gen != 1 {
			t.Fatalf("first generation = %d, want 1", gen)
		}
		prev = gen
	}
	if prev != 5 {
		t.Fatalf("final generation = %d, want 5", prev)
	}
}

// TestNextCRLGenerationSurvivesReopen proves the issuer counter is durable: a
// service restart (DB reopen) must not rewind the counter and re-issue a lower
// generation. Uses a file-backed DB so the reopen reads persisted state.
func TestNextCRLGenerationSurvivesReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "entitlements.db")

	db1, err := OpenEntitlementDB(t.Context(), dbPath)
	if err != nil {
		t.Fatalf("open db1: %v", err)
	}
	var last uint64
	for i := 0; i < 3; i++ {
		if last, err = db1.NextCRLGeneration(t.Context()); err != nil {
			t.Fatalf("NextCRLGeneration: %v", err)
		}
	}
	if last != 3 {
		t.Fatalf("pre-reopen generation = %d, want 3", last)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("close db1: %v", err)
	}

	// Reopen the SAME file: the counter must continue from where it left off,
	// not reset to 0.
	db2, err := OpenEntitlementDB(t.Context(), dbPath)
	if err != nil {
		t.Fatalf("open db2: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })

	next, err := db2.NextCRLGeneration(t.Context())
	if err != nil {
		t.Fatalf("NextCRLGeneration after reopen: %v", err)
	}
	if next != 4 {
		t.Fatalf("post-reopen generation = %d, want 4 (counter rewound on restart)", next)
	}
}

// TestNextCRLGenerationDBError verifies the issuer counter fails closed when the
// backing store is unusable: a closed DB must surface an error rather than
// silently return a generation that was never persisted.
func TestNextCRLGenerationDBError(t *testing.T) {
	db, err := OpenEntitlementDB(t.Context(), ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	if _, err := db.NextCRLGeneration(t.Context()); err == nil {
		t.Fatal("NextCRLGeneration on a closed DB must error, got nil")
	}
}

func TestNextCRLGenerationSQLErrors(t *testing.T) {
	t.Run("seed failure fails closed", func(t *testing.T) {
		db := openTestDB(t)
		if _, err := db.db.ExecContext(t.Context(), `DROP TABLE crl_generation`); err != nil {
			t.Fatalf("drop crl_generation: %v", err)
		}
		_, err := db.NextCRLGeneration(t.Context())
		if err == nil || !strings.Contains(err.Error(), "seed crl generation") {
			t.Fatalf("NextCRLGeneration err = %v, want seed crl generation", err)
		}
	})

	t.Run("advance failure fails closed", func(t *testing.T) {
		db := openTestDB(t)
		_, err := db.db.ExecContext(t.Context(), `
			CREATE TRIGGER crl_generation_block_update
			BEFORE UPDATE ON crl_generation
			BEGIN
				SELECT RAISE(ABORT, 'blocked crl generation update');
			END`)
		if err != nil {
			t.Fatalf("create update trigger: %v", err)
		}
		_, err = db.NextCRLGeneration(t.Context())
		if err == nil || !strings.Contains(err.Error(), "advance crl generation") {
			t.Fatalf("NextCRLGeneration err = %v, want advance crl generation", err)
		}
	})

	t.Run("read failure fails closed", func(t *testing.T) {
		db := openTestDB(t)
		_, err := db.db.ExecContext(t.Context(), `
			CREATE TRIGGER crl_generation_delete_after_update
			AFTER UPDATE ON crl_generation
			BEGIN
				DELETE FROM crl_generation WHERE id = NEW.id;
			END`)
		if err != nil {
			t.Fatalf("create delete trigger: %v", err)
		}
		_, err = db.NextCRLGeneration(t.Context())
		if err == nil || !strings.Contains(err.Error(), "read crl generation") {
			t.Fatalf("NextCRLGeneration err = %v, want read crl generation", err)
		}
	})
}
