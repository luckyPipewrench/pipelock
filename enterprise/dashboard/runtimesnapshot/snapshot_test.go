//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtimesnapshot

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/edition"
)

func TestWriteReadRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "dashboard", "runtime-snapshot.json")
	snap := NewEnvelope(now, "producer-1", "policy-hash", []edition.AgentBudgetSnapshot{{
		Agent: "agent-alpha",
		BudgetSnapshot: edition.BudgetSnapshot{
			RequestCount:      7,
			ByteCount:         4096,
			UniqueDomainCount: 2,
			WindowStart:       now.Add(-time.Hour),
			MaxRequests:       100,
			MaxBytes:          1 << 20,
			MaxUniqueDomains:  10,
			WindowMinutes:     60,
		},
	}})

	if err := Write(path, snap); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat written snapshot: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("snapshot mode = %04o, want 0600", got)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat snapshot dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o750 {
		t.Fatalf("snapshot dir mode = %04o, want 0750", got)
	}

	got, fresh, err := Read(path, time.Minute, now.Add(5*time.Second))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Version != Version || got.ProducerID != "producer-1" || got.PolicyHash != "policy-hash" {
		t.Fatalf("unexpected envelope metadata: %+v", got)
	}
	if len(got.Budgets) != 1 {
		t.Fatalf("budget rows = %d, want 1", len(got.Budgets))
	}
	if got.Budgets[0].Agent != "agent-alpha" || got.Budgets[0].UniqueDomainCount != 2 {
		t.Fatalf("unexpected budget row: %+v", got.Budgets[0])
	}
	if fresh.Age != 5*time.Second || fresh.Stale {
		t.Fatalf("freshness = %+v, want age 5s stale=false", fresh)
	}
}

func TestReadFailClosed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()

	tests := []struct {
		name    string
		write   func(t *testing.T) string
		wantErr error
	}{
		{
			name: "missing",
			write: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(dir, "missing.json")
			},
			wantErr: ErrMissing,
		},
		{
			name: "bad_json",
			write: func(t *testing.T) string {
				t.Helper()
				return writeSnapshotBytes(t, dir, "bad.json", []byte(`{"version":`))
			},
			wantErr: ErrMalformed,
		},
		{
			name: "symlink",
			write: func(t *testing.T) string {
				t.Helper()
				target := writeTestSnapshot(t, dir, "target.json", Envelope{ProducedAt: now})
				link := filepath.Join(dir, "link.json")
				if err := os.Symlink(target, link); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				return link
			},
			wantErr: ErrMalformed,
		},
		{
			name: "loose_permissions",
			write: func(t *testing.T) string {
				t.Helper()
				path := writeTestSnapshot(t, dir, "loose.json", Envelope{ProducedAt: now})
				// Loosen the just-written 0o600 fixture to group/other-readable
				// so Read must reject it. The mode is derived at runtime from the
				// current mode (not a literal) so this stays an honest fixture
				// without a lint-suppression directive.
				info, err := os.Stat(path)
				if err != nil {
					t.Fatalf("stat fixture: %v", err)
				}
				if err := os.Chmod(path, info.Mode()|0o044); err != nil {
					t.Fatalf("chmod fixture: %v", err)
				}
				return path
			},
			wantErr: ErrMalformed,
		},
		{
			name: "unknown_top_level_field",
			write: func(t *testing.T) string {
				t.Helper()
				return writeSnapshotBytes(t, dir, "unknown-root.json", []byte(`{"version":1,"produced_at":"2026-07-10T12:00:00Z","target_url":"https://api.vendor.example/secret"}`))
			},
			wantErr: ErrMalformed,
		},
		{
			name: "unknown_budget_field",
			write: func(t *testing.T) string {
				t.Helper()
				return writeSnapshotBytes(t, dir, "unknown-budget.json", []byte(`{"version":1,"produced_at":"2026-07-10T12:00:00Z","budgets":[{"agent":"agent-alpha","request_count":1,"domains":["api.vendor.example"]}]}`))
			},
			wantErr: ErrMalformed,
		},
		{
			name: "unknown_version",
			write: func(t *testing.T) string {
				t.Helper()
				return writeSnapshotBytes(t, dir, "version.json", []byte(`{"version":2,"produced_at":"2026-07-10T12:00:00Z"}`))
			},
			wantErr: ErrUnsupportedVersion,
		},
		{
			name: "future_timestamp",
			write: func(t *testing.T) string {
				t.Helper()
				return writeTestSnapshot(t, dir, "future.json", Envelope{ProducedAt: now.Add(time.Minute)})
			},
			wantErr: ErrFutureProducedAt,
		},
		{
			name: "stale",
			write: func(t *testing.T) string {
				t.Helper()
				return writeTestSnapshot(t, dir, "stale.json", Envelope{ProducedAt: now.Add(-time.Minute)})
			},
			wantErr: ErrStale,
		},
		{
			name: "oversized",
			write: func(t *testing.T) string {
				t.Helper()
				return writeSnapshotBytes(t, dir, "big.json", make([]byte, MaxFileBytes+1))
			},
			wantErr: ErrOversized,
		},
		{
			name: "negative_budget_count",
			write: func(t *testing.T) string {
				t.Helper()
				return writeTestSnapshot(t, dir, "negative.json", Envelope{
					ProducedAt: now,
					Budgets:    []AgentBudgetRow{{Agent: "agent-alpha", RequestCount: -1}},
				})
			},
			wantErr: ErrMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := Read(tt.write(t), 30*time.Second, now)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Read error = %v, want errors.Is(%v)", err, tt.wantErr)
			}
		})
	}
}

func TestReadCapsBudgetRows(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	rows := make([]AgentBudgetRow, 0, MaxBudgetRows+1)
	for i := 0; i <= MaxBudgetRows; i++ {
		rows = append(rows, AgentBudgetRow{Agent: "agent"})
	}
	path := writeTestSnapshot(t, t.TempDir(), "many.json", Envelope{ProducedAt: now, Budgets: rows})

	snap, _, err := Read(path, time.Minute, now)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(snap.Budgets) != MaxBudgetRows {
		t.Fatalf("budget rows = %d, want cap %d", len(snap.Budgets), MaxBudgetRows)
	}
	if !snap.Truncated.Budgets {
		t.Fatal("Truncated.Budgets = false, want true")
	}
}

func writeTestSnapshot(t *testing.T, dir, name string, snap Envelope) string {
	t.Helper()
	snap.Version = Version
	path := filepath.Join(dir, name)
	if err := Write(path, snap); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return path
}

func writeSnapshotBytes(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}
