// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func wantStopTimeoutDirective() string {
	return fmt.Sprintf("TimeoutStopSec=%d", int64(cliutil.ServiceStopTimeout/time.Second))
}

// TestRenderSystemUnit_StatesStopBudget pins the fresh-install half: both unit
// shapes state the stop budget inside [Service] instead of inheriting systemd's
// 90 s default, which a receipt-group close on a small host can outlast.
func TestRenderSystemUnit_StatesStopBudget(t *testing.T) {
	for _, version := range []int{0, 252, systemdNotifyReloadMinVersion} {
		env, _, _ := newFakeEnv(t)
		env.systemdVersion = version
		body := renderSystemUnit(env)
		if !unitServiceSetsDirective(body, "TimeoutStopSec") {
			t.Fatalf("systemd %d unit sets no active stop budget:\n%s", version, body)
		}
		if !strings.Contains(body, "\n"+wantStopTimeoutDirective()+"\n") {
			t.Fatalf("systemd %d unit lacks %q:\n%s", version, wantStopTimeoutDirective(), body)
		}
	}
	if cliutil.ServiceStopTimeout <= cliutil.ServiceStartTimeout {
		t.Fatalf("stop budget %s is not longer than systemd's 90 s stock stop default", cliutil.ServiceStopTimeout)
	}
}

func TestEnsureStopTimeoutInUnitMigratesALegacyUnit(t *testing.T) {
	env, unit := unitEnv(t, legacyUnitWithoutMarker)
	if err := ensureStopTimeoutInUnit(env); err != nil {
		t.Fatalf("ensureStopTimeoutInUnit: %v", err)
	}
	updated, err := os.ReadFile(filepath.Clean(unit))
	if err != nil {
		t.Fatal(err)
	}
	body := string(updated)
	if !unitServiceSetsDirective(body, "TimeoutStopSec") || !strings.Contains(body, wantStopTimeoutDirective()) {
		t.Fatalf("stop timeout not added inside [Service]:\n%s", body)
	}
	for _, keep := range []string{"User=pipelock-proxy", "Restart=on-failure", "WantedBy=multi-user.target"} {
		if !strings.Contains(body, keep) {
			t.Errorf("existing unit setting %q was lost", keep)
		}
	}
}

// TestEnsureStopTimeoutInUnitKeepsAnOperatorChoice covers the direction an
// unconditional insert gets wrong: a second TimeoutStopSec later in [Service]
// would silently replace a budget the operator chose, and TimeoutSec= sets the
// stop timeout as well.
func TestEnsureStopTimeoutInUnitKeepsAnOperatorChoice(t *testing.T) {
	for _, line := range []string{"TimeoutStopSec=30min", "TimeoutStopSec = infinity", "TimeoutSec=45", "TimeoutStopSec=\nTimeoutStopSec=15min", "TimeoutStopSec=30min\nTimeoutStopSec=", "TimeoutStopSec=1h \\\n"} {
		t.Run(line, func(t *testing.T) {
			body := strings.Replace(legacyUnitWithoutMarker, "Restart=on-failure\n", "Restart=on-failure\n"+line+"\n", 1)
			env, unit := unitEnv(t, body)
			if err := ensureStopTimeoutInUnit(env); err != nil {
				t.Fatalf("ensureStopTimeoutInUnit: %v", err)
			}
			updated, err := os.ReadFile(filepath.Clean(unit))
			if err != nil {
				t.Fatal(err)
			}
			if string(updated) != body {
				t.Fatalf("an operator-chosen stop budget was changed:\n%s", updated)
			}
		})
	}
}

// TestEnsureStopTimeoutInUnitIgnoresSettingsSystemdWouldNotApply mirrors the
// marker test: text outside [Service] or in a comment sets nothing at runtime.
func TestEnsureStopTimeoutInUnitIgnoresSettingsSystemdWouldNotApply(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"in [Unit]", "[Unit]\nTimeoutStopSec=5\n\n[Service]\nType=simple\n"},
		{"in [Install]", "[Service]\nType=simple\n\n[Install]\nTimeoutStopSec=5\n"},
		{"hash comment", "[Service]\nType=simple\n# TimeoutStopSec=5\n"},
		{"semicolon comment", "[Service]\nType=simple\n; TimeoutSec=5\n"},
		{"prefix of another key", "[Service]\nType=simple\nTimeoutStopFailureMode=abort\n"},
		// systemd joins a backslash-continued line, so this TimeoutStopSec is part
		// of the Environment= value, not a directive.
		{"inside a continued value", "[Service]\nType=simple\nEnvironment=LABEL=foo \\\nTimeoutStopSec=20min\n"},
		{"continued across a comment", "[Service]\nEnvironment=LABEL=foo \\\n# note\nTimeoutSec=45\n"},
		// systemd ignores an empty timeout assignment.
		{"empty assignment", "[Service]\nType=simple\nTimeoutStopSec=\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, unit := unitEnv(t, tt.body)
			if err := ensureStopTimeoutInUnit(env); err != nil {
				t.Fatalf("ensureStopTimeoutInUnit: %v", err)
			}
			updated, err := os.ReadFile(filepath.Clean(unit))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(updated), "[Service]\n"+wantStopTimeoutDirective()+"\n") {
				t.Errorf("no active stop budget was added; systemd would not apply the one present:\n%s", updated)
			}
		})
	}
}

func TestEnsureStopTimeoutInUnitIsIdempotent(t *testing.T) {
	env, unit := unitEnv(t, legacyUnitWithoutMarker)
	for range 2 {
		if err := ensureStopTimeoutInUnit(env); err != nil {
			t.Fatalf("ensureStopTimeoutInUnit: %v", err)
		}
	}
	updated, err := os.ReadFile(filepath.Clean(unit))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(updated), "TimeoutStopSec="); got != 1 {
		t.Errorf("TimeoutStopSec appears %d times, want 1; a repeated upgrade must not accumulate lines", got)
	}
}

func TestEnsureStopTimeoutInUnitRefusesAnUnusableUnit(t *testing.T) {
	t.Run("symlinked unit", func(t *testing.T) {
		env, unit := unitEnv(t, "")
		target := filepath.Join(filepath.Dir(unit), "elsewhere.service")
		if err := os.WriteFile(target, []byte(legacyUnitWithoutMarker), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, unit); err != nil {
			t.Fatal(err)
		}
		if err := ensureStopTimeoutInUnit(env); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("err = %v, want a symlink refusal", err)
		}
		after, err := os.ReadFile(filepath.Clean(target))
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != legacyUnitWithoutMarker {
			t.Error("the symlink target was modified")
		}
	})
	t.Run("no Service section", func(t *testing.T) {
		env, _ := unitEnv(t, "[Unit]\nDescription=broken\n")
		if err := ensureStopTimeoutInUnit(env); err == nil || !strings.Contains(err.Error(), "no [Service] section") {
			t.Fatalf("err = %v, want a missing-section refusal", err)
		}
	})
	t.Run("unwritable unit", func(t *testing.T) {
		env, _ := unitEnv(t, legacyUnitWithoutMarker)
		env.writeFile = func(string, []byte, os.FileMode) error { return errors.New("read-only file system") }
		if err := ensureStopTimeoutInUnit(env); err == nil || !strings.Contains(err.Error(), "write service unit") {
			t.Fatalf("err = %v, want the failed write reported", err)
		}
	})
}

// TestUpgradeCarriesTheStopTimeoutOntoALegacyUnit runs the whole upgrade so the
// test fails if the flow stops calling the migration, not only if the helper
// breaks.
func TestUpgradeCarriesTheStopTimeoutOntoALegacyUnit(t *testing.T) {
	env := testUpgradeEnv(t)
	if err := writeFileAtomic(env.unitPath, []byte(legacyUnitWithoutMarker), 0o644); err != nil {
		t.Fatal(err)
	}
	env.runCmd = successRunCmd(env, []byte("new-binary-marker"))
	if err := runUpgrade(context.Background(), env, upgradeOpts{}); err != nil {
		t.Fatalf("upgrade failed: %v", err)
	}
	updated, err := os.ReadFile(filepath.Clean(env.unitPath))
	if err != nil {
		t.Fatal(err)
	}
	if !unitServiceSetsDirective(string(updated), "TimeoutStopSec") {
		t.Fatalf("upgrade left a legacy unit on systemd's default stop budget:\n%s", updated)
	}
}

// TestUnitServiceSetsDirectiveFollowsSystemdSyntax pins the parser on the
// logical-line cases physical-line matching gets wrong.
func TestUnitServiceSetsDirectiveFollowsSystemdSyntax(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"plain", "[Service]\nTimeoutStopSec=5min\n", true},
		{"spaced", "[Service]\nTimeoutStopSec = 5min\n", true},
		{"continued value", "[Service]\nTimeoutStopSec=5 \\\nmin\n", true},
		{"continuation open at end of file", "[Service]\nTimeoutStopSec=1h \\", true},
		{"swallowed by a continued Environment", "[Service]\nEnvironment=A=b \\\nTimeoutStopSec=5min\n", false},
		{"empty assignment alone", "[Service]\nTimeoutStopSec=\n", false},
		{"empty assignment does not undo a value", "[Service]\nTimeoutStopSec=5min\nTimeoutStopSec=\n", true},
		{"value after an empty assignment", "[Service]\nTimeoutStopSec=\nTimeoutSec=45\n", true},
		{"other section", "[Unit]\nTimeoutStopSec=5min\n[Service]\nType=simple\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unitServiceSetsDirective(tt.body, "TimeoutStopSec", "TimeoutSec"); got != tt.want {
				t.Fatalf("unitServiceSetsDirective = %v, want %v for:\n%s", got, tt.want, tt.body)
			}
		})
	}
}

// TestUnitMigrationsUseTheServiceHeaderSystemdReads covers the writer half of
// the parser: insertion must land after the header systemd reads as [Service],
// never after a "[Service]" swallowed by a continuation or one spelled with
// inner spaces, which systemd treats as an unknown section.
func TestUnitMigrationsUseTheServiceHeaderSystemdReads(t *testing.T) {
	marker := "Environment=" + config.ContainmentManagedEnvKey + "=" + config.ContainmentManagedEnvValue
	tests := []struct {
		name string
		body string
	}{
		{"header swallowed by a continuation", "[Unit]\nDescription=Pipelock \\\n[Service]\nTimeoutStopSec=20min\n\n[Service]\nType=simple\n"},
		{"inner spaces make an unknown section", "[ Service ]\nTimeoutStopSec=20min\n" + marker + "\n\n[Service]\nType=simple\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, unit := unitEnv(t, tt.body)
			if err := ensureContainmentMarkerInUnit(env); err != nil {
				t.Fatalf("ensureContainmentMarkerInUnit: %v", err)
			}
			if err := ensureStopTimeoutInUnit(env); err != nil {
				t.Fatalf("ensureStopTimeoutInUnit: %v", err)
			}
			updated, err := os.ReadFile(filepath.Clean(unit))
			if err != nil {
				t.Fatal(err)
			}
			body := string(updated)
			if !unitServiceSetsDirective(body, "TimeoutStopSec") || !unitHasActiveContainmentMarker(body, marker) {
				t.Fatalf("settings were not placed where systemd reads them:\n%s", body)
			}
			// Both must follow the active header, the last "[Service]" line.
			active := strings.LastIndex(body, "\n[Service]\n")
			if strings.LastIndex(body, wantStopTimeoutDirective()) < active || strings.LastIndex(body, marker) < active {
				t.Fatalf("a setting was inserted under an inactive header:\n%s", body)
			}
		})
	}

	t.Run("only an inactive header is refused", func(t *testing.T) {
		for _, body := range []string{"[ Service ]\nType=simple\n", "[Unit]\nDescription=x \\\n[Service]\nType=simple\n"} {
			env, _ := unitEnv(t, body)
			if err := ensureStopTimeoutInUnit(env); err == nil || !strings.Contains(err.Error(), "no [Service] section") {
				t.Fatalf("err = %v for a unit systemd reads without [Service]:\n%s", err, body)
			}
		}
	})
}
