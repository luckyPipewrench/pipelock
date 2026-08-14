// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const legacyUnitWithoutMarker = `[Unit]
Description=Pipelock proxy

[Service]
Type=simple
User=pipelock-proxy
ExecStart=/usr/local/bin/pipelock run --config /etc/pipelock/pipelock.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
`

func unitEnv(t *testing.T, body string) (*upgradeEnv, string) {
	t.Helper()
	dir := t.TempDir()
	unit := filepath.Join(dir, "pipelock.service")
	if body != "" {
		if err := os.WriteFile(unit, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := testUpgradeEnv(t)
	env.unitPath = unit
	return env, unit
}

// TestEnsureContainmentMarkerInUnitMigratesALegacyUnit covers the case that made
// this necessary: a host installed before the containment runtime guard existed.
//
// Without the migration the guard protects only fresh installs, so a release note
// saying the runtime disables an unsafe metrics listener would be true of a new
// host and false of every existing one.
func TestEnsureContainmentMarkerInUnitMigratesALegacyUnit(t *testing.T) {
	env, unit := unitEnv(t, legacyUnitWithoutMarker)

	if err := ensureContainmentMarkerInUnit(env); err != nil {
		t.Fatalf("ensureContainmentMarkerInUnit: %v", err)
	}

	updated, err := os.ReadFile(filepath.Clean(unit))
	if err != nil {
		t.Fatal(err)
	}
	body := string(updated)
	marker := "Environment=" + config.ContainmentManagedEnvKey + "=" + config.ContainmentManagedEnvValue
	if !strings.Contains(body, marker) {
		t.Fatalf("marker not added:\n%s", body)
	}
	// The marker has to be inside [Service]; systemd ignores an Environment line
	// placed in [Unit] or [Install], so position is the whole point.
	serviceIdx := strings.Index(body, "[Service]")
	markerIdx := strings.Index(body, marker)
	installIdx := strings.Index(body, "[Install]")
	if markerIdx < serviceIdx || markerIdx > installIdx {
		t.Errorf("marker is outside the [Service] section; systemd would ignore it:\n%s", body)
	}
	// The operator's other settings survive: this edits a line, it does not
	// regenerate the unit.
	for _, keep := range []string{"User=pipelock-proxy", "Restart=on-failure", "WantedBy=multi-user.target"} {
		if !strings.Contains(body, keep) {
			t.Errorf("existing unit setting %q was lost", keep)
		}
	}
}

func TestEnsureContainmentMarkerInUnitIsIdempotent(t *testing.T) {
	marker := "Environment=" + config.ContainmentManagedEnvKey + "=" + config.ContainmentManagedEnvValue
	current := strings.Replace(legacyUnitWithoutMarker, "[Service]\n", "[Service]\n"+marker+"\n", 1)
	env, unit := unitEnv(t, current)

	if err := ensureContainmentMarkerInUnit(env); err != nil {
		t.Fatalf("ensureContainmentMarkerInUnit: %v", err)
	}

	updated, err := os.ReadFile(filepath.Clean(unit))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(updated), marker); got != 1 {
		t.Errorf("marker appears %d times, want exactly 1; a repeated upgrade must not accumulate lines", got)
	}
}

// TestUpgradeCarriesTheContainmentMarkerOntoALegacyUnit exercises the CALL SITE,
// not just the helper.
//
// The helper's own tests invoke it directly, so they keep passing if the upgrade
// flow stops calling it. This runs the whole upgrade against a legacy unit and
// requires the marker afterwards, which is the behavior an operator on an older
// host actually depends on.
func TestUpgradeCarriesTheContainmentMarkerOntoALegacyUnit(t *testing.T) {
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
	marker := "Environment=" + config.ContainmentManagedEnvKey + "=" + config.ContainmentManagedEnvValue
	if !strings.Contains(string(updated), marker) {
		t.Fatalf("upgrade left a legacy unit without the containment marker, so the runtime guard stays inactive on exactly the hosts this command brings current:\n%s", updated)
	}
}

func TestEnsureContainmentMarkerInUnitRefusesAnUnusableUnit(t *testing.T) {
	t.Run("missing unit", func(t *testing.T) {
		env, _ := unitEnv(t, "")
		err := ensureContainmentMarkerInUnit(env)
		if err == nil {
			t.Fatal("a missing unit was accepted; this command upgrades a containment-managed host")
		}
		if !strings.Contains(err.Error(), "read service unit") {
			t.Errorf("error = %q, want it to name the unread unit", err.Error())
		}
	})

	t.Run("no Service section", func(t *testing.T) {
		env, _ := unitEnv(t, "[Unit]\nDescription=broken\n")
		err := ensureContainmentMarkerInUnit(env)
		if err == nil {
			t.Fatal("a unit with no [Service] section was accepted; there is nowhere correct to put the marker")
		}
		if !strings.Contains(err.Error(), "no [Service] section") {
			t.Errorf("error = %q, want it to say why it refused", err.Error())
		}
	})

	t.Run("unwritable unit", func(t *testing.T) {
		env, _ := unitEnv(t, legacyUnitWithoutMarker)
		env.writeFile = func(string, []byte, os.FileMode) error { return errors.New("read-only file system") }
		err := ensureContainmentMarkerInUnit(env)
		if err == nil {
			t.Fatal("a failed write was reported as success")
		}
		if !strings.Contains(err.Error(), "write service unit") {
			t.Errorf("error = %q, want it to name the failed write", err.Error())
		}
	})
}
