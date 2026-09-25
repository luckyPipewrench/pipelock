// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// ---------------------------------------------------------------------------
// Shared fixtures for this file. Prefixed covDisp so they cannot collide with
// covNS/covPub helpers other sessions add to this package concurrently.
// ---------------------------------------------------------------------------

// covDispPrepareDisplayEnv wires an installEnv (from newFakeEnv) with a real,
// stat-able xvfbPath and a writable displayUnitPath so xdisplay.go's install
// orchestration can run end to end against a tmpdir.
func covDispPrepareDisplayEnv(t *testing.T) (*installEnv, *fakeRunner) {
	t.Helper()
	env, runner, _ := newFakeEnv(t)
	env.xvfbPath = filepath.Join(t.TempDir(), "Xvfb")
	if err := os.WriteFile(env.xvfbPath, []byte("xvfb"), 0o600); err != nil {
		t.Fatalf("write fake xvfb binary: %v", err)
	}
	env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "pipelock-agent-display.service")
	env.displayAuthorityPath = filepath.Join(t.TempDir(), "agent-state", "Xauthority")
	authorityDir := filepath.Dir(env.displayAuthorityPath)
	if err := os.MkdirAll(authorityDir, 0o700); err != nil {
		t.Fatalf("create fake Xauthority parent: %v", err)
	}
	realLstat := env.lstat
	trustedDirs := make(map[string]struct{})
	for current := filepath.Clean(authorityDir); ; current = filepath.Dir(current) {
		trustedDirs[current] = struct{}{}
		if current == string(os.PathSeparator) {
			break
		}
	}
	env.lstat = func(path string) (os.FileInfo, error) {
		info, err := realLstat(path)
		if err == nil {
			if _, ok := trustedDirs[filepath.Clean(path)]; ok && info.IsDir() {
				return fakeFileInfo{mode: os.ModeDir | 0o755, sys: fakeFileSysWithUID(0)}, nil
			}
		}
		return info, err
	}
	return env, runner
}

// covDispWriteManagedConfig writes containment.display config under env's
// managed config path so loadContainmentDisplay/stepProvisionAgentDisplay
// pick it up.
func covDispWriteManagedConfig(t *testing.T, env *installEnv, body string) {
	t.Helper()
	if err := os.WriteFile(managedPipelockConfigPath(env), []byte(body), 0o600); err != nil {
		t.Fatalf("write managed config: %v", err)
	}
}

// covDispStaleUnixSocket creates a plain regular file (not a listening
// socket) at a unix-socket-shaped path. It passes an os.Stat existence check
// (the doorway pre-flight in runNetnsForward) but refuses any connection
// attempt, standing in for a doorway whose listener died after install but
// whose socket path was never cleaned up.
func covDispStaleUnixSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cvst")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write stale doorway placeholder: %v", err)
	}
	return path
}

// covDispHoldOpenDoorway starts a unix listener that accepts exactly one
// connection, reads a single byte from it onto received, and otherwise holds
// the connection open (no echo, no close). Used to force proxyOneNetnsConn
// into its ctx.Done() select branch instead of its io.Copy-finished branch:
// the test only cancels once a byte has round-tripped end to end, which
// proves the upstream dial and both copy goroutines are already live.
func covDispHoldOpenDoorway(t *testing.T) (path string, received <-chan byte) {
	t.Helper()
	dir, err := os.MkdirTemp("", "cvho")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path = filepath.Join(dir, "h.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatalf("listen unix %s: %v", path, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	recv := make(chan byte, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		t.Cleanup(func() { _ = conn.Close() })
		buf := make([]byte, 1)
		if _, readErr := conn.Read(buf); readErr == nil {
			recv <- buf[0]
		}
	}()
	return path, recv
}

// ---------------------------------------------------------------------------
// xdisplay.go: pure helpers
// ---------------------------------------------------------------------------

func TestCovDispResolveLaunchDisplay(t *testing.T) {
	enabled := true
	disabled := false
	number := 7
	for _, tc := range []struct {
		name            string
		cfg             *config.Config
		operatorDisplay string
		xvfbPresent     bool
		want            string
	}{
		{
			name:            "operator display always wins",
			cfg:             nil,
			operatorDisplay: "  :3  ",
			want:            "  :3  ",
		},
		{
			name: "nil config with no operator display resolves empty",
			cfg:  nil,
			want: "",
		},
		{
			name:        "omitted config enabled follows xvfb presence",
			cfg:         &config.Config{},
			xvfbPresent: true,
			want:        ":99",
		},
		{
			name:        "omitted config disabled when xvfb absent",
			cfg:         &config.Config{},
			xvfbPresent: false,
			want:        "",
		},
		{
			name: "explicit disabled overrides xvfb presence",
			cfg: &config.Config{Containment: config.ContainmentConfig{
				Display: config.ContainmentDisplay{Enabled: &disabled},
			}},
			xvfbPresent: true,
			want:        "",
		},
		{
			name: "explicit enabled with a configured number",
			cfg: &config.Config{Containment: config.ContainmentConfig{
				Display: config.ContainmentDisplay{Enabled: &enabled, Number: &number},
			}},
			want: ":7",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveLaunchDisplay(tc.cfg, tc.operatorDisplay, tc.xvfbPresent)
			if got != tc.want {
				t.Fatalf("resolveLaunchDisplay() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCovDispLocalDisplaySocket(t *testing.T) {
	for _, tc := range []struct {
		name    string
		display string
		wantOK  bool
		want    string
	}{
		{name: "no colon prefix", display: "abc", wantOK: false},
		{name: "empty string", display: "", wantOK: false},
		{name: "non-numeric number", display: ":abc", wantOK: false},
		{name: "negative number", display: ":-1", wantOK: false},
		{name: "above ceiling", display: ":1000", wantOK: false},
		{name: "boundary ceiling accepted", display: ":999", wantOK: true, want: displaySocketPath(999)},
		{name: "simple number", display: ":5", wantOK: true, want: displaySocketPath(5)},
		{name: "screen suffix is cut", display: ":5.0", wantOK: true, want: displaySocketPath(5)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := localDisplaySocket(tc.display)
			if ok != tc.wantOK {
				t.Fatalf("localDisplaySocket(%q) ok = %v, want %v", tc.display, ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Fatalf("localDisplaySocket(%q) = %q, want %q", tc.display, got, tc.want)
			}
		})
	}
}

func TestCovDispXvfbInstalled(t *testing.T) {
	realBinary := t.TempDir() + "/Xvfb"
	if err := os.WriteFile(realBinary, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		env  *installEnv
		want bool
	}{
		{name: "nil env", env: nil, want: false},
		{name: "nil stat hook", env: &installEnv{xvfbPath: realBinary}, want: false},
		{
			name: "stat error means absent",
			env: &installEnv{
				xvfbPath: filepath.Join(t.TempDir(), "missing"),
				stat:     os.Stat,
			},
			want: false,
		},
		{
			name: "stat success means present",
			env:  &installEnv{xvfbPath: realBinary, stat: os.Stat},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := xvfbInstalled(tc.env); got != tc.want {
				t.Fatalf("xvfbInstalled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCovDispLoadContainmentDisplay(t *testing.T) {
	t.Run("missing config returns zero value with no error", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		got, err := loadContainmentDisplay(env)
		if err != nil {
			t.Fatalf("loadContainmentDisplay: %v", err)
		}
		if got != (config.ContainmentDisplay{}) {
			t.Fatalf("got %+v, want zero value", got)
		}
	})

	t.Run("unreadable config wraps the load error", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		// A directory at the managed config path is a real, deterministic
		// non-ErrNotExist failure for config.LoadForInspection.
		if err := os.MkdirAll(managedPipelockConfigPath(env), 0o750); err != nil {
			t.Fatal(err)
		}
		_, err := loadContainmentDisplay(env)
		if err == nil || !strings.Contains(err.Error(), "load containment display config") {
			t.Fatalf("err = %v, want a wrapped load failure", err)
		}
	})

	t.Run("configured display is returned", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: true\n    number: 42\n")
		got, err := loadContainmentDisplay(env)
		if err != nil {
			t.Fatalf("loadContainmentDisplay: %v", err)
		}
		if !got.IsEnabled(false) || got.EffectiveNumber() != 42 {
			t.Fatalf("got %+v, want enabled with number 42", got)
		}
	})
}

// ---------------------------------------------------------------------------
// xdisplay.go: captureDisplayPreState
// ---------------------------------------------------------------------------

func TestCovDispCaptureDisplayPreState(t *testing.T) {
	t.Run("stat error other than not-exist is wrapped", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		env.stat = func(string) (os.FileInfo, error) { return nil, errors.New("boom stat") }
		err := captureDisplayPreState(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "boom stat") || !strings.Contains(err.Error(), env.displayUnitPath) {
			t.Fatalf("err = %v, want a wrapped stat failure naming the unit path", err)
		}
	})

	t.Run("systemctl inspection failure is wrapped", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		runner.on(argvFor(testSystemctl, "is-enabled", filepath.Base(env.displayUnitPath)), "", 0, errors.New("dbus down"))
		err := captureDisplayPreState(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "inspect display unit state") {
			t.Fatalf("err = %v, want an inspect-state wrap", err)
		}
	})

	t.Run("success records prior enabled and active state", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		unit := filepath.Base(env.displayUnitPath)
		runner.on(argvFor(testSystemctl, "is-enabled", unit), "enabled\n", 0, nil)
		runner.on(argvFor(testSystemctl, "is-active", unit), "active\n", 0, nil)
		if err := captureDisplayPreState(context.Background(), env); err != nil {
			t.Fatalf("captureDisplayPreState: %v", err)
		}
		if env.prevDisplayUnitExisted {
			t.Fatal("no unit file was written, prevDisplayUnitExisted should be false")
		}
		if !env.prevDisplayEnabled || !env.prevDisplayActive || !env.prevDisplayStateKnown {
			t.Fatalf("prev state = enabled=%v active=%v known=%v, want all true",
				env.prevDisplayEnabled, env.prevDisplayActive, env.prevDisplayStateKnown)
		}
	})
}

// ---------------------------------------------------------------------------
// xdisplay.go: stepProvisionAgentDisplay
// ---------------------------------------------------------------------------

func TestCovDispStepProvisionAgentDisplayApply(t *testing.T) {
	t.Run("loadContainmentDisplay failure propagates", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		if err := os.MkdirAll(managedPipelockConfigPath(env), 0o750); err != nil {
			t.Fatal(err)
		}
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if applied || err == nil || !strings.Contains(err.Error(), "load containment display config") {
			t.Fatalf("apply() = (%v, %v), want a load failure", applied, err)
		}
	})

	t.Run("captureDisplayPreState failure propagates", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		runner.on(argvFor(testSystemctl, "is-active", filepath.Base(env.displayUnitPath)), "", 0, errors.New("dbus down"))
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if applied || err == nil || !strings.Contains(err.Error(), "inspect display unit state") {
			t.Fatalf("apply() = (%v, %v), want a pre-state failure", applied, err)
		}
	})

	t.Run("disabled with no prior unit is a no-op", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: false\n")
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if applied || err != nil {
			t.Fatalf("apply() = (%v, %v), want (false, nil)", applied, err)
		}
	})

	t.Run("disabled with an unmanaged prior unit refuses to touch it", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: false\n")
		if err := os.WriteFile(env.displayUnitPath, []byte("[Service]\nExecStart=/bin/true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if applied || err == nil || !strings.Contains(err.Error(), "is not Pipelock-managed") {
			t.Fatalf("apply() = (%v, %v), want (false, unmanaged-unit refusal)", applied, err)
		}
	})

	t.Run("disabled removes a managed prior unit", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: false\n")
		body := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, displayNumber: 99, xvfbPath: env.xvfbPath})
		if err := os.WriteFile(env.displayUnitPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if !applied || err != nil {
			t.Fatalf("apply() = (%v, %v), want (true, nil)", applied, err)
		}
		if _, statErr := os.Stat(env.displayUnitPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("managed unit file should have been removed, stat err = %v", statErr)
		}
		var sawDisable bool
		for _, c := range runner.calls {
			if c.name == testSystemctl && len(c.args) >= 2 && c.args[0] == "disable" {
				sawDisable = true
			}
		}
		if !sawDisable {
			t.Fatalf("expected a systemctl disable call, got %v", runner.calls)
		}
	})

	t.Run("disabled with a prior unit readFile failure propagates", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: false\n")
		if err := os.WriteFile(env.displayUnitPath, []byte("placeholder"), 0o600); err != nil {
			t.Fatal(err)
		}
		env.readFile = func(string) ([]byte, error) { return nil, errors.New("disk read failed") }
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if applied || err == nil || !strings.Contains(err.Error(), "read display unit") || !strings.Contains(err.Error(), "disk read failed") {
			t.Fatalf("apply() = (%v, %v), want (false, a wrapped read-display-unit failure)", applied, err)
		}
	})

	t.Run("disabled removal fails when restoreBackup fails", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: false\n")
		body := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, displayNumber: 99, xvfbPath: env.xvfbPath})
		if err := os.WriteFile(env.displayUnitPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		env.removeFile = func(string) error { return errors.New("remove refused") }
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if !applied || err == nil || !strings.Contains(err.Error(), "remove refused") {
			t.Fatalf("apply() = (%v, %v), want (true, the underlying restoreBackup failure)", applied, err)
		}
	})

	t.Run("disabled removal fails when systemctl disable fails", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: false\n")
		body := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, displayNumber: 99, xvfbPath: env.xvfbPath})
		if err := os.WriteFile(env.displayUnitPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		unit := filepath.Base(env.displayUnitPath)
		runner.on(argvFor(testSystemctl, "disable", "--now", unit), "manager refused", 1, nil)
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if !applied || err == nil {
			t.Fatalf("apply() = (%v, %v), want (true, error)", applied, err)
		}
	})

	t.Run("enabled but xvfb binary missing refuses to provision", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		env.xvfbPath = filepath.Join(t.TempDir(), "no-such-xvfb")
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: true\n    number: 5\n")
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if applied || err == nil || !strings.Contains(err.Error(), "display provisioning requires") {
			t.Fatalf("apply() = (%v, %v), want a missing-xvfb refusal", applied, err)
		}
	})

	t.Run("enabled fails when ensureContainmentUnit cannot write the unit", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: true\n    number: 5\n")
		unitDir := filepath.Dir(env.displayUnitPath)
		env.mkdirAll = func(path string, mode os.FileMode) error {
			if path == unitDir {
				return errors.New("mkdir refused")
			}
			return os.MkdirAll(path, mode)
		}
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if !applied || err == nil || !strings.Contains(err.Error(), "mkdir refused") {
			t.Fatalf("apply() = (%v, %v), want (true, the underlying mkdir failure after cookie creation)", applied, err)
		}
	})

	t.Run("enabled fresh install succeeds and reconciles", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: true\n    number: 5\n")
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if !applied || err != nil {
			t.Fatalf("apply() = (%v, %v), want (true, nil)", applied, err)
		}
		body, readErr := os.ReadFile(filepath.Clean(env.displayUnitPath))
		if readErr != nil || !strings.HasPrefix(string(body), displayUnitMarker) {
			t.Fatalf("managed unit not written correctly: %v %q", readErr, body)
		}
		var sawEnable bool
		unit := filepath.Base(env.displayUnitPath)
		for _, c := range runner.calls {
			if c.name == testSystemctl && len(c.args) == 3 && c.args[0] == "enable" && c.args[1] == "--now" && c.args[2] == unit {
				sawEnable = true
			}
		}
		if !sawEnable {
			t.Fatalf("expected systemctl enable --now %s, got %v", unit, runner.calls)
		}
	})

	t.Run("enabled reconciles when unit already matches but was previously inactive", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: true\n    number: 5\n")
		body := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, displayNumber: 5, xvfbPath: env.xvfbPath})
		if err := os.MkdirAll(filepath.Dir(env.displayUnitPath), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(env.displayUnitPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		unit := filepath.Base(env.displayUnitPath)
		runner.on(argvFor(testSystemctl, "is-enabled", unit), "enabled\n", 0, nil)
		runner.on(argvFor(testSystemctl, "is-active", unit), "inactive\n", 0, nil)
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if !applied || err != nil {
			t.Fatalf("apply() = (%v, %v), want (true, nil) from reconciliation alone", applied, err)
		}
	})

	t.Run("every active provision restarts Xvfb to rotate its cookie", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			priorNumber int
			active      bool
			wantRestart bool
		}{
			{"changed active", 99, true, true},
			{"changed inactive", 99, false, false},
			{"unchanged active", 5, true, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				env, runner := covDispPrepareDisplayEnv(t)
				covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: true\n    number: 5\n")
				hostname, err := os.Hostname()
				if err != nil {
					t.Fatal(err)
				}
				previousCookie := make([]byte, displayAuthorityCookieSize)
				previousAuthority, err := encodeDisplayAuthority(hostname, "5", previousCookie)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(env.displayAuthorityPath, previousAuthority, displayAuthorityFileMode); err != nil {
					t.Fatal(err)
				}
				prior := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, displayNumber: tc.priorNumber, xvfbPath: env.xvfbPath})
				if err := os.WriteFile(env.displayUnitPath, []byte(prior), 0o600); err != nil {
					t.Fatal(err)
				}
				unit := filepath.Base(env.displayUnitPath)
				runner.on(argvFor(testSystemctl, "is-enabled", unit), "enabled\n", 0, nil)
				state := "inactive\n"
				if tc.active {
					state = "active\n"
				}
				runner.on(argvFor(testSystemctl, "is-active", unit), state, 0, nil)
				if _, err := stepProvisionAgentDisplay().apply(context.Background(), env); err != nil {
					t.Fatalf("apply: %v", err)
				}
				rotatedAuthority, err := os.ReadFile(env.displayAuthorityPath)
				if err != nil {
					t.Fatalf("read rotated Xauthority: %v", err)
				}
				if bytes.Equal(rotatedAuthority, previousAuthority) {
					t.Fatal("Xauthority cookie did not rotate during re-provision")
				}
				restarts := 0
				for _, call := range runner.calls {
					if call.name == testSystemctl && len(call.args) == 2 && call.args[0] == "restart" && call.args[1] == unit {
						restarts++
					}
				}
				if (restarts == 1) != tc.wantRestart {
					t.Fatalf("restart calls = %d, want restart=%t; calls=%v", restarts, tc.wantRestart, runner.calls)
				}
			})
		}
	})

	t.Run("enabled fails when daemon-reload fails", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: true\n    number: 5\n")
		runner.on(argvFor(testSystemctl, "daemon-reload"), "", 1, nil)
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if err == nil {
			t.Fatalf("apply() = (%v, %v), want an error from failed daemon-reload", applied, err)
		}
	})

	t.Run("enabled fails when enable --now fails", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: true\n    number: 5\n")
		unit := filepath.Base(env.displayUnitPath)
		runner.on(argvFor(testSystemctl, "enable", "--now", unit), "manager refused", 1, nil)
		applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
		if !applied || err == nil {
			t.Fatalf("apply() = (%v, %v), want (true, error)", applied, err)
		}
	})
}

func TestCovDispStepProvisionAgentDisplayUndo(t *testing.T) {
	t.Run("restores a removed managed unit and re-enables it", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: false\n")
		body := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, displayNumber: 99, xvfbPath: env.xvfbPath})
		if err := os.WriteFile(env.displayUnitPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		unit := filepath.Base(env.displayUnitPath)
		runner.on(argvFor(testSystemctl, "is-enabled", unit), "enabled\n", 0, nil)
		runner.on(argvFor(testSystemctl, "is-active", unit), "active\n", 0, nil)

		st := stepProvisionAgentDisplay()
		applied, err := st.apply(context.Background(), env)
		if !applied || err != nil {
			t.Fatalf("apply() = (%v, %v), want (true, nil)", applied, err)
		}
		if _, statErr := os.Stat(env.displayUnitPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("unit should be removed after apply, stat err = %v", statErr)
		}

		if err := st.undo(context.Background(), env); err != nil {
			t.Fatalf("undo: %v", err)
		}
		restored, readErr := os.ReadFile(filepath.Clean(env.displayUnitPath))
		if readErr != nil || string(restored) != body {
			t.Fatalf("undo did not restore the exact managed body: %v %q", readErr, restored)
		}
		var sawEnable, sawStart bool
		for _, c := range runner.calls {
			if c.name != testSystemctl || len(c.args) < 2 {
				continue
			}
			if c.args[0] == "enable" && c.args[len(c.args)-1] == unit {
				sawEnable = true
			}
			if c.args[0] == "start" && c.args[len(c.args)-1] == unit {
				sawStart = true
			}
		}
		if !sawEnable || !sawStart {
			t.Fatalf("undo should re-enable and start the restored unit: %v", runner.calls)
		}
	})

	t.Run("restoring a removed managed unit fails when the write fails", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: false\n")
		body := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, displayNumber: 99, xvfbPath: env.xvfbPath})
		if err := os.WriteFile(env.displayUnitPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		unit := filepath.Base(env.displayUnitPath)
		runner.on(argvFor(testSystemctl, "is-enabled", unit), "enabled\n", 0, nil)
		runner.on(argvFor(testSystemctl, "is-active", unit), "active\n", 0, nil)

		st := stepProvisionAgentDisplay()
		applied, err := st.apply(context.Background(), env)
		if !applied || err != nil {
			t.Fatalf("apply() = (%v, %v), want (true, nil)", applied, err)
		}
		env.writeFile = func(string, []byte, os.FileMode) error { return errors.New("write refused") }
		if err := st.undo(context.Background(), env); err == nil || !strings.Contains(err.Error(), "write refused") {
			t.Fatalf("undo err = %v, want the underlying write failure", err)
		}
	})

	t.Run("restoring a removed managed unit fails when daemon-reload fails", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: false\n")
		body := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, displayNumber: 99, xvfbPath: env.xvfbPath})
		if err := os.WriteFile(env.displayUnitPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		unit := filepath.Base(env.displayUnitPath)
		runner.on(argvFor(testSystemctl, "is-enabled", unit), "enabled\n", 0, nil)
		runner.on(argvFor(testSystemctl, "is-active", unit), "active\n", 0, nil)

		st := stepProvisionAgentDisplay()
		applied, err := st.apply(context.Background(), env)
		if !applied || err != nil {
			t.Fatalf("apply() = (%v, %v), want (true, nil)", applied, err)
		}
		runner.on(argvFor(testSystemctl, "daemon-reload"), "manager refused", 1, nil)
		if err := st.undo(context.Background(), env); err == nil {
			t.Fatal("expected the daemon-reload failure to propagate")
		}
	})

	t.Run("restoring a removed managed unit fails when re-enabling fails", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: false\n")
		body := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, displayNumber: 99, xvfbPath: env.xvfbPath})
		if err := os.WriteFile(env.displayUnitPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		unit := filepath.Base(env.displayUnitPath)
		runner.on(argvFor(testSystemctl, "is-enabled", unit), "enabled\n", 0, nil)
		runner.on(argvFor(testSystemctl, "is-active", unit), "active\n", 0, nil)

		st := stepProvisionAgentDisplay()
		applied, err := st.apply(context.Background(), env)
		if !applied || err != nil {
			t.Fatalf("apply() = (%v, %v), want (true, nil)", applied, err)
		}
		runner.on(argvFor(testSystemctl, "enable", unit), "manager refused", 1, nil)
		if err := st.undo(context.Background(), env); err == nil {
			t.Fatal("expected the re-enable failure to propagate")
		}
	})

	t.Run("restoring a unit that was neither enabled nor active skips both calls", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: false\n")
		body := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, displayNumber: 99, xvfbPath: env.xvfbPath})
		if err := os.WriteFile(env.displayUnitPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		unit := filepath.Base(env.displayUnitPath)
		runner.on(argvFor(testSystemctl, "is-enabled", unit), "disabled\n", 0, nil)
		runner.on(argvFor(testSystemctl, "is-active", unit), "inactive\n", 0, nil)

		st := stepProvisionAgentDisplay()
		applied, err := st.apply(context.Background(), env)
		if !applied || err != nil {
			t.Fatalf("apply() = (%v, %v), want (true, nil)", applied, err)
		}
		if err := st.undo(context.Background(), env); err != nil {
			t.Fatalf("undo: %v", err)
		}
		for _, c := range runner.calls {
			if c.name == testSystemctl && len(c.args) >= 1 && (c.args[0] == "enable" || c.args[0] == "start") {
				t.Fatalf("a unit that was never enabled/active should not be re-enabled/started: %v", runner.calls)
			}
		}
	})

	t.Run("undo of a fresh install delegates to restoreAgentDisplay", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: true\n    number: 5\n")
		st := stepProvisionAgentDisplay()
		applied, err := st.apply(context.Background(), env)
		if !applied || err != nil {
			t.Fatalf("apply() = (%v, %v), want (true, nil)", applied, err)
		}
		if err := st.undo(context.Background(), env); err != nil {
			t.Fatalf("undo: %v", err)
		}
		if _, statErr := os.Stat(env.displayUnitPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("undo of a fresh install should remove the unit it created, stat err = %v", statErr)
		}
	})
}

// ---------------------------------------------------------------------------
// xdisplay.go: restoreAgentDisplay / actionRemoveAgentDisplay
// ---------------------------------------------------------------------------

func TestCovDispRestoreAgentDisplay(t *testing.T) {
	t.Run("cleanup failure propagates", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		unit := filepath.Base(env.displayUnitPath)
		runner.on(argvFor(testSystemctl, "disable", "--now", unit), "manager refused", 1, nil)
		err := restoreAgentDisplay(context.Background(), env)
		if err == nil {
			t.Fatal("expected the disable failure to propagate")
		}
	})

	t.Run("restoreBackup failure propagates", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		if err := os.WriteFile(env.displayUnitPath, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
		env.removeFile = func(string) error { return errors.New("permission denied") }
		err := restoreAgentDisplay(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("err = %v, want the underlying remove failure", err)
		}
	})

	t.Run("daemon-reload failure propagates", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		runner.on(argvFor(testSystemctl, "daemon-reload"), "", 1, nil)
		err := restoreAgentDisplay(context.Background(), env)
		if err == nil {
			t.Fatal("expected the daemon-reload failure to propagate")
		}
	})

	t.Run("prior state unknown skips enable and start", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		env.prevDisplayStateKnown = false
		env.prevDisplayEnabled = true
		env.prevDisplayActive = true
		if err := restoreAgentDisplay(context.Background(), env); err != nil {
			t.Fatalf("restoreAgentDisplay: %v", err)
		}
		unit := filepath.Base(env.displayUnitPath)
		for _, c := range runner.calls {
			if c.name == testSystemctl && len(c.args) >= 1 && (c.args[0] == "enable" || c.args[0] == "start") {
				t.Fatalf("unknown prior state must not re-enable/start: %v", runner.calls)
			}
		}
		_ = unit
	})

	t.Run("enable failure propagates when prior state was enabled", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		env.prevDisplayStateKnown = true
		env.prevDisplayEnabled = true
		unit := filepath.Base(env.displayUnitPath)
		runner.on(argvFor(testSystemctl, "enable", unit), "manager refused", 1, nil)
		err := restoreAgentDisplay(context.Background(), env)
		if err == nil {
			t.Fatal("expected the enable failure to propagate")
		}
	})

	t.Run("start failure propagates when prior state was active", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		env.prevDisplayStateKnown = true
		env.prevDisplayActive = true
		unit := filepath.Base(env.displayUnitPath)
		runner.on(argvFor(testSystemctl, "start", unit), "manager refused", 1, nil)
		err := restoreAgentDisplay(context.Background(), env)
		if err == nil {
			t.Fatal("expected the start failure to propagate")
		}
	})

	t.Run("full success re-enables and starts", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		env.prevDisplayStateKnown = true
		env.prevDisplayEnabled = true
		env.prevDisplayActive = true
		if err := restoreAgentDisplay(context.Background(), env); err != nil {
			t.Fatalf("restoreAgentDisplay: %v", err)
		}
		unit := filepath.Base(env.displayUnitPath)
		var sawEnable, sawStart bool
		for _, c := range runner.calls {
			if c.name == testSystemctl && len(c.args) >= 1 {
				if c.args[0] == "enable" && c.args[len(c.args)-1] == unit {
					sawEnable = true
				}
				if c.args[0] == "start" && c.args[len(c.args)-1] == unit {
					sawStart = true
				}
			}
		}
		if !sawEnable || !sawStart {
			t.Fatalf("expected enable and start calls, got %v", runner.calls)
		}
	})
}

func TestCovDispActionRemoveAgentDisplayUndo(t *testing.T) {
	t.Run("empty display unit path is a no-op", func(t *testing.T) {
		env := &installEnv{}
		if err := actionRemoveAgentDisplay().undo(context.Background(), env); err != nil {
			t.Fatalf("undo: %v", err)
		}
	})

	t.Run("non-empty path delegates to restoreAgentDisplay", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		env.prevDisplayStateKnown = true
		env.prevDisplayEnabled = true
		if err := actionRemoveAgentDisplay().undo(context.Background(), env); err != nil {
			t.Fatalf("undo: %v", err)
		}
		if env.prevDisplayStateKnown {
			t.Fatal("undo must reset prevDisplayStateKnown before delegating, per its own comment")
		}
		var sawDisable bool
		for _, c := range runner.calls {
			if c.name == testSystemctl && len(c.args) >= 1 && c.args[0] == "disable" {
				sawDisable = true
			}
		}
		if !sawDisable {
			t.Fatalf("expected a systemctl disable call, got %v", runner.calls)
		}
	})
}

// ---------------------------------------------------------------------------
// xdisplay.go: isManagedDisplayUnitFile
// ---------------------------------------------------------------------------

func TestCovDispIsManagedDisplayUnitFile(t *testing.T) {
	goodBody := renderAgentDisplayUnit(&installEnv{agentUserName: testAgentUser, displayNumber: 99, xvfbPath: "/usr/bin/Xvfb"})
	for _, tc := range []struct {
		name     string
		readFile func(string) ([]byte, error)
		want     bool
	}{
		{
			name:     "read error means not managed",
			readFile: func(string) ([]byte, error) { return nil, errors.New("boom") },
			want:     false,
		},
		{
			name:     "missing marker means not managed",
			readFile: func(string) ([]byte, error) { return []byte("[Service]\nUser=pipelock-agent\n"), nil },
			want:     false,
		},
		{
			name: "marker present but User does not match",
			readFile: func(string) ([]byte, error) {
				return []byte(strings.Replace(goodBody, "User=pipelock-agent", "User=someone-else", 1)), nil
			},
			want: false,
		},
		{
			name:     "matching managed unit",
			readFile: func(string) ([]byte, error) { return []byte(goodBody), nil },
			want:     true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isManagedDisplayUnitFile(tc.readFile, "/etc/systemd/system/pipelock-agent-display.service", testAgentUser); got != tc.want {
				t.Fatalf("isManagedDisplayUnitFile() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// xdisplay.go: probeAgentDisplay
// ---------------------------------------------------------------------------

// covDispProbeSocket creates a real unix socket file mode 0700 and returns
// its path, so fileOwnerUID sees a genuine *syscall.Stat_t.
func covDispProbeSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cvsk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "X99")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatalf("listen unix %s: %v", path, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := os.Chmod(path, os.ModeSocket|0o700); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}
	return path
}

func TestCovDispProbeAgentDisplay(t *testing.T) {
	const agentUser = testAgentUser
	selfUID := strconv.Itoa(os.Getuid())

	matchingBody := func(number int) string {
		return renderAgentDisplayUnit(&installEnv{agentUserName: agentUser, displayNumber: number, xvfbPath: "/usr/bin/Xvfb"})
	}

	t.Run("config load failure other than not-exist fails closed", func(t *testing.T) {
		dir := t.TempDir() // a directory path makes LoadForInspection fail with "not a regular file"
		env := &probeEnv{configPath: dir, agentUserName: agentUser}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "read containment display config") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want a config-load failure", status, detail)
		}
	})

	t.Run("absent config with no xvfb passes as disabled fallback", func(t *testing.T) {
		env := &probeEnv{
			configPath:      filepath.Join(t.TempDir(), "missing.yaml"),
			agentUserName:   agentUser,
			displayUnitPath: filepath.Join(t.TempDir(), "unit.service"),
			xvfbPath:        "/usr/bin/Xvfb",
			stat:            func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
			runCmd: func(context.Context, string, ...string) (string, int, error) {
				return "inactive\n", 0, nil
			},
		}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusPass || !strings.Contains(detail, "managed config is absent") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want the config-absent pass message", status, detail)
		}
	})

	t.Run("nil stat hook defaults xvfb presence to true and disabled config still passes", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(configPath, []byte("containment:\n  display:\n    enabled: false\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := &probeEnv{
			configPath:    configPath,
			agentUserName: agentUser,
			runCmd: func(context.Context, string, ...string) (string, int, error) {
				return "inactive\n", 0, nil
			},
		}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusPass || !strings.Contains(detail, "fallback is disabled") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want the fallback-disabled pass message", status, detail)
		}
	})

	t.Run("disabled config but unit still active fails", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(configPath, []byte("containment:\n  display:\n    enabled: false\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := &probeEnv{
			configPath:    configPath,
			agentUserName: agentUser,
			runCmd: func(context.Context, string, ...string) (string, int, error) {
				return "active\n", 0, nil
			},
		}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "remains active") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want a still-active failure", status, detail)
		}
	})

	t.Run("disabled config and is-active inspection error fails", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(configPath, []byte("containment:\n  display:\n    enabled: false\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := &probeEnv{
			configPath:    configPath,
			agentUserName: agentUser,
			runCmd: func(context.Context, string, ...string) (string, int, error) {
				return "", 0, errors.New("dbus down")
			},
		}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "inspect disabled display unit") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want an inspect failure", status, detail)
		}
	})

	t.Run("enabled config with unreadable unit file fails", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(configPath, []byte("containment:\n  display:\n    enabled: true\n    number: 99\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := &probeEnv{
			configPath:      configPath,
			agentUserName:   agentUser,
			displayUnitPath: filepath.Join(t.TempDir(), "unit.service"),
			xvfbPath:        "/usr/bin/Xvfb",
			readFile:        func(string) ([]byte, error) { return nil, errors.New("no such file") },
		}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "read display unit") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want a read failure", status, detail)
		}
	})

	t.Run("enabled config with a tampered unit entry fails on that key", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(configPath, []byte("containment:\n  display:\n    enabled: true\n    number: 99\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		tampered := strings.Replace(matchingBody(99), "UMask=0077", "UMask=0022", 1)
		env := &probeEnv{
			configPath:      configPath,
			agentUserName:   agentUser,
			displayUnitPath: filepath.Join(t.TempDir(), "unit.service"),
			xvfbPath:        "/usr/bin/Xvfb",
			readFile:        func(string) ([]byte, error) { return []byte(tampered), nil },
		}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "missing exact UMask=0077") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want a UMask tamper failure", status, detail)
		}
	})

	t.Run("enabled config with is-enabled mismatch fails", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(configPath, []byte("containment:\n  display:\n    enabled: true\n    number: 99\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := &probeEnv{
			configPath:      configPath,
			agentUserName:   agentUser,
			displayUnitPath: filepath.Join(t.TempDir(), "unit.service"),
			xvfbPath:        "/usr/bin/Xvfb",
			readFile:        func(string) ([]byte, error) { return []byte(matchingBody(99)), nil },
			runCmd: func(_ context.Context, _ string, args ...string) (string, int, error) {
				if len(args) >= 1 && args[0] == "is-enabled" {
					return "disabled\n", 0, nil
				}
				return "active\n", 0, nil
			},
		}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "is-enabled is disabled, want enabled") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want an is-enabled mismatch failure", status, detail)
		}
	})

	// covDispEnabledActiveRunCmd answers systemctl is-enabled/is-active with
	// the values a fully matching, running managed unit would report.
	covDispEnabledActiveRunCmd := func(_ context.Context, _ string, args ...string) (string, int, error) {
		if len(args) >= 1 && args[0] == "is-enabled" {
			return systemctlEnabled + "\n", 0, nil
		}
		return systemctlActive + "\n", 0, nil
	}

	t.Run("enabled config with an unstattable socket fails", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(configPath, []byte("containment:\n  display:\n    enabled: true\n    number: 99\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := &probeEnv{
			configPath:      configPath,
			agentUserName:   agentUser,
			displayUnitPath: filepath.Join(t.TempDir(), "unit.service"),
			xvfbPath:        "/usr/bin/Xvfb",
			readFile:        func(string) ([]byte, error) { return []byte(matchingBody(99)), nil },
			runCmd:          covDispEnabledActiveRunCmd,
			stat:            func(string) (os.FileInfo, error) { return nil, errors.New("no such socket") },
		}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "stat display socket") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want a socket-stat failure", status, detail)
		}
	})

	t.Run("enabled config with a non-socket mode fails", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(configPath, []byte("containment:\n  display:\n    enabled: true\n    number: 99\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		regularFile := filepath.Join(t.TempDir(), "not-a-socket")
		if err := os.WriteFile(regularFile, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := &probeEnv{
			configPath:      configPath,
			agentUserName:   agentUser,
			displayUnitPath: filepath.Join(t.TempDir(), "unit.service"),
			xvfbPath:        "/usr/bin/Xvfb",
			readFile:        func(string) ([]byte, error) { return []byte(matchingBody(99)), nil },
			runCmd:          covDispEnabledActiveRunCmd,
			displaySocket:   func(int) string { return regularFile },
			stat:            os.Stat,
		}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "want socket 0700") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want a socket-mode failure", status, detail)
		}
	})

	t.Run("enabled config with an unknown lookup user fails", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(configPath, []byte("containment:\n  display:\n    enabled: true\n    number: 99\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		socket := covDispProbeSocket(t)
		env := &probeEnv{
			configPath:      configPath,
			agentUserName:   agentUser,
			displayUnitPath: filepath.Join(t.TempDir(), "unit.service"),
			xvfbPath:        "/usr/bin/Xvfb",
			readFile:        func(string) ([]byte, error) { return []byte(matchingBody(99)), nil },
			runCmd:          covDispEnabledActiveRunCmd,
			displaySocket:   func(int) string { return socket },
			stat:            os.Stat,
			lookupUser:      func(string) (*user.User, error) { return nil, user.UnknownUserError(agentUser) },
		}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "lookup display owner") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want a lookup failure", status, detail)
		}
	})

	t.Run("enabled config with a non-numeric uid fails to parse", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(configPath, []byte("containment:\n  display:\n    enabled: true\n    number: 99\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		socket := covDispProbeSocket(t)
		env := &probeEnv{
			configPath:      configPath,
			agentUserName:   agentUser,
			displayUnitPath: filepath.Join(t.TempDir(), "unit.service"),
			xvfbPath:        "/usr/bin/Xvfb",
			readFile:        func(string) ([]byte, error) { return []byte(matchingBody(99)), nil },
			runCmd:          covDispEnabledActiveRunCmd,
			displaySocket:   func(int) string { return socket },
			stat:            os.Stat,
			lookupUser:      func(string) (*user.User, error) { return &user.User{Uid: "not-a-number"}, nil },
		}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "parse display owner uid") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want a uid parse failure", status, detail)
		}
	})

	t.Run("enabled config with a mismatched socket owner fails", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(configPath, []byte("containment:\n  display:\n    enabled: true\n    number: 99\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		socket := covDispProbeSocket(t)
		env := &probeEnv{
			configPath:      configPath,
			agentUserName:   agentUser,
			displayUnitPath: filepath.Join(t.TempDir(), "unit.service"),
			xvfbPath:        "/usr/bin/Xvfb",
			readFile:        func(string) ([]byte, error) { return []byte(matchingBody(99)), nil },
			runCmd:          covDispEnabledActiveRunCmd,
			displaySocket:   func(int) string { return socket },
			stat:            os.Stat,
			// A uid that certainly is not this test process's own uid: the
			// real socket on disk is owned by whoever created it (us).
			lookupUser: func(string) (*user.User, error) { return &user.User{Uid: strconv.Itoa(os.Getuid() + 1)}, nil },
		}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "not owned by the contained agent uid") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want an ownership failure", status, detail)
		}
	})

	t.Run("full success reports the active display and its owner", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(configPath, []byte("containment:\n  display:\n    enabled: true\n    number: 99\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		socket := covDispProbeSocket(t)
		env := &probeEnv{
			configPath:      configPath,
			agentUserName:   agentUser,
			displayUnitPath: filepath.Join(t.TempDir(), "unit.service"),
			xvfbPath:        "/usr/bin/Xvfb",
			readFile:        func(string) ([]byte, error) { return []byte(matchingBody(99)), nil },
			runCmd:          covDispEnabledActiveRunCmd,
			displaySocket:   func(int) string { return socket },
			stat:            os.Stat,
			lookupUser:      func(string) (*user.User, error) { return &user.User{Uid: selfUID}, nil },
		}
		status, detail := probeAgentDisplay(context.Background(), env)
		if status != statusPass || !strings.Contains(detail, ":99") || !strings.Contains(detail, "0700") {
			t.Fatalf("probeAgentDisplay() = (%q, %q), want a full pass naming :99 and 0700", status, detail)
		}
	})
}

// ---------------------------------------------------------------------------
// runtime_contract.go: managedDisplayFallback
// ---------------------------------------------------------------------------

func TestCovDispManagedDisplayFallback(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  *installEnv
		want string
	}{
		{
			name: "enabled uses the configured display number",
			env:  &installEnv{displayEnabled: true, displayNumber: 42},
			want: ":42",
		},
		{
			name: "disabled falls back to empty",
			env:  &installEnv{displayEnabled: false, displayNumber: 42},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := managedDisplayFallback(tc.env); got != tc.want {
				t.Fatalf("managedDisplayFallback() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// run.go: runContainRun's service-posture namespace-asserter guard
// ---------------------------------------------------------------------------

func TestCovDispRunContainRunRequiresServiceNamespaceAsserter(t *testing.T) {
	runEnv := containRunEnv{
		probe:  allPassEnv(t),
		launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
		emitPosture: func(*config.Config, ed25519.PrivateKey, string, *probeEnv, []string) (postureEmission, error) {
			return postureEmission{}, nil
		},
		// assertServiceNamespace intentionally left nil.
	}
	err := runContainRun(context.Background(), nil, io.Discard, io.Discard, runEnv, containRunOptions{servicePrestart: true}, []string{"claude"})
	if err == nil || !strings.Contains(err.Error(), "service posture namespace assertion is unavailable") {
		t.Fatalf("err = %v, want the missing-asserter refusal", err)
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitGeneral {
		t.Errorf("exit code = %d, want ExitGeneral", cliutil.ExitCodeOf(err))
	}
}

// ---------------------------------------------------------------------------
// service_posture.go: runDefaultServicePosture
// ---------------------------------------------------------------------------

func TestCovDispRunDefaultServicePostureWiresPortAndDelegates(t *testing.T) {
	cmd := &cobra.Command{}
	err := runDefaultServicePosture(cmd, containRunOptions{port: 12345}, nil)
	if err == nil || !strings.Contains(err.Error(), "usage: pipelock contain run") {
		t.Fatalf("err = %v, want the empty-args usage refusal from the delegated runContainRun", err)
	}
}

// ---------------------------------------------------------------------------
// netns_forward.go: pure helpers
// ---------------------------------------------------------------------------

func TestCovDispNetnsForwardOptsDialNetworkAndAddress(t *testing.T) {
	for _, tc := range []struct {
		name        string
		opts        netnsForwardOpts
		wantNetwork string
		wantAddress string
	}{
		{
			name:        "unix target",
			opts:        netnsForwardOpts{target: "/run/pipelock/doorway.sock"},
			wantNetwork: "unix",
			wantAddress: "/run/pipelock/doorway.sock",
		},
		{
			name:        "tcp target",
			opts:        netnsForwardOpts{targetTCP: "127.0.0.1:8888"},
			wantNetwork: "tcp",
			wantAddress: "127.0.0.1:8888",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.opts.dialNetwork(); got != tc.wantNetwork {
				t.Fatalf("dialNetwork() = %q, want %q", got, tc.wantNetwork)
			}
			if got := tc.opts.dialAddress(); got != tc.wantAddress {
				t.Fatalf("dialAddress() = %q, want %q", got, tc.wantAddress)
			}
		})
	}
}

func TestCovDispListenerFromSystemdRejectsMismatchedEnv(t *testing.T) {
	t.Run("LISTEN_PID does not match this process", func(t *testing.T) {
		t.Setenv("LISTEN_PID", "0")
		t.Setenv("LISTEN_FDS", "1")
		_, err := listenerFromSystemd()
		if err == nil || !strings.Contains(err.Error(), "LISTEN_PID") || !strings.Contains(err.Error(), "not this process") {
			t.Fatalf("err = %v, want a LISTEN_PID mismatch refusal", err)
		}
	})

	t.Run("LISTEN_FDS is not exactly one", func(t *testing.T) {
		t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
		t.Setenv("LISTEN_FDS", "2")
		_, err := listenerFromSystemd()
		if err == nil || !strings.Contains(err.Error(), "expected exactly one socket from systemd") {
			t.Fatalf("err = %v, want a LISTEN_FDS refusal", err)
		}
	})

	t.Run("LISTEN_FDS is not numeric", func(t *testing.T) {
		t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
		t.Setenv("LISTEN_FDS", "not-a-number")
		_, err := listenerFromSystemd()
		if err == nil || !strings.Contains(err.Error(), "expected exactly one socket from systemd") {
			t.Fatalf("err = %v, want a LISTEN_FDS refusal", err)
		}
	})
}

// ---------------------------------------------------------------------------
// netns_forward.go: netnsForwardCmd delegating into runNetnsForward
// ---------------------------------------------------------------------------

func TestCovDispNetnsForwardCmdWrapsForwarderFailure(t *testing.T) {
	cmd := netnsForwardCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--listen", "127.0.0.1:0", "--target", filepath.Join(t.TempDir(), "missing.sock")})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "is not usable") {
		t.Fatalf("err = %v, want the forwarder's doorway refusal wrapped by the command", err)
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitGeneral {
		t.Errorf("exit code = %d, want ExitGeneral", cliutil.ExitCodeOf(err))
	}
}

func TestCovDispNetnsForwardCmdReturnsCleanlyOnCancel(t *testing.T) {
	target := newDoorwayEcho(t)
	addr := testport.ListenAddrs(t, 1)[0]

	cmd := netnsForwardCmd()
	out := &lockedBuffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--listen", addr, "--target", target})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	testwait.For(t, testwait.Deadline(5*time.Second), func() bool {
		return strings.Contains(out.String(), "contained-namespace proxy")
	}, "forwarder command never reported its listener")
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancel should be a clean shutdown through the command too, got %v", err)
		}
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("forwarder command did not stop on context cancellation")
	}
}

// ---------------------------------------------------------------------------
// netns_forward.go: systemd-listener source through the full runNetnsForward
// ---------------------------------------------------------------------------

func TestCovDispRunNetnsForwardSystemdListenerFailureIsWrapped(t *testing.T) {
	t.Setenv("LISTEN_PID", "0") // guaranteed mismatch regardless of ambient environment
	var out bytes.Buffer
	err := runNetnsForward(context.Background(), netnsForwardOpts{
		systemdListener: true,
		targetTCP:       "127.0.0.1:1", // targetTCP skips the pre-listen doorway stat check
	}, &out)
	if err == nil || !strings.Contains(err.Error(), "listen on systemd socket activation") {
		t.Fatalf("err = %v, want a wrapped systemd-listener failure", err)
	}
	if !strings.Contains(err.Error(), "LISTEN_PID") {
		t.Fatalf("err = %v, want the underlying LISTEN_PID detail preserved", err)
	}
}

// ---------------------------------------------------------------------------
// netns_forward.go: an accepted connection whose forward fails is logged,
// not silently dropped.
// ---------------------------------------------------------------------------

func TestCovDispRunNetnsForwardLogsPerConnectionFailure(t *testing.T) {
	staleDoorway := covDispStaleUnixSocket(t)
	addr := testport.ListenAddrs(t, 1)[0]

	out := &lockedBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runNetnsForward(ctx, netnsForwardOpts{listen: addr, target: staleDoorway}, out) }()

	testwait.For(t, testwait.Deadline(5*time.Second), func() bool {
		return strings.Contains(out.String(), "contained-namespace proxy")
	}, "forwarder never reported its listener")

	conn, dialErr := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if dialErr != nil {
		t.Fatalf("dial forwarder: %v", dialErr)
	}
	t.Cleanup(func() { _ = conn.Close() })

	testwait.For(t, testwait.Deadline(5*time.Second), func() bool {
		return strings.Contains(out.String(), "contained-namespace proxy connection failed")
	}, "forwarder never logged the failed per-connection forward")
	if !strings.Contains(out.String(), "dial host doorway") {
		t.Fatalf("connection-failure log missing the dial detail: %s", out.String())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("forwarder did not stop after cancel")
	}
}

// ---------------------------------------------------------------------------
// netns_forward.go: proxyOneNetnsConn returns cleanly on context cancel while
// a copy is still idle (the select's ctx.Done() branch, not the done branch).
// ---------------------------------------------------------------------------

func TestCovDispProxyOneNetnsConnReturnsOnContextCancel(t *testing.T) {
	doorway, received := covDispHoldOpenDoorway(t)

	agent, forwarded := net.Pipe()
	t.Cleanup(func() { _ = agent.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- proxyOneNetnsConn(ctx, forwarded, "unix", doorway) }()

	if err := agent.SetDeadline(time.Now().Add(testwait.Deadline(5 * time.Second))); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Write([]byte("x")); err != nil {
		t.Fatalf("write probe byte through the forwarder: %v", err)
	}
	select {
	case <-received:
		// The byte reached the doorway, so the upstream dial completed and
		// both copy goroutines are live: cancelling now is guaranteed to hit
		// the select's ctx.Done() branch rather than racing dial setup.
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("doorway never received the forwarded probe byte")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("proxyOneNetnsConn on cancel = %v, want nil", err)
		}
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("proxyOneNetnsConn did not return after context cancellation")
	}
}
