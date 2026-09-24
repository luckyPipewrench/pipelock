// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	displayUnitMarker = "# Managed by `pipelock contain install`."
	defaultXvfbPath   = "/usr/bin/Xvfb"
	// displaySocketWaitAttempts and displaySocketWaitInterval bound how long
	// ExecStartPost polls for the Xvfb Unix socket before chmod-ing it. Xvfb
	// on a slow or loaded first-boot host (cold page cache, contended CPU
	// under a fleet-wide install) has been observed to take longer than the
	// 5s a short poll budgets; 20s gives real headroom without leaving a
	// wedged Xvfb process spinning the unit's ExecStartPost indefinitely, and
	// failing the unit afterward (rather than silently continuing without
	// tightening the socket mode) keeps this fail-closed: a wide-open shared
	// socket is never left protected, either it is tightened or the unit is
	// down and probe 22 catches it.
	displaySocketWaitAttempts = 200
	displaySocketWaitInterval = "0.1"
)

func displayName(number int) string { return ":" + strconv.Itoa(number) }

func displaySocketPath(number int) string {
	return filepath.Join("/tmp/.X11-unix", "X"+strconv.Itoa(number))
}

// resolveLaunchDisplay picks the display a contained tool is launched with.
// An operator-supplied value always wins, so a real desktop session is
// unchanged. Otherwise the managed display is used when provisioning
// resolves to on, which for an omitted config means "this host has an X
// server".
func resolveLaunchDisplay(cfg *config.Config, operatorDisplay string, xvfbPresent bool) string {
	if strings.TrimSpace(operatorDisplay) != "" {
		return operatorDisplay
	}
	if cfg != nil && cfg.Containment.Display.IsEnabled(xvfbPresent) {
		return displayName(cfg.Containment.Display.EffectiveNumber())
	}
	return ""
}

func localDisplaySocket(display string) (string, bool) {
	if !strings.HasPrefix(display, ":") {
		return "", false
	}
	numberText := strings.TrimPrefix(display, ":")
	if before, _, ok := strings.Cut(numberText, "."); ok {
		numberText = before
	}
	number, err := strconv.Atoi(numberText)
	if err != nil || number < 0 || number > 999 {
		return "", false
	}
	return displaySocketPath(number), true
}

// xvfbInstalled reports whether the host has the X server this display is
// built on. It is the only input to the omitted-config default: provisioning
// happens where it can succeed and is skipped where it cannot, instead of
// failing an install on a host that will never run a browser.
func xvfbInstalled(env *installEnv) bool {
	if env == nil || env.stat == nil {
		return false
	}
	_, err := env.stat(env.xvfbPath)
	return err == nil
}

func loadContainmentDisplay(env *installEnv) (config.ContainmentDisplay, error) {
	cfg, err := config.LoadForInspection(managedPipelockConfigPath(env))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config.ContainmentDisplay{}, nil
		}
		return config.ContainmentDisplay{}, fmt.Errorf("load containment display config: %w", err)
	}
	return cfg.Containment.Display, nil
}

func renderAgentDisplayUnit(env *installEnv) string {
	number := env.displayNumber
	socket := displaySocketPath(number)
	return strings.Join([]string{
		displayUnitMarker,
		"[Unit]",
		"Description=Pipelock contained agent X display",
		"After=systemd-tmpfiles-setup.service",
		"",
		"[Service]",
		"Type=simple",
		"User=" + env.agentUserName,
		"Group=" + env.agentUserName,
		"UMask=0077",
		"ExecStart=" + env.xvfbPath + " " + displayName(number) + " -screen 0 1280x1024x24 -nolisten tcp -nolisten local -listen unix",
		"ExecStartPost=/usr/bin/bash -c 'for i in {1.." + strconv.Itoa(displaySocketWaitAttempts) + "}; do if [ -S \"$1\" ]; then chmod 0700 \"$1\"; exit; fi; sleep " + displaySocketWaitInterval + "; done; exit 1' _ " + socket,
		"Restart=on-failure",
		"RestartSec=2",
		"",
		"[Install]",
		"WantedBy=multi-user.target",
		"",
	}, "\n")
}

func captureDisplayPreState(ctx context.Context, env *installEnv) error {
	_, err := env.stat(env.displayUnitPath)
	env.prevDisplayUnitExisted = err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", env.displayUnitPath, err)
	}
	enabled, _, enabledErr := env.runCmd(ctx, "systemctl", "is-enabled", filepath.Base(env.displayUnitPath))
	active, _, activeErr := env.runCmd(ctx, "systemctl", "is-active", filepath.Base(env.displayUnitPath))
	if enabledErr != nil || activeErr != nil {
		return fmt.Errorf("inspect display unit state: %w", errors.Join(enabledErr, activeErr))
	}
	env.prevDisplayEnabled = strings.TrimSpace(enabled) == systemctlEnabled
	env.prevDisplayActive = strings.TrimSpace(active) == systemctlActive
	env.prevDisplayStateKnown = true
	return nil
}

// stepProvisionAgentDisplay installs, updates, or removes the optional
// agent-owned Xvfb display used by browser tools that have no headless
// mode. It must run before stepWriteContainedLaunchWrapper and
// stepWriteLaunchWrapper so env.displayEnabled/env.displayNumber are known
// when those wrappers render their systemd-run invocation.
func stepProvisionAgentDisplay() step {
	var removedManagedBody []byte
	return step{
		name: "provision-agent-display",
		desc: "provision the optional agent-owned Xvfb fallback display",
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			display, err := loadContainmentDisplay(env)
			if err != nil {
				return false, err
			}
			enabled := display.IsEnabled(xvfbInstalled(env))
			env.displayEnabled = enabled
			env.displayNumber = display.EffectiveNumber()
			if err := captureDisplayPreState(ctx, env); err != nil {
				return false, err
			}
			if !enabled {
				if !env.prevDisplayUnitExisted {
					return false, nil
				}
				body, readErr := env.readFile(env.displayUnitPath)
				if readErr != nil {
					return false, fmt.Errorf("read display unit: %w", readErr)
				}
				if !strings.HasPrefix(string(body), displayUnitMarker+"\n") {
					return false, fmt.Errorf("%s exists but is not Pipelock-managed", env.displayUnitPath)
				}
				removedManagedBody = append([]byte(nil), body...)
				if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", filepath.Base(env.displayUnitPath)); err != nil {
					return true, err
				}
				if err := restoreBackup(env, env.displayUnitPath); err != nil {
					return true, err
				}
				return true, runOrErr(ctx, env, "systemctl", "daemon-reload")
			}
			if _, err := env.stat(env.xvfbPath); err != nil {
				return false, fmt.Errorf("display provisioning requires %s: %w", env.xvfbPath, err)
			}
			changed, err := ensureContainmentUnit(env, env.displayUnitPath, renderAgentDisplayUnit(env))
			if err != nil {
				return changed, err
			}
			if err := runOrErr(ctx, env, "systemctl", "daemon-reload"); err != nil {
				return changed, err
			}
			if err := runOrErr(ctx, env, "systemctl", "enable", "--now", filepath.Base(env.displayUnitPath)); err != nil {
				return true, err
			}
			reconciled := !env.prevDisplayEnabled || !env.prevDisplayActive
			return changed || reconciled, nil
		},
		undo: func(ctx context.Context, env *installEnv) error {
			if removedManagedBody != nil {
				if err := backupAndWrite(env, env.displayUnitPath, removedManagedBody, modeUnitFile); err != nil {
					return err
				}
				if err := runOrErr(ctx, env, "systemctl", "daemon-reload"); err != nil {
					return err
				}
				unit := filepath.Base(env.displayUnitPath)
				if env.prevDisplayEnabled {
					if err := runOrErr(ctx, env, "systemctl", "enable", unit); err != nil {
						return err
					}
				}
				if env.prevDisplayActive {
					return runOrErr(ctx, env, "systemctl", "start", unit)
				}
				return nil
			}
			return restoreAgentDisplay(ctx, env)
		},
	}
}

func restoreAgentDisplay(ctx context.Context, env *installEnv) error {
	unit := filepath.Base(env.displayUnitPath)
	if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", unit); err != nil {
		return err
	}
	if err := restoreBackup(env, env.displayUnitPath); err != nil {
		return err
	}
	if err := runOrErr(ctx, env, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if env.prevDisplayStateKnown && env.prevDisplayEnabled {
		if err := runOrErr(ctx, env, "systemctl", "enable", unit); err != nil {
			return err
		}
	}
	if env.prevDisplayStateKnown && env.prevDisplayActive {
		return runOrErr(ctx, env, "systemctl", "start", unit)
	}
	return nil
}

func actionRemoveAgentDisplay() step {
	return step{
		name: "remove-agent-display",
		desc: "stop and remove the managed agent display unit",
		undo: func(ctx context.Context, env *installEnv) error {
			if env.displayUnitPath == "" {
				return nil
			}
			env.prevDisplayStateKnown = false
			return restoreAgentDisplay(ctx, env)
		},
	}
}

// isManagedDisplayUnitFile reports whether the unit file at path is the
// Pipelock-managed display unit for agentUserName: it carries the managed
// marker header and its [Service] block has the exact User/Group/UMask
// entries and the network-isolation flags renderAgentDisplayUnit emits. This
// is deliberately looser than probeAgentDisplay's full comparison (it does
// not pin the display number or the Xvfb path) because its only job is
// telling the network-namespace probe's live-process audit "this process
// belongs to the display service we installed", not re-auditing the display
// feature itself; probe 22 (agent_display) owns that.
func isManagedDisplayUnitFile(readFile func(string) ([]byte, error), path, agentUserName string) bool {
	body, err := readFile(path)
	if err != nil {
		return false
	}
	text := string(body)
	if !strings.HasPrefix(text, displayUnitMarker+"\n") {
		return false
	}
	for key, value := range map[string]string{
		"User":  agentUserName,
		"Group": agentUserName,
		"UMask": "0077",
	} {
		if !unitHasExactEntry(text, "Service", key, value) {
			return false
		}
	}
	return strings.Contains(text, "ExecStart=") && strings.Contains(text, " -nolisten tcp -nolisten local -listen unix")
}

func probeAgentDisplay(ctx context.Context, env *probeEnv) (string, string) {
	cfg, err := config.LoadForInspection(env.configPath)
	configAbsent := false
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return statusFail, fmt.Sprintf("read containment display config: %v", err)
		}
		configAbsent = true
		cfg = config.Defaults()
	}
	display := cfg.Containment.Display
	unit := filepath.Base(env.displayUnitPath)
	xvfbPresent := true
	if env.stat != nil {
		_, statErr := env.stat(env.xvfbPath)
		xvfbPresent = statErr == nil
	}
	if !display.IsEnabled(xvfbPresent) {
		state, _, runErr := env.runCmd(ctx, "systemctl", "is-active", unit)
		if runErr != nil {
			return statusFail, fmt.Sprintf("inspect disabled display unit: %v", runErr)
		}
		if strings.TrimSpace(state) == systemctlActive {
			return statusFail, "containment display is disabled in config but its unit remains active"
		}
		if configAbsent {
			return statusPass, "managed config is absent and no display unit is active"
		}
		return statusPass, "containment display fallback is disabled"
	}
	number := display.EffectiveNumber()
	body, err := env.readFile(env.displayUnitPath)
	if err != nil {
		return statusFail, fmt.Sprintf("read display unit: %v", err)
	}
	// Carry the probe's own X server path into the expectation, or the
	// rendered comparison asks for an empty ExecStart and every real unit
	// fails a check that looks like a tampering alarm.
	checkEnv := &installEnv{agentUserName: env.agentUserName, displayNumber: number, xvfbPath: env.xvfbPath}
	renderedLines := strings.Split(renderAgentDisplayUnit(checkEnv), "\n")
	wantExec := strings.TrimPrefix(renderedLines[10], "ExecStart=")
	wantExecPost := strings.TrimPrefix(renderedLines[11], "ExecStartPost=")
	for key, value := range map[string]string{
		"User":          env.agentUserName,
		"Group":         env.agentUserName,
		"UMask":         "0077",
		"ExecStart":     wantExec,
		"ExecStartPost": wantExecPost,
	} {
		if !unitHasExactEntry(string(body), "Service", key, value) {
			return statusFail, fmt.Sprintf("display unit is missing exact %s=%s", key, value)
		}
	}
	if !strings.Contains(string(body), " -nolisten tcp -nolisten local -listen unix") {
		return statusFail, "display unit does not disable TCP and abstract-local transports"
	}
	for _, query := range []struct{ verb, want string }{{"is-enabled", systemctlEnabled}, {"is-active", systemctlActive}} {
		out, _, runErr := env.runCmd(ctx, "systemctl", query.verb, unit)
		if runErr != nil || strings.TrimSpace(out) != query.want {
			return statusFail, fmt.Sprintf("display unit %s is %s, want %s", query.verb, oneLine(out), query.want)
		}
	}
	socketPath := displaySocketPath(number)
	if env.displaySocket != nil {
		socketPath = env.displaySocket(number)
	}
	info, err := env.stat(socketPath)
	if err != nil {
		return statusFail, fmt.Sprintf("stat display socket: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o700 {
		return statusFail, fmt.Sprintf("display socket mode is %s, want socket 0700", info.Mode())
	}
	agent, err := env.lookupUser(env.agentUserName)
	if err != nil {
		return statusFail, fmt.Sprintf("lookup display owner: %v", err)
	}
	wantUID, err := strconv.ParseUint(agent.Uid, 10, 32)
	if err != nil {
		return statusFail, fmt.Sprintf("parse display owner uid: %v", err)
	}
	ownerUID, ok := fileOwnerUID(info)
	if !ok || uint64(ownerUID) != wantUID {
		return statusFail, "display socket is not owned by the contained agent uid"
	}
	return statusPass, fmt.Sprintf("display %s is active with an agent-owned 0700 Unix socket", displayName(number))
}
