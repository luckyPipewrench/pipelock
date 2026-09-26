// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	displayUnitMarker = "# Managed by `pipelock contain install`."
	defaultXvfbPath   = "/usr/bin/Xvfb"
	defaultXvncPath   = "/usr/bin/Xvnc"
	viewerRFBSocket   = "/run/pipelock-agent-display/rfb.sock"
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
	// An Xauthority record is about 50 bytes; cap agent-owned input before
	// privileged provisioning allocates memory for a rollback copy.
	maxDisplayAuthorityBytes = 64 << 10
)

var errDisplayAuthorityOversize = errors.New("xauthority file exceeds size limit")

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

// xvncCandidates is the one search order install, verify, and doctor share.
// It deliberately ignores PATH: install runs as root, whose PATH puts
// /usr/local/bin first, while verify rebuilds the expected unit from this
// list. Two different lookups would render one ExecStart and expect another,
// failing every verify on hosts where they disagree. Debian ships the binary
// as Xtigervnc with Xvnc as an optional alternative.
var xvncCandidates = []string{defaultXvncPath, "/usr/bin/Xtigervnc", "/usr/local/bin/Xvnc"}

// resolveXvncPath returns the first installed candidate, or "" when none is.
func resolveXvncPath(stat func(string) (os.FileInfo, error)) string {
	for _, path := range xvncCandidates {
		if _, err := stat(path); err == nil {
			return path
		}
	}
	return ""
}

func findXvnc(env *installEnv) (string, error) {
	if env.xvncPath != "" {
		if _, err := env.stat(env.xvncPath); err == nil {
			return env.xvncPath, nil
		}
	}
	if path := resolveXvncPath(env.stat); path != "" {
		return path, nil
	}
	return "", fmt.Errorf("TigerVNC Xvnc missing; install %s", xvncPackage(env.platformFamily))
}

func xvncPackage(family string) string {
	if family == platformFamilyDebian {
		return "tigervnc-standalone-server"
	}
	body, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "TigerVNC Xvnc"
	}
	return xvncPackageForOSRelease(string(body))
}

func xvncPackageForOSRelease(body string) string {
	fields := make(map[string]string)
	for _, line := range strings.Split(body, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			fields[key] = strings.Trim(value, `"'`)
		}
	}
	if fields["ID"] != "fedora" {
		return "TigerVNC Xvnc"
	}
	version, err := strconv.Atoi(fields["VERSION_ID"])
	if err != nil {
		return "TigerVNC Xvnc"
	}
	if version >= 44 {
		return "tigervnc-x11-server"
	}
	return "tigervnc-server-minimal"
}

func loadContainmentDisplay(env *installEnv) (config.ContainmentDisplay, error) {
	cfg, err := config.LoadForInspection(managedPipelockConfigPath(env))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config.ContainmentDisplay{}, nil
		}
		return config.ContainmentDisplay{}, fmt.Errorf("load containment display config: %w", err)
	}
	if err := cfg.Containment.Display.Validate(); err != nil {
		return config.ContainmentDisplay{}, err
	}
	return cfg.Containment.Display, nil
}

// managedXSocketMode is the X socket mode the display unit sets after start:
// only the agent may connect, so no other local user can reach its display.
const managedXSocketMode os.FileMode = 0o700

func renderAgentDisplayUnit(env *installEnv) string {
	number := env.displayNumber
	socket := displaySocketPath(number)
	if env.displayConfig.EffectiveBackend() == "xvnc" {
		rfbSocket := displayRFBPath(env.rfbSocketPath)
		xvnc := env.xvncPath
		if xvnc == "" {
			xvnc = defaultXvncPath
		}
		rfbGroup, rfbMode := viewerUserName, "0600"
		if viewerRFBEnabled(env.displayConfig) {
			rfbMode = "0660"
		}
		clipboard := " -AcceptCutText=0 -SendCutText=0 -SendPrimary=0 -SetPrimary=0"
		if env.displayConfig.Viewer.Clipboard != nil && *env.displayConfig.Viewer.Clipboard {
			clipboard = ""
		}
		post := "chmod 0700 \"$1\" || exit 1"
		// TigerVNC Xvnc.man documents the RFB socket, TCP disable, and clipboard parameters:
		// https://github.com/TigerVNC/tigervnc/blob/master/unix/xserver/hw/vnc/Xvnc.man
		return strings.Join([]string{
			displayUnitMarker, "[Unit]", "Description=Pipelock contained agent X display",
			"After=systemd-tmpfiles-setup.service", "", "[Service]", "Type=simple",
			"User=" + env.agentUserName, "Group=" + rfbGroup, "UMask=0077",
			// RuntimeDirectory with User= would make the directory agent-owned.
			// A privileged pre-start action owns it as root while Xvnc gets only
			// group create/traverse access. Contained agent processes lack that gid.
			"ExecStartPre=+/usr/bin/install -d -o root -g " + viewerUserName + " -m 0730 /run/pipelock-agent-display",
			"ExecStart=" + xvnc + " " + displayName(number) + " -auth " + displayAuthorityPath(env) + " -geometry " + env.displayConfig.EffectiveGeometry() + " -depth 24 -nolisten tcp -nolisten local -listen unix -rfbunixpath " + rfbSocket + " -rfbunixmode " + rfbMode + " -rfbport -1 -SecurityTypes None -AlwaysShared" + clipboard,
			"ExecStartPost=/usr/bin/bash -c 'for i in {1.." + strconv.Itoa(displaySocketWaitAttempts) + "}; do if [ -S \"$1\" ] && [ -S \"$2\" ]; then " + post + "; exit; fi; sleep " + displaySocketWaitInterval + "; done; exit 1' _ " + socket + " " + rfbSocket,
			"Restart=on-failure", "RestartSec=2", "", "[Install]", "WantedBy=multi-user.target", "",
		}, "\n")
	}
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
		"ExecStart=" + env.xvfbPath + " " + displayName(number) + " -auth " + displayAuthorityPath(env) + " -screen 0 " + env.displayConfig.EffectiveGeometry() + "x24 -nolisten tcp -nolisten local -listen unix",
		"ExecStartPost=/usr/bin/bash -c 'for i in {1.." + strconv.Itoa(displaySocketWaitAttempts) + "}; do if [ -S \"$1\" ]; then chmod 0700 \"$1\"; exit; fi; sleep " + displaySocketWaitInterval + "; done; exit 1' _ " + socket,
		"Restart=on-failure",
		"RestartSec=2",
		"",
		"[Install]",
		"WantedBy=multi-user.target",
		"",
	}, "\n")
}

func displayRFBPath(override string) string {
	if override != "" {
		return override
	}
	return viewerRFBSocket
}

func legacyViewerSocketPath(agentHome string) string {
	return filepath.Join(agentHome, ".local/state/pipelock/display/rfb.sock")
}

// viewerTraverseDirs lists the legacy home-directory ACL chain for upgrade cleanup.
func viewerTraverseDirs(agentHome string) []string {
	dirs := []string{agentHome}
	rel, err := filepath.Rel(agentHome, filepath.Dir(filepath.Join(agentHome, ".local/state/pipelock/display/rfb.sock")))
	if err != nil {
		return dirs
	}
	dir := agentHome
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		dir = filepath.Join(dir, part)
		dirs = append(dirs, dir)
	}
	return dirs
}

// removeViewerTraverseACL removes the obsolete home-socket access independently
// of the unit text. A failed cleanup is retried on the next install or rollback.
func removeViewerTraverseACL(ctx context.Context, env *installEnv) error {
	if env.agentHome == "" {
		return nil
	}
	stat := env.lstat
	if stat == nil {
		stat = env.stat
	}
	if stat == nil {
		return errors.New("legacy viewer ACL stat unavailable")
	}
	for _, dir := range viewerTraverseDirs(env.agentHome) {
		info, err := stat(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("inspect viewer traverse directory %s: %w", dir, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("legacy viewer traverse path %s is not a real directory", dir)
		}
		if err := revokeViewerTraverseDir(ctx, env, dir); err != nil {
			return err
		}
	}
	socket := legacyViewerSocketPath(env.agentHome)
	info, err := stat(socket)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect legacy RFB socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("legacy RFB path %s is not a socket", socket)
	}
	if err := revokeViewerTraverseDir(ctx, env, socket); err != nil {
		return err
	}
	if err := env.removeFile(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove legacy RFB socket: %w", err)
	}
	return nil
}

func revokeViewerTraverseDir(ctx context.Context, env *installEnv, dir string) error {
	acl, err := readAccessACL(ctx, env.runCmd, dir)
	if err != nil {
		return fmt.Errorf("read legacy viewer ACL on %s: %w", dir, err)
	}
	if env.proxyUserName != "" {
		if err := runOrErr(ctx, env, "setfacl", "-x", "u:"+env.proxyUserName, dir); err != nil {
			return fmt.Errorf("revoke viewer traverse ACL on %s: %w", dir, err)
		}
	}
	for _, raw := range strings.Split(acl, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		parts := strings.Split(line, ":")
		prefix := ""
		if len(parts) == 4 && parts[0] == "default" {
			prefix, parts = "d:", parts[1:]
		}
		if len(parts) != 3 || parts[1] == "" || (parts[0] != "user" && parts[0] != "group") {
			continue
		}
		if parts[0] == "user" && parts[1] == env.operatorUser {
			continue
		}
		if parts[0] == "user" && parts[1] == env.proxyUserName && prefix == "" {
			continue
		}
		entry := prefix + string(parts[0][0]) + ":" + parts[1]
		if err := runOrErr(ctx, env, "setfacl", "-x", entry, dir); err != nil {
			return fmt.Errorf("revoke viewer traverse ACL on %s: %w", dir, err)
		}
	}
	// setfacl normally recalculates the mask after -x. An old mask with no
	// remaining named entries must not retain permissions beyond group::.
	groupPerms := aclGroupPermissions(acl)
	if groupPerms == "" {
		return fmt.Errorf("legacy viewer ACL on %s lacks group permissions", dir)
	}
	if err := runOrErr(ctx, env, "setfacl", "--mask", "-m", "g::"+groupPerms, dir); err != nil {
		return fmt.Errorf("restore legacy viewer ACL mask on %s: %w", dir, err)
	}
	return nil
}

func aclGroupPermissions(acl string) string {
	for _, line := range strings.Split(acl, "\n") {
		if strings.HasPrefix(line, "group::") {
			return strings.TrimSpace(strings.SplitN(strings.TrimPrefix(line, "group::"), "#", 2)[0])
		}
	}
	return ""
}

func checkLegacyViewerACL(ctx context.Context, run runCommand, stat func(string) (os.FileInfo, error), home, operator string) error {
	if home == "" {
		return nil
	}
	if stat == nil {
		return errors.New("legacy viewer ACL stat unavailable")
	}
	for _, dir := range viewerTraverseDirs(home) {
		info, err := stat(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect legacy viewer ACL: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("legacy viewer path %s is not a real directory", dir)
		}
		acl, err := readAccessACL(ctx, run, dir)
		if err != nil {
			return fmt.Errorf("read legacy viewer ACL on %s: %w", dir, err)
		}
		group, mask, operatorEntry := "", "", false
		for _, raw := range strings.Split(acl, "\n") {
			line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
			parts := strings.Split(line, ":")
			// getfacl -p prints the unqualified group and mask entries as
			// "group::perm" / "mask::perm" (tag, empty qualifier, perms), so
			// these are 3 fields with an empty middle field, not 2.
			if len(parts) == 3 && parts[1] == "" {
				switch parts[0] {
				case "group":
					group = parts[2]
				case "mask":
					mask = parts[2]
				}
			}
			if len(parts) == 4 && parts[0] == "default" && (parts[1] == "user" || parts[1] == "group") && parts[2] != "" && (parts[1] != "user" || parts[2] != operator) {
				return fmt.Errorf("legacy viewer ACL retains default named entry on %s", dir)
			}
			if len(parts) == 3 && parts[1] != "" {
				if parts[0] == "user" && parts[1] == operator {
					operatorEntry = true
				} else if parts[0] == "user" || parts[0] == "group" {
					return fmt.Errorf("legacy viewer ACL retains non-operator entry on %s", dir)
				}
			}
		}
		if group == "" || (!operatorEntry && mask != "" && mask != group) {
			return fmt.Errorf("legacy viewer ACL mask is not restored on %s", dir)
		}
	}
	socket := legacyViewerSocketPath(home)
	if _, err := stat(socket); err == nil {
		return fmt.Errorf("legacy RFB socket remains at %s", socket)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect legacy RFB socket: %w", err)
	}
	return nil
}

func viewerRFBEnabled(display config.ContainmentDisplay) bool {
	return display.Viewer.Enabled != nil && *display.Viewer.Enabled
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
	var previousAuthority []byte
	var previousAuthorityExisted bool
	return step{
		name: "provision-agent-display",
		desc: "provision the optional agent-owned Xvfb fallback display",
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			display, err := loadContainmentDisplay(env)
			if err != nil {
				return false, err
			}
			enabled := display.IsEnabled(xvfbInstalled(env))
			env.displayConfig = display
			if err := checkViewerOperatorIdentity(env); err != nil {
				return false, err
			}
			if display.EffectiveBackend() == "xvnc" && enabled {
				path, findErr := findXvnc(env)
				if findErr != nil {
					return false, findErr
				}
				env.xvncPath = path
			}
			env.displayEnabled = enabled
			env.displayNumber = display.EffectiveNumber()
			if err := captureDisplayPreState(ctx, env); err != nil {
				return false, err
			}
			// Revoke before changing the unit so a failed revoke remains retryable.
			if err := removeViewerTraverseACL(ctx, env); err != nil {
				return false, err
			}
			if !enabled {
				if !env.prevDisplayUnitExisted {
					previousAuthority, previousAuthorityExisted, err = readDisplayAuthority(env)
					if err != nil {
						return false, err
					}
					err := removeDisplayAuthority(env)
					return err == nil && previousAuthorityExisted, err
				}
				body, readErr := env.readFile(env.displayUnitPath)
				if readErr != nil {
					return false, fmt.Errorf("read display unit: %w", readErr)
				}
				if !strings.HasPrefix(string(body), displayUnitMarker+"\n") {
					return false, fmt.Errorf("%s exists but is not Pipelock-managed", env.displayUnitPath)
				}
				previousAuthority, previousAuthorityExisted, err = readDisplayAuthority(env)
				if err != nil {
					return false, err
				}
				removedManagedBody = append([]byte(nil), body...)
				if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", filepath.Base(env.displayUnitPath)); err != nil {
					return true, err
				}
				if err := restoreBackup(env, env.displayUnitPath); err != nil {
					return true, err
				}
				if err := removeDisplayAuthority(env); err != nil {
					return true, err
				}
				return true, runOrErr(ctx, env, "systemctl", "daemon-reload")
			}
			if display.EffectiveBackend() == "xvfb" {
				if _, err := env.stat(env.xvfbPath); err != nil {
					return false, fmt.Errorf("display provisioning requires %s: %w", env.xvfbPath, err)
				}
			}
			previousAuthority, previousAuthorityExisted, err = readDisplayAuthority(env)
			if err != nil {
				return false, err
			}
			if err := writeDisplayAuthority(env, rand.Reader); err != nil {
				return false, errors.Join(err, restoreDisplayAuthority(env, previousAuthority, previousAuthorityExisted))
			}
			_, err = ensureContainmentUnit(env, env.displayUnitPath, renderAgentDisplayUnit(env))
			if err != nil {
				return true, err
			}
			if err := runOrErr(ctx, env, "systemctl", "daemon-reload"); err != nil {
				return true, err
			}
			if err := runOrErr(ctx, env, "systemctl", "enable", "--now", filepath.Base(env.displayUnitPath)); err != nil {
				return true, err
			}
			// Every run writes a fresh cookie, so a running display restarts to read it.
			if env.prevDisplayActive {
				if err := runOrErr(ctx, env, "systemctl", "restart", filepath.Base(env.displayUnitPath)); err != nil {
					return true, err
				}
			}
			// A prior install may have granted the proxy traverse access to the
			// agent home. The runtime socket never needs that grant, including
			// when the viewer remains enabled across an upgrade.
			if display.EffectiveBackend() == "xvnc" {
				stat := env.lstat
				if stat == nil {
					stat = env.stat
				}
				if err := checkDisplaySocket(stat, displaySocketPath(env.displayNumber), managedXSocketMode); err != nil {
					return true, fmt.Errorf("x display socket: %w", err)
				}
				rfb := displayRFBPath(env.rfbSocketPath)
				if err := checkRFBRuntimeDirectory(stat, env.lookupUser, rfb); err != nil {
					return true, err
				}
				mode := os.FileMode(0o600)
				if viewerRFBEnabled(display) {
					mode = 0o660
				}
				if err := checkDisplaySocket(stat, rfb, mode); err != nil {
					return true, fmt.Errorf("RFB socket: %w", err)
				}
				if viewerRFBEnabled(display) {
					if err := checkViewerRFBGroup(stat, env.lookupUser, rfb); err != nil {
						return true, err
					}
				}
				if env.lookupUser != nil {
					user, err := env.lookupUser(env.agentUserName)
					if err != nil {
						return true, fmt.Errorf("lookup RFB owner: %w", err)
					}
					uid, err := strconv.ParseUint(user.Uid, 10, 32)
					if err != nil {
						return true, fmt.Errorf("parse RFB owner uid: %w", err)
					}
					for _, path := range []string{displaySocketPath(env.displayNumber), rfb} {
						info, err := stat(path)
						if err != nil {
							return true, fmt.Errorf("stat display socket %s: %w", path, err)
						}
						ownerUID, ok := fileOwnerUID(info)
						if !ok || uint64(ownerUID) != uid {
							return true, fmt.Errorf("display socket %s is not owned by the contained agent", path)
						}
					}
				}
			}
			return true, nil
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
				if err := restoreDisplayAuthority(env, previousAuthority, previousAuthorityExisted); err != nil {
					return err
				}
				if env.prevDisplayActive {
					return runOrErr(ctx, env, "systemctl", "start", unit)
				}
				return nil
			}
			// Put the previous cookie back before the display restarts, so the
			// restored Xvfb and the Xauthority file carry the same cookie.
			if err := restoreDisplayAuthority(env, previousAuthority, previousAuthorityExisted); err != nil {
				return err
			}
			return restoreAgentDisplay(ctx, env)
		},
	}
}

func checkDisplaySocket(stat func(string) (os.FileInfo, error), path string, mode os.FileMode) error {
	info, err := stat(path)
	if err != nil {
		return fmt.Errorf("%s missing: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != mode {
		return fmt.Errorf("%s is %s, want socket %04o", path, info.Mode(), mode)
	}
	return nil
}

func checkRFBRuntimeDirectory(stat func(string) (os.FileInfo, error), lookup lookupUserFunc, socket string) error {
	info, err := stat(filepath.Dir(socket))
	if err != nil {
		return fmt.Errorf("RFB runtime directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o730 {
		return fmt.Errorf("RFB runtime directory mode is %s, want 0730", info.Mode())
	}
	if lookup == nil {
		return errors.New("RFB runtime identity lookup unavailable")
	}
	viewer, err := lookup(viewerUserName)
	if err != nil {
		return fmt.Errorf("RFB runtime group: %w", err)
	}
	group, err := strconv.ParseUint(viewer.Gid, 10, 32)
	if err != nil {
		return fmt.Errorf("RFB runtime group: %w", err)
	}
	uid, uidOK := fileOwnerUID(info)
	gid, gidOK := fileOwnerGID(info)
	if !uidOK || !gidOK || uid != 0 || uint64(gid) != group {
		return errors.New("RFB runtime directory has wrong owner or group")
	}
	return nil
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
				return removeViewerTraverseACL(ctx, env)
			}
			env.prevDisplayStateKnown = false
			restoreErr := restoreAgentDisplay(ctx, env)
			authorityErr := removeDisplayAuthority(env)
			aclErr := removeViewerTraverseACL(ctx, env)
			return errors.Join(restoreErr, authorityErr, aclErr)
		},
	}
}

const (
	displayAuthorityFamilyLocal = 256
	displayAuthorityName        = "MIT-MAGIC-COOKIE-1"
	displayAuthorityCookieSize  = 16
	displayAuthorityFileMode    = 0o600
)

func displayAuthorityPath(env *installEnv) string {
	if env != nil && env.displayAuthorityPath != "" {
		return env.displayAuthorityPath
	}
	return defaultDisplayAuthorityPath
}

func encodeDisplayAuthority(hostname, displayNumber string, cookie []byte) ([]byte, error) {
	if len(cookie) != displayAuthorityCookieSize {
		return nil, fmt.Errorf("xauthority cookie has %d bytes, want %d", len(cookie), displayAuthorityCookieSize)
	}
	var out strings.Builder
	out.Grow(12 + len(hostname) + len(displayNumber) + len(displayAuthorityName) + len(cookie))
	putU16 := func(n uint16) {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], n)
		out.Write(b[:])
	}
	putField := func(s []byte) error {
		if len(s) > int(^uint16(0)) {
			return errors.New("xauthority field is too long")
		}
		length := len(s)
		out.WriteByte(byte((length >> 8) & 0xff))
		out.WriteByte(byte(length & 0xff))
		out.Write(s)
		return nil
	}
	putU16(displayAuthorityFamilyLocal)
	for _, field := range [][]byte{[]byte(hostname), []byte(displayNumber), []byte(displayAuthorityName), cookie} {
		if err := putField(field); err != nil {
			return nil, err
		}
	}
	return []byte(out.String()), nil
}

func writeDisplayAuthority(env *installEnv, random io.Reader) error {
	if random == nil {
		return errors.New("xauthority random source is nil")
	}
	path := displayAuthorityPath(env)
	dir := filepath.Dir(path)
	if err := ensureDisplayAuthorityDir(env, dir); err != nil {
		return err
	}
	cookie := make([]byte, displayAuthorityCookieSize)
	if _, err := io.ReadFull(random, cookie); err != nil {
		return fmt.Errorf("generate Xauthority cookie: %w", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("get hostname for Xauthority record: %w", err)
	}
	data, err := encodeDisplayAuthority(hostname, strconv.Itoa(env.displayNumber), cookie)
	if err != nil {
		return err
	}
	if err := ensureSafeWriteTarget(env, path); err != nil {
		return err
	}
	if err := env.writeFile(path, data, displayAuthorityFileMode); err != nil {
		return fmt.Errorf("write Xauthority file: %w", err)
	}
	uid, gid, err := uidGidFor(env, env.agentUserName)
	if err != nil {
		return errors.Join(err, env.removeFile(path))
	}
	if err := env.chown(path, uid, gid); err != nil {
		removeErr := env.removeFile(path)
		return errors.Join(fmt.Errorf("chown Xauthority file: %w", err), removeErr)
	}
	return nil
}

func ensureDisplayAuthorityDir(env *installEnv, dir string) error {
	clean := filepath.Clean(dir)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("xauthority state directory %s is not absolute", clean)
	}
	if err := rejectSymlinkParents(env, dir); err != nil {
		return err
	}
	for current := clean; ; current = filepath.Dir(current) {
		info, err := env.lstat(current)
		if errors.Is(err, os.ErrNotExist) && current == clean {
			// The state directory may be created after validating every parent.
		} else if err != nil {
			return fmt.Errorf("stat Xauthority directory %s: %w", current, err)
		} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("xauthority parent %s is not a real directory", current)
		} else if owner, ok := fileOwnerUID(info); !ok || owner != 0 {
			return fmt.Errorf("xauthority parent %s is not root-owned", current)
		} else if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("xauthority parent %s is writable by non-root users", current)
		}
		if current == string(os.PathSeparator) {
			break
		}
	}
	info, err := env.lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		if err := env.mkdirAll(clean, 0o711); err != nil {
			return fmt.Errorf("create Xauthority state directory: %w", err)
		}
		info, err = env.lstat(clean)
	}
	if err != nil {
		return fmt.Errorf("stat Xauthority state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("xauthority state path %s is not a real directory", clean)
	}
	owner, ok := fileOwnerUID(info)
	if !ok || owner != 0 {
		return fmt.Errorf("xauthority state directory %s is not root-owned", clean)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("xauthority state directory %s is writable by non-root users", clean)
	}
	if info.Mode().Perm() != 0o711 {
		if err := env.chmod(clean, 0o711); err != nil {
			return fmt.Errorf("chmod Xauthority state directory: %w", err)
		}
	}
	return nil
}

func readDisplayAuthority(env *installEnv) ([]byte, bool, error) {
	path := displayAuthorityPath(env)
	reader := env.readFileBounded
	if reader == nil {
		reader = readContainFileBounded
	}
	data, err := reader(path, maxDisplayAuthorityBytes)
	if errors.Is(err, errDisplayAuthorityOversize) {
		return nil, false, fmt.Errorf("xauthority file %s exceeds the size limit; remove or reduce it before provisioning the display: %w", path, err)
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read Xauthority file: %w", err)
	}
	return data, true, nil
}

func readContainFileBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read bounded file: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w (%d bytes)", errDisplayAuthorityOversize, limit)
	}
	return data, nil
}

func removeDisplayAuthority(env *installEnv) error {
	err := env.removeFile(displayAuthorityPath(env))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove Xauthority file: %w", err)
	}
	return nil
}

func restoreDisplayAuthority(env *installEnv, data []byte, existed bool) error {
	if !existed {
		return removeDisplayAuthority(env)
	}
	path := displayAuthorityPath(env)
	if err := ensureDisplayAuthorityDir(env, filepath.Dir(path)); err != nil {
		return err
	}
	if err := ensureSafeWriteTarget(env, path); err != nil {
		return err
	}
	if err := env.writeFile(path, data, displayAuthorityFileMode); err != nil {
		return fmt.Errorf("restore Xauthority file: %w", err)
	}
	uid, gid, err := uidGidFor(env, env.agentUserName)
	if err != nil {
		return err
	}
	if err := env.chown(path, uid, gid); err != nil {
		return fmt.Errorf("restore Xauthority ownership: %w", err)
	}
	return nil
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
		"UMask": "0077",
	} {
		if !unitHasExactEntry(text, "Service", key, value) {
			return false
		}
	}
	agentGroup := unitHasExactEntry(text, "Service", "Group", agentUserName)
	viewerGroup := unitHasExactEntry(text, "Service", "Group", viewerUserName) && strings.Contains(text, " -rfbunixpath "+viewerRFBSocket)
	if agentGroup || viewerGroup {
		return strings.Contains(text, "ExecStart=") && strings.Contains(text, " -nolisten tcp -nolisten local -listen unix")
	}
	return false
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
	checkEnv := &installEnv{agentUserName: env.agentUserName, proxyUserName: env.proxyUserName, agentHome: env.agentHome, rfbSocketPath: env.rfbSocketPath, displayNumber: number, xvfbPath: env.xvfbPath, xvncPath: env.xvncPath, displayConfig: display}
	renderedLines := strings.Split(renderAgentDisplayUnit(checkEnv), "\n")
	wantExec, wantExecPost := "", ""
	wantGroup := env.agentUserName
	if display.EffectiveBackend() == "xvnc" {
		wantGroup = viewerUserName
	}
	for _, line := range renderedLines {
		if strings.HasPrefix(line, "ExecStart=") {
			wantExec = strings.TrimPrefix(line, "ExecStart=")
		}
		if strings.HasPrefix(line, "ExecStartPost=") {
			wantExecPost = strings.TrimPrefix(line, "ExecStartPost=")
		}
	}
	for key, value := range map[string]string{
		"User":          env.agentUserName,
		"Group":         wantGroup,
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
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != managedXSocketMode {
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
	return statusPass, fmt.Sprintf("%s display %s is active with an agent-owned 0700 Unix socket", display.EffectiveBackend(), displayName(number))
}

func probeAgentDisplayRFB(ctx context.Context, env *probeEnv) (string, string) {
	cfg, err := config.LoadForInspection(env.configPath)
	if err != nil {
		return statusFail, fmt.Sprintf("read containment display config: %v", err)
	}
	if cfg.Containment.Display.EffectiveBackend() != "xvnc" {
		return statusPass, "RFB display is not configured"
	}
	body, err := env.readFile(env.displayUnitPath)
	if err != nil {
		return statusFail, fmt.Sprintf("read display unit: %v", err)
	}
	path := displayRFBPath(env.rfbSocketPath)
	modeText := "0600"
	if viewerRFBEnabled(cfg.Containment.Display) {
		modeText = "0660"
	}
	if !strings.Contains(string(body), " -rfbunixpath "+path+" -rfbunixmode "+modeText+" -rfbport -1 ") {
		return statusFail, "display unit must disable TCP RFB and use the managed Unix socket"
	}
	lstat := env.lstat
	if lstat == nil {
		lstat = env.stat
	}
	info, err := lstat(path)
	if err != nil {
		return statusFail, fmt.Sprintf("RFB socket missing; rerun contain install: %v", err)
	}
	mode := os.FileMode(0o600)
	if viewerRFBEnabled(cfg.Containment.Display) {
		mode = 0o660
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != mode {
		return statusFail, fmt.Sprintf("RFB socket mode is %s, want socket %04o", info.Mode(), mode)
	}
	if viewerRFBEnabled(cfg.Containment.Display) {
		if err := checkViewerRFBGroup(lstat, env.lookupUser, path); err != nil {
			return statusFail, err.Error()
		}
	}
	agent, err := env.lookupUser(env.agentUserName)
	if err != nil {
		return statusFail, fmt.Sprintf("lookup RFB owner: %v", err)
	}
	uid, err := strconv.ParseUint(agent.Uid, 10, 32)
	if err != nil {
		return statusFail, fmt.Sprintf("parse RFB owner uid: %v", err)
	}
	ownerUID, ok := fileOwnerUID(info)
	if !ok || uint64(ownerUID) != uid {
		return statusFail, "RFB socket is not owned by the contained agent uid"
	}
	return statusPass, "agent-owned RFB Unix socket is private and TCP RFB is disabled"
}
