// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func probeViewerService(ctx context.Context, env *probeEnv) (string, string) {
	cfg, err := config.LoadForInspection(env.configPath)
	if err != nil {
		return statusFail, fmt.Sprintf("viewer config: %v", err)
	}
	service, socket := viewerUnitPaths(&installEnv{displayUnitPath: env.displayUnitPath})
	if !viewerRFBEnabled(cfg.Containment.Display) {
		for _, path := range []string{service, socket} {
			if _, err := env.stat(path); err == nil {
				return statusFail, "viewer disabled but unit remains: " + path
			} else if !os.IsNotExist(err) {
				return statusFail, err.Error()
			}
		}
		return statusPass, "viewer disabled"
	}
	if err := config.ValidateViewerOrigin(cfg.Containment.Display.Viewer.PublicOrigin); err != nil {
		return statusFail, err.Error()
	}
	install := &installEnv{displayUnitPath: env.displayUnitPath, agentHome: env.agentHome, agentUserName: env.agentUserName, proxyUserName: env.proxyUserName, pipelockTarget: env.pipelockTarget, displayNumber: cfg.Containment.Display.EffectiveNumber(), displayConfig: cfg.Containment.Display}
	for path, want := range map[string]string{service: renderViewerServiceUnit(install), socket: renderViewerSocketUnit(cfg.Containment.Display.Viewer)} {
		body, err := env.readFile(path)
		if err != nil {
			return statusFail, fmt.Sprintf("viewer unit %s: %v", path, err)
		}
		if string(body) != want {
			return statusFail, "viewer unit drift: " + path
		}
	}
	if out, code, err := env.runCmd(ctx, "systemctl", "is-active", filepath.Base(socket)); err != nil || code != 0 || strings.TrimSpace(out) != systemctlActive {
		return statusFail, "viewer socket unit is inactive"
	}
	path := viewerHostSocket(cfg.Containment.Display.Viewer)
	statSocket := env.lstat
	if statSocket == nil {
		statSocket = env.stat
	}
	info, err := statSocket(path)
	if err != nil {
		return statusFail, fmt.Sprintf("viewer socket missing: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return statusFail, fmt.Sprintf("viewer socket mode is %s, want socket 0600", info.Mode())
	}
	account, err := env.lookupUser(cfg.Containment.Display.Viewer.OperatorUser)
	if err != nil {
		return statusFail, fmt.Sprintf("viewer socket owner lookup: %v", err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return statusFail, err.Error()
	}
	ownerUID, ok := fileOwnerUID(info)
	if !ok || uint64(ownerUID) != uid {
		return statusFail, "viewer socket admits wrong user"
	}
	return statusPass, "viewer socket unit active with operator-owned 0600 socket"
}

func probeViewerRFBAccess(ctx context.Context, env *probeEnv) (string, string) {
	cfg, err := config.LoadForInspection(env.configPath)
	if err != nil {
		return statusFail, fmt.Sprintf("viewer config: %v", err)
	}
	path := filepath.Join(env.agentHome, ".local/state/pipelock/display/rfb.sock")
	info, err := env.lstat(path)
	if err != nil {
		return statusFail, fmt.Sprintf("RFB socket: %v", err)
	}
	mode := os.FileMode(0o600)
	if viewerRFBEnabled(cfg.Containment.Display) {
		mode = 0o660
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != mode {
		return statusFail, fmt.Sprintf("RFB socket mode is %s, want %04o", info.Mode(), mode)
	}
	if err := checkViewerRFBACL(ctx, env.runCmd, path, env.proxyUserName, viewerRFBEnabled(cfg.Containment.Display)); err != nil {
		return statusFail, err.Error()
	}
	return statusPass, "RFB socket ACL matches viewer setting"
}
