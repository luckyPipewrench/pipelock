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

func probeLegacyViewerACL(ctx context.Context, env *probeEnv) (string, string) {
	operator := ""
	cfg, err := config.LoadForInspection(env.configPath)
	if err == nil {
		operator = cfg.Containment.Display.Viewer.OperatorUser
	} else if !errors.Is(err, os.ErrNotExist) {
		return statusFail, fmt.Sprintf("viewer config: %v", err)
	}
	lstat := env.lstat
	if lstat == nil {
		lstat = env.stat
	}
	if err := checkLegacyViewerACL(ctx, env.runCmd, lstat, env.agentHome, operator); err != nil {
		return statusFail, err.Error()
	}
	return statusPass, "obsolete agent-home viewer access is absent"
}

func probeViewerService(ctx context.Context, env *probeEnv) (string, string) {
	cfg, err := config.LoadForInspection(env.configPath)
	if err != nil {
		return statusFail, fmt.Sprintf("viewer config: %v", err)
	}
	lstat := env.lstat
	if lstat == nil {
		lstat = env.stat
	}
	if err := checkLegacyViewerACL(ctx, env.runCmd, lstat, env.agentHome, cfg.Containment.Display.Viewer.OperatorUser); err != nil {
		return statusFail, err.Error()
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
	install := &installEnv{displayUnitPath: env.displayUnitPath, agentHome: env.agentHome, rfbSocketPath: env.rfbSocketPath, agentUserName: env.agentUserName, proxyUserName: env.proxyUserName, pipelockTarget: env.pipelockTarget, displayNumber: cfg.Containment.Display.EffectiveNumber(), displayConfig: cfg.Containment.Display}
	if _, err := env.stat(socket); err == nil {
		return statusFail, "legacy viewer HTTP socket unit remains"
	} else if !os.IsNotExist(err) {
		return statusFail, err.Error()
	}
	for path, want := range map[string]string{service: renderViewerServiceUnit(install)} {
		body, err := env.readFile(path)
		if err != nil {
			return statusFail, fmt.Sprintf("viewer unit %s: %v", path, err)
		}
		if string(body) != want {
			return statusFail, "viewer unit drift: " + path
		}
	}
	if out, code, err := env.runCmd(ctx, "systemctl", "is-active", filepath.Base(service)); err != nil || code != 0 || strings.TrimSpace(out) != systemctlActive {
		return statusFail, "viewer service unit is inactive"
	}
	path := viewerControlSocket
	statSocket := env.lstat
	if statSocket == nil {
		statSocket = env.stat
	}
	info, err := statSocket(path)
	if err != nil {
		return statusFail, fmt.Sprintf("viewer socket missing: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 {
		return statusFail, fmt.Sprintf("viewer socket mode is %s, want socket 0660", info.Mode())
	}
	account, err := env.lookupUser(viewerUserName)
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
	if err := checkViewerControlACL(ctx, env.runCmd, path, cfg.Containment.Display.Viewer.OperatorUser); err != nil {
		return statusFail, err.Error()
	}
	if err := checkViewerGroup(ctx, env.runCmd, account.Gid); err != nil {
		return statusFail, err.Error()
	}
	if err := checkViewerProxyIsolation(ctx, env.runCmd, env.proxyUserName); err != nil {
		return statusFail, err.Error()
	}
	return statusPass, "viewer service active with dedicated-user 0660 control socket"
}

func probeViewerRFBAccess(ctx context.Context, env *probeEnv) (string, string) {
	cfg, err := config.LoadForInspection(env.configPath)
	if err != nil {
		return statusFail, fmt.Sprintf("viewer config: %v", err)
	}
	path := displayRFBPath(env.rfbSocketPath)
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
	if err := checkRFBRuntimeDirectory(env.lstat, env.lookupUser, path); err != nil {
		return statusFail, err.Error()
	}
	if err := checkRFBGroup(env.lstat, env.lookupUser, path, viewerUserName); err != nil {
		return statusFail, err.Error()
	}
	return statusPass, "RFB socket mode and group match viewer setting"
}
