// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	viewerUnitBase      = "pipelock-contain-viewer"
	viewerControlSocket = "/run/pipelock-contain-viewer/control.sock"
)

func viewerUnitPaths(env *installEnv) (string, string) {
	dir := filepath.Dir(env.displayUnitPath)
	return filepath.Join(dir, viewerUnitBase+".service"), filepath.Join(dir, viewerUnitBase+".socket")
}

func renderViewerServiceUnit(env *installEnv) string {
	v := env.displayConfig.Viewer
	rfb := filepath.Join(env.agentHome, ".local/state/pipelock/display/rfb.sock")
	clipboard := "false"
	if v.Clipboard != nil && *v.Clipboard {
		clipboard = "true"
	}
	return fmt.Sprintf("%s\n[Unit]\nDescription=Pipelock contained display viewer\n\n[Service]\nType=exec\nUser=%s\nGroup=%s\nRuntimeDirectory=pipelock-contain-viewer\nRuntimeDirectoryMode=0700\nExecStartPre=/usr/bin/setfacl -m u:%s:--x /run/pipelock-contain-viewer\nExecStart=%s contain viewer serve --display %s --rfb-socket %s --operator-user %s --agent-user %s --clipboard=%s\nPrivateTmp=true\nNoNewPrivileges=true\nProtectHome=read-only\nProtectSystem=strict\n\n[Install]\nWantedBy=multi-user.target\n", displayUnitMarker, env.proxyUserName, env.proxyUserName, v.OperatorUser, env.pipelockTarget, displayName(env.displayNumber), rfb, v.OperatorUser, env.agentUserName, clipboard)
}

// stepProvisionViewer installs one long-running service and removes a legacy
// HTTP socket unit when upgrading an existing installation.
func stepProvisionViewer() step {
	type priorUnit struct {
		exists, enabled, active bool
		body                    []byte
	}
	var prior [2]priorUnit
	return step{name: "provision-display-viewer", desc: "provision contained display viewer", apply: func(ctx context.Context, env *installEnv) (bool, error) {
		service, socket := viewerUnitPaths(env)
		paths := []string{service, socket}
		for i, path := range paths {
			body, err := env.readFile(path)
			if err == nil {
				prior[i].exists = true
				prior[i].body = append([]byte(nil), body...)
			} else if !errors.Is(err, os.ErrNotExist) {
				return false, err
			}
			out, code, err := env.runCmd(ctx, "systemctl", "is-enabled", filepath.Base(path))
			if err != nil {
				return false, err
			}
			prior[i].enabled = code == 0 && strings.TrimSpace(out) == systemctlEnabled
			out, code, err = env.runCmd(ctx, "systemctl", "is-active", filepath.Base(path))
			if err != nil {
				return false, err
			}
			prior[i].active = code == 0 && strings.TrimSpace(out) == systemctlActive
			if prior[i].exists && !strings.HasPrefix(string(prior[i].body), displayUnitMarker+"\n") {
				return false, fmt.Errorf("%s is not Pipelock-managed", path)
			}
		}
		if prior[1].exists || prior[1].active || prior[1].enabled {
			if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", filepath.Base(socket)); err != nil {
				return true, err
			}
			if err := removeManagedViewerUnit(env, socket); err != nil {
				return true, err
			}
		}
		if !viewerRFBEnabled(env.displayConfig) {
			if prior[0].exists || prior[0].active || prior[0].enabled {
				if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", filepath.Base(service)); err != nil {
					return true, err
				}
				if err := removeManagedViewerUnit(env, service); err != nil {
					return true, err
				}
			}
			if !prior[0].exists && !prior[1].exists {
				return false, nil
			}
			return true, runOrErr(ctx, env, "systemctl", "daemon-reload")
		}
		if env.displayConfig.EffectiveBackend() != "xvnc" || !env.displayEnabled {
			return false, errors.New("viewer requires an enabled Xvnc display")
		}
		changed, err := ensureContainmentUnit(env, service, renderViewerServiceUnit(env))
		if err != nil {
			return true, err
		}
		if err := runOrErr(ctx, env, "systemctl", "daemon-reload"); err != nil {
			return true, err
		}
		if changed && prior[0].active {
			if err := runOrErr(ctx, env, "systemctl", "restart", filepath.Base(service)); err != nil {
				return true, err
			}
		}
		if err := runOrErr(ctx, env, "systemctl", "enable", "--now", filepath.Base(service)); err != nil {
			return true, err
		}
		return changed || prior[1].exists || !prior[0].active, nil
	}, undo: func(ctx context.Context, env *installEnv) error {
		service, socket := viewerUnitPaths(env)
		paths := []string{service, socket}
		for _, path := range paths {
			if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", filepath.Base(path)); err != nil {
				return err
			}
		}
		for i, path := range paths {
			if prior[i].exists {
				if err := env.writeFile(path, prior[i].body, modeUnitFile); err != nil {
					return err
				}
			} else if err := removeManagedViewerUnit(env, path); err != nil {
				return err
			}
		}
		if err := runOrErr(ctx, env, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		for i, path := range paths {
			if prior[i].enabled {
				if err := runOrErr(ctx, env, "systemctl", "enable", filepath.Base(path)); err != nil {
					return err
				}
			}
			if prior[i].active {
				if err := runOrErr(ctx, env, "systemctl", "start", filepath.Base(path)); err != nil {
					return err
				}
			}
		}
		return nil
	}}
}

func actionRemoveViewer() step {
	return step{name: "remove-display-viewer", desc: "stop and remove contained display viewer", undo: func(ctx context.Context, env *installEnv) error {
		service, socket := viewerUnitPaths(env)
		if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", filepath.Base(socket)); err != nil {
			return err
		}
		if err := runSystemctlCleanupUnit(ctx, env, "stop", filepath.Base(service)); err != nil {
			return err
		}
		for _, path := range []string{service, socket} {
			if err := removeManagedViewerUnit(env, path); err != nil {
				return err
			}
		}
		return runOrErr(ctx, env, "systemctl", "daemon-reload")
	}}
}

func removeManagedViewerUnit(env *installEnv, path string) error {
	for _, candidate := range []string{path, path + ".bak"} {
		body, err := env.readFile(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(body), displayUnitMarker+"\n") {
			return fmt.Errorf("%s is not Pipelock-managed", candidate)
		}
		if err := env.removeFile(candidate); err != nil {
			return err
		}
	}
	return nil
}
