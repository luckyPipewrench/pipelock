// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

const (
	viewerUnitBase      = "pipelock-contain-viewer"
	viewerControlSocket = "/run/pipelock-contain-viewer/control.sock"
	viewerUserName      = "pipelock-viewer"
)

// The viewer has its own identity. Its primary group is used only for the
// display runtime directory and RFB socket; the proxy is never a member.
func stepCreateViewerUser() step {
	return step{name: "create-viewer-user", desc: "create dedicated display viewer user", apply: func(ctx context.Context, env *installEnv) (bool, error) {
		if err := checkViewerProxyIsolation(ctx, env.runCmd, env.proxyUserName); err != nil {
			return false, err
		}
		account, err := env.lookupUser(viewerUserName)
		if err == nil {
			if account.Uid == "0" || account.Gid == "0" {
				return false, errors.New("viewer account must not be root")
			}
			for _, other := range []string{env.agentUserName, env.proxyUserName, env.operatorUser} {
				if other == "" {
					continue
				}
				peer, lookupErr := env.lookupUser(other)
				if lookupErr != nil {
					return false, fmt.Errorf("inspect viewer identity boundary: %w", lookupErr)
				}
				if account.Uid == peer.Uid {
					return false, errors.New("viewer account shares another containment identity")
				}
			}
			if err := checkViewerGroup(ctx, env.runCmd, account.Gid); err != nil {
				return false, err
			}
			return false, nil
		}
		if !errors.As(err, new(user.UnknownUserError)) {
			return false, fmt.Errorf("viewer account lookup: %w", err)
		}
		return true, runOrErr(ctx, env, "useradd", "--system", "--shell", env.nologinPath, "--home-dir", "/var/lib/"+viewerUserName, "--no-create-home", "--user-group", viewerUserName)
	}, undo: func(ctx context.Context, env *installEnv) error {
		if _, err := env.lookupUser(viewerUserName); errors.As(err, new(user.UnknownUserError)) {
			return nil
		} else if err != nil {
			return err
		}
		return runOrErr(ctx, env, "userdel", "-r", viewerUserName)
	}}
}

func checkViewerOperatorIdentity(env *installEnv) error {
	if !viewerRFBEnabled(env.displayConfig) {
		return nil
	}
	operator, err := env.lookupUser(env.displayConfig.Viewer.OperatorUser)
	if err != nil {
		return fmt.Errorf("lookup viewer operator: %w", err)
	}
	for _, name := range []string{env.agentUserName, env.proxyUserName, viewerUserName} {
		if name == "" {
			continue
		}
		peer, lookupErr := env.lookupUser(name)
		if errors.As(lookupErr, new(user.UnknownUserError)) && name == viewerUserName {
			continue
		}
		if lookupErr != nil {
			return fmt.Errorf("lookup containment service account %s: %w", name, lookupErr)
		}
		if operator.Uid == peer.Uid {
			return errors.New("viewer operator must have a distinct identity from containment service accounts")
		}
	}
	return nil
}

func checkViewerGroup(ctx context.Context, run runCommand, gid string) error {
	out, code, err := run(ctx, "getent", "group", viewerUserName)
	if err != nil || code != 0 {
		return fmt.Errorf("inspect viewer group: %w", errors.Join(err, fmt.Errorf("exit %d", code)))
	}
	parts := strings.Split(strings.TrimSpace(out), ":")
	if len(parts) != 4 || parts[0] != viewerUserName || parts[2] != gid {
		return errors.New("viewer account has unexpected primary group")
	}
	if parts[3] != "" {
		return errors.New("viewer group has supplementary members")
	}
	return nil
}

func checkViewerProxyIsolation(ctx context.Context, run runCommand, proxy string) error {
	if proxy == "" {
		return nil
	}
	out, code, err := run(ctx, "id", "-nG", proxy)
	if err != nil || code != 0 {
		return fmt.Errorf("inspect proxy group membership: %w", errors.Join(err, fmt.Errorf("exit %d", code)))
	}
	for _, group := range strings.Fields(out) {
		if group == viewerUserName {
			return errors.New("proxy account must not be in the viewer group")
		}
	}
	return nil
}

func viewerUnitPaths(env *installEnv) (string, string) {
	dir := filepath.Dir(env.displayUnitPath)
	return filepath.Join(dir, viewerUnitBase+".service"), filepath.Join(dir, viewerUnitBase+".socket")
}

func renderViewerServiceUnit(env *installEnv) string {
	v := env.displayConfig.Viewer
	rfb := displayRFBPath(env.rfbSocketPath)
	clipboard := "false"
	if v.Clipboard != nil && *v.Clipboard {
		clipboard = "true"
	}
	return fmt.Sprintf("%s\n[Unit]\nDescription=Pipelock contained display viewer\nAfter=%s\nRequires=%s\n\n[Service]\nType=exec\nUser=%s\nGroup=%s\nRuntimeDirectory=pipelock-contain-viewer\nRuntimeDirectoryMode=0700\nExecStartPre=/usr/bin/setfacl -n -m u:%s:--x,g::---,o::---,m::--x /run/pipelock-contain-viewer\nExecStart=%s contain viewer serve --display %s --rfb-socket %s --operator-user %s --agent-user %s --clipboard=%s\nPrivateTmp=true\nNoNewPrivileges=true\nProtectHome=true\nProtectSystem=strict\n\n[Install]\nWantedBy=multi-user.target\n", displayUnitMarker, filepath.Base(env.displayUnitPath), filepath.Base(env.displayUnitPath), viewerUserName, viewerUserName, v.OperatorUser, env.pipelockTarget, displayName(env.displayNumber), rfb, v.OperatorUser, env.agentUserName, clipboard)
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
		changedState := func() bool {
			for _, unit := range prior {
				if unit.exists || unit.active || unit.enabled {
					return true
				}
			}
			return false
		}
		service, socket := viewerUnitPaths(env)
		paths := []string{service, socket}
		if err := validateManagedViewerUnits(env, paths...); err != nil {
			return false, err
		}
		if viewerRFBEnabled(env.displayConfig) && (env.displayConfig.EffectiveBackend() != "xvnc" || !env.displayEnabled) {
			return false, errors.New("viewer requires an enabled Xvnc display")
		}
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
			if !changedState() {
				return false, nil
			}
			return true, runOrErr(ctx, env, "systemctl", "daemon-reload")
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
		return changed || prior[1].exists || prior[1].active || prior[1].enabled || !prior[0].active || !prior[0].enabled, nil
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
		if err := validateManagedViewerUnits(env, service, socket); err != nil {
			return err
		}
		if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", filepath.Base(socket)); err != nil {
			return err
		}
		if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", filepath.Base(service)); err != nil {
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

func validateManagedViewerUnits(env *installEnv, paths ...string) error {
	for _, path := range paths {
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
		}
	}
	return nil
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
