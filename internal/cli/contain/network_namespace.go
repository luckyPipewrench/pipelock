// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

type loopbackForwarderInventory struct {
	Services []loopbackForwarderRecord `json:"services"`
}

type loopbackForwarderRecord struct {
	Unit      string `json:"unit"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Owner     string `json:"owner"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at"`
}

func loopbackForwarderUnitBase(host string, port int) string {
	family := "v4"
	if host == "::1" {
		family = "v6"
	}
	return fmt.Sprintf("pipelock-agent-loopback-%s-%d", family, port)
}

func systemdListenAddress(host string, port int) string {
	if host == "::1" {
		return fmt.Sprintf("[::1]:%d", port)
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func renderDeclaredLoopbackSocketUnit(service config.ContainmentLoopbackService) string {
	return fmt.Sprintf(`[Unit]
Description=Pipelock declared loopback service inside the contained-agent network namespace
Requires=%s
After=%s
JoinsNamespaceOf=%s

[Socket]
ListenStream=%s
PrivateNetwork=true
NoDelay=true

[Install]
WantedBy=sockets.target
`, containedNetworkNamespaceUnit, containedNetworkNamespaceUnit, containedNetworkNamespaceUnit, systemdListenAddress(service.Host, service.Port))
}

func renderDeclaredLoopbackForwarderUnit(proxyUser string, service config.ContainmentLoopbackService) string {
	return fmt.Sprintf(`[Unit]
Description=Forward one declared contained-agent loopback service to the host

[Service]
Type=notify
User=%s
Group=%s
ExecStart=%s %s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
`, proxyUser, proxyUser, systemdSocketProxydPath, systemdListenAddress(service.Host, service.Port))
}

func desiredLoopbackForwarders(services []config.ContainmentLoopbackService) loopbackForwarderInventory {
	inv := loopbackForwarderInventory{Services: make([]loopbackForwarderRecord, 0, len(services))}
	for _, service := range services {
		inv.Services = append(inv.Services, loopbackForwarderRecord{
			Unit:      loopbackForwarderUnitBase(service.Host, service.Port),
			Host:      service.Host,
			Port:      service.Port,
			Owner:     service.Owner,
			Reason:    service.Reason,
			ExpiresAt: service.ExpiresAt,
		})
	}
	return inv
}

func readLoopbackForwarderInventory(env *installEnv) (loopbackForwarderInventory, error) {
	data, err := env.readFile(env.loopbackForwarderInvPath)
	if errors.Is(err, os.ErrNotExist) {
		return loopbackForwarderInventory{}, nil
	}
	if err != nil {
		return loopbackForwarderInventory{}, fmt.Errorf("read loopback forwarder inventory: %w", err)
	}
	return decodeLoopbackForwarderInventory(data)
}

func decodeLoopbackForwarderInventory(data []byte) (loopbackForwarderInventory, error) {
	var inv loopbackForwarderInventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return loopbackForwarderInventory{}, fmt.Errorf("parse loopback forwarder inventory: %w", err)
	}
	for _, record := range inv.Services {
		if record.Unit != loopbackForwarderUnitBase(record.Host, record.Port) {
			return loopbackForwarderInventory{}, fmt.Errorf("loopback forwarder inventory contains non-canonical unit %q", record.Unit)
		}
	}
	return inv, nil
}

const (
	containedNetworkNamespaceUnit = "pipelock-agent-netns.service"
	containedProxyForwarderUnit   = "pipelock-agent-proxy"
	systemdSocketProxydPath       = "/usr/lib/systemd/systemd-socket-proxyd"
	legacyOwnedLoopbackInputChain = "pipelock_owned_loopback_input"
)

// The contained agent keeps the long-standing 127.0.0.1 proxy contract. A
// systemd socket is created inside this unit's private network namespace and
// its host-namespace service forwards accepted connections to the real
// host-loopback proxy. We deliberately rejected a veth because it would add a
// routed interface plus packet-filter state solely to reach one socket, and
// rejected moving an additional Pipelock listener into this namespace because
// the proxy itself needs host-network egress. Socket activation crosses only
// the one explicitly declared listening socket and creates no route at all.
func renderContainedNetworkNamespaceUnit() string {
	return `[Unit]
Description=Pipelock contained-agent network namespace
Before=pipelock-agent-proxy.socket

[Service]
Type=simple
ExecStart=/usr/bin/sleep infinity
PrivateNetwork=true
NoNewPrivileges=true
`
}

func probeAgentNetworkNamespace(ctx context.Context, env *probeEnv) (string, string) {
	units := []struct {
		path string
		want string
	}{
		{env.networkNamespaceUnitPath, renderContainedNetworkNamespaceUnit()},
		{env.proxyForwarderSocketPath, renderContainedProxySocketUnit(env.port)},
		{env.proxyForwarderServicePath, renderContainedProxyForwarderUnit(env.proxyUserName, env.port)},
	}
	for _, unit := range units {
		if strings.TrimSpace(unit.path) == "" {
			return statusFail, "contained network namespace unit paths are not configured"
		}
		body, err := env.readFile(filepath.Clean(unit.path))
		if err != nil {
			return statusFail, fmt.Sprintf("read contained network namespace unit %s: %v", unit.path, err)
		}
		if string(body) != unit.want {
			return statusFail, fmt.Sprintf("contained network namespace unit %s does not match the managed definition; rerun `pipelock contain install`", unit.path)
		}
	}
	services, problem, unusable := declaredContainmentLoopbackServicesForVerify(env, env.port)
	if unusable {
		return statusFail, "containment.loopback_services cannot be forwarded into the private namespace: " + problem
	}
	wantInventory, err := json.MarshalIndent(desiredLoopbackForwarders(services), "", "  ")
	if err != nil {
		return statusFail, fmt.Sprintf("encode expected loopback forwarder inventory: %v", err)
	}
	wantInventory = append(wantInventory, '\n')
	gotInventory, err := env.readFile(env.loopbackForwarderInvPath)
	if err != nil {
		return statusFail, fmt.Sprintf("read loopback forwarder inventory %s: %v", env.loopbackForwarderInvPath, err)
	}
	if string(gotInventory) != string(wantInventory) {
		return statusFail, "loopback forwarder inventory does not match containment.loopback_services; run `pipelock contain reload-nft-rules`"
	}
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	for _, service := range services {
		unit := loopbackForwarderUnitBase(service.Host, service.Port)
		socketPath := filepath.Join(unitDir, unit+".socket")
		servicePath := filepath.Join(unitDir, unit+".service")
		for path, want := range map[string]string{
			socketPath:  renderDeclaredLoopbackSocketUnit(service),
			servicePath: renderDeclaredLoopbackForwarderUnit(env.proxyUserName, service),
		} {
			body, readErr := env.readFile(path)
			if readErr != nil || string(body) != want {
				return statusFail, fmt.Sprintf("declared loopback forwarder %s is missing or drifted; run `pipelock contain reload-nft-rules`", path)
			}
		}
		socket := unit + ".socket"
		if out, code, stateErr := env.runCmd(ctx, "systemctl", "is-enabled", socket); stateErr != nil || code != 0 || strings.TrimSpace(out) != systemctlEnabled {
			return statusFail, fmt.Sprintf("declared loopback forwarder %s is not persistently enabled", socket)
		}
		if out, code, stateErr := env.runCmd(ctx, "systemctl", "is-active", socket); stateErr != nil || code != 0 || strings.TrimSpace(out) != systemctlActive {
			return statusFail, fmt.Sprintf("declared loopback forwarder %s is not active", socket)
		}
	}

	socketUnit := filepath.Base(env.proxyForwarderSocketPath)
	if out, code, err := env.runCmd(ctx, "systemctl", "is-enabled", socketUnit); err != nil || code != 0 || strings.TrimSpace(out) != systemctlEnabled {
		return statusFail, fmt.Sprintf("contained proxy socket %s is not persistently enabled (%s)", socketUnit, oneLine(out))
	}
	if out, code, err := env.runCmd(ctx, "systemctl", "is-active", socketUnit); err != nil || code != 0 || strings.TrimSpace(out) != systemctlActive {
		return statusFail, fmt.Sprintf("contained proxy socket %s is not active (%s)", socketUnit, oneLine(out))
	}
	namespaceUnit := filepath.Base(env.networkNamespaceUnitPath)
	if out, code, err := env.runCmd(ctx, "systemctl", "is-active", namespaceUnit); err != nil || code != 0 || strings.TrimSpace(out) != systemctlActive {
		return statusFail, fmt.Sprintf("contained network namespace %s is not active (%s)", namespaceUnit, oneLine(out))
	}

	pidOut, code, err := env.runCmd(ctx, "systemctl", "show", namespaceUnit, "--property=MainPID", "--value")
	if err != nil || code != 0 {
		return statusFail, fmt.Sprintf("read contained network namespace pid for %s: %v", namespaceUnit, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(pidOut))
	if err != nil || pid <= 1 {
		return statusFail, fmt.Sprintf("contained network namespace %s has invalid MainPID %q", namespaceUnit, oneLine(pidOut))
	}
	agentNamespace, err := env.readLink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return statusFail, fmt.Sprintf("read contained network namespace identity: %v", err)
	}
	hostNamespace, err := env.readLink("/proc/1/ns/net")
	if err != nil {
		return statusFail, fmt.Sprintf("read host network namespace identity: %v", err)
	}
	if agentNamespace == hostNamespace {
		return statusFail, fmt.Sprintf("contained network namespace %s resolves to the host network namespace", namespaceUnit)
	}

	if env.networkNamespaceProbe != nil {
		return env.networkNamespaceProbe(ctx, env)
	}
	return probeNetworkNamespaceBoundary(ctx, env)
}

func probeNetworkNamespaceBoundary(ctx context.Context, env *probeEnv) (string, string) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return statusFail, fmt.Sprintf("start host-loopback namespace canary: %v", err)
	}
	defer func() { _ = listener.Close() }()

	canaryArgs := namespaceProbeSystemdRunArgs(env, []string{
		env.curlPath,
		"--noproxy", "*",
		"--connect-timeout", "1",
		"--max-time", "2",
		"--silent", "--show-error", "--fail",
		"http://" + listener.Addr().String() + "/",
	})
	_, canaryCode, canaryErr := env.runCmd(ctx, systemdRunPath, canaryArgs...)
	if canaryErr != nil {
		return statusFail, fmt.Sprintf("run host-loopback namespace canary: %v", canaryErr)
	}
	if canaryCode == 0 {
		return statusFail, fmt.Sprintf("contained agent reached host loopback canary %s", listener.Addr())
	}
	proxyArgs := namespaceProbeSystemdRunArgs(env, []string{
		env.curlPath,
		"--noproxy", "*",
		"--connect-timeout", "2",
		"--max-time", "5",
		"--silent", "--show-error", "--fail",
		"http://127.0.0.1:" + strconv.Itoa(env.port) + "/health",
	})
	proxyOut, proxyCode, proxyErr := env.runCmd(ctx, systemdRunPath, proxyArgs...)
	if proxyErr != nil {
		return statusFail, fmt.Sprintf("run contained proxy reachability probe: %v", proxyErr)
	}
	if proxyCode != 0 {
		return statusFail, fmt.Sprintf("contained namespace cannot reach the proxy socket (exit=%d): %s", proxyCode, oneLine(proxyOut))
	}
	return statusPass, fmt.Sprintf("private namespace %s cannot reach host loopback and can reach its socket-activated proxy", containedNetworkNamespaceUnit)
}

func namespaceProbeSystemdRunArgs(env *probeEnv, command []string) []string {
	args := []string{
		"--wait",
		"--collect",
		"--service-type=oneshot",
		"--property=PrivateNetwork=true",
		"--property=JoinsNamespaceOf=" + containedNetworkNamespaceUnit,
		"--uid=" + env.agentUserName,
		"--pipe",
		"--",
	}
	return append(args, command...)
}

func renderContainedProxySocketUnit(port int) string {
	return fmt.Sprintf(`[Unit]
Description=Pipelock proxy socket inside the contained-agent network namespace
Requires=%s
After=%s
JoinsNamespaceOf=%s

[Socket]
ListenStream=127.0.0.1:%d
PrivateNetwork=true
NoDelay=true

[Install]
WantedBy=sockets.target
`, containedNetworkNamespaceUnit, containedNetworkNamespaceUnit, containedNetworkNamespaceUnit, port)
}

func renderContainedProxyForwarderUnit(proxyUser string, port int) string {
	return fmt.Sprintf(`[Unit]
Description=Forward contained-agent proxy connections to the host Pipelock listener
Requires=pipelock.service
After=pipelock.service

[Service]
Type=notify
User=%s
Group=%s
ExecStart=%s 127.0.0.1:%d
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
`, proxyUser, proxyUser, systemdSocketProxydPath, port)
}

type unitRuntimeState struct {
	enabled bool
	active  bool
}

func systemdUnitRuntimeState(ctx context.Context, env *installEnv, unit string) unitRuntimeState {
	var state unitRuntimeState
	if out, _, err := env.runCmd(ctx, "systemctl", "is-enabled", unit); err == nil {
		state.enabled = strings.TrimSpace(out) == systemctlEnabled
	}
	if out, _, err := env.runCmd(ctx, "systemctl", "is-active", unit); err == nil {
		state.active = strings.TrimSpace(out) == systemctlActive
	}
	return state
}

// stepInstallNetworkNamespace installs the namespace anchor and the
// namespace-bound proxy socket as one transactional unit. Runtime state is
// captured before any write so a later failed install restores both files and
// enabled/active state instead of leaving a half-installed boundary behind.
func stepInstallNetworkNamespace() step {
	return stepInstallNetworkNamespaceWithServices(nil)
}

func stepInstallNetworkNamespaceWithServices(serviceOverride *[]config.ContainmentLoopbackService) step {
	var previousSockets map[string]unitRuntimeState
	var previousNamespace unitRuntimeState
	var previousLegacyAnchor unitRuntimeState
	var legacyAnchorTouched bool
	var touched []string
	var retired map[string][]byte
	return step{
		name: "install-agent-network-namespace",
		desc: "install the private agent network namespace and proxy socket forwarder",
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			var services []config.ContainmentLoopbackService
			if serviceOverride != nil {
				services = append([]config.ContainmentLoopbackService(nil), (*serviceOverride)...)
			} else {
				var err error
				services, err = declaredContainmentLoopbackServices(env, env.proxyPort)
				if err != nil {
					return false, err
				}
			}
			oldInventory, err := readLoopbackForwarderInventory(env)
			if err != nil {
				return false, err
			}
			desiredInventory := desiredLoopbackForwarders(services)
			inventoryBytes, err := json.MarshalIndent(desiredInventory, "", "  ")
			if err != nil {
				return false, fmt.Errorf("encode loopback forwarder inventory: %w", err)
			}
			inventoryBytes = append(inventoryBytes, '\n')
			if err := env.mkdirAll(filepath.Dir(env.loopbackForwarderInvPath), modeDirTraversable); err != nil {
				return false, fmt.Errorf("create loopback forwarder inventory directory: %w", err)
			}

			type managedFile struct {
				path string
				body string
				mode os.FileMode
			}
			paths := []managedFile{
				{env.networkNamespaceUnitPath, renderContainedNetworkNamespaceUnit(), modeUnitFile},
				{env.proxyForwarderSocketPath, renderContainedProxySocketUnit(env.proxyPort), modeUnitFile},
				{env.proxyForwarderServicePath, renderContainedProxyForwarderUnit(env.proxyUserName, env.proxyPort), modeUnitFile},
				{env.loopbackForwarderInvPath, string(inventoryBytes), modeConfigSecret},
			}
			unitDir := filepath.Dir(env.proxyForwarderSocketPath)
			desiredUnits := make(map[string]bool, len(services))
			for _, service := range services {
				unit := loopbackForwarderUnitBase(service.Host, service.Port)
				desiredUnits[unit] = true
				paths = append(paths,
					managedFile{filepath.Join(unitDir, unit+".socket"), renderDeclaredLoopbackSocketUnit(service), modeUnitFile},
					managedFile{filepath.Join(unitDir, unit+".service"), renderDeclaredLoopbackForwarderUnit(env.proxyUserName, service), modeUnitFile},
				)
			}
			for _, item := range paths {
				if item.path == "" {
					return false, errors.New("contained network namespace unit path is not configured")
				}
			}

			previousSockets = make(map[string]unitRuntimeState, len(services)+len(oldInventory.Services)+1)
			proxySocket := filepath.Base(env.proxyForwarderSocketPath)
			previousSockets[proxySocket] = systemdUnitRuntimeState(ctx, env, proxySocket)
			for _, record := range oldInventory.Services {
				unit := record.Unit + ".socket"
				previousSockets[unit] = systemdUnitRuntimeState(ctx, env, unit)
			}
			for unit := range desiredUnits {
				socket := unit + ".socket"
				if _, ok := previousSockets[socket]; !ok {
					previousSockets[socket] = systemdUnitRuntimeState(ctx, env, socket)
				}
			}
			previousNamespace = systemdUnitRuntimeState(ctx, env, filepath.Base(env.networkNamespaceUnitPath))
			legacyAnchorTouched = false
			retired = make(map[string][]byte)
			if env.ownedLoopbackAnchorUnitPath != "" {
				previousLegacyAnchor = systemdUnitRuntimeState(ctx, env, filepath.Base(env.ownedLoopbackAnchorUnitPath))
			}
			touched = nil
			for _, item := range paths {
				if existing, err := env.readFile(item.path); err == nil && string(existing) == item.body {
					if err := env.chmod(item.path, item.mode); err != nil {
						return false, fmt.Errorf("chmod %s: %w", item.path, err)
					}
					continue
				}
				if err := backupAndWrite(env, item.path, []byte(item.body), item.mode); err != nil {
					return len(touched) > 0, fmt.Errorf("write %s: %w", item.path, err)
				}
				touched = append(touched, item.path)
			}
			for _, record := range oldInventory.Services {
				if desiredUnits[record.Unit] {
					continue
				}
				socket := record.Unit + ".socket"
				if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", socket); err != nil {
					return true, fmt.Errorf("disable stale loopback forwarder %s: %w", socket, err)
				}
				for _, suffix := range []string{".socket", ".service"} {
					path := filepath.Join(unitDir, record.Unit+suffix)
					if _, statErr := env.stat(path); errors.Is(statErr, os.ErrNotExist) {
						continue
					} else if statErr != nil {
						return true, fmt.Errorf("stat stale loopback forwarder %s: %w", path, statErr)
					}
					body, readErr := env.readFile(path)
					if readErr != nil {
						return true, fmt.Errorf("read stale loopback forwarder %s: %w", path, readErr)
					}
					// The current file is Pipelock's managed unit. Restore its
					// pre-install backup now instead of backing up the managed
					// file again; otherwise a successful revoke strands operator
					// state behind the deterministic unit name. Undo reconstructs
					// this exact managed body if a later install action fails.
					if err := restoreBackup(env, path); err != nil {
						return true, fmt.Errorf("restore operator state behind stale loopback forwarder %s: %w", path, err)
					}
					retired[path] = body
				}
			}
			if err := runOrErr(ctx, env, "systemctl", "daemon-reload"); err != nil {
				return len(touched) > 0, fmt.Errorf("reload systemd after installing contained network namespace: %w", err)
			}
			for socket := range previousSockets {
				if strings.HasPrefix(socket, "pipelock-agent-loopback-") && !desiredUnits[strings.TrimSuffix(socket, ".socket")] {
					continue
				}
				if err := runOrErr(ctx, env, "systemctl", "enable", "--now", socket); err != nil {
					// systemctl may have enabled or started the unit before reporting
					// a dependency failure. Mark the step applied so runSteps invokes
					// undo and restores both the file and runtime state.
					return true, fmt.Errorf("enable contained namespace socket %s: %w", socket, err)
				}
			}
			// Retire the superseded cgroup anchor only after the private namespace
			// socket is live. Keeping both would leave two mechanisms that can
			// disagree; on any later install failure undo restores the old file and
			// its exact prior runtime state.
			if path := env.ownedLoopbackAnchorUnitPath; path != "" {
				if _, statErr := env.stat(path); statErr == nil {
					unit := filepath.Base(path)
					if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", unit); err != nil {
						return true, fmt.Errorf("disable legacy owned-loopback anchor %s: %w", unit, err)
					}
					if _, err := backupCurrentToBak(env, path); err != nil {
						return true, fmt.Errorf("backup legacy owned-loopback anchor %s: %w", path, err)
					}
					if err := env.removeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
						return true, fmt.Errorf("remove legacy owned-loopback anchor %s: %w", path, err)
					}
					legacyAnchorTouched = true
					touched = append(touched, path)
					if err := runOrErr(ctx, env, "systemctl", "daemon-reload"); err != nil {
						return true, fmt.Errorf("reload systemd after retiring legacy owned-loopback anchor: %w", err)
					}
				} else if !errors.Is(statErr, os.ErrNotExist) {
					return true, fmt.Errorf("stat legacy owned-loopback anchor %s: %w", path, statErr)
				}
			}
			changed := len(touched) > 0 || len(retired) > 0 || !previousNamespace.active
			for socket, state := range previousSockets {
				if socket == proxySocket || desiredUnits[strings.TrimSuffix(socket, ".socket")] {
					changed = changed || !state.enabled || !state.active
				}
			}
			return changed, nil
		},
		undo: func(ctx context.Context, env *installEnv) error {
			var errs []error
			namespaceUnit := filepath.Base(env.networkNamespaceUnitPath)
			for socket, state := range previousSockets {
				if !state.active {
					if err := runSystemctlCleanupUnit(ctx, env, "stop", socket); err != nil {
						errs = append(errs, err)
					}
				}
				if !state.enabled {
					if err := runSystemctlCleanupUnit(ctx, env, "disable", socket); err != nil {
						errs = append(errs, err)
					}
				}
			}
			if !previousNamespace.active {
				if err := runSystemctlCleanupUnit(ctx, env, "stop", namespaceUnit); err != nil {
					errs = append(errs, err)
				}
			}
			for i := len(touched) - 1; i >= 0; i-- {
				if err := restoreBackup(env, touched[i]); err != nil {
					errs = append(errs, err)
				}
			}
			for path, body := range retired {
				if err := backupAndWrite(env, path, body, modeUnitFile); err != nil {
					errs = append(errs, fmt.Errorf("restore retired managed forwarder %s: %w", path, err))
				}
			}
			if err := runOrErr(ctx, env, "systemctl", "daemon-reload"); err != nil {
				errs = append(errs, err)
			}
			for socket, state := range previousSockets {
				if state.enabled {
					if err := runOrErr(ctx, env, "systemctl", "enable", socket); err != nil {
						errs = append(errs, err)
					}
				}
				if state.active {
					if err := runOrErr(ctx, env, "systemctl", "start", socket); err != nil {
						errs = append(errs, err)
					}
				}
			}
			if previousNamespace.active {
				if err := runOrErr(ctx, env, "systemctl", "start", namespaceUnit); err != nil {
					errs = append(errs, err)
				}
			}
			if legacyAnchorTouched {
				unit := filepath.Base(env.ownedLoopbackAnchorUnitPath)
				if previousLegacyAnchor.enabled {
					if err := runOrErr(ctx, env, "systemctl", "enable", unit); err != nil {
						errs = append(errs, err)
					}
				}
				if previousLegacyAnchor.active {
					if err := runOrErr(ctx, env, "systemctl", "start", unit); err != nil {
						errs = append(errs, err)
					}
				}
			}
			return errors.Join(errs...)
		},
	}
}
