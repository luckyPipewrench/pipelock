// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

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

const loopbackHostProbeTimeout = 250 * time.Millisecond

// warnUnavailableHostLoopbackServices catches a declaration that has nothing
// to forward on the host. The declaration is still honored: a host service may
// be intentionally stopped during install and started later. The warning is
// important because honoring it reserves the same address inside the agent's
// namespace; if the contained tool meant to own that port itself, its bind
// fails far away from the configuration mistake that caused the collision.
func warnUnavailableHostLoopbackServices(
	ctx context.Context,
	services []config.ContainmentLoopbackService,
	dial dialFunc,
	warn func(string),
) {
	if dial == nil || warn == nil {
		return
	}
	for _, service := range services {
		address := net.JoinHostPort(service.Host, strconv.Itoa(service.Port))
		conn, err := dial(ctx, "tcp", address, loopbackHostProbeTimeout)
		if err == nil {
			_ = conn.Close()
			continue
		}
		if ctx.Err() != nil {
			return
		}
		warn(fmt.Sprintf(
			"containment.loopback_services entry %s has no reachable host TCP listener (%v); Pipelock will still reserve %s inside the agent namespace. Remove this entry if the contained tool owns that port",
			address, err, address,
		))
	}
}

// declaredLoopbackDoorwayPath is the per-service host doorway. Each declared
// service gets its own socket so one service's reachability cannot be widened
// by another's, and so revoking one removes exactly one filesystem object.
func declaredLoopbackDoorwayPath(host string, port int) string {
	return "/run/" + loopbackForwarderUnitBase(host, port) + ".sock"
}

// renderDeclaredLoopbackSocketUnit declares one host doorway per declared
// loopback service. Like the proxy doorway it is a PATHNAME unix socket in the
// HOST namespace, because systemd.socket(5) allocates every .socket listener
// there no matter what PrivateNetwork= says. The in-namespace listener that
// the agent actually connects to comes from the forwarder service below.
func renderDeclaredLoopbackSocketUnit(agentUser string, service config.ContainmentLoopbackService) string {
	return fmt.Sprintf(`[Unit]
Description=Pipelock host doorway for one declared contained-agent loopback service

[Socket]
ListenStream=%s
SocketMode=0660
SocketUser=root
SocketGroup=%s
RemoveOnStop=true

[Install]
WantedBy=sockets.target
`, declaredLoopbackDoorwayPath(service.Host, service.Port), agentUser)
}

// renderDeclaredLoopbackNamespaceForwarderUnit creates the in-namespace
// listener for one declared service. It is a service because JoinsNamespaceOf=
// places a unit's PROCESSES in the namespace, which is what is needed, and
// which a socket unit's listener never gets.
func renderDeclaredLoopbackNamespaceForwarderUnit(pipelockPath, agentUser string, service config.ContainmentLoopbackService) string {
	base := loopbackForwarderUnitBase(service.Host, service.Port)
	return fmt.Sprintf(`[Unit]
Description=Pipelock declared loopback listener inside the contained-agent network namespace
Requires=%s
After=%s
Requires=%s.socket
After=%s.socket
JoinsNamespaceOf=%s

[Service]
Type=simple
User=%s
Group=%s
ExecStart=%s contain netns-forward --listen %s --target %s
PrivateNetwork=true
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
Restart=on-failure

[Install]
WantedBy=multi-user.target
`, containedNetworkNamespaceUnit, containedNetworkNamespaceUnit,
		base, base, containedNetworkNamespaceUnit,
		agentUser, agentUser, pipelockPath,
		systemdListenAddress(service.Host, service.Port),
		declaredLoopbackDoorwayPath(service.Host, service.Port))
}

// renderDeclaredLoopbackForwarderUnit relays one declared service's host
// doorway to its real loopback address. It runs the Pipelock binary rather
// than systemd-socket-proxyd: on an SELinux system the proxyd binary
// transitions into systemd_socket_proxyd_t, and any mount-namespace sandbox
// directive here (PrivateTmp=, ProtectHome=, ProtectSystem=) makes the kernel
// refuse that transition as unbounded. The unit then starts cleanly and every
// connect returns EACCES, visible only as one "Failed to connect to remote
// host: Permission denied" line in its own journal. Our own binary takes no
// domain transition, so it keeps the full sandbox.
func renderDeclaredLoopbackForwarderUnit(pipelockPath, proxyUser string, service config.ContainmentLoopbackService) string {
	return fmt.Sprintf(`[Unit]
Description=Forward one declared contained-agent loopback service to the host

[Service]
Type=exec
User=%s
Group=%s
ExecStart=%s contain netns-forward --systemd-listener --target-tcp %s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
`, proxyUser, proxyUser, pipelockPath, systemdListenAddress(service.Host, service.Port))
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
	containedNetworkNamespaceUnit   = "pipelock-agent-netns.service"
	containedProxyForwarderUnit     = "pipelock-agent-proxy"
	containedNamespaceForwarderUnit = "pipelock-agent-netns-forward.service"
	containedNamespaceIdentityPath  = "/run/pipelock-contain/agent-netns.id"
	// containedDoorwaySocketPath is the one filesystem object the contained
	// namespace may cross. It sits directly in /run rather than a subdirectory
	// so the socket unit does not depend on anything else having created a
	// directory first; /run is tmpfs, so no stale socket survives a reboot,
	// and RemoveOnStop= clears it when the socket stops.
	containedDoorwaySocketPath    = "/run/pipelock-agent-proxy.sock"
	legacyOwnedLoopbackInputChain = "pipelock_owned_loopback_input"
	legacyOwnedLoopbackMark       = "0x504c4b01"
	legacyOwnedLoopbackSlice      = "pipelock_contained.slice"
)

// The contained agent keeps the long-standing 127.0.0.1 proxy contract. That
// listener lives INSIDE this unit's private network namespace and is created
// by pipelock contain netns-forward, which joins the namespace and forwards to
// a pathname unix socket on the host. See netns_forward.go for why a systemd
// socket unit cannot supply it: systemd.socket(5) allocates every .socket
// listener in the HOST network namespace, whatever PrivateNetwork= says.
//
// We deliberately rejected a veth because it would add a routed interface plus
// packet-filter state solely to reach one socket, and rejected moving an
// additional Pipelock listener into this namespace because the proxy itself
// needs host-network egress. The unix doorway crosses only one explicitly
// declared filesystem object and creates no route at all.
func renderContainedNetworkNamespaceUnit() string {
	return `[Unit]
Description=Pipelock contained-agent network namespace
Before=pipelock-agent-netns-forward.service

[Service]
Type=simple
ExecStart=/usr/bin/sleep infinity
ExecStartPost=/bin/sh -c '/usr/bin/readlink /proc/self/ns/net > /run/pipelock-contain/agent-netns.id'
PrivateNetwork=true
NoNewPrivileges=true
RuntimeDirectory=pipelock-contain
RuntimeDirectoryMode=0755
UMask=0022
`
}

func probeAgentNetworkNamespace(ctx context.Context, env *probeEnv) (string, string) {
	units := []struct {
		path string
		want string
	}{
		{env.networkNamespaceUnitPath, renderContainedNetworkNamespaceUnit()},
		{env.proxyForwarderSocketPath, renderContainedProxySocketUnit(env.agentUserName)},
		{env.proxyForwarderServicePath, renderContainedProxyForwarderUnit(env.pipelockTarget, env.proxyUserName, env.port)},
		{env.namespaceForwarderServicePath, renderContainedNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, env.port)},
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
		nsPath := filepath.Join(unitDir, unit+"-netns.service")
		for path, want := range map[string]string{
			socketPath:  renderDeclaredLoopbackSocketUnit(env.agentUserName, service),
			servicePath: renderDeclaredLoopbackForwarderUnit(env.pipelockTarget, env.proxyUserName, service),
			nsPath:      renderDeclaredLoopbackNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, service),
		} {
			body, readErr := env.readFile(path)
			if readErr != nil || string(body) != want {
				return statusFail, fmt.Sprintf("declared loopback forwarder %s is missing or drifted; run `pipelock contain reload-nft-rules`", path)
			}
		}
	}

	if socketStatus, socketDetail := probeManagedDoorwaySockets(ctx, env, services); socketStatus != statusPass {
		return socketStatus, socketDetail
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

	var boundaryStatus, boundaryDetail string
	if env.networkNamespaceProbe != nil {
		boundaryStatus, boundaryDetail = env.networkNamespaceProbe(ctx, env)
	} else {
		boundaryStatus, boundaryDetail = probeNetworkNamespaceBoundary(ctx, env)
	}
	if boundaryStatus != statusPass {
		return boundaryStatus, boundaryDetail
	}
	var processStatus, processDetail string
	if env.agentProcessNetnsProbe != nil {
		processStatus, processDetail = env.agentProcessNetnsProbe(ctx, env, agentNamespace)
	} else {
		processStatus, processDetail = probeAgentProcessNamespaces(ctx, env, agentNamespace)
	}
	if processStatus != statusPass {
		return processStatus, processDetail
	}
	return statusPass, boundaryDetail + "; " + processDetail
}

func managedDoorwaySocketNames(proxySocketPath string, services []config.ContainmentLoopbackService) []string {
	units := make([]string, 0, len(services)+1)
	units = append(units, filepath.Base(proxySocketPath))
	for _, service := range services {
		units = append(units, loopbackForwarderUnitBase(service.Host, service.Port)+".socket")
	}
	sort.Strings(units)
	return units
}

// probeManagedDoorwaySockets makes a failed or inactive socket an explicit
// containment failure. Socket-activated forwarder services can be inactive
// between connections; the socket is the continuously active doorway.
func probeManagedDoorwaySockets(ctx context.Context, env *probeEnv, services []config.ContainmentLoopbackService) (string, string) {
	for _, socket := range managedDoorwaySocketNames(env.proxyForwarderSocketPath, services) {
		if out, code, err := env.runCmd(ctx, "systemctl", "is-enabled", socket); err != nil || code != 0 || strings.TrimSpace(out) != systemctlEnabled {
			return statusFail, fmt.Sprintf("managed doorway socket %s is not persistently enabled (%s); run `systemctl reset-failed %s && systemctl start %s`", socket, oneLine(out), socket, socket)
		}
		if out, code, err := env.runCmd(ctx, "systemctl", "is-active", socket); err != nil || code != 0 || strings.TrimSpace(out) != systemctlActive {
			return statusFail, fmt.Sprintf("managed doorway socket %s is %s; run `systemctl reset-failed %s && systemctl start %s`", socket, oneLine(out), socket, socket)
		}
	}
	return statusPass, "all managed doorway sockets are enabled and active"
}

// probeAgentProcessNamespaces catches services installed before the namespace
// feature, or custom services whose User= is correct but whose network
// namespace properties were never updated. Every live process under the
// managed agent UID must occupy the anchor namespace; merely finding the unit
// files healthy does not establish that runtime fact.
func probeAgentProcessNamespaces(_ context.Context, env *probeEnv, agentNamespace string) (string, string) {
	agent, err := env.lookupUser(env.agentUserName)
	if err != nil {
		return statusFail, fmt.Sprintf("lookup %s for live namespace audit: %v", env.agentUserName, err)
	}
	agentUID, err := strconv.Atoi(agent.Uid)
	if err != nil || agentUID <= 0 {
		return statusFail, fmt.Sprintf("%s has invalid uid %q for live namespace audit", env.agentUserName, agent.Uid)
	}
	procRoot := env.procRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	if env.readDir == nil {
		return statusFail, "live agent process namespace audit is unavailable"
	}
	entries, err := env.readDir(procRoot)
	if err != nil {
		return statusFail, fmt.Sprintf("list live processes for namespace audit: %v", err)
	}
	checked := 0
	var outside []string
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || !entry.IsDir() {
			continue
		}
		statusPath := filepath.Join(procRoot, entry.Name(), "status")
		status, err := env.readFile(statusPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return statusFail, fmt.Sprintf("read process %d identity for namespace audit: %v", pid, err)
		}
		effectiveUID, err := effectiveUIDFromProcStatus(status)
		if err != nil {
			return statusFail, fmt.Sprintf("read process %d identity for namespace audit: %v", pid, err)
		}
		if effectiveUID != agentUID {
			continue
		}
		statPath := filepath.Join(procRoot, entry.Name(), "stat")
		stat, err := env.readFile(statPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return statusFail, fmt.Sprintf("read process %d start time for namespace audit: %v", pid, err)
		}
		startTime, err := processStartTimeFromProcStat(stat)
		if err != nil {
			return statusFail, fmt.Sprintf("read process %d start time for namespace audit: %v", pid, err)
		}
		namespace, err := env.readLink(filepath.Join(procRoot, entry.Name(), "ns", "net"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return statusFail, fmt.Sprintf("read process %d network namespace: %v", pid, err)
		}
		// Re-read identity and start time after the namespace. The effective
		// UID alone is insufficient because Linux may recycle a PID for a new
		// process under the same account.
		status, err = env.readFile(statusPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return statusFail, fmt.Sprintf("re-read process %d identity for namespace audit: %v", pid, err)
		}
		effectiveUID, err = effectiveUIDFromProcStatus(status)
		if err != nil {
			return statusFail, fmt.Sprintf("re-read process %d identity for namespace audit: %v", pid, err)
		}
		if effectiveUID != agentUID {
			continue
		}
		stat, err = env.readFile(statPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return statusFail, fmt.Sprintf("re-read process %d start time for namespace audit: %v", pid, err)
		}
		currentStartTime, err := processStartTimeFromProcStat(stat)
		if err != nil {
			return statusFail, fmt.Sprintf("re-read process %d start time for namespace audit: %v", pid, err)
		}
		if currentStartTime != startTime {
			continue
		}
		checked++
		if namespace != agentNamespace {
			outside = append(outside, strconv.Itoa(pid))
		}
	}
	if len(outside) > 0 {
		return statusFail, fmt.Sprintf("%s has live process(es) outside the managed network namespace (pid %s); update or stop the stale agent service", env.agentUserName, strings.Join(outside, ", "))
	}
	return statusPass, fmt.Sprintf("%d live %s process(es) use the managed network namespace", checked, env.agentUserName)
}

func processStartTimeFromProcStat(stat []byte) (string, error) {
	// Field 2 (comm) is parenthesized and may contain spaces or parentheses.
	// Splitting after its final ')' leaves fields 3 onward, with starttime
	// (field 22) at zero-based index 19.
	closeParen := bytes.LastIndexByte(stat, ')')
	if closeParen < 0 {
		return "", errors.New("malformed stat: missing command terminator")
	}
	fields := strings.Fields(string(stat[closeParen+1:]))
	if len(fields) <= 19 {
		return "", errors.New("malformed stat: missing start time")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", fmt.Errorf("malformed stat start time %q", fields[19])
	}
	return fields[19], nil
}

func effectiveUIDFromProcStatus(status []byte) (int, error) {
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) != 4 {
			return 0, fmt.Errorf("malformed Uid field %q", line)
		}
		uid, err := strconv.Atoi(fields[1])
		if err != nil || uid < 0 {
			return 0, fmt.Errorf("malformed effective uid in %q", line)
		}
		return uid, nil
	}
	return 0, errors.New("missing Uid field")
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

// renderContainedProxySocketUnit declares the host-side doorway. It is a
// PATHNAME unix socket on purpose: network_namespaces(7) isolates only the
// abstract unix namespace, so a path-addressed socket is reachable from inside
// the agent's namespace while carrying no route and no interface. The socket
// lives in the host namespace because that is the only place systemd will put
// a .socket listener; SocketMode/SocketGroup are what actually restrict who
// may cross it.
func renderContainedProxySocketUnit(agentUser string) string {
	return fmt.Sprintf(`[Unit]
Description=Pipelock host doorway socket for the contained-agent namespace

[Socket]
ListenStream=%s
SocketMode=0660
SocketUser=root
SocketGroup=%s
RemoveOnStop=true

[Install]
WantedBy=sockets.target
`, containedDoorwaySocketPath, agentUser)
}

// renderContainedNamespaceForwarderUnit creates the in-namespace listener. It
// is a service rather than a socket because JoinsNamespaceOf= places a unit's
// PROCESSES in the namespace, which is exactly what is needed here and exactly
// what a socket unit's listener does not get.
func renderContainedNamespaceForwarderUnit(pipelockPath, agentUser string, port int) string {
	return fmt.Sprintf(`[Unit]
Description=Pipelock proxy listener inside the contained-agent network namespace
Requires=%s
After=%s
Requires=%s.socket
After=%s.socket
JoinsNamespaceOf=%s

[Service]
Type=simple
User=%s
Group=%s
ExecStart=%s contain netns-forward --listen 127.0.0.1:%d --target %s
PrivateNetwork=true
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
Restart=on-failure

[Install]
WantedBy=multi-user.target
`, containedNetworkNamespaceUnit, containedNetworkNamespaceUnit,
		containedProxyForwarderUnit, containedProxyForwarderUnit,
		containedNetworkNamespaceUnit,
		agentUser, agentUser, pipelockPath, port, containedDoorwaySocketPath)
}

// renderContainedProxyForwarderUnit relays the host doorway to Pipelock's own
// loopback listener. See the declared-loopback forwarder above for why this
// runs the Pipelock binary instead of systemd-socket-proxyd.
func renderContainedProxyForwarderUnit(pipelockPath, proxyUser string, port int) string {
	return fmt.Sprintf(`[Unit]
Description=Forward contained-agent proxy connections to the host Pipelock listener
Requires=pipelock.service
After=pipelock.service

[Service]
Type=exec
User=%s
Group=%s
ExecStart=%s contain netns-forward --systemd-listener --target-tcp 127.0.0.1:%d
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
`, proxyUser, proxyUser, pipelockPath, port)
}

type unitRuntimeState struct {
	enabled bool
	active  bool
}

// managedNamespaceRuntimeUnit describes every unit that can execute the
// installed binary while it is being replaced. Socket-activated services are
// intentionally restored by starting their socket, never directly: they need
// systemd's listener file descriptor and are normally inactive between calls.
type managedNamespaceRuntimeUnit struct {
	name            string
	socket          bool
	socketActivated bool
}

func managedNamespaceRuntimeUnits(env *installEnv) ([]managedNamespaceRuntimeUnit, error) {
	inv, err := readLoopbackForwarderInventory(env)
	if err != nil {
		return nil, err
	}
	units := []managedNamespaceRuntimeUnit{
		{name: filepath.Base(env.networkNamespaceUnitPath)},
		{name: filepath.Base(env.proxyForwarderSocketPath), socket: true},
		{name: filepath.Base(env.proxyForwarderServicePath), socketActivated: true},
		{name: filepath.Base(env.namespaceForwarderServicePath)},
	}
	for _, record := range inv.Services {
		units = append(units,
			managedNamespaceRuntimeUnit{name: record.Unit + ".socket", socket: true},
			managedNamespaceRuntimeUnit{name: record.Unit + ".service", socketActivated: true},
			managedNamespaceRuntimeUnit{name: record.Unit + "-netns.service"},
		)
	}
	sort.Slice(units, func(i, j int) bool { return units[i].name < units[j].name })
	return units, nil
}

func captureManagedNamespaceRuntimeState(ctx context.Context, env *installEnv, units []managedNamespaceRuntimeUnit) map[string]unitRuntimeState {
	states := make(map[string]unitRuntimeState, len(units))
	for _, unit := range units {
		states[unit.name] = systemdUnitRuntimeState(ctx, env, unit.name)
	}
	return states
}

// quiesceManagedNamespaceRuntimeUnits closes doorway sockets before a binary
// swap. Stopping their services first prevents a still-active accepted
// connection from using the replacement before its matching command surface is
// installed.
func quiesceManagedNamespaceRuntimeUnits(ctx context.Context, env *installEnv, units []managedNamespaceRuntimeUnit, states map[string]unitRuntimeState) error {
	for _, unit := range units {
		if !unit.socket && states[unit.name].active {
			if err := runSystemctlCleanupUnit(ctx, env, "stop", unit.name); err != nil {
				return fmt.Errorf("stop managed forwarder %s before binary replacement: %w", unit.name, err)
			}
		}
	}
	for _, unit := range units {
		if unit.socket && states[unit.name].active {
			if err := runSystemctlCleanupUnit(ctx, env, "stop", unit.name); err != nil {
				return fmt.Errorf("stop managed doorway socket %s before binary replacement: %w", unit.name, err)
			}
		}
	}
	return nil
}

// restoreManagedNamespaceRuntimeUnits clears systemd start limits before
// restoring active doorway sockets and ordinary forwarders. A failed restore is
// returned to the installer so rollback cannot claim containment recovered.
func restoreManagedNamespaceRuntimeUnits(ctx context.Context, env *installEnv, units []managedNamespaceRuntimeUnit, states map[string]unitRuntimeState) error {
	var errs []error
	for _, unit := range units {
		if err := runSystemctlCleanupUnit(ctx, env, "reset-failed", unit.name); err != nil {
			errs = append(errs, fmt.Errorf("reset failed managed unit %s: %w", unit.name, err))
		}
	}
	for _, unit := range units {
		if states[unit.name].enabled {
			if err := runOrErr(ctx, env, "systemctl", "enable", unit.name); err != nil {
				errs = append(errs, fmt.Errorf("enable managed unit %s: %w", unit.name, err))
			}
		}
		if states[unit.name].active && !unit.socketActivated {
			if err := runOrErr(ctx, env, "systemctl", "start", unit.name); err != nil {
				errs = append(errs, fmt.Errorf("start managed unit %s: %w", unit.name, err))
			}
		}
	}
	return errors.Join(errs...)
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
			warnUnavailableHostLoopbackServices(ctx, services, env.dialCtx, func(message string) {
				_, _ = fmt.Fprintln(env.errOut, "WARNING: "+message)
			})
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
				{env.proxyForwarderSocketPath, renderContainedProxySocketUnit(env.agentUserName), modeUnitFile},
				{env.proxyForwarderServicePath, renderContainedProxyForwarderUnit(env.pipelockTarget, env.proxyUserName, env.proxyPort), modeUnitFile},
				{env.namespaceForwarderServicePath, renderContainedNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, env.proxyPort), modeUnitFile},
				{env.loopbackForwarderInvPath, string(inventoryBytes), modeConfigSecret},
			}
			unitDir := filepath.Dir(env.proxyForwarderSocketPath)
			desiredUnits := make(map[string]bool, len(services))
			for _, service := range services {
				unit := loopbackForwarderUnitBase(service.Host, service.Port)
				desiredUnits[unit] = true
				paths = append(paths,
					managedFile{filepath.Join(unitDir, unit+".socket"), renderDeclaredLoopbackSocketUnit(env.agentUserName, service), modeUnitFile},
					managedFile{filepath.Join(unitDir, unit+".service"), renderDeclaredLoopbackForwarderUnit(env.pipelockTarget, env.proxyUserName, service), modeUnitFile},
					managedFile{filepath.Join(unitDir, unit+"-netns.service"), renderDeclaredLoopbackNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, service), modeUnitFile},
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
			// The in-namespace listener is a service, not a socket, so it is not
			// in previousSockets and has to be started explicitly. --now matters:
			// enable alone writes the boot symlink and leaves the namespace with
			// no listener until the host reboots, which on a containment feature
			// means the agent silently has no proxy.
			if err := runOrErr(ctx, env, "systemctl", "enable", "--now", containedNamespaceForwarderUnit); err != nil {
				return true, fmt.Errorf("enable contained namespace forwarder %s: %w", containedNamespaceForwarderUnit, err)
			}
			// Same for each declared loopback service: its in-namespace listener
			// is a service, so enabling the socket alone leaves the agent with a
			// host doorway and nothing inside the namespace to connect to.
			for unit := range desiredUnits {
				nsUnit := unit + "-netns.service"
				if err := runOrErr(ctx, env, "systemctl", "enable", "--now", nsUnit); err != nil {
					return true, fmt.Errorf("enable declared loopback namespace listener %s: %w", nsUnit, err)
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
			// Stop the in-namespace listener before the namespace holder, and
			// before restoring unit files, so it cannot be left running against
			// a definition that no longer exists. Cleanup tolerates an absent
			// unit: a failure earlier in apply may mean it was never written.
			if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", containedNamespaceForwarderUnit); err != nil {
				errs = append(errs, err)
			}
			for socket := range previousSockets {
				base := strings.TrimSuffix(socket, ".socket")
				if !strings.HasPrefix(base, "pipelock-agent-loopback-") {
					continue
				}
				if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", base+"-netns.service"); err != nil {
					errs = append(errs, err)
				}
			}
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
