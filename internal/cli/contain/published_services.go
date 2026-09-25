// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Published services are the INBOUND sibling of declared loopback services.
// The agent runs a listener on its own namespace loopback; Pipelock publishes
// it through an operator-owned Unix socket on the host. An explicit TCP host
// listener also admits other local accounts. The shape reuses the proxy
// doorway's socket activation, reversed:
//
//	operator -> host pathname socket (systemd .socket, owner operator, 0600)
//	         -> socket-activated `contain netns-forward --systemd-listener
//	            --target-tcp <agent loopback>` that JOINS the agent namespace
//
// systemd allocates the .socket listener in the host namespace
// (systemd.socket(5)) and hands its descriptor to the activated service, whose
// processes JoinsNamespaceOf= places in the agent namespace, so its dial of
// 127.0.0.1:<agent_port> lands on the agent's own loopback. The relay runs as
// the proxy service user, never the agent uid: the agent gains no host-side
// process, no nft exception is needed because the dial never leaves the
// private namespace, and the live agent-process audit stays clean.
//
// Everything crossing this doorway is agent-controlled content in both
// directions. Pipelock ships the doorway, not a viewer, and never serves it
// beyond loopback.

type publishedServiceRecordSet struct {
	Services []publishedServiceRecord `json:"services"`
}

type publishedServiceRecord struct {
	Unit         string `json:"unit"`
	Name         string `json:"name"`
	AgentHost    string `json:"agent_host"`
	AgentPort    int    `json:"agent_port"`
	HostSocket   string `json:"host_socket"`
	HostListen   string `json:"host_listen,omitempty"`
	OperatorUser string `json:"operator_user"`
	Owner        string `json:"owner"`
	Reason       string `json:"reason"`
	ExpiresAt    string `json:"expires_at"`
}

const publishedServiceSocketMode = os.FileMode(0o600)

func publishedServiceUnitBase(name string) string {
	return "pipelock-published-" + name
}

// publishedServiceTCPUnitBase names the loopback TCP opt-in pair. It is a
// separate socket AND service because systemd hands an activated service the
// descriptors of every socket that names it, and the relay adopts exactly one.
func publishedServiceTCPUnitBase(name string) string {
	return publishedServiceUnitBase(name) + "-tcp"
}

func publishedServiceRecordPath(loopbackRecordPath string) string {
	return filepath.Join(filepath.Dir(loopbackRecordPath), "published-services.json")
}

func publishedAgentTarget(service config.ContainmentPublishedService) string {
	return systemdListenAddress(service.EffectiveAgentHost(), service.AgentPort)
}

// renderPublishedSocketUnit renders the operator-facing endpoint. Owner is the
// operator and mode 0600, so the kernel admits only that uid (and root) at
// connect(2); DirectoryMode= makes any parent systemd creates root-owned and
// not group or world writable.
func renderPublishedSocketUnit(service config.ContainmentPublishedService) string {
	return fmt.Sprintf(`[Unit]
Description=Pipelock endpoint publishing one contained-agent service to its operator

[Socket]
ListenStream=%s
SocketUser=%s
SocketGroup=root
SocketMode=0600
DirectoryMode=0755
RemoveOnStop=true

[Install]
WantedBy=sockets.target
`, service.EffectiveHostSocket(), service.OperatorUser)
}

// renderPublishedTCPSocketUnit renders the explicit loopback TCP opt-in. A TCP
// socket cannot be restricted to one uid; every local account can connect.
func renderPublishedTCPSocketUnit(service config.ContainmentPublishedService) string {
	return fmt.Sprintf(`[Unit]
Description=Pipelock loopback TCP endpoint publishing one contained-agent service

[Socket]
ListenStream=%s
BindIPv6Only=ipv6-only

[Install]
WantedBy=sockets.target
`, service.HostListen)
}

// renderPublishedForwarderUnit is the socket-activated relay into the agent
// namespace. See the file comment for why it runs as the proxy user.
func renderPublishedForwarderUnit(pipelockPath, proxyUser string, service config.ContainmentPublishedService) string {
	return fmt.Sprintf(`[Unit]
Description=Relay one published contained-agent service into the agent namespace
Requires=%s
After=%s
JoinsNamespaceOf=%s

[Service]
Type=exec
User=%s
Group=%s
ExecStart=%s contain netns-forward --systemd-listener --target-tcp %s
PrivateNetwork=true
PrivateTmp=true
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
`, containedNetworkNamespaceUnit, containedNetworkNamespaceUnit, containedNetworkNamespaceUnit,
		proxyUser, proxyUser, pipelockPath, publishedAgentTarget(service))
}

type publishedManagedFile struct {
	path string
	body string
}

// publishedServiceFiles lists every unit file one publication owns.
func publishedServiceFiles(unitDir, pipelockPath, proxyUser string, service config.ContainmentPublishedService) []publishedManagedFile {
	base := publishedServiceUnitBase(service.Name)
	relay := renderPublishedForwarderUnit(pipelockPath, proxyUser, service)
	files := []publishedManagedFile{
		{filepath.Join(unitDir, base+".socket"), renderPublishedSocketUnit(service)},
		{filepath.Join(unitDir, base+".service"), relay},
	}
	if service.HostListen != "" {
		tcp := publishedServiceTCPUnitBase(service.Name)
		files = append(files,
			publishedManagedFile{filepath.Join(unitDir, tcp+".socket"), renderPublishedTCPSocketUnit(service)},
			publishedManagedFile{filepath.Join(unitDir, tcp+".service"), relay},
		)
	}
	return files
}

// publishedRecordUnitNames lists the unit names a recorded publication may
// have left behind, including the TCP pair, so revocation never strands one.
func publishedRecordUnitNames(record publishedServiceRecord) []string {
	names := []string{record.Unit + ".socket", record.Unit + ".service"}
	if record.HostListen != "" {
		tcp := publishedServiceTCPUnitBase(record.Name)
		names = append(names, tcp+".socket", tcp+".service")
	}
	return names
}

func publishedServiceSockets(service config.ContainmentPublishedService) []string {
	sockets := []string{publishedServiceUnitBase(service.Name) + ".socket"}
	if service.HostListen != "" {
		sockets = append(sockets, publishedServiceTCPUnitBase(service.Name)+".socket")
	}
	return sockets
}

func desiredPublishedServices(services []config.ContainmentPublishedService) publishedServiceRecordSet {
	set := publishedServiceRecordSet{Services: make([]publishedServiceRecord, 0, len(services))}
	for _, service := range services {
		set.Services = append(set.Services, publishedServiceRecord{
			Unit:         publishedServiceUnitBase(service.Name),
			Name:         service.Name,
			AgentHost:    service.EffectiveAgentHost(),
			AgentPort:    service.AgentPort,
			HostSocket:   service.EffectiveHostSocket(),
			HostListen:   service.HostListen,
			OperatorUser: service.OperatorUser,
			Owner:        service.Owner,
			Reason:       service.Reason,
			ExpiresAt:    service.ExpiresAt,
		})
	}
	return set
}

func encodePublishedServiceRecords(set publishedServiceRecordSet) ([]byte, error) {
	data, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode published service records: %w", err)
	}
	return append(data, '\n'), nil
}

func decodePublishedServiceRecords(data []byte) (publishedServiceRecordSet, error) {
	var set publishedServiceRecordSet
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&set); err != nil {
		return publishedServiceRecordSet{}, fmt.Errorf("parse published service records: %w", err)
	}
	for _, record := range set.Services {
		if !config.ValidPublishedServiceName(record.Name) || record.Unit != publishedServiceUnitBase(record.Name) {
			return publishedServiceRecordSet{}, fmt.Errorf("published service records contain non-canonical unit %q", record.Unit)
		}
	}
	return set, nil
}

func readPublishedServiceRecords(env *installEnv) (publishedServiceRecordSet, error) {
	data, err := env.readFile(publishedServiceRecordPath(env.loopbackForwarderInvPath))
	if errors.Is(err, os.ErrNotExist) {
		return publishedServiceRecordSet{}, nil
	}
	if err != nil {
		return publishedServiceRecordSet{}, fmt.Errorf("read published service records: %w", err)
	}
	return decodePublishedServiceRecords(data)
}

// containmentPublishedServicesFromMapping decodes containment.published_services
// strictly. It also returns the raw declared loopback list, used only for the
// port-collision check, so a publication is refused for colliding with a
// loopback declaration even when that declaration is itself unusable.
func containmentPublishedServicesFromMapping(root *yaml.Node) ([]config.ContainmentPublishedService, []config.ContainmentLoopbackService, error) {
	containment := mappingValue(root, "containment")
	if absentContainmentValue(containment) {
		return nil, nil, nil
	}
	if containment.Kind != yaml.MappingNode {
		return nil, nil, errors.New("containment must be a mapping")
	}
	loopback, _ := containmentLoopbackServicesFromMapping(root)
	services := mappingValue(containment, "published_services")
	if absentContainmentValue(services) {
		return nil, loopback, nil
	}
	if services.Kind != yaml.SequenceNode {
		return nil, nil, errors.New("containment.published_services must be a list")
	}
	data, err := yaml.Marshal(services)
	if err != nil {
		return nil, nil, fmt.Errorf("encode containment.published_services: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var declared []config.ContainmentPublishedService
	if err := decoder.Decode(&declared); err != nil {
		return nil, nil, fmt.Errorf("parse containment.published_services: %w", err)
	}
	return declared, loopback, nil
}

// parseContainmentPublishedServicesFromConfigBytes is the single parser that
// install (fails closed), reload (drops to zero publications), and verify
// (reports FAIL) all use, so they agree on what counts as honorable.
func parseContainmentPublishedServicesFromConfigBytes(data []byte, proxyPort int, now time.Time) ([]config.ContainmentPublishedService, error) {
	root, err := parseSingleYAMLDocument(data)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, fmt.Errorf("parse managed config: %w", err)
	}
	mapping := documentMapping(root)
	if mapping == nil {
		return nil, errors.New("managed config must be a YAML mapping")
	}
	declared, loopback, err := containmentPublishedServicesFromMapping(mapping)
	if err != nil {
		return nil, err
	}
	if err := config.ValidateContainmentPublishedServices(declared, loopback, effectiveProxyPort(mapping, proxyPort), now); err != nil {
		return nil, err
	}
	return declared, nil
}

func declaredContainmentPublishedServices(env *installEnv, proxyPort int) ([]config.ContainmentPublishedService, error) {
	data, err := env.readFile(managedPipelockConfigPath(env))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read managed config %s: %w", managedPipelockConfigPath(env), err)
	}
	declared, err := parseContainmentPublishedServicesFromConfigBytes(data, proxyPort, time.Now())
	if err != nil {
		return nil, fmt.Errorf("managed config %s: %w", managedPipelockConfigPath(env), err)
	}
	return declared, nil
}

// checkPublishedOperators resolves every operator before anything is written.
// Publishing to the agent's own account would hand the agent a host-side
// endpoint into itself, so it is refused rather than rendered.
func checkPublishedOperators(env *installEnv, services []config.ContainmentPublishedService) error {
	for _, service := range services {
		if service.OperatorUser == env.agentUserName {
			return fmt.Errorf("containment.published_services %s: operator_user must not be the contained agent account %s", service.Name, env.agentUserName)
		}
		if env.lookupUser == nil {
			return fmt.Errorf("containment.published_services %s: cannot resolve operator_user %s", service.Name, service.OperatorUser)
		}
		if _, err := env.lookupUser(service.OperatorUser); err != nil {
			return fmt.Errorf("containment.published_services %s: operator_user %s does not exist: %w", service.Name, service.OperatorUser, err)
		}
	}
	return nil
}

// stepInstallPublishedServices reconciles published services from the managed
// config (or the override the reload path passes) against the recorded set:
// new ones are written and started, changed ones re-rendered, and removed or
// expired ones stopped and their unit files restored, so a doorway never
// outlives its declaration. A failure undoes every file and runtime change
// back to the captured prior state.
func stepInstallPublishedServices(serviceOverride *[]config.ContainmentPublishedService) step {
	var previous map[string]unitRuntimeState
	var touched []string
	var retired map[string][]byte
	return step{
		name: "install-published-services",
		desc: "publish declared contained-agent services to their operators",
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			var services []config.ContainmentPublishedService
			if serviceOverride != nil {
				services = append([]config.ContainmentPublishedService(nil), (*serviceOverride)...)
			} else {
				var err error
				services, err = declaredContainmentPublishedServices(env, env.proxyPort)
				if err != nil {
					return false, err
				}
			}
			if err := checkPublishedOperators(env, services); err != nil {
				return false, err
			}
			old, err := readPublishedServiceRecords(env)
			if err != nil {
				return false, err
			}
			recordPath := publishedServiceRecordPath(env.loopbackForwarderInvPath)
			if len(services) == 0 && len(old.Services) == 0 {
				if _, statErr := env.stat(recordPath); errors.Is(statErr, os.ErrNotExist) {
					// Nothing declared and nothing ever published: leave no
					// file behind on hosts that never use the feature.
					return false, nil
				}
			}
			recordBytes, err := encodePublishedServiceRecords(desiredPublishedServices(services))
			if err != nil {
				return false, err
			}
			if err := env.mkdirAll(filepath.Dir(recordPath), modeDirTraversable); err != nil {
				return false, fmt.Errorf("create published service record directory: %w", err)
			}
			unitDir := filepath.Dir(env.proxyForwarderSocketPath)
			var files []publishedManagedFile
			desired := make(map[string]bool)
			changedUnit := make(map[string]bool)
			for _, service := range services {
				for _, item := range publishedServiceFiles(unitDir, env.pipelockTarget, env.proxyUserName, service) {
					desired[filepath.Base(item.path)] = true
					files = append(files, item)
				}
			}

			previous = make(map[string]unitRuntimeState)
			for _, record := range old.Services {
				for _, unit := range publishedRecordUnitNames(record) {
					previous[unit] = systemdUnitRuntimeState(ctx, env, unit)
				}
			}
			for unit := range desired {
				if _, ok := previous[unit]; !ok {
					previous[unit] = systemdUnitRuntimeState(ctx, env, unit)
				}
			}
			touched = nil
			retired = make(map[string][]byte)
			for _, item := range files {
				mode := modeUnitFile
				if item.path == recordPath {
					mode = modeConfigSecret
				}
				if existing, readErr := env.readFile(item.path); readErr == nil && string(existing) == item.body {
					if err := env.chmod(item.path, mode); err != nil {
						return len(touched) > 0, fmt.Errorf("chmod %s: %w", item.path, err)
					}
					continue
				}
				if err := backupAndWrite(env, item.path, []byte(item.body), mode); err != nil {
					return len(touched) > 0, fmt.Errorf("write %s: %w", item.path, err)
				}
				touched = append(touched, item.path)
				changedUnit[filepath.Base(item.path)] = true
			}
			// Revoke before starting anything new: a removed or expired
			// publication must be closed even if a later start fails.
			for _, record := range old.Services {
				for _, unit := range publishedRecordUnitNames(record) {
					if desired[unit] {
						continue
					}
					if strings.HasSuffix(unit, ".socket") {
						if err := runSystemctlCleanupUnit(ctx, env, "disable", "--now", unit); err != nil {
							return true, fmt.Errorf("close revoked published endpoint %s: %w", unit, err)
						}
					} else if err := runSystemctlCleanupUnit(ctx, env, "stop", unit); err != nil {
						return true, fmt.Errorf("stop revoked published relay %s: %w", unit, err)
					}
				}
				for _, unit := range publishedRecordUnitNames(record) {
					if desired[unit] {
						continue
					}
					path := filepath.Join(unitDir, unit)
					body, readErr := env.readFile(path)
					if errors.Is(readErr, os.ErrNotExist) {
						continue
					}
					if readErr != nil {
						return true, fmt.Errorf("read revoked published unit %s: %w", path, readErr)
					}
					if err := restoreBackup(env, path); err != nil {
						return true, fmt.Errorf("remove revoked published unit %s: %w", path, err)
					}
					retired[path] = body
				}
			}
			// Keep revoked units recorded until every disable has completed.
			if existing, readErr := env.readFile(recordPath); readErr == nil && bytes.Equal(existing, recordBytes) {
				if err := env.chmod(recordPath, modeConfigSecret); err != nil {
					return true, fmt.Errorf("chmod published service records: %w", err)
				}
			} else {
				if err := backupAndWrite(env, recordPath, recordBytes, modeConfigSecret); err != nil {
					return true, fmt.Errorf("write published service records: %w", err)
				}
				touched = append(touched, recordPath)
			}
			if err := runOrErr(ctx, env, "systemctl", "daemon-reload"); err != nil {
				return true, fmt.Errorf("reload systemd after publishing services: %w", err)
			}
			for _, service := range services {
				for _, socket := range publishedServiceSockets(service) {
					relay := strings.TrimSuffix(socket, ".socket") + ".service"
					// A running relay keeps its old ExecStart and descriptor;
					// stop it so the next connection activates the new one.
					if changedUnit[relay] && previous[relay].active {
						if err := runOrErr(ctx, env, "systemctl", "stop", relay); err != nil {
							return true, fmt.Errorf("stop changed published relay %s: %w", relay, err)
						}
					}
					if changedUnit[socket] && previous[socket].active {
						if err := runOrErr(ctx, env, "systemctl", "restart", socket); err != nil {
							return true, fmt.Errorf("restart changed published endpoint %s: %w", socket, err)
						}
					}
					if err := runOrErr(ctx, env, "systemctl", "enable", "--now", socket); err != nil {
						return true, fmt.Errorf("enable published endpoint %s: %w", socket, err)
					}
				}
			}
			changed := len(touched) > 0 || len(retired) > 0
			for unit := range desired {
				if strings.HasSuffix(unit, ".socket") {
					changed = changed || !previous[unit].enabled || !previous[unit].active
				}
			}
			return changed, nil
		},
		undo: func(ctx context.Context, env *installEnv) error {
			var errs []error
			units := make([]string, 0, len(previous))
			for unit := range previous {
				units = append(units, unit)
			}
			sort.Strings(units)
			for _, unit := range units {
				state := previous[unit]
				if !state.active {
					if err := runSystemctlCleanupUnit(ctx, env, "stop", unit); err != nil {
						errs = append(errs, err)
					}
				}
				if !state.enabled && strings.HasSuffix(unit, ".socket") {
					if err := runSystemctlCleanupUnit(ctx, env, "disable", unit); err != nil {
						errs = append(errs, err)
					}
				}
			}
			for i := len(touched) - 1; i >= 0; i-- {
				if err := restoreBackup(env, touched[i]); err != nil {
					errs = append(errs, err)
				}
			}
			for path, body := range retired {
				if err := backupAndWrite(env, path, body, modeUnitFile); err != nil {
					errs = append(errs, fmt.Errorf("restore retired published unit %s: %w", path, err))
				}
			}
			if err := runOrErr(ctx, env, "systemctl", "daemon-reload"); err != nil {
				errs = append(errs, err)
			}
			for _, unit := range units {
				state := previous[unit]
				if state.enabled {
					if err := runOrErr(ctx, env, "systemctl", "enable", unit); err != nil {
						errs = append(errs, err)
					}
				}
				if state.active && strings.HasSuffix(unit, ".socket") {
					if err := runOrErr(ctx, env, "systemctl", "start", unit); err != nil {
						errs = append(errs, err)
					}
				}
			}
			return errors.Join(errs...)
		},
	}
}

// removePublishedServices is rollback's teardown: close every recorded
// endpoint and restore the unit files and record to their pre-install state.
func removePublishedServices(ctx context.Context, env *installEnv) error {
	if env.loopbackForwarderInvPath == "" {
		return nil
	}
	set, err := readPublishedServiceRecords(env)
	if err != nil {
		return err
	}
	var errs []error
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	for _, record := range set.Services {
		for _, unit := range publishedRecordUnitNames(record) {
			args := []string{"stop", unit}
			if strings.HasSuffix(unit, ".socket") {
				args = []string{"disable", "--now", unit}
			}
			if err := runSystemctlCleanupUnit(ctx, env, args...); err != nil {
				errs = append(errs, err)
			}
		}
		for _, unit := range publishedRecordUnitNames(record) {
			path := filepath.Join(unitDir, unit)
			if err := restoreBackup(env, path); err != nil {
				errs = append(errs, fmt.Errorf("restore %s: %w", path, err))
			}
		}
	}
	path := publishedServiceRecordPath(env.loopbackForwarderInvPath)
	if err := restoreBackup(env, path); err != nil {
		errs = append(errs, fmt.Errorf("restore %s: %w", path, err))
	}
	return errors.Join(errs...)
}

// reconcileDeclaredContainmentPublishedServicesForReload fails closed: any
// problem reading or validating the declaration yields zero publications, so
// the reload closes every doorway rather than keeping a stale one open.
func reconcileDeclaredContainmentPublishedServicesForReload(env *nftReloadEnv, proxyPort int) []config.ContainmentPublishedService {
	now := time.Now
	if env.now != nil {
		now = env.now
	}
	data, err := env.readFile(env.configPath)
	if err != nil {
		// The loopback reconciler already warned about an absent or
		// unreadable managed config; the outcome here is the same.
		return nil
	}
	declared, err := parseContainmentPublishedServicesFromConfigBytes(data, proxyPort, now())
	if err != nil {
		if env.warn != nil {
			env.warn(fmt.Sprintf("containment: managed config %s declares containment.published_services that Pipelock cannot honor (%v); closing every published service until it is fixed — remove or re-approve the offending entry, then run `pipelock contain reload-nft-rules`", env.configPath, err))
		}
		return nil
	}
	return declared
}

// declaredContainmentPublishedServicesForVerify mirrors the loopback reader:
// an unreadable config or an unhonorable declaration is a problem verify
// reports, never an empty list it passes.
func declaredContainmentPublishedServicesForVerify(env *probeEnv, proxyPort int) ([]config.ContainmentPublishedService, string, bool) {
	data, err := env.readFile(env.configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", false
		}
		return nil, fmt.Sprintf("read managed config %s: %v", env.configPath, err), true
	}
	declared, err := parseContainmentPublishedServicesFromConfigBytes(data, proxyPort, time.Now())
	if err != nil {
		return nil, err.Error(), true
	}
	return declared, "", false
}

// probePublishedServices reports each publication's live state. The failure
// classes are deliberately distinct because each has a different remedy:
// drift (reinstall), bridge failed (the endpoint or relay is down), access
// denied (the endpoint admits the wrong principal), wrong namespace (the relay
// is not dialing the agent's loopback), absent listener (the agent is not
// serving). Any state the probe cannot read is a failure, never a pass.
func probePublishedServices(ctx context.Context, env *probeEnv, holderPID int, agentNamespace string) (string, string) {
	services, problem, unusable := declaredContainmentPublishedServicesForVerify(env, env.port)
	if unusable {
		return statusFail, "containment.published_services cannot be honored: " + problem
	}
	recordPath := publishedServiceRecordPath(env.loopbackForwarderInvPath)
	got, err := env.readFile(recordPath)
	switch {
	case errors.Is(err, os.ErrNotExist) && len(services) == 0:
		return statusPass, "no published services declared"
	case err != nil:
		return statusFail, fmt.Sprintf("read published service records %s: %v", recordPath, err)
	}
	want, err := encodePublishedServiceRecords(desiredPublishedServices(services))
	if err != nil {
		return statusFail, err.Error()
	}
	if !bytes.Equal(got, want) {
		return statusFail, "published service records do not match containment.published_services; run `pipelock contain reload-nft-rules`"
	}
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	procRoot := env.procRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	for _, service := range services {
		for _, item := range publishedServiceFiles(unitDir, env.pipelockTarget, env.proxyUserName, service) {
			body, readErr := env.readFile(item.path)
			if readErr != nil || string(body) != item.body {
				return statusFail, fmt.Sprintf("published service %s: unit %s is missing or drifted; run `pipelock contain reload-nft-rules`", service.Name, item.path)
			}
		}
		for _, socket := range publishedServiceSockets(service) {
			if out, code, runErr := env.runCmd(ctx, "systemctl", "is-enabled", socket); runErr != nil || code != 0 || strings.TrimSpace(out) != systemctlEnabled {
				return statusFail, fmt.Sprintf("published service %s: bridge failed: endpoint %s is not persistently enabled (%s)", service.Name, socket, oneLine(out))
			}
			if out, code, runErr := env.runCmd(ctx, "systemctl", "is-active", socket); runErr != nil || code != 0 || strings.TrimSpace(out) != systemctlActive {
				return statusFail, fmt.Sprintf("published service %s: bridge failed: endpoint %s is %s", service.Name, socket, oneLine(out))
			}
		}
		if status, detail := probePublishedSocketAccess(env, service); status != statusPass {
			return status, detail
		}
		relay := publishedServiceUnitBase(service.Name) + ".service"
		out, _, runErr := env.runCmd(ctx, "systemctl", "is-active", relay)
		state := strings.TrimSpace(out)
		switch {
		case runErr != nil:
			return statusFail, fmt.Sprintf("published service %s: relay %s state unknown: %v", service.Name, relay, runErr)
		case state == "failed":
			return statusFail, fmt.Sprintf("published service %s: bridge failed: relay %s is failed; run `systemctl reset-failed %s` and inspect its journal", service.Name, relay, relay)
		case state == systemctlActive:
			pidOut, code, pidErr := env.runCmd(ctx, "systemctl", "show", relay, "--property=MainPID", "--value")
			pid, convErr := strconv.Atoi(strings.TrimSpace(pidOut))
			if pidErr != nil || code != 0 || convErr != nil || pid <= 1 {
				return statusFail, fmt.Sprintf("published service %s: relay %s namespace unknown (MainPID %q)", service.Name, relay, oneLine(pidOut))
			}
			ns, nsErr := env.readLink(filepath.Join(procRoot, strconv.Itoa(pid), "ns", "net"))
			if nsErr != nil {
				return statusFail, fmt.Sprintf("published service %s: relay %s namespace unknown: %v", service.Name, relay, nsErr)
			}
			if ns != agentNamespace {
				return statusFail, fmt.Sprintf("published service %s: wrong namespace: relay %s runs in %s, not the agent namespace %s", service.Name, relay, ns, agentNamespace)
			}
		case state == "inactive" || state == "activating" || state == "deactivating":
			// Socket-activated and idle: the unit definition was verified
			// above, and the next connection activates it in the namespace.
		default:
			return statusFail, fmt.Sprintf("published service %s: relay %s is in unrecognized state %q", service.Name, relay, state)
		}
		listening, listenErr := agentNamespaceListens(env, procRoot, holderPID, service.EffectiveAgentHost(), service.AgentPort)
		if listenErr != nil {
			return statusFail, fmt.Sprintf("published service %s: agent listener state unknown: %v", service.Name, listenErr)
		}
		if !listening {
			return statusFail, fmt.Sprintf("published service %s: absent listener: no matching listener on %s (an IPv6-only or unknown wildcard does not count for an IPv4 target)", service.Name, publishedAgentTarget(service))
		}
	}
	for _, service := range services {
		if service.HostListen != "" {
			return statusPass, fmt.Sprintf("%d published service(s) reach their agent listener; Unix sockets admit only their operator, and TCP host listeners admit any local account on the host", len(services))
		}
	}
	return statusPass, fmt.Sprintf("%d published service(s) reach their agent listener and admit only their operator", len(services))
}

// probePublishedSocketAccess checks the one property that decides who can
// connect to a unix socket: its owner and mode. Only root and the named
// operator may pass.
func probePublishedSocketAccess(env *probeEnv, service config.ContainmentPublishedService) (string, string) {
	path := service.EffectiveHostSocket()
	if env.stat == nil || env.lookupUser == nil {
		return statusFail, fmt.Sprintf("published service %s: endpoint access unknown: probe cannot inspect %s", service.Name, path)
	}
	info, err := env.stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return statusFail, fmt.Sprintf("published service %s: bridge failed: endpoint %s does not exist", service.Name, path)
	}
	if err != nil {
		return statusFail, fmt.Sprintf("published service %s: endpoint access unknown: %v", service.Name, err)
	}
	operator, err := env.lookupUser(service.OperatorUser)
	if err != nil {
		return statusFail, fmt.Sprintf("published service %s: access denied: operator_user %s does not resolve: %v", service.Name, service.OperatorUser, err)
	}
	uid, ok := fileOwnerUID(info)
	if !ok {
		return statusFail, fmt.Sprintf("published service %s: endpoint access unknown: owner of %s unreadable", service.Name, path)
	}
	if info.Mode()&os.ModeSocket == 0 || strconv.FormatUint(uint64(uid), 10) != operator.Uid || info.Mode().Perm() != publishedServiceSocketMode {
		return statusFail, fmt.Sprintf("published service %s: access denied: endpoint %s must be a socket owned by %s with mode 0600 (found uid %d mode %v)", service.Name, path, service.OperatorUser, uid, info.Mode())
	}
	return statusPass, ""
}

// agentNamespaceListens reads the socket table of the namespace holder.
// /proc/<pid>/net/tcp reports the network namespace of that process (proc(5)),
// so this sees the agent's listeners without entering the namespace. A
// wildcard listener counts only within the target's address family.
func agentNamespaceListens(env *probeEnv, procRoot string, holderPID int, host string, port int) (bool, error) {
	if holderPID <= 1 {
		return false, fmt.Errorf("namespace holder pid %d is invalid", holderPID)
	}
	want := map[string]bool{"00000000000000000000000000000000": true}
	files := []string{"tcp6"}
	if host == "::1" {
		want["00000000000000000000000001000000"] = true
	} else {
		// IPV6_V6ONLY may be set per socket, independent of the namespace
		// default. A tcp6 wildcard cannot prove IPv4 acceptance.
		files = []string{"tcp"}
		want["0100007F"] = true
		want["00000000"] = true
	}
	portHex := fmt.Sprintf("%04X", port)
	for _, name := range files {
		data, err := env.readFile(filepath.Join(procRoot, strconv.Itoa(holderPID), "net", name))
		if err != nil {
			if name == "tcp6" && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return false, err
		}
		for i, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if i == 0 || len(fields) < 4 {
				continue
			}
			addr, p, ok := strings.Cut(fields[1], ":")
			if ok && p == portHex && fields[3] == "0A" && want[addr] {
				return true, nil
			}
		}
	}
	return false, nil
}
