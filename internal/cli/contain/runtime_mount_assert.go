// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// systemd service code (v257 exec-invoke.c:3323, also v261:3933) uses
// /run/systemd/incoming, despite systemd.exec(5) naming /run/host/incoming.
const (
	systemdIncomingPath    = "/run/systemd/incoming"
	systemdPropagationRoot = "/systemd/propagate/"
)

var (
	errRuntimeMountEvidenceUnavailable = errors.New("runtime mount evidence is unavailable")
	errManagedRuntimeMask              = errors.New("managed runtime mask is not applied")
	errUnexpectedRuntimeExposure       = errors.New("unexpected runtime exposure")
)

func unexpectedRuntimeExposure(path, reason string) error {
	return fmt.Errorf("%w: %q: %s", errUnexpectedRuntimeExposure, path, reason)
}

type runtimeMount struct {
	device, root, filesystem string
	id, parent               string
	options                  []string
}

// Mountinfo, rather than unit configuration alone, proves the restrictions
// applied to this caller. PID 1 remains in the host mount namespace for contain
// launches, so its filesystem identities distinguish a new tmpfs from host shm.
func assertManagedRuntimeMounts(env netnsAssertEnv) error {
	if err := checkManagedRuntimeMounts(env); err != nil {
		return runtimeMountRefusal(err)
	}
	return nil
}

func runtimeMountRefusal(err error) error {
	if errors.Is(err, errRuntimeMountEvidenceUnavailable) {
		return fmt.Errorf("runtime socket isolation cannot be verified: %w; permit the posture checker to read /proc/self/mountinfo, /proc/1/mountinfo and runtime directories; check procfs hidepid and access permissions", err)
	}
	if errors.Is(err, errManagedRuntimeMask) {
		return fmt.Errorf("runtime socket isolation is not applied: %w; retain the managed ProtectHome=tmpfs profile, remove conflicting unit overrides or binds at this path, rerun `pipelock contain install` and restart the agent service", err)
	}
	if errors.Is(err, errUnexpectedRuntimeExposure) {
		return fmt.Errorf("runtime socket isolation is not applied: %w; remove the extra bind, unit drop-in or credential setting (for example LoadCredential creates /run/credentials) exposing this path, then restart the agent service", err)
	}
	return fmt.Errorf("runtime socket isolation is not applied: %w; add %s to the agent unit; update managed wrappers with `pipelock contain install` and restart the agent service", err, strings.Join(runtimeSocketProperties(), ", "))
}

func checkManagedRuntimeMounts(env netnsAssertEnv) error {
	return checkRuntimeMountsForProperties(env, runtimeSocketTemporaryFileSystems())
}

func checkRuntimeMountsForProperties(env netnsAssertEnv, required []string) error {
	if env.readFile == nil || env.readDir == nil {
		return fmt.Errorf("%w: runtime mount readers are unavailable", errRuntimeMountEvidenceUnavailable)
	}
	self, err := readRuntimeMounts(env, "/proc/self/mountinfo")
	if err != nil {
		return err
	}
	host, err := readRuntimeMounts(env, "/proc/1/mountinfo")
	if err != nil {
		return err
	}
	// A bind of some other host tmpfs root has root / and a device distinct from
	// the host mount at the same path, yet stays shared with the host after this
	// check. systemd creates the private masks inside the unit's namespace only,
	// so their devices are absent from PID 1's whole table, hidden entries included.
	hostDevices, err := hostMountDevices(env)
	if err != nil {
		return err
	}
	for _, property := range required {
		path, _, _ := strings.Cut(property, ":")
		mount, ok := self[path]
		if !ok || mount.filesystem != "tmpfs" || mount.root != "/" {
			return fmt.Errorf("%s must be a private tmpfs mount", path)
		}
		hostMount, ok := host[path]
		for parent := filepath.Dir(path); !ok; parent = filepath.Dir(parent) {
			hostMount, ok = host[parent]
			if parent == "/" {
				break
			}
		}
		if ok && mount.device != hostMount.device && hostDevices[mount.device] {
			// The requested property is present, but something binds a host
			// filesystem over it; adding the property again cannot help.
			return unexpectedRuntimeExposure(path, path+" does not have a verified private filesystem identity: it is shared with a host mount")
		}
		if !ok || mount.device == hostMount.device {
			return fmt.Errorf("%s does not have a verified private filesystem identity", path)
		}
		options := []string{"ro"}
		if path == "/dev/shm" {
			options = []string{"rw", "nosuid", "nodev", "noexec"}
		}
		for _, option := range options {
			if !slices.Contains(mount.options, option) {
				return fmt.Errorf("%s mount lacks %s", path, option)
			}
		}
	}
	identity, ok := self[containedNamespaceIdentityPath]
	if !ok || !slices.Contains(identity.options, "ro") {
		return fmt.Errorf("namespace identity must have its own read-only bind mount")
	}
	entries, err := env.readDir("/run")
	if err != nil {
		return fmt.Errorf("%w: inspect isolated runtime directory /run: %w", errRuntimeMountEvidenceUnavailable, err)
	}
	// Enumerate the whole runtime tree, including mounts hidden by overmounts.
	// Only the declared private masks, identity bind and propagation bind belong.
	allowed := map[string]bool{containedNamespaceIdentityPath: true, systemdIncomingPath: true}
	protectHome := slices.Contains(env.unitProperties, protectHomeTmpfsProperty)
	if protectHome {
		allowed["/run/user"] = true
	}
	for _, property := range required {
		path, _, _ := strings.Cut(property, ":")
		allowed[path] = true
	}
	for _, path := range slices.Sorted(maps.Keys(self)) {
		if isRuntimeMountPath(path) && !allowed[path] {
			if protectHome && strings.HasPrefix(path, "/run/user/") {
				return fmt.Errorf("%w: %q has a mount beneath the managed /run/user mask", errManagedRuntimeMask, path)
			}
			return unexpectedRuntimeExposure(path, "unexpected mount in isolated runtime tree")
		}
	}
	for _, entry := range entries {
		path := "/run/" + entry.Name()
		if !entry.IsDir() {
			if protectHome && entry.Name() == "user" {
				return fmt.Errorf("%w: /run/user must be a directory", errManagedRuntimeMask)
			}
			return unexpectedRuntimeExposure(path, "/run must contain only the managed namespace identity and verified systemd mount propagation")
		}
		switch entry.Name() {
		case "pipelock-contain":
			// The identity directory is checked below.
		case "user":
			if !protectHome {
				return unexpectedRuntimeExposure(path, "/run must contain only requested runtime masks; /run/user is allowed only for a Pipelock-rendered launch profile that requests ProtectHome=tmpfs")
			}
		case "systemd":
			if err := checkRuntimeDirectoryEntry(env, path, "incoming", true); err != nil {
				return err
			}
			if err := checkSystemdPropagation(env, self, host); err != nil {
				return err
			}
		default:
			return unexpectedRuntimeExposure(path, "/run must contain only the managed namespace identity and verified systemd mount propagation")
		}
	}
	if protectHome {
		if err := checkProtectHomeRuntimeMask(env, self, host, hostDevices); err != nil {
			return err
		}
	}
	return checkRuntimeDirectoryEntry(env, "/run/pipelock-contain", "agent-netns.id", false)
}

func checkRuntimeDirectoryEntry(env netnsAssertEnv, path, name string, directory bool) error {
	entries, err := env.readDir(path)
	if err != nil {
		return fmt.Errorf("%w: inspect isolated runtime directory %s: %w", errRuntimeMountEvidenceUnavailable, path, err)
	}
	if len(entries) != 1 || entries[0].Name() != name || entries[0].IsDir() != directory || (!directory && !entries[0].Type().IsRegular()) {
		kind := "regular file"
		if directory {
			kind = "directory"
		}
		for _, entry := range entries {
			if entry.Name() != name || entry.IsDir() != directory || (!directory && !entry.Type().IsRegular()) {
				return unexpectedRuntimeExposure(filepath.Join(path, entry.Name()), fmt.Sprintf("%s must contain only %s as a %s", path, name, kind))
			}
		}
		return unexpectedRuntimeExposure(path, fmt.Sprintf("%s must contain only %s as a %s", path, name, kind))
	}
	return nil
}

// systemd v257 namespace.c:193-197 and v261:206-210 map ProtectHome=tmpfs
// to read-only tmpfs masks at /home, /root and /run/user.
func checkProtectHomeRuntimeMask(env netnsAssertEnv, self, host map[string]runtimeMount, hostDevices map[string]bool) error {
	mount, ok := self["/run/user"]
	if !ok || mount.filesystem != "tmpfs" || mount.root != "/" || !slices.Contains(mount.options, "ro") {
		return fmt.Errorf("%w: /run/user must be the requested read-only tmpfs mask with root /", errManagedRuntimeMask)
	}
	if hostRun, ok := host["/run"]; !ok || mount.device == hostRun.device {
		return fmt.Errorf("%w: /run/user must have a private filesystem identity distinct from host /run", errManagedRuntimeMask)
	}
	if hostDevices[mount.device] {
		return fmt.Errorf("%w: /run/user is shared with a host mount, not a private mask", errManagedRuntimeMask)
	}
	// The table above mounts the mask with mode=0755, so every caller can list
	// it. An unlistable directory may still be traversable to a known socket.
	entries, err := env.readDir("/run/user")
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w: /run/user mask must be listable; systemd mounts it with mode=0755", errManagedRuntimeMask)
	}
	if err != nil {
		return fmt.Errorf("%w: inspect /run/user mask: %w", errRuntimeMountEvidenceUnavailable, err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("%w: %q: /run/user mask must be empty", errManagedRuntimeMask, filepath.Join("/run/user", entries[0].Name()))
	}
	return nil
}

// hostMountDevices collects every device in PID 1's mount table. Only the
// device field is read, so overmounted and hidden host entries still count.
func hostMountDevices(env netnsAssertEnv) (map[string]bool, error) {
	data, err := env.readFile("/proc/1/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("%w: read runtime mount evidence /proc/1/mountinfo: %w", errRuntimeMountEvidenceUnavailable, err)
	}
	devices := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("malformed runtime mount evidence in /proc/1/mountinfo")
		}
		devices[fields[2]] = true
	}
	return devices, nil
}

func checkSystemdPropagation(env netnsAssertEnv, self, host map[string]runtimeMount) error {
	mount, ok := self[systemdIncomingPath]
	if !ok {
		return unexpectedRuntimeExposure(systemdIncomingPath, "must have its own systemd propagation mount")
	}
	if !strings.HasPrefix(mount.root, systemdPropagationRoot) || filepath.Clean(mount.root) != mount.root {
		return unexpectedRuntimeExposure(systemdIncomingPath, "mount root must be under "+systemdPropagationRoot)
	}
	// The shared reader identifies the last unified-cgroup component. A legacy
	// hierarchy or cgroup namespace rooted at / may hide the service identity;
	// retain the source-directory constraint when no service name is visible.
	unit := processSystemdUnit(env.readFile, "/proc/self/cgroup")
	if strings.HasSuffix(unit, ".service") && mount.root != systemdPropagationRoot+unit {
		return unexpectedRuntimeExposure(systemdIncomingPath, "propagation root does not match this unit "+unit)
	}
	if hostRun, ok := host["/run"]; !ok || mount.device != hostRun.device {
		return unexpectedRuntimeExposure(systemdIncomingPath, "propagation device must match host /run")
	}
	if !slices.Contains(mount.options, "ro") {
		return unexpectedRuntimeExposure(systemdIncomingPath, "systemd propagation mount must be read-only")
	}
	if env.lstat == nil {
		return fmt.Errorf("%w: propagation stat reader is unavailable", errRuntimeMountEvidenceUnavailable)
	}
	info, err := env.lstat(systemdIncomingPath)
	if err != nil {
		return fmt.Errorf("%w: inspect propagation directory %s: %w", errRuntimeMountEvidenceUnavailable, systemdIncomingPath, err)
	}
	uid, known := fileOwnerUID(info)
	// systemd v257 namespace.c:2807 creates the host propagation source with
	// mkdir_p(..., 0600). Its read-only bind must remain root-only, not a doorway.
	if !known || uid != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return unexpectedRuntimeExposure(systemdIncomingPath, "must be a root-owned directory with no group or other permissions")
	}
	entries, err := env.readDir(systemdIncomingPath)
	if err != nil && !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w: inspect propagation contents %s: %w", errRuntimeMountEvidenceUnavailable, systemdIncomingPath, err)
	}
	if len(entries) != 0 {
		return unexpectedRuntimeExposure(filepath.Join(systemdIncomingPath, entries[0].Name()), "systemd propagation directory must be empty when readable")
	}
	return nil
}

func isRuntimeMountPath(path string) bool {
	for _, root := range []string{"/run", "/var/run", "/dev/shm"} {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

// mountinfo escapes whitespace and backslashes with these octal sequences
// (Linux fs/proc_namespace.c seq_path_root(..., " \t\n\\")). Decode before comparing paths.
func runtimeMountPath(path string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(path)
}

func readRuntimeMounts(env netnsAssertEnv, path string) (map[string]runtimeMount, error) {
	data, err := env.readFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read runtime mount evidence %s: %w", errRuntimeMountEvidenceUnavailable, path, err)
	}
	candidates := make(map[string]map[string]runtimeMount)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		separator := slices.Index(fields, "-")
		if separator < 6 || separator+3 >= len(fields) {
			return nil, fmt.Errorf("malformed runtime mount evidence in %s", path)
		}
		// The host table supplies fixed filesystem identities only. Its unrelated
		// descendants can be hidden by overmounts and need not form a visible
		// stack. The caller table still inventories the entire runtime tree.
		// Decode kernel path escaping before classifying that tree.
		// An overmount's parent is
		// the mount it shadows at the same path, not necessarily its directory
		// parent. Keep that chain to select the visible top without relying on
		// the order of lines or on mount IDs increasing monotonically.
		target := runtimeMountPath(fields[4])
		fixedTarget := target == "/" || target == "/dev" || target == "/var" || target == "/run" || target == "/var/run" || target == "/dev/shm"
		if !fixedTarget && (path == "/proc/1/mountinfo" || !isRuntimeMountPath(target)) {
			continue
		}
		if candidates[target] == nil {
			candidates[target] = make(map[string]runtimeMount)
		}
		if _, exists := candidates[target][fields[0]]; exists {
			return nil, fmt.Errorf("duplicate runtime mount identity for %s", target)
		}
		candidates[target][fields[0]] = runtimeMount{id: fields[0], parent: fields[1], device: fields[2], root: runtimeMountPath(fields[3]), filesystem: fields[separator+1], options: strings.Split(fields[5], ",")}
	}
	mounts := make(map[string]runtimeMount)
	for target, stack := range candidates {
		covered := make(map[string]bool)
		for _, mount := range stack {
			covered[mount.parent] = true
		}
		visible := 0
		for _, mount := range stack {
			if !covered[mount.id] {
				mounts[target] = mount
				visible++
			}
		}
		if visible != 1 {
			return nil, fmt.Errorf("ambiguous runtime mount evidence for %s", target)
		}
	}
	return mounts, nil
}
