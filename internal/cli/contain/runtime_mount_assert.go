// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// systemd.exec(5) documents /run/host/incoming; systemd's service launcher
// also uses /run/systemd/incoming. Both stage mounts from /run/systemd/propagate.
const (
	systemdIncomingPath    = "/run/systemd/incoming"
	hostIncomingPath       = "/run/host/incoming"
	systemdPropagationRoot = "/systemd/propagate/"
)

var errRuntimeMountEvidenceUnavailable = errors.New("runtime mount evidence is unavailable")

type runtimeMount struct {
	device, root, filesystem string
	id, parent               string
	options                  []string
}

// Only mountinfo, rather than unit configuration, proves the restrictions
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
	for _, entry := range entries {
		if !entry.IsDir() {
			return fmt.Errorf("/run must contain only the managed namespace identity and verified systemd mount propagation")
		}
		switch entry.Name() {
		case "pipelock-contain":
			// The identity directory is checked below.
		case "systemd", "host":
			path := "/run/" + entry.Name()
			if err := checkRuntimeDirectoryEntry(env, path, "incoming", true); err != nil {
				return err
			}
			mount, ok := self[path+"/incoming"]
			if !ok {
				return fmt.Errorf("%s/incoming must have its own systemd propagation mount", path)
			}
			if !strings.HasPrefix(mount.root, systemdPropagationRoot) || filepath.Clean(mount.root) != mount.root {
				return fmt.Errorf("%s/incoming mount root must be under %s", path, systemdPropagationRoot)
			}
			if !slices.Contains(mount.options, "ro") {
				return fmt.Errorf("%s/incoming systemd propagation mount must be read-only", path)
			}
		default:
			return fmt.Errorf("/run must contain only the managed namespace identity and verified systemd mount propagation")
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
		return fmt.Errorf("%s must contain only %s as a %s", path, name, kind)
	}
	return nil
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
		// Required paths have no mountinfo escaping. An overmount's parent is
		// the mount it shadows at the same path, not necessarily its directory
		// parent. Keep that chain to select the visible top without relying on
		// the order of lines or on mount IDs increasing monotonically.
		target := fields[4]
		if target != "/" && target != "/dev" && target != "/var" && target != "/run" && target != "/var/run" && target != "/dev/shm" && target != containedNamespaceIdentityPath && target != systemdIncomingPath && target != hostIncomingPath {
			continue
		}
		if candidates[target] == nil {
			candidates[target] = make(map[string]runtimeMount)
		}
		if _, exists := candidates[target][fields[0]]; exists {
			return nil, fmt.Errorf("duplicate runtime mount identity for %s", target)
		}
		candidates[target][fields[0]] = runtimeMount{id: fields[0], parent: fields[1], device: fields[2], root: fields[3], filesystem: fields[separator+1], options: strings.Split(fields[5], ",")}
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
