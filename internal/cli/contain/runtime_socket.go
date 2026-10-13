// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	protectHomeTmpfsProperty = "ProtectHome=tmpfs"
	runtimeProtectHomeEnv    = "PIPELOCK_CONTAIN_PROTECT_HOME"
)

// This private unit setting carries the property producer's intent to the
// in-unit checker. Every managed producer sets it, including an empty value
// when off, and plk-launch's env -i drops it before executing the workload.
func runtimeProtectHomeSetting(properties []string) string {
	value := ""
	for _, property := range properties {
		if property == protectHomeTmpfsProperty {
			value = "tmpfs"
		}
	}
	return runtimeProtectHomeEnv + "=" + value
}

// runtimeSocketProperties is independent of the optional filesystem profile.
// Network namespaces do not isolate pathname Unix sockets. Only the immutable
// namespace identity is needed inside a tool service; the proxy is reached
// over loopback through its separately confined forwarder.
func runtimeSocketProperties() []string {
	return append(runtimeSocketMountProperties(), "BindReadOnlyPaths="+containedNamespaceIdentityPath)
}

// runtimeSocketTemporaryFileSystems preserves the mount options used by every
// managed unit, including the optional separate /var/run mount.
func runtimeSocketTemporaryFileSystems() []string {
	properties := runtimeSocketMountProperties()
	mounts := make([]string, 0, len(properties))
	for _, property := range properties {
		mounts = append(mounts, strings.TrimPrefix(property, "TemporaryFileSystem="))
	}
	return mounts
}

func runtimeSocketMountProperties() []string {
	resolved, err := filepath.EvalSymlinks("/var/run")
	if os.IsNotExist(err) {
		resolved = "/run"
	}
	// Unknown resolution keeps the separate mount, so systemd refuses setup
	// if it cannot hide that path. Never mount the same resolved target twice.
	return runtimeSocketMountsForRunPath(resolved)
}

func runtimeSocketMountsForRunPath(resolved string) []string {
	properties := []string{
		"TemporaryFileSystem=/run:ro",
		"TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec",
	}
	if resolved != "/run" {
		properties = append(properties, "TemporaryFileSystem=/var/run:ro")
	}
	return properties
}
