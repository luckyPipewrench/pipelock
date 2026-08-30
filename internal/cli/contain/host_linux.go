// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// requireContainHost rejects environments that cannot own the host lifecycle
// containment installs. In particular, an init image can be root but cannot
// create host users, install a host systemd service, or persist nftables rules.
func requireContainHost() error {
	return requireContainHostWith(os.Stat, os.ReadFile)
}

func requireContainHostWith(
	stat func(string) (os.FileInfo, error),
	readFile func(string) ([]byte, error),
) error {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := stat(marker); err == nil {
			return unsupportedContainHostError("container marker " + marker + " is present")
		} else if !errors.Is(err, os.ErrNotExist) {
			return unsupportedContainHostError(fmt.Sprintf("cannot inspect container marker %s: %v", marker, err))
		}
	}

	pidOne, err := readFile("/proc/1/comm")
	if err != nil {
		return unsupportedContainHostError(fmt.Sprintf("cannot inspect host init process: %v", err))
	}
	if init := strings.TrimSpace(string(pidOne)); init != "systemd" {
		return unsupportedContainHostError(fmt.Sprintf("PID 1 is %q, not systemd", init))
	}
	cgroup, err := readFile("/proc/1/cgroup")
	if err != nil {
		return unsupportedContainHostError(fmt.Sprintf("cannot inspect host cgroup: %v", err))
	}
	if containerCgroup(string(cgroup)) {
		return unsupportedContainHostError("PID 1 cgroup identifies a container runtime")
	}
	return nil
}

var containerCgroupPath = regexp.MustCompile(`(?m):[^\n]*(?:/(?:docker(?:/|$)|kubepods(?:\.slice)?(?:/|$)|(?:docker|cri-containerd|crio|libpod)-[^/]+\.scope(?:/|$)))`)

// containerCgroup recognizes the common cgroup path forms emitted by Docker,
// Kubernetes runtimes, and Podman. It is deliberately not a claim of complete
// container detection.
func containerCgroup(cgroup string) bool {
	return containerCgroupPath.MatchString(cgroup)
}

func unsupportedContainHostError(reason string) error {
	return fmt.Errorf(
		"pipelock contain install requires a supported Linux host with systemd as PID 1; %s. "+
			"Container and init-image environments cannot install host users, systemd units, or nftables rules. "+
			"Run this command on the host instead",
		reason,
	)
}
