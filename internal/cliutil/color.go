// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"os"
	"strings"
)

// UseColor reports whether stdout supports color output.
// Returns false when NO_COLOR is set or stdout is not a terminal.
func UseColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// DetectRunContext determines whether the process runs on a host, in a
// container, or in a Kubernetes pod.
func DetectRunContext() string {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return RunContextPod
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return RunContextContainer
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") ||
			strings.Contains(s, "kubepods") {
			return RunContextContainer
		}
	}
	return RunContextHost
}

// Run context constants returned by DetectRunContext.
const (
	RunContextHost      = "host"
	RunContextContainer = "container"
	RunContextPod       = "pod"
)
