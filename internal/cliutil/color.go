// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"io/fs"
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
	return detectRunContext(os.Getenv("KUBERNETES_SERVICE_HOST"), os.DirFS("/"))
}

func detectRunContext(kubernetesHost string, root fs.FS) string {
	if kubernetesHost != "" {
		return RunContextPod
	}
	// Runtime markers survive private cgroup namespaces, where PID 1's
	// cgroup path is just "/" and carries no runtime name.
	for _, marker := range []string{".dockerenv", "run/.containerenv"} {
		if _, err := fs.Stat(root, marker); err == nil {
			return RunContextContainer
		}
	}
	if data, err := fs.ReadFile(root, "proc/1/cgroup"); err == nil {
		s := string(data)
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") ||
			strings.Contains(s, "kubepods") || strings.Contains(s, "libpod") ||
			strings.Contains(s, "podman") || strings.Contains(s, "cri-o") {
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
