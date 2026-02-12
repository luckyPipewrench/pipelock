package cli

import (
	"os"
	"strings"
)

// isContainerized checks whether the process is running inside a container.
// Checks Docker/Podman (/.dockerenv), Kubernetes (KUBERNETES_SERVICE_HOST),
// and cgroup-based detection (/proc/1/cgroup containing docker/containerd/podman).
func isContainerized() bool {
	// Docker/Podman: /.dockerenv exists
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Kubernetes: service host env var is injected by kubelet
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}

	// cgroup-based: /proc/1/cgroup references container runtime
	data, err := os.ReadFile("/proc/1/cgroup") //nolint:gosec // G304: fixed path
	if err == nil {
		content := string(data)
		if strings.Contains(content, "docker") ||
			strings.Contains(content, "containerd") ||
			strings.Contains(content, "podman") ||
			strings.Contains(content, "cri-o") {
			return true
		}
	}

	return false
}
