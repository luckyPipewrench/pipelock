package cli

import (
	"os"
	"testing"
)

func TestIsContainerized_HostEnvironment(t *testing.T) {
	// On a host machine without KUBERNETES_SERVICE_HOST set, this should
	// return false (unless we're actually in a container, which is unlikely
	// in CI/test environments). We test the env var path specifically.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	_ = os.Unsetenv("KUBERNETES_SERVICE_HOST") //nolint:errcheck // best-effort for test clarity

	// We can't control /.dockerenv or /proc/1/cgroup, but the function
	// should at least not panic.
	_ = isContainerized()
}

func TestIsContainerized_KubernetesEnvVar(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")

	if !isContainerized() {
		t.Error("expected isContainerized=true with KUBERNETES_SERVICE_HOST set")
	}
}
