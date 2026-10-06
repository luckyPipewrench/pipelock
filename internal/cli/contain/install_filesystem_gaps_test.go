// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderContainedLaunchWrapperIncludesExpandEnvironment(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.systemdVersion = systemdExpandEnvironmentMinVersion
	body := renderContainedLaunchWrapper(env)
	if !strings.Contains(body, "--expand-environment=no") {
		t.Fatalf("wrapper missing expand-environment:\n%s", body)
	}
	env.systemdVersion = systemdExpandEnvironmentMinVersion - 1
	older := renderContainedLaunchWrapper(env)
	if strings.Contains(older, "--expand-environment=no") {
		t.Fatal("older systemd wrapper emitted expand-environment")
	}
}

func TestStagePipelockConfigFailsWhenFilesystemDefaultCannotStat(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	src := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(src, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	managed := managedPipelockConfigPath(env)
	env.stat = func(path string) (os.FileInfo, error) {
		if path == managed {
			return nil, errors.New("stat denied")
		}
		return os.Stat(path)
	}
	staged := stepStagePipelockConfig(installOpts{configSource: src})
	applied, err := staged.apply(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "stat managed config") {
		t.Fatalf("applied=%v err=%v", applied, err)
	}
}
