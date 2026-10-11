// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import "testing"

func TestDangerousEnvironmentParity(t *testing.T) {
	for _, key := range []string{"GIT_CONFIG_COUNT", "GIT_SSH_COMMAND", "DYLD_INSERT_LIBRARIES", "GLIBC_TUNABLES", "ZDOTDIR", "PROMPT_COMMAND", "pythonpath", "HOME", "PATH", "TMPDIR", "XDG_CONFIG_HOME"} {
		if !IsDangerousEnvKey(key) {
			t.Errorf("accepted runtime control %s", key)
		}
	}
}
