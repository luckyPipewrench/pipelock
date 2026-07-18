// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"os"
	"strings"
)

const (
	childWorkspaceEnv = "__PIPELOCK_SANDBOX_WORKSPACE"
	childCommandEnv   = "__PIPELOCK_SANDBOX_COMMAND"
	childExtraEnv     = "__PIPELOCK_SANDBOX_EXTRA_ENV"
	childPolicyEnv    = "__PIPELOCK_SANDBOX_POLICY"
)

func initChildEnvironment(overrides []string) []string {
	keys := map[string]struct{}{
		initEnvKey:        {},
		standaloneInitEnv: {},
		strictEnvKey:      {},
		noNetNSEnvKey:     {},
		sandboxSocketEnv:  {},
		childWorkspaceEnv: {},
		childCommandEnv:   {},
		childExtraEnv:     {},
		childPolicyEnv:    {},
	}
	for _, entry := range overrides {
		key, _, _ := strings.Cut(entry, "=")
		keys[key] = struct{}{}
	}

	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := keys[key]; !replaced {
			env = append(env, entry)
		}
	}
	return append(env, overrides...)
}
