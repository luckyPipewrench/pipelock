// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !subprocess_coverage

package sandbox

import "os"

func prepareSubprocessCoverage(policy Policy, env []string) (Policy, []string) {
	return policy, env
}

func flushSubprocessCoverage() error {
	return nil
}

func reportSubprocessCoverageError(error) {}

func exitSandboxProcess(code int) {
	os.Exit(code)
}
