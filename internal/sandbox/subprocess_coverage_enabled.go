// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build subprocess_coverage

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/coverage"
	"strings"
)

const subprocessCoverageMarker = "PIPELOCK_SUBPROCESS_COVERAGE"

func prepareSubprocessCoverage(policy Policy, env []string) (Policy, []string) {
	dir, err := validatedSubprocessCoverageDir()
	if err != nil || dir == "" {
		return policy, env
	}

	policy.AllowRWDirs = append(policy.AllowRWDirs, dir)
	env = append(env, "GOCOVERDIR="+dir, subprocessCoverageMarker+"=1")
	return policy, env
}

func flushSubprocessCoverage() error {
	dir, err := validatedSubprocessCoverageDir()
	if err != nil {
		return err
	}
	if dir == "" {
		return nil
	}

	return errors.Join(
		coverage.WriteMetaDir(dir),
		coverage.WriteCountersDir(dir),
	)
}

func validatedSubprocessCoverageDir() (string, error) {
	if os.Getenv(subprocessCoverageMarker) != "1" {
		return "", nil
	}
	raw := os.Getenv("GOCOVERDIR")
	if raw == "" {
		return "", nil
	}
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf("subprocess coverage directory must be absolute")
	}
	dir := filepath.Clean(raw)
	if filepath.Dir(dir) != "/tmp" || !strings.HasPrefix(filepath.Base(dir), "pipelock-covdata-") {
		return "", fmt.Errorf("subprocess coverage directory must be a dedicated /tmp/pipelock-covdata-* directory")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("stat subprocess coverage directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return "", fmt.Errorf("subprocess coverage directory must be a private 0700 directory")
	}
	return dir, nil
}

func reportSubprocessCoverageError(err error) {
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[sandbox] write subprocess coverage: %v\n", err)
	}
}

func exitSandboxProcess(code int) {
	reportSubprocessCoverageError(flushSubprocessCoverage())
	os.Exit(code)
}
