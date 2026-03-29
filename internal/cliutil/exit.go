// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package cliutil provides shared helpers used across CLI subpackages.
// It exists to break import cycles: the root cli package imports subpackages,
// and subpackages import cliutil (never cli).
package cliutil

import (
	"errors"
	"strconv"
)

// Pipelock exit codes are part of the stable CLI contract. Scripts, CI
// pipelines, and IDE integrations may depend on these values. Do not change
// existing codes without a major version bump.
const (
	// ExitOK is a clean shutdown (default, not typically set explicitly).
	ExitOK = 0
	// ExitGeneral is the default for unclassified errors (cobra default).
	ExitGeneral = 1
	// ExitConfig indicates a configuration error (bad YAML, missing file, validation failure).
	ExitConfig = 2
	// ExitSecurity indicates a security event caused termination (kill switch, block_all).
	ExitSecurity = 3
	// ExitSubprocess indicates the wrapped subprocess (MCP server) exited with a non-zero status.
	ExitSubprocess = 10
)

// ExitError wraps an error with a specific exit code for main() to use.
type ExitError struct {
	Err  error
	Code int
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return "exit code " + strconv.Itoa(e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

// ExitCodeError wraps err with a non-standard exit code.
// Returns nil when err is nil (no error to wrap).
func ExitCodeError(code int, err error) error {
	if err == nil {
		return nil
	}
	return &ExitError{Err: err, Code: code}
}

// ExitCodeOf returns the exit code for an error, defaulting to 1.
func ExitCodeOf(err error) int {
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return 1
}
