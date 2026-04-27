// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cli/runtime"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// errNoCaptureDir is returned when neither --capture-dir nor
// learn.capture_dir is set. Callers and tests check for this via
// errors.Is.
var errNoCaptureDir = errors.New(
	"learn observe requires --capture-dir or learn.capture_dir to be set",
)

// errRelativeCaptureDir is returned when the resolved capture dir is not
// absolute. Recorder JSONL placement must be unambiguous regardless of
// the proxy's working directory.
var errRelativeCaptureDir = errors.New(
	"learn observe: capture dir must be absolute",
)

// observeRunner is the runtime entry point used by observeCmd. Tests
// replace it with a stub so that exercising the cobra wiring does not
// actually start the proxy.
//
// The default builds a Server via runtime.NewServer and runs it under a
// signal-handling context that cancels on SIGINT/SIGTERM. This mirrors
// `pipelock run` so observation cleanup (recorder flush, capture close)
// goes through the same lifecycle.
var observeRunner = runObserveServer

// observeCmd returns the `pipelock learn observe` subcommand. It runs the
// proxy in capture mode with the learn observation pipeline enabled.
//
// Behavior is intentionally a thin facade over `pipelock run --capture-output`:
// the underlying runtime, hot reload, and signal handling all live in
// internal/cli/runtime. observeCmd loads the configured config, ensures
// learn.enabled and learn.capture_dir are set in the effective Config, then
// hands off to the runtime via ServerOpts.
func observeCmd() *cobra.Command {
	var (
		configPath string
		captureDir string
	)

	cmd := &cobra.Command{
		Use:   "observe",
		Short: "Run the proxy in observation mode for learn-and-lock",
		Long: `Run the proxy with the learn observation pipeline enabled.

The proxy listens for traffic, scans it through the normal pipeline, and
writes recorder JSONL evidence into --capture-dir. Each entry carries an
event_kind classifier sourced from the action verb at scan time. The
classification metadata feeds the compile stage (later phase) and is the
input the unclassified-rate ship gate measures against.

Privacy filtering is on by default: regulated-class fields are dropped
before reaching the recorder; internal-class fields are salt-hashed (see
learn.privacy.salt_source); sensitive-class fields require an explicit
opt-in annotation in the originating contract.

This subcommand is a thin facade over 'pipelock run --capture-output': it
loads the configured config, ensures the learn block is enabled, and
delegates to the same runtime. The proxy exits cleanly on SIGINT/SIGTERM.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runObserve(cmd, configPath, captureDir)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "",
		"path to pipelock config file (default: ~/.pipelock/pipelock.yaml or PIPELOCK_CONFIG)")
	cmd.Flags().StringVar(&captureDir, "capture-dir", "",
		"directory to write recorder JSONL evidence (overrides learn.capture_dir; required if not in config)")
	return cmd
}

// runObserve loads the config, derives the effective capture dir, mutates
// the config to enable the learn pipeline, and hands off to observeRunner.
// All non-runtime logic lives in pure helpers so tests can exercise it
// without starting the proxy.
func runObserve(cmd *cobra.Command, configPath, captureDir string) error {
	cfg, err := cliutil.LoadConfigOrDefault(configPath)
	if err != nil {
		return err
	}

	effectiveDir, err := resolveCaptureDir(cfg, captureDir)
	if err != nil {
		return err
	}

	enableLearnObservation(cfg, effectiveDir)

	sessionID := uuid.NewString()
	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"observation session started: session_id=%s capture_dir=%s\n",
		sessionID, effectiveDir)

	opts := runtime.ServerOpts{
		ConfigFile:    configPath,
		CaptureOutput: effectiveDir,
		Stdout:        cmd.OutOrStdout(),
		Stderr:        cmd.ErrOrStderr(),
	}
	return observeRunner(cmd.Context(), opts)
}

// resolveCaptureDir returns the effective capture directory, preferring
// the flag value over the config value and rejecting empty / relative
// paths. Pure function so tests do not need to start the proxy.
func resolveCaptureDir(cfg *config.Config, flagDir string) (string, error) {
	effective := flagDir
	if effective == "" {
		effective = cfg.Learn.CaptureDir
	}
	if effective == "" {
		return "", errNoCaptureDir
	}
	if !filepath.IsAbs(effective) {
		return "", fmt.Errorf("%w: %q", errRelativeCaptureDir, effective)
	}
	return effective, nil
}

// enableLearnObservation mutates cfg so that the learn observation
// pipeline is on with the resolved capture dir. The runtime config is
// the source of truth for downstream components (recorder, privacy
// enforcer, metrics); a thin facade like observeCmd must not bypass it.
func enableLearnObservation(cfg *config.Config, captureDir string) {
	cfg.Learn.Enabled = true
	cfg.Learn.CaptureDir = captureDir
}

// runObserveServer is the production observeRunner. It builds a Server
// from opts and runs it under a signal-handling context. Test code
// overrides observeRunner to avoid starting the proxy.
func runObserveServer(ctx context.Context, opts runtime.ServerOpts) error {
	srv, err := runtime.NewServer(opts)
	if err != nil {
		return err
	}

	sigCtx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return srv.Start(sigCtx)
}
