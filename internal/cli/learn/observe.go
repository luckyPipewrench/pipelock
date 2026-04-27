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

// loadConfig is the package-level seam for cliutil.LoadConfigOrDefault.
// Tests override it to inject a config without going through disk.
var loadConfig = cliutil.LoadConfigOrDefault

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
		Long: `Run the proxy in observation mode for the learn-and-lock pipeline.

The proxy listens for traffic, scans it through the normal pipeline, and
writes hash-chained recorder JSONL evidence into --capture-dir. Each entry
carries an event_kind classifier on the recorder envelope and an
action_class field on the capture summary; both feed the compile stage
that lands in a follow-up.

Today this command is a thin facade over 'pipelock run --capture-output':
it validates that --capture-dir or learn.capture_dir is set and absolute,
emits a session-id banner, and hands off to the same runtime. The
'learn:' config block (enabled, capture_dir, privacy.salt_source,
privacy.public_allowlist_default) is structural plumbing: the data-class
enforcement, salt-hashing, and regulated-data blocking the privacy
package implements wire through in the next phase, when the compile-time
classifier is available to attach data classes to observation events.
Until that wiring lands, this command produces the same recorder output
as 'pipelock run --capture-output' plus the new event_kind metadata.

The proxy exits cleanly on SIGINT/SIGTERM.`,
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

// runObserve loads the config, derives the effective capture dir, and hands
// off to observeRunner. The loaded config is consulted to read
// learn.capture_dir as a fallback when --capture-dir is not supplied; the
// runtime reloads opts.ConfigFile from disk and is the source of truth for
// every other field. The CLI does NOT mutate cfg — any such mutation would
// be silently dropped on the runtime's reload, and the privacy enforcer
// surface (LoadSalt + Apply) is not yet wired into the capture writer
// path, so a "we set learn.enabled=true" claim would overstate behavior.
//
// All non-runtime logic lives in pure helpers so tests can exercise it
// without starting the proxy.
func runObserve(cmd *cobra.Command, configPath, captureDir string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	effectiveDir, err := resolveCaptureDir(cfg, captureDir)
	if err != nil {
		return err
	}

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
