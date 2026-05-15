// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

type caRefreshOpts struct {
	dryRun       bool
	caOutput     string
	bundleOutput string
	systemBundle string
}

func caRefreshCmd() *cobra.Command {
	var opts caRefreshOpts

	cmd := &cobra.Command{
		Use:   "ca-refresh",
		Short: "Rebuild /etc/pipelock/combined-ca.pem after CA rotation",
		Long: `Re-export the Pipelock TLS-MITM CA and rebuild the combined CA bundle
that pipelock-agent uses to validate TLS. Run after rotating pipelock's CA
(rare; typically only when ` + "`pipelock tls init`" + ` is rerun).

Wrappers and the systemd unit do not need to be touched: they read
/etc/pipelock/combined-ca.pem at runtime.

Must be run as root.

Exit codes:
  0  CA bundle refreshed (or already up to date).
  1  Export / read / write failed.
  2  Precondition error (not root, source bundle missing).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !opts.dryRun && os.Geteuid() != 0 {
				return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("ca-refresh must be run as root (use sudo)"))
			}
			env := defaultInstallEnv(cmd.OutOrStdout())
			if opts.caOutput != "" {
				env.caExportPath = opts.caOutput
			}
			if opts.bundleOutput != "" {
				env.caBundlePath = opts.bundleOutput
			}
			return runCARefresh(cmd.Context(), env, opts)
		},
	}

	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print planned actions without mutating state")
	cmd.Flags().StringVar(&opts.caOutput, "ca-output", "", "destination for the Pipelock-only CA (default /etc/pipelock/ca.pem)")
	cmd.Flags().StringVar(&opts.bundleOutput, "bundle-output", "", "destination for the combined bundle (default /etc/pipelock/combined-ca.pem)")
	cmd.Flags().StringVar(&opts.systemBundle, "system-bundle", defaultSystemCABundle, "source system CA bundle to combine with")

	return cmd
}

func runCARefresh(ctx context.Context, env *installEnv, opts caRefreshOpts) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// The cobra RunE wrapper does the os.Geteuid root check; tests drive
	// this function directly with fakes.
	systemBundle := opts.systemBundle
	if systemBundle == "" {
		systemBundle = defaultSystemCABundle
	}
	systemBundle = filepath.Clean(systemBundle)
	env.caExportPath = filepath.Clean(env.caExportPath)
	env.caBundlePath = filepath.Clean(env.caBundlePath)
	if err := validateCARefreshPaths(env, systemBundle); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}

	if opts.dryRun {
		_, _ = fmt.Fprintln(env.out, "pipelock contain ca-refresh — planned:")
		_, _ = fmt.Fprintf(env.out, "  1. re-export pipelock CA to %s (as %s)\n", env.caExportPath, env.proxyUserName)
		_, _ = fmt.Fprintf(env.out, "  2. write combined bundle to %s (mode 0o644)\n", env.caBundlePath)
		return nil
	}

	if err := exportPipelockCA(ctx, env); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
	}
	if err := rebuildCombinedBundle(env, systemBundle); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
	}
	_, _ = fmt.Fprintln(env.out, "ca-refresh complete.")
	return nil
}

func validateCARefreshPaths(env *installEnv, systemBundle string) error {
	if !filepath.IsAbs(systemBundle) {
		return fmt.Errorf("--system-bundle %q must be absolute", systemBundle)
	}
	if info, err := env.lstat(systemBundle); err != nil {
		return fmt.Errorf("--system-bundle %q: %w", systemBundle, err)
	} else if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("--system-bundle %q is a symlink; pass the resolved bundle path", systemBundle)
	} else if info.IsDir() {
		return fmt.Errorf("--system-bundle %q is a directory", systemBundle)
	}
	for flag, path := range map[string]string{
		"--ca-output":     env.caExportPath,
		"--bundle-output": env.caBundlePath,
	} {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("%s %q must be absolute", flag, path)
		}
		if !pathWithin(env.configDir, path) {
			return fmt.Errorf("%s %q must stay under %s", flag, path, env.configDir)
		}
		if err := ensureSafeWriteTarget(env, path); err != nil {
			return fmt.Errorf("%s %q: %w", flag, path, err)
		}
	}
	return nil
}

// exportPipelockCA writes pipelock-proxy's TLS-MITM CA to env.caExportPath.
//
// pipelock stores the CA under each user's $HOME/.pipelock/ — on a fresh
// install pipelock-proxy's home dir is empty so `show-ca` would fail.
// The flow is therefore:
//
//  1. Try `show-ca`. If it succeeds (CA already exists), capture stdout.
//  2. Otherwise run `tls init` to materialize the CA, then `show-ca`.
//
// Stdout is captured in Go and validated as PEM-shaped before being
// written to disk. There is no --output flag on the underlying CLI; the
// runbook's `--output` reference was speculative and never shipped.
func exportPipelockCA(ctx context.Context, env *installEnv) error {
	if err := ensureSafeWriteTarget(env, env.caExportPath); err != nil {
		return fmt.Errorf("validate CA export path %s: %w", env.caExportPath, err)
	}
	// Drop any stale on-disk export so a partial write can't fool the
	// combined-bundle step into reading old bytes.
	_ = env.removeFile(env.caExportPath)

	out, code, err := runShowCA(ctx, env)
	if err != nil {
		return err
	}
	if code != 0 {
		// Likely "ca.pem not found" because pipelock-proxy has no CA
		// yet. Initialize then retry. tls init is also captured so an
		// init failure surfaces a clear error instead of an opaque exit.
		initOut, initCode, initErr := env.runCmd(ctx,
			"sudo", "-n", "-u", env.proxyUserName, "--",
			env.pipelockTarget, "tls", "init",
		)
		if initErr != nil {
			return fmt.Errorf("exec sudo pipelock tls init: %w (captured %d bytes of output)", initErr, len(initOut))
		}
		if initCode != 0 {
			return fmt.Errorf("pipelock tls init exited %d (captured %d bytes of output)", initCode, len(initOut))
		}
		out, code, err = runShowCA(ctx, env)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("pipelock tls show-ca after init exited %d (captured %d bytes of output)", code, len(out))
		}
	}

	if err := validateSingleCAPEM([]byte(out)); err != nil {
		return fmt.Errorf("pipelock tls show-ca returned invalid CA PEM: %w", err)
	}
	return env.writeFile(env.caExportPath, []byte(out), modeCAReadable)
}

func validateSingleCAPEM(data []byte) error {
	block, rest := pem.Decode(data)
	if block == nil {
		return errors.New("no PEM certificate block")
	}
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("unexpected PEM block type %q", block.Type)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("extra data after certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	if !cert.IsCA {
		return errors.New("certificate is not a CA")
	}
	return nil
}

// runShowCA shells out to `sudo -n -u pipelock-proxy pipelock tls show-ca`
// and returns (stdout, exitCode, startupErr). Factored so the caller can
// retry after `tls init` without duplicating the argv.
func runShowCA(ctx context.Context, env *installEnv) (string, int, error) {
	out, code, err := env.runCmd(ctx,
		"sudo", "-n", "-u", env.proxyUserName, "--",
		env.pipelockTarget, "tls", "show-ca",
	)
	if err != nil {
		return out, code, fmt.Errorf("exec sudo pipelock tls show-ca: %w", err)
	}
	return out, code, nil
}

// rebuildCombinedBundle reads the system bundle and the pipelock CA and
// writes the combined file. Atomic write via backupAndWrite so a crash
// mid-write doesn't leave pipelock-agent with a half-written bundle.
func rebuildCombinedBundle(env *installEnv, systemBundle string) error {
	sys, err := env.readFile(systemBundle)
	if err != nil {
		return fmt.Errorf("read system CA bundle %s: %w", systemBundle, err)
	}
	pl, err := env.readFile(env.caExportPath)
	if err != nil {
		return fmt.Errorf("read pipelock CA %s: %w", env.caExportPath, err)
	}
	bundle := append([]byte{}, sys...)
	if len(bundle) > 0 && bundle[len(bundle)-1] != '\n' {
		bundle = append(bundle, '\n')
	}
	bundle = append(bundle, pl...)
	return backupAndWrite(env, env.caBundlePath, bundle, modeCAReadable)
}
