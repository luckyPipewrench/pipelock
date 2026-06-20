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
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

type caRefreshOpts struct {
	dryRun                      bool
	force                       bool
	regenerateOnSnapshotRestore bool
	caOutput                    string
	bundleOutput                string
	systemBundle                string
}

const snapshotCARepeatGuard = 10 * time.Minute

func caRefreshCmd() *cobra.Command {
	var opts caRefreshOpts

	cmd := &cobra.Command{
		Use:   "ca-refresh",
		Short: "Rebuild /etc/pipelock/combined-ca.pem after CA rotation",
		Long: `Re-export the Pipelock TLS-MITM CA and rebuild the combined CA bundle
that pipelock-agent uses to validate TLS. Run after rotating pipelock's CA
(rare; typically only when ` + "`pipelock tls init`" + ` is rerun).

Use --regenerate-on-snapshot-restore as a post-restore runbook step when a
VM or disk snapshot may have copied the old TLS-intercept CA private key onto
a fresh host. The flag regenerates the contain-managed CA as pipelock-proxy
before exporting the new certificate and rebuilding the agent bundle.
To prevent accidental repeated rotations, a second snapshot regeneration
within ten minutes is refused unless --force is set. The repeat guard uses
/etc/pipelock/contain/snapshot-ca-refresh.timestamp, not CA file mtimes.
Operators should periodically prune old .prerotate.* CA-key backups after
their rollback window expires.

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
			env.errOut = cmd.ErrOrStderr()
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
	cmd.Flags().BoolVar(&opts.force, "force", false, "allow snapshot CA regeneration even when a recent snapshot regeneration marker exists")
	cmd.Flags().BoolVar(&opts.regenerateOnSnapshotRestore, "regenerate-on-snapshot-restore", false, "force-generate a fresh contain-managed CA before rebuilding the bundle")
	cmd.Flags().StringVar(&opts.caOutput, "ca-output", "", "destination for the Pipelock-only CA (default /etc/pipelock/ca.pem)")
	cmd.Flags().StringVar(&opts.bundleOutput, "bundle-output", "", "destination for the combined bundle (default /etc/pipelock/combined-ca.pem)")
	cmd.Flags().StringVar(&opts.systemBundle, "system-bundle", "", "source system CA bundle to combine with (default: auto-detect for this Linux distro)")

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
		systemBundle = env.systemCABundlePath
	}
	systemBundle = filepath.Clean(systemBundle)
	resolvedSystemBundle, err := resolveSystemBundlePath(env, systemBundle)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	systemBundle = resolvedSystemBundle
	env.caExportPath = filepath.Clean(env.caExportPath)
	env.caBundlePath = filepath.Clean(env.caBundlePath)
	if err := validateCARefreshPaths(env, systemBundle); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	now := time.Now().UTC()
	if opts.regenerateOnSnapshotRestore {
		if err := validateSnapshotRegenerationPreconditions(env, opts, now); err != nil {
			return cliutil.ExitCodeError(cliutil.ExitConfig, err)
		}
	}

	if opts.dryRun {
		if opts.regenerateOnSnapshotRestore {
			writeSnapshotCAWarning(env)
		}
		_, _ = fmt.Fprintln(env.out, "pipelock contain ca-refresh — planned:")
		i := 1
		if opts.regenerateOnSnapshotRestore {
			_, _ = fmt.Fprintf(env.out, "  %d. back up contain-managed CA material under %s\n", i, filepath.Join(env.configDir, "tls"))
			i++
			_, _ = fmt.Fprintf(env.out, "  %d. regenerate contain-managed CA as %s (snapshot restore)\n", i, env.proxyUserName)
			i++
		}
		_, _ = fmt.Fprintf(env.out, "  %d. re-export pipelock CA to %s (as %s)\n", i, env.caExportPath, env.proxyUserName)
		i++
		_, _ = fmt.Fprintf(env.out, "  %d. write combined bundle to %s (mode 0o644)\n", i, env.caBundlePath)
		return nil
	}

	if opts.regenerateOnSnapshotRestore {
		writeSnapshotCAWarning(env)
		if err := regeneratePipelockCA(ctx, env, now); err != nil {
			return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
		}
		if err := writeSnapshotRefreshMarker(env, now); err != nil {
			return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
		}
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

func writeSnapshotCAWarning(env *installEnv) {
	w := env.errOut
	if w == nil {
		w = env.out
	}
	if w == nil {
		return
	}
	_, _ = fmt.Fprintln(w, "WARNING: snapshot CA regeneration replaces the Pipelock TLS CA.")
	_, _ = fmt.Fprintln(w, "Update host trust stores and restart agent processes that pin /etc/pipelock/combined-ca.pem, SSL_CERT_FILE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS, CURL_CA_BUNDLE, or copied CA bundles.")
	_, _ = fmt.Fprintln(w, "Kubernetes sidecars and other deployments with separate CA material must follow their own CA rotation runbooks.")
}

func writeSnapshotForceWarning(env *installEnv, last time.Time) {
	w := env.errOut
	if w == nil {
		w = env.out
	}
	if w == nil {
		return
	}
	_, _ = fmt.Fprintf(w, "WARN: --force bypassed the snapshot CA repeat guard; previous regeneration marker was %s.\n", last.Format(time.RFC3339))
}

func containManagedTLSCertPath(env *installEnv) string {
	certPath := filepath.Join(env.configDir, "tls", "ca.pem")
	if pathExists(env, certPath) {
		return certPath
	}
	return ""
}

func snapshotRefreshMarkerPath(env *installEnv) string {
	return filepath.Join(env.configDir, "contain", "snapshot-ca-refresh.timestamp")
}

func validateSnapshotRegenerationPreconditions(env *installEnv, opts caRefreshOpts, now time.Time) error {
	certPath := filepath.Join(env.configDir, "tls", "ca.pem")
	keyPath := filepath.Join(env.configDir, "tls", "ca-key.pem")
	for _, item := range []struct {
		label string
		path  string
	}{
		{label: "certificate", path: certPath},
		{label: "private key", path: keyPath},
	} {
		info, err := env.lstat(item.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("contain-managed TLS CA %s %s does not exist; run contain install before snapshot CA regeneration", item.label, item.path)
			}
			return fmt.Errorf("stat contain-managed TLS CA %s %s: %w", item.label, item.path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("contain-managed TLS CA %s %s is a symlink; refusing snapshot CA regeneration", item.label, item.path)
		}
		if info.IsDir() {
			return fmt.Errorf("contain-managed TLS CA %s %s is a directory", item.label, item.path)
		}
	}
	data, err := env.readFile(snapshotRefreshMarkerPath(env))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read snapshot CA regeneration marker: %w", err)
	}
	last, err := time.Parse(time.RFC3339Nano, string(bytes.TrimSpace(data)))
	if err != nil {
		return fmt.Errorf("parse snapshot CA regeneration marker: %w", err)
	}
	if now.Sub(last) >= snapshotCARepeatGuard {
		return nil
	}
	if opts.force {
		writeSnapshotForceWarning(env, last)
		return nil
	}
	if now.Sub(last) < snapshotCARepeatGuard {
		return fmt.Errorf("snapshot CA was regenerated at %s; use --force to rotate again within %s", last.Format(time.RFC3339), snapshotCARepeatGuard)
	}
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

func resolveSystemBundlePath(env *installEnv, systemBundle string) (string, error) {
	clean := filepath.Clean(systemBundle)
	if !filepath.IsAbs(clean) {
		return clean, nil
	}
	info, err := env.lstat(clean)
	if err != nil {
		return clean, nil
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return clean, nil
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", fmt.Errorf("resolve --system-bundle %q: %w", clean, err)
	}
	return filepath.Clean(resolved), nil
}

// regeneratePipelockCA force-generates the contain-managed TLS-MITM CA as
// pipelock-proxy. This is intentionally opt-in: normal ca-refresh preserves
// the existing CA and only refreshes the exported bundle.
func regeneratePipelockCA(ctx context.Context, env *installEnv, now time.Time) error {
	certPath := filepath.Join(env.configDir, "tls", "ca.pem")
	keyPath := filepath.Join(env.configDir, "tls", "ca-key.pem")
	if err := backupSnapshotCAFile(env, certPath, modeCAReadable, now); err != nil {
		return err
	}
	if err := backupSnapshotCAFile(env, keyPath, modePinSecret, now); err != nil {
		return err
	}
	args := []string{"-n", "-u", env.proxyUserName, "--", env.pipelockTarget, "tls", "init", "--force"}
	if certPath := containManagedTLSCertPath(env); certPath != "" {
		args = append(args, "--out", filepath.Dir(certPath))
	}
	out, code, err := env.runCmd(ctx, "sudo", args...)
	if err != nil {
		return fmt.Errorf("exec sudo pipelock tls init --force: %w (captured %d bytes of output)", err, len(out))
	}
	if code != 0 {
		return fmt.Errorf("pipelock tls init --force exited %d (captured %d bytes of output)", code, len(out))
	}
	return nil
}

func backupSnapshotCAFile(env *installEnv, path string, mode os.FileMode, now time.Time) error {
	clean := filepath.Clean(path)
	data, err := env.readFile(clean)
	if err != nil {
		return fmt.Errorf("read CA material for backup %s: %w", clean, err)
	}
	backup := fmt.Sprintf("%s.prerotate.%s", clean, now.UTC().Format("20060102T150405.000000000Z"))
	if err := ensureSafeWriteTarget(env, backup); err != nil {
		return fmt.Errorf("validate CA backup path %s: %w", backup, err)
	}
	if _, err := env.lstat(backup); err == nil {
		return fmt.Errorf("refusing to overwrite existing CA backup %s", backup)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat CA backup %s: %w", backup, err)
	}
	if err := env.writeFile(backup, data, mode); err != nil {
		return fmt.Errorf("write CA backup %s: %w", backup, err)
	}
	return nil
}

func writeSnapshotRefreshMarker(env *installEnv, now time.Time) error {
	path := snapshotRefreshMarkerPath(env)
	if err := env.mkdirAll(filepath.Dir(path), modeDirTraversable); err != nil {
		return fmt.Errorf("create snapshot CA marker directory: %w", err)
	}
	if err := env.chmod(filepath.Dir(path), modeDirTraversable); err != nil {
		return fmt.Errorf("chmod snapshot CA marker directory: %w", err)
	}
	if err := env.writeFile(path, []byte(now.Format(time.RFC3339Nano)+"\n"), modeAllowListReadable); err != nil {
		return fmt.Errorf("write snapshot CA regeneration marker: %w", err)
	}
	return nil
}

// exportPipelockCA writes pipelock-proxy's TLS-MITM CA to env.caExportPath.
//
// pipelock stores the default CA under each user's $HOME/.pipelock/.
// Contain config migration may instead move CA material to
// /etc/pipelock/tls; when that managed cert exists, ca-refresh exports it so
// the agent bundle matches the CA the system service actually uses. On a
// fresh install the selected CA path may be empty so `show-ca` would fail.
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

	certPath := containManagedTLSCertPath(env)
	out, code, err := runShowCA(ctx, env, certPath)
	if err != nil {
		return err
	}
	if code != 0 {
		// Likely "ca.pem not found" because the selected CA path does
		// not exist yet. Initialize then retry. tls init is also
		// captured so an init failure surfaces a clear error instead of
		// an opaque exit.
		args := []string{"-n", "-u", env.proxyUserName, "--", env.pipelockTarget, "tls", "init"}
		if certPath != "" {
			args = append(args, "--out", filepath.Dir(certPath))
		}
		initOut, initCode, initErr := env.runCmd(ctx, "sudo", args...)
		if initErr != nil {
			return fmt.Errorf("exec sudo pipelock tls init: %w (captured %d bytes of output)", initErr, len(initOut))
		}
		if initCode != 0 {
			return fmt.Errorf("pipelock tls init exited %d (captured %d bytes of output)", initCode, len(initOut))
		}
		out, code, err = runShowCA(ctx, env, certPath)
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
func runShowCA(ctx context.Context, env *installEnv, certPath string) (string, int, error) {
	args := []string{"-n", "-u", env.proxyUserName, "--", env.pipelockTarget, "tls", "show-ca"}
	if certPath != "" {
		args = append(args, "--cert", certPath)
	}
	out, code, err := env.runCmd(ctx, "sudo", args...)
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
