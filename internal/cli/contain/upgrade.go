// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// This file implements `pipelock contain upgrade`, a containment-aware
// one-command upgrade that atomically replaces the deployed binary, re-pins
// the integrity hash, restarts the service, and verifies the containment
// boundary — rolling back both binary and pin on any post-replacement failure.
//
// Checked 2026-08-03: no existing contain subcommand performs this lifecycle.
// `pipelock update` (internal/cli/selfupdate) replaces the binary but is
// unaware of the containment integrity pin, leaving probe 10 stale.
// `pipelock contain install --pipelock-binary` re-pins but requires the
// operator to have already obtained and verified the candidate binary.
// This command bridges the gap.

package contain

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// upgradeOpts collects flag-derived state for the upgrade subcommand.
type upgradeOpts struct {
	version string
}

// upgradeEnv is the injectable dependency surface for the upgrade orchestration.
// Every external operation is a function value so tests can exercise the full
// fail-closed/rollback logic against temp dirs and fake binaries.
type upgradeEnv struct {
	out    io.Writer
	errOut io.Writer

	// Filesystem operations.
	stat       func(path string) (os.FileInfo, error)
	readFile   func(path string) ([]byte, error)
	writeFile  func(path string, contents []byte, mode os.FileMode) error
	mkdirAll   func(path string, mode os.FileMode) error
	hashFile   func(path string) (string, error)
	removeFile func(path string) error

	// Subprocess execution.
	runCmd runCommand

	// File inspection (Lstat does not follow symlinks).
	lstat func(path string) (os.FileInfo, error)

	// Ownership operations (nil in unit tests against temp dirs).
	lookupUser lookupUserFunc
	chown      func(path string, uid, gid int) error
	chmod      func(path string, mode os.FileMode) error

	// Paths.
	proxyUserName  string
	pipelockTarget string
	integrityDir   string
	integrityPin   string
	serviceName    string

	// Readiness.
	readinessTimeout time.Duration
}

func defaultUpgradeEnv(out, errOut io.Writer) *upgradeEnv {
	return &upgradeEnv{
		out:              out,
		errOut:           errOut,
		stat:             os.Stat,
		lstat:            os.Lstat,
		readFile:         os.ReadFile,
		writeFile:        writeFileAtomic,
		mkdirAll:         os.MkdirAll,
		hashFile:         sha256HexOfFile,
		removeFile:       os.Remove,
		runCmd:           realRunCommand,
		lookupUser:       user.Lookup,
		chown:            os.Chown,
		chmod:            os.Chmod,
		proxyUserName:    defaultProxyUser,
		pipelockTarget:   defaultPipelockTarget,
		integrityDir:     defaultIntegrityDir,
		integrityPin:     defaultIntegrityPin,
		serviceName:      defaultServiceName,
		readinessTimeout: installReadinessTimeout,
	}
}

func upgradeCmd() *cobra.Command {
	var opts upgradeOpts

	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Download, verify, and install a new pipelock release with containment integrity re-pin",
		Long: `Perform a containment-aware upgrade of the pipelock binary.

The upgrade is FAIL-CLOSED at every step:

  1. Download and verify the candidate release by invoking the DEPLOYED
     binary's 'pipelock update', which verifies the release manifest,
     checksums, and signatures fail-closed before replacing itself.
  2. Re-pin the integrity hash against the newly deployed binary.
  3. Restart the pipelock systemd service and wait for readiness.
  4. Run 'contain verify' and require exit 0 (every probe passed).

If any step after binary replacement fails, the previous binary AND its
integrity pin are restored before exit.

This eliminates the gap between 'pipelock update' and the containment
integrity pin: an ordinary update leaves the pin stale, causing probe 10
to report a mismatch on a host that is actually healthy.

Release-signature verification is performed by the deployed binary, not by
whichever copy you invoke this command from. A build with no embedded release
keyring cannot verify a release and its 'update' step will refuse; recover
such a host with 'contain install --pipelock-binary <path>' after independent
signature, checksum, and attestation verification.

Must be run as root.

Exit codes:
  0  Upgrade completed and verified.
  1  Upgrade failed; previous state restored.
  2  Precondition error (not root, deployed binary missing or not a regular file, or no integrity pin).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 {
				return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("upgrade must be run as root (use sudo)"))
			}
			env := defaultUpgradeEnv(cmd.OutOrStdout(), cmd.ErrOrStderr())
			return runUpgrade(cmd.Context(), env, opts)
		},
	}

	cmd.Flags().StringVar(&opts.version, "version", "", "install a specific release tag (e.g. v3.2.0) instead of the latest")

	return cmd
}

var (
	errUpgradeVerify    = errors.New("post-upgrade verification failed")
	errUpgradeRestart   = errors.New("service restart failed")
	errUpgradeRepin     = errors.New("integrity re-pin failed")
	errUpgradeRollback  = errors.New("rollback failed")
	errUpgradeUpdate    = errors.New("pipelock update failed")
	errUpgradeIntegrity = errors.New("pre-upgrade integrity check failed")
)

func runUpgrade(ctx context.Context, env *upgradeEnv, opts upgradeOpts) error {
	w := env.out

	// NOTE: there is deliberately NO invoker-side release-keyring preflight
	// here. An earlier draft checked releasetrust.PublicKeyringHex, which is
	// linked into whichever binary INVOKED this command, and then delegated
	// the actual verified update to the DEPLOYED binary at env.pipelockTarget.
	// Those are different artifacts whenever the operator runs a copy that is
	// not the deployed one, so the check decided about one binary while the
	// consequence landed on another.

	// ── Step 1: verify the deployed binary is a regular, non-symlink file ─
	target := filepath.Clean(env.pipelockTarget)
	info, lstatErr := env.lstat(target)
	if lstatErr != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf(
			"deployed binary not found at %s: %w", target, lstatErr))
	}
	if !info.Mode().IsRegular() {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf(
			"deployed binary at %s is not a regular file (mode %s); refusing to execute",
			target, info.Mode()))
	}

	// ── Step 2: verify binary against integrity pin BEFORE executing it ──
	// This is the critical pre-execution check: if the binary has been
	// tampered with, the pin (written by our own installer at a known-good
	// time) will not match. We hash with the trusted in-process
	// implementation and compare with constant-time equality, so a
	// compromised binary never gets root execution.
	oldPin, oldPinErr := env.readFile(env.integrityPin)
	switch {
	case oldPinErr == nil:
		// Pin exists — verify the deployed binary against it.
		pinned := strings.TrimSpace(string(oldPin))
		if _, decErr := hex.DecodeString(pinned); decErr != nil || len(pinned) != sha256HexLen ||
			pinned != strings.ToLower(pinned) {
			return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf(
				"%w: pin file %s contains malformed SHA-256 (length %d)",
				errUpgradeIntegrity, env.integrityPin, len(pinned)))
		}
		currentHash, hashErr := env.hashFile(target)
		if hashErr != nil {
			return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf(
				"%w: hash deployed binary %s: %w", errUpgradeIntegrity, target, hashErr))
		}
		if subtle.ConstantTimeCompare([]byte(currentHash), []byte(pinned)) != 1 {
			return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf(
				"%w: deployed binary hash does not match integrity pin (binary may be tampered; "+
					"recover with 'contain install --pipelock-binary <path>' after independent verification)",
				errUpgradeIntegrity))
		}
		_, _ = fmt.Fprintln(w, "pre-upgrade integrity check passed")
	case errors.Is(oldPinErr, fs.ErrNotExist):
		// No pin file — this is a first install or the pin was never written.
		// FAIL-CLOSED: refuse to execute an unpinned binary as root.
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf(
			"%w: no integrity pin at %s; cannot verify deployed binary before executing it as root "+
				"(run 'contain install' first to establish the pin, or "+
				"'contain install --pipelock-binary <path>' to re-pin a known-good binary)",
			errUpgradeIntegrity, env.integrityPin))
	default:
		// Pin file exists but is unreadable (permission error, I/O error).
		// FAIL-CLOSED: an unreadable pin could be tamper evidence.
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf(
			"%w: cannot read integrity pin %s: %w (refusing to proceed; "+
				"an unreadable pin may indicate tampering)",
			errUpgradeIntegrity, env.integrityPin, oldPinErr))
	}

	// ── Step 3: back up the current binary ──────────────────────────────
	_, _ = fmt.Fprintln(w, "backing up current binary...")
	backupPath := target + ".upgrade-bak"
	if err := upgradeCopyFile(env, target, backupPath); err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf(
			"backing up current binary: %w", err))
	}
	_, _ = fmt.Fprintf(w, "  backup at %s\n", backupPath)

	// ── Rollback helper ─────────────────────────────────────────────────
	// Direction: restores binary FIRST (so the pin is always consistent
	// with whatever is on disk), then pin, then best-effort restart.
	rollbackAll := func() error {
		var errs []error
		_, _ = fmt.Fprintln(w, "restoring previous binary...")
		if binErr := upgradeCopyFile(env, backupPath, target); binErr != nil {
			errs = append(errs, fmt.Errorf("restore binary: %w", binErr))
		}
		_, _ = fmt.Fprintln(w, "restoring previous integrity pin...")
		if pinErr := env.writeFile(env.integrityPin, oldPin, modePinSecret); pinErr != nil {
			errs = append(errs, fmt.Errorf("restore pin: %w", pinErr))
		} else if ownErr := upgradeRestorePinOwnership(env); ownErr != nil {
			// The rollback path must hand the pin back to the proxy user for
			// the same reason the forward path does: this command runs as
			// root, so a pin written here is root-owned, and the service that
			// reads it does not run as root. Restoring the contents but not
			// the ownership would leave a rolled-back host reporting a false
			// integrity mismatch -- the exact failure this command exists to
			// eliminate, reintroduced through its own recovery path.
			errs = append(errs, fmt.Errorf("restore pin ownership: %w", ownErr))
		}
		_, _, _ = env.runCmd(ctx, "systemctl", "daemon-reload")
		if _, code, rErr := env.runCmd(ctx, "systemctl", "restart", env.serviceName); rErr != nil || code != 0 {
			_, _ = fmt.Fprintf(env.errOut,
				"warning: best-effort restart of %s after rollback did not succeed (code %d, err %v)\n",
				env.serviceName, code, rErr)
		}
		if len(errs) > 0 {
			return fmt.Errorf("%w: %w", errUpgradeRollback, errors.Join(errs...))
		}
		return nil
	}

	// ── Step 4: download, verify, and install the candidate ─────────────
	_, _ = fmt.Fprintln(w, "downloading and verifying candidate release...")
	version, updateErr := upgradeRunUpdate(ctx, env, opts)
	if updateErr != nil {
		// Check whether the binary actually changed before doing a full
		// rollback with service restart. A network/signature failure that
		// aborted before touching the binary should not restart a healthy
		// service.
		newHash, hashErr := env.hashFile(target)
		backupHash, bkHashErr := env.hashFile(backupPath)
		binaryChanged := hashErr != nil || bkHashErr != nil || newHash != backupHash

		if binaryChanged {
			if rbErr := rollbackAll(); rbErr != nil {
				return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.Join(
					fmt.Errorf("%w: %w", errUpgradeUpdate, updateErr),
					fmt.Errorf("%w (backup retained at %s)", rbErr, backupPath)))
			}
		}
		_ = env.removeFile(backupPath)
		if binaryChanged {
			return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf(
				"%w: %w (rolled back)", errUpgradeUpdate, updateErr))
		}
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf(
			"%w: %w", errUpgradeUpdate, updateErr))
	}
	_, _ = fmt.Fprintf(w, "  installed %s\n", version)

	// ── Step 5: re-pin integrity against the new binary ─────────────────
	_, _ = fmt.Fprintln(w, "re-pinning binary integrity...")
	if err := upgradeRepinIntegrity(env); err != nil {
		_, _ = fmt.Fprintf(env.errOut, "re-pin failed: %v\n", err)
		if rbErr := rollbackAll(); rbErr != nil {
			return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.Join(
				fmt.Errorf("%w: %w", errUpgradeRepin, err),
				fmt.Errorf("%w (backup retained at %s)", rbErr, backupPath)))
		}
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf(
			"%w: %w (rolled back)", errUpgradeRepin, err))
	}
	_, _ = fmt.Fprintln(w, "  integrity pin updated")

	// ── Step 6: restart the pipelock service ────────────────────────────
	_, _ = fmt.Fprintln(w, "restarting pipelock service...")
	if err := upgradeRestartAndWait(ctx, env); err != nil {
		_, _ = fmt.Fprintf(env.errOut, "restart failed: %v\n", err)
		if rbErr := rollbackAll(); rbErr != nil {
			return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.Join(
				fmt.Errorf("%w: %w", errUpgradeRestart, err),
				fmt.Errorf("%w (backup retained at %s)", rbErr, backupPath)))
		}
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf(
			"%w: %w (rolled back)", errUpgradeRestart, err))
	}
	_, _ = fmt.Fprintln(w, "  service restarted and ready")

	// ── Step 7: final verification ──────────────────────────────────────
	_, _ = fmt.Fprintln(w, "running post-upgrade verification...")
	if err := upgradePostVerify(ctx, env); err != nil {
		_, _ = fmt.Fprintf(env.errOut, "post-upgrade verify failed: %v\n", err)
		if rbErr := rollbackAll(); rbErr != nil {
			return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.Join(
				fmt.Errorf("%w: %w", errUpgradeVerify, err),
				fmt.Errorf("%w (backup retained at %s)", rbErr, backupPath)))
		}
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf(
			"%w: %w (rolled back)", errUpgradeVerify, err))
	}
	_, _ = fmt.Fprintln(w, "  verification passed")

	// ── Success ─────────────────────────────────────────────────────────
	_ = env.removeFile(backupPath)
	_, _ = fmt.Fprintf(w, "upgrade to %s completed successfully\n", version)
	return nil
}

// upgradeRunUpdate shells out to the deployed binary's update command.
func upgradeRunUpdate(ctx context.Context, env *upgradeEnv, opts upgradeOpts) (string, error) {
	args := []string{"update", "--yes"}
	if opts.version != "" {
		args = append(args, "--version", opts.version)
	}

	out, code, err := env.runCmd(ctx, env.pipelockTarget, args...)
	if err != nil {
		return "", fmt.Errorf("exec pipelock update: %w", err)
	}
	if code != 0 {
		return "", fmt.Errorf("pipelock update exited %d: %s", code, truncateForErr(out))
	}
	return upgradeExtractVersion(out), nil
}

// upgradeExtractVersion parses the version from selfupdate output.
// The matched prefixes ("Updated to ", "latest release. Nothing to do") are
// the exact strings emitted by internal/cli/selfupdate/cmd.go; keep them in
// sync and see TestUpgrade_VersionParsing for the parser contract.
func upgradeExtractVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Updated to ") {
			rest := strings.TrimPrefix(line, "Updated to ")
			if fields := strings.Fields(rest); len(fields) > 0 {
				return strings.TrimRight(fields[0], ".")
			}
		}
		if strings.Contains(line, "latest release. Nothing to do") {
			return "current (already up to date)"
		}
	}
	return "unknown"
}

// upgradeRepinIntegrity hashes the deployed binary and writes the pin file.
func upgradeRepinIntegrity(env *upgradeEnv) error {
	target := filepath.Clean(env.pipelockTarget)
	hash, err := env.hashFile(target)
	if err != nil {
		return fmt.Errorf("hash deployed binary %s: %w", target, err)
	}
	if err := env.mkdirAll(env.integrityDir, modeDirPrivate); err != nil {
		return fmt.Errorf("mkdir %s: %w", env.integrityDir, err)
	}
	contents := []byte(hash + "\n")
	if err := env.writeFile(env.integrityPin, contents, modePinSecret); err != nil {
		return fmt.Errorf("write pin %s: %w", env.integrityPin, err)
	}
	return upgradeRestorePinOwnership(env)
}

// upgradeRestorePinOwnership hands the freshly written pin back to the proxy
// user.
//
// The pin is written by this command running as root, so without this it would
// be left root-owned at 0600. The Pipelock service runs as the proxy user and
// reads the pin at runtime, so a root-owned pin makes the binary-integrity
// probe fail on a host that is otherwise perfectly healthy. That is precisely
// the false mismatch this whole command exists to eliminate, so leaving it
// would have reintroduced the bug through the fix for it.
//
// Mirrors ensureIntegrityOwnership in install.go, which cannot be reused
// directly because it takes *installEnv.
func upgradeRestorePinOwnership(env *upgradeEnv) error {
	u, err := env.lookupUser(env.proxyUserName)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", env.proxyUserName, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("parse uid for %s: %w", env.proxyUserName, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("parse gid for %s: %w", env.proxyUserName, err)
	}
	if err := env.chmod(env.integrityPin, modePinSecret); err != nil {
		return fmt.Errorf("chmod %s: %w", env.integrityPin, err)
	}
	if err := env.chown(env.integrityPin, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", env.integrityPin, err)
	}
	return nil
}

// upgradeRestartAndWait does daemon-reload + restart + readiness poll.
func upgradeRestartAndWait(ctx context.Context, env *upgradeEnv) error {
	if _, code, err := env.runCmd(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	} else if code != 0 {
		return fmt.Errorf("daemon-reload exited %d", code)
	}

	out, code, err := env.runCmd(ctx, "systemctl", "restart", env.serviceName)
	if err != nil {
		return fmt.Errorf("restart %s: %w", env.serviceName, err)
	}
	if code != 0 {
		return fmt.Errorf("restart %s exited %d: %s", env.serviceName, code, truncateForErr(out))
	}

	// Poll for active state with a ticker (no time.Sleep).
	deadline := time.After(env.readinessTimeout)
	ticker := time.NewTicker(readinessInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("service %s not ready after %s", env.serviceName, env.readinessTimeout)
		case <-ticker.C:
			isOut, isCode, isErr := env.runCmd(ctx, "systemctl", "is-active", env.serviceName)
			if isErr != nil {
				continue
			}
			if isCode == 0 && strings.TrimSpace(isOut) == "active" {
				return nil
			}
		}
	}
}

// upgradePostVerify runs the newly deployed binary's contain verify command.
func upgradePostVerify(ctx context.Context, env *upgradeEnv) error {
	out, code, err := env.runCmd(ctx, env.pipelockTarget, "contain", "verify")
	if err != nil {
		return fmt.Errorf("exec contain verify: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("contain verify exited %d: %s", code, truncateForErr(out))
	}
	return nil
}

// upgradeCopyFile copies src to dst preserving the source permissions. It
// backs the deployed binary up before replacement and restores it on rollback.
func upgradeCopyFile(env *upgradeEnv, src, dst string) error {
	data, err := env.readFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	info, err := env.stat(src)
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	if err := env.writeFile(dst, data, info.Mode().Perm()); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return nil
}
