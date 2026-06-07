// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// installEnv is the OS-facing dependency surface used by every mutating
// subcommand. Each operation is a function value so tests can inject fakes
// without touching the real filesystem, /etc/sudoers, or the running
// systemd. Real construction is via defaultInstallEnv(); tests build a
// struct literal with their own hooks.
type installEnv struct {
	// runCmd shells out. Returns merged stdout+stderr (bounded), the
	// process exit code, and a startup error (nil if the binary ran even
	// when it exited non-zero). Same contract as verify.go's runCommand.
	runCmd runCommand

	// stat / readFile / writeFile / removeFile mirror the os package. They
	// are abstracted only so tests can run on a tmpdir without sudo. Path
	// arguments are absolute by convention; the orchestration code
	// constructs them via env helpers (etcPath, wrapperPath, ...).
	stat       func(path string) (os.FileInfo, error)
	lstat      func(path string) (os.FileInfo, error)
	readFile   func(path string) ([]byte, error)
	writeFile  func(path string, contents []byte, mode os.FileMode) error
	removeFile func(path string) error
	mkdirAll   func(path string, mode os.FileMode) error
	chown      func(path string, uid, gid int) error
	rename     func(oldPath, newPath string) error
	chmod      func(path string, mode os.FileMode) error
	symlink    func(target, linkPath string) error

	// lookupUser resolves system users by name. Used to translate the
	// configured proxy/agent user names into numeric UIDs for nft rules
	// and chown calls.
	lookupUser lookupUserFunc

	// selfPath returns the absolute path of the currently-executing
	// pipelock binary. Used to default the --pipelock-binary flag and to
	// compute the integrity-pin hash.
	selfPath func() (string, error)

	// hashFile reads path and returns its SHA-256 as a hex string. Split
	// from runCmd so tests can pin without round-tripping through sha256sum.
	hashFile func(path string) (string, error)

	// Output sink for human progress lines. cmd.OutOrStdout() in production.
	out    io.Writer
	errOut io.Writer

	// Static configuration. These mirror the constants in verify.go so the
	// two subsystems agree on filesystem layout. Made fields rather than
	// constants so the install subcommand can accept flag overrides.
	operatorUser      string
	proxyUserName     string
	agentUserName     string
	configDir         string
	dataDir           string
	wrapperDir        string
	systemUnitPath    string
	nftRulesPath      string
	nftMainPath       string
	sudoersPath       string
	caBundlePath      string
	caExportPath      string
	integrityDir      string
	integrityPin      string
	wrapperInvPath    string
	toolsListPath     string // plk-launch's runtime allow-list (tab-separated NAME\tTARGET)
	workspaceInvPath  string
	undiciShimPath    string // node undici proxy shim loaded via NODE_OPTIONS
	profileScriptPath string // /etc/profile.d login-shell runtime contract
	agentHome         string // contained agent home (per-tool config destination)
	pipelockBinary    string // source binary path passed to --pipelock-binary
	pipelockTarget    string // destination, default /usr/local/bin/pipelock
	proxyPort         int

	prevNFTTableDump       string
	prevNftablesEnabled    bool
	prevNftablesStateKnown bool
	archivedBackups        map[string][]string
}

// defaultInstallEnv wires installEnv to the real OS. Callers fill in
// pipelockBinary (from --pipelock-binary or os.Executable) before running
// steps. operatorUser defaults to $SUDO_USER and is only honored if non-empty
// - step1 (preflight) errors out cleanly if root invoked install without
// sudo (where $SUDO_USER is empty) and -- no override flag was passed.
func defaultInstallEnv(out io.Writer) *installEnv {
	return &installEnv{
		runCmd:            realRunCommand,
		stat:              os.Stat,
		lstat:             os.Lstat,
		readFile:          os.ReadFile,
		writeFile:         writeFileAtomic,
		removeFile:        os.Remove,
		mkdirAll:          os.MkdirAll,
		chown:             os.Chown,
		rename:            os.Rename,
		chmod:             os.Chmod,
		symlink:           os.Symlink,
		lookupUser:        user.Lookup,
		selfPath:          os.Executable,
		hashFile:          sha256HexOfFile,
		out:               out,
		errOut:            os.Stderr,
		operatorUser:      os.Getenv("SUDO_USER"),
		proxyUserName:     defaultProxyUser,
		agentUserName:     defaultAgentUser,
		configDir:         defaultConfigDir,
		dataDir:           defaultDataDir,
		wrapperDir:        defaultWrapperDir,
		systemUnitPath:    defaultSystemUnitPath,
		nftRulesPath:      defaultNFTRulesPath,
		nftMainPath:       defaultNFTMainConfigPath,
		sudoersPath:       defaultSudoersPath,
		caBundlePath:      defaultCABundlePath,
		caExportPath:      defaultCAExportPath,
		integrityDir:      defaultIntegrityDir,
		integrityPin:      defaultIntegrityPin,
		wrapperInvPath:    defaultWrapperInvPath,
		toolsListPath:     defaultToolsListPath,
		workspaceInvPath:  defaultWorkspaceInvPath,
		undiciShimPath:    defaultUndiciShimPath,
		profileScriptPath: defaultProfileScriptPath,
		agentHome:         "/home/" + defaultAgentUser,
		pipelockTarget:    defaultPipelockTarget,
		proxyPort:         defaultProxyPort,
	}
}

// Additional layout constants. They live alongside the verify.go defaults
// so the two subsystems agree on filesystem layout. Names are picked to
// avoid collision with verify.go constants.
const (
	defaultConfigDir         = "/etc/pipelock"
	defaultDataDir           = "/var/lib/pipelock"
	defaultSystemUnitPath    = "/etc/systemd/system/pipelock.service"
	defaultNFTRulesPath      = "/etc/nftables.d/50-pipelock-containment.nft"
	defaultNFTMainConfigPath = "/etc/sysconfig/nftables.conf"
	defaultSudoersPath       = "/etc/sudoers.d/50-pipelock-agent"
	defaultCAExportPath      = "/etc/pipelock/ca.pem"
	defaultIntegrityDir      = "/etc/pipelock/integrity"
	defaultIntegrityPin      = "/etc/pipelock/integrity/binary-pin.sha256"
	defaultWrapperInvPath    = "/etc/pipelock/contain/wrappers.json"
	defaultToolsListPath     = "/etc/pipelock/contain/tools.list"
	defaultWorkspaceInvPath  = "/etc/pipelock/contain/workspaces.json"
	defaultPipelockTarget    = "/usr/local/bin/pipelock"
	defaultSystemCABundle    = "/etc/ssl/certs/ca-bundle.crt"

	// File modes. The model is "pipelock-agent UID must be able to read every
	// non-secret file the wrappers depend on at runtime, but cannot read
	// secrets (config, integrity pin)." The CA files contain public
	// certificates only; the runtime allow-list and wrapper inventory contain
	// tool names/paths only. Mutation remains gated by root-owned directories.
	modeCAReadable        os.FileMode = 0o644 // public CA certs, read by pipelock-agent
	modeAllowListReadable os.FileMode = 0o644 // runtime policy metadata, read by pipelock-agent
	modeConfigSecret      os.FileMode = 0o640 // /etc/pipelock/pipelock.yaml - pipelock-proxy reads, pipelock-agent denied
	modePinSecret         os.FileMode = 0o600 // integrity pin - pipelock-proxy only
	modeSudoers           os.FileMode = 0o440 // /etc/sudoers.d/*
	modeWrapperExec       os.FileMode = 0o755 // /usr/local/bin/plk-* wrappers, executed by operator
	modeUnitFile          os.FileMode = 0o644
	modeNFTFile           os.FileMode = 0o644
	modeNFTMainConfig     os.FileMode = 0o600
	// Directory modes. modeDirTraversable is intentionally world-traversable
	// because pipelock-agent is a separate UID and must walk into
	// /etc/pipelock/contain; modeDirPrivate is for dirs containing only
	// pipelock-proxy-readable secrets (integrity pin, captures).
	modeDirTraversable os.FileMode = 0o755
	modeDirPrivate     os.FileMode = 0o750
	// modeDirSystem is retained for callers that don't yet distinguish
	// traversable from private. Prefer the explicit variants in new code.
	modeDirSystem   os.FileMode = 0o750
	modeDirReadable os.FileMode = 0o755
)

const backupArchiveTimeFormat = "2006-01-02T15:04:05.000000000Z"

var backupArchiveNow = func() time.Time {
	return time.Now().UTC()
}

// writeFileAtomic writes path by creating a sibling .tmp and renaming it
// into place. This makes installs robust to crash mid-write: either the
// previous content stays intact, or the new content is fully present.
func writeFileAtomic(path string, contents []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".pipelock-contain-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmpName, path, err)
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	return nil
}

func syncDir(dir string) error {
	clean := filepath.Clean(dir)
	dirFile, err := os.Open(clean) //nolint:gosec // G304: parent dir is derived from the already-opened temp file target and used only for fsync.
	if err != nil {
		return fmt.Errorf("open dir %s: %w", clean, err)
	}
	syncErr := dirFile.Sync()
	closeErr := dirFile.Close()
	if syncErr != nil {
		// Some platforms/filesystems reject directory fsync. The temp file
		// itself was already fsynced; keep atomic writes portable there.
		if errors.Is(syncErr, syscall.EINVAL) || errors.Is(syncErr, syscall.ENOTSUP) {
			return nil
		}
		return fmt.Errorf("sync dir %s: %w", clean, syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close dir %s: %w", clean, closeErr)
	}
	return nil
}

// sha256HexOfFile computes SHA-256 of the file at path and returns the
// lower-case hex digest. Used for the integrity pin write at install and
// the integrity probe at verify.
func sha256HexOfFile(path string) (string, error) {
	clean := filepath.Clean(path)
	f, err := os.Open(clean) //nolint:gosec // G304: clean path; binary pin is install-time TOFU, see contain-cli-design §3.2
	if err != nil {
		return "", fmt.Errorf("open %s: %w", clean, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", clean, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// backupAndWrite writes a new version of path while preserving the old
// content as path.bak. The .bak is created via atomic rename so a crash
// mid-backup either leaves the original in place or has fully moved it
// aside. If path.bak already exists, it is archived instead of overwritten;
// step undo functions look for path.bak and restore it.
//
// If path doesn't exist, no .bak is created; the new file is written as-is.
func backupAndWrite(env *installEnv, path string, contents []byte, mode os.FileMode) error {
	clean := filepath.Clean(path)
	backedUp, err := backupCurrentToBak(env, clean)
	if err != nil {
		return err
	}
	if err := env.writeFile(clean, contents, mode); err != nil {
		var restoreErr error
		if backedUp {
			restoreErr = restoreBackup(env, clean)
		} else if removeErr := env.removeFile(clean); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			restoreErr = fmt.Errorf("remove failed write %s: %w", clean, removeErr)
		}
		if restoreErr != nil {
			return errors.Join(fmt.Errorf("write %s: %w", clean, err), restoreErr)
		}
		return fmt.Errorf("write %s: %w", clean, err)
	}
	return nil
}

// backupCurrentToBak ensures path.bak contains path's current content. If a
// prior path.bak exists and differs, it is rotated to
// path.bak.archived-<RFC3339 UTC timestamp> first so upgrades keep history
// without blocking reinstall. If the existing backup already equals the
// current file, it is left in place and the caller can overwrite/remove path.
func backupCurrentToBak(env *installEnv, path string) (bool, error) {
	clean := filepath.Clean(path)
	if err := ensureSafeWriteTarget(env, clean); err != nil {
		return false, err
	}
	info, err := env.lstat(clean)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", clean, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%s is a symlink; refusing privileged write", clean)
	}
	current, err := env.readFile(clean)
	if err != nil {
		return false, fmt.Errorf("read %s for backup: %w", clean, err)
	}

	bak := clean + ".bak"
	archive, err := rotateBackupIfNeeded(env, bak, current)
	if err != nil {
		return false, err
	}
	if archive == "" {
		if bakData, err := env.readFile(bak); err == nil && bytesEqual(bakData, current) {
			return true, nil
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("read backup %s: %w", bak, err)
		}
	}

	if err := env.rename(clean, bak); err != nil {
		if archive != "" {
			if restoreErr := env.rename(archive, bak); restoreErr != nil {
				return false, errors.Join(
					fmt.Errorf("backup %s -> %s: %w", clean, bak, err),
					fmt.Errorf("restore archived backup %s -> %s: %w", archive, bak, restoreErr),
				)
			}
			forgetArchivedBackup(env, bak, archive)
		}
		return false, fmt.Errorf("backup %s -> %s: %w", clean, bak, err)
	}
	return true, nil
}

func rotateBackupIfNeeded(env *installEnv, bak string, current []byte) (string, error) {
	info, err := env.lstat(bak)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("stat %s: %w", bak, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to overwrite symlink backup %s", bak)
	}
	bakData, err := env.readFile(bak)
	if err != nil {
		return "", fmt.Errorf("read backup %s: %w", bak, err)
	}
	if bytesEqual(bakData, current) {
		return "", nil
	}
	archive, err := nextBackupArchivePath(env, bak, backupArchiveNow())
	if err != nil {
		return "", err
	}
	if err := env.rename(bak, archive); err != nil {
		return "", fmt.Errorf("archive backup %s -> %s: %w", bak, archive, err)
	}
	rememberArchivedBackup(env, bak, archive)
	return archive, nil
}

func nextBackupArchivePath(env *installEnv, bak string, now time.Time) (string, error) {
	base := fmt.Sprintf("%s.archived-%s", filepath.Clean(bak), now.UTC().Format(backupArchiveTimeFormat))
	for i := 0; ; i++ {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s.%d", base, i)
		}
		if info, err := env.lstat(candidate); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			continue
		} else if errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		} else {
			return "", fmt.Errorf("stat archive backup %s: %w", candidate, err)
		}
	}
}

func rememberArchivedBackup(env *installEnv, bak, archive string) {
	if env.archivedBackups == nil {
		env.archivedBackups = make(map[string][]string)
	}
	env.archivedBackups[bak] = append(env.archivedBackups[bak], archive)
}

func forgetArchivedBackup(env *installEnv, bak, archive string) {
	if len(env.archivedBackups) == 0 {
		return
	}
	archives := env.archivedBackups[bak]
	for i := len(archives) - 1; i >= 0; i-- {
		if archives[i] != archive {
			continue
		}
		archives = append(archives[:i], archives[i+1:]...)
		if len(archives) == 0 {
			delete(env.archivedBackups, bak)
			return
		}
		env.archivedBackups[bak] = archives
		return
	}
}

func ensureSafeWriteTarget(env *installEnv, path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("%s is not an absolute path", clean)
	}
	if err := ensureSafeDirectory(env, filepath.Dir(clean)); err != nil {
		return err
	}
	info, err := env.lstat(clean)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", clean, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing privileged write", clean)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", clean)
	}
	return nil
}

func ensureSafeDirectory(env *installEnv, path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("%s is not an absolute path", clean)
	}
	if err := rejectSymlinkParents(env, clean); err != nil {
		return err
	}
	info, err := env.lstat(clean)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", clean, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing privileged write", clean)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", clean)
	}
	return nil
}

// restoreBackup is the inverse of backupAndWrite, used by undo functions.
// If path.bak exists, restore it over path. If path.bak does not exist,
// remove path (the install created it fresh). Errors that don't matter for
// rollback (target already gone) are swallowed.
func restoreBackup(env *installEnv, path string) error {
	clean := filepath.Clean(path)
	bak := clean + ".bak"
	if info, err := env.lstat(bak); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("backup %s is a symlink; refusing restore", bak)
		}
		// Best-effort cleanup of any non-bak file first; rename below
		// then atomically promotes the backup.
		_ = env.removeFile(clean)
		if err := env.rename(bak, clean); err != nil {
			return fmt.Errorf("restore %s from %s: %w", clean, bak, err)
		}
		return restoreLatestArchivedBackup(env, bak)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", bak, err)
	}
	if err := env.removeFile(clean); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", clean, err)
	}
	return nil
}

// restoreBackupIfPresent restores path.bak over path when a backup exists.
// If no backup exists, it leaves path untouched. Use this for host-owned
// files such as /etc/sysconfig/nftables.conf where deleting the file on
// rollback would be worse than leaving a harmless managed include absent.
func restoreBackupIfPresent(env *installEnv, path string) error {
	clean := filepath.Clean(path)
	bak := clean + ".bak"
	info, err := env.lstat(bak)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", bak, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("backup %s is a symlink; refusing restore", bak)
	}
	_ = env.removeFile(clean)
	if err := env.rename(bak, clean); err != nil {
		return fmt.Errorf("restore %s from %s: %w", clean, bak, err)
	}
	return restoreLatestArchivedBackup(env, bak)
}

func restoreLatestArchivedBackup(env *installEnv, bak string) error {
	archive := popArchivedBackup(env, filepath.Clean(bak))
	if archive == "" {
		return nil
	}
	info, err := env.lstat(archive)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat archived backup %s: %w", archive, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("archived backup %s is a symlink; refusing restore", archive)
	}
	if err := env.rename(archive, bak); err != nil {
		return fmt.Errorf("restore archived backup %s -> %s: %w", archive, bak, err)
	}
	return nil
}

func popArchivedBackup(env *installEnv, bak string) string {
	if len(env.archivedBackups) == 0 {
		return ""
	}
	archives := env.archivedBackups[bak]
	if len(archives) == 0 {
		return ""
	}
	archive := archives[len(archives)-1]
	archives = archives[:len(archives)-1]
	if len(archives) == 0 {
		delete(env.archivedBackups, bak)
	} else {
		env.archivedBackups[bak] = archives
	}
	return archive
}

// resolveUIDs returns the numeric UIDs for the configured proxy and agent
// users. Returns an error wrapping os/user.UnknownUserError when either is
// missing - callers translate that into a clear install error.
func resolveUIDs(env *installEnv) (proxyUID, agentUID int, err error) {
	proxy, err := env.lookupUser(env.proxyUserName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup %s: %w", env.proxyUserName, err)
	}
	agent, err := env.lookupUser(env.agentUserName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup %s: %w", env.agentUserName, err)
	}
	pUID, err := strconv.Atoi(proxy.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse proxy uid %q: %w", proxy.Uid, err)
	}
	aUID, err := strconv.Atoi(agent.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse agent uid %q: %w", agent.Uid, err)
	}
	return pUID, aUID, nil
}

// uidGidFor looks up a system user and returns its uid+gid as ints.
func uidGidFor(env *installEnv, name string) (uid, gid int, err error) {
	u, err := env.lookupUser(name)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup %s: %w", name, err)
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid for %s: %w", name, err)
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid for %s: %w", name, err)
	}
	return uid, gid, nil
}

// runOrErr is a thin wrapper around env.runCmd that turns a non-zero exit
// into an error. Used by steps that shell out for side effects only and
// don't need to inspect the output.
func runOrErr(ctx context.Context, env *installEnv, name string, args ...string) error {
	out, code, err := env.runCmd(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("exec %s: %w", name, err)
	}
	if code != 0 {
		return fmt.Errorf("%s exited %d: %s", name, code, truncateForErr(out))
	}
	return nil
}

// truncateForErr trims long subprocess output to a single readable line for
// inclusion in an error message. Real diagnostic detail still flows to the
// dry-run / verbose stream; this is just the error message that propagates
// up to the caller.
func truncateForErr(s string) string {
	const maxLen = 200
	s = collapseWS(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}

// collapseWS turns any run of whitespace into a single space. Keeps error
// messages on one line regardless of how the subprocess formatted output.
// Iterates over bytes (not runes) because the only whitespace we collapse
// is ASCII and we want to preserve multi-byte UTF-8 sequences verbatim.
func collapseWS(s string) string {
	var b []byte
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\n' || c == '\t' || c == '\r' {
			if !prevSpace {
				b = append(b, ' ')
				prevSpace = true
			}
			continue
		}
		b = append(b, c)
		prevSpace = false
	}
	start, end := 0, len(b)
	for start < end && b[start] == ' ' {
		start++
	}
	for end > start && b[end-1] == ' ' {
		end--
	}
	return string(b[start:end])
}

// pathExists is a small helper used in step idempotency checks. Treats any
// non-NotExist error as existence to avoid silently re-applying a step on a
// permissions error (better to surface the real error in apply()).
func pathExists(env *installEnv, path string) bool {
	_, err := env.stat(path)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

// expectExec ensures the binary at name is executable. Used by preflight
// checks (nft, systemctl, visudo). Returns a clear error message naming the
// missing binary.
func expectExec(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("required executable %q not found in PATH: %w", name, err)
	}
	return nil
}
