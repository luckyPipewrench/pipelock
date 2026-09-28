// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// Evidence ACL: durable, operator-only read access to pipelock's evidence dirs.
//
// The data dir (/var/lib/pipelock) is created 0o750 and chowned to
// pipelock-proxy, so the human operator can only read the audit log and the
// signed receipt chain with sudo. That opacity once hid a live receipt-chain
// bug until it was dug out with sudo. This grants the resolved operator user a
// minimal POSIX ACL so they can verify the receipt chain offline without sudo.
//
// SECURITY: the grant is a USER-scoped ACL for the resolved operator only.
// It is deliberately NOT a group ACL: the contained agent (pipelock-agent,
// uid 966) shares the operator's group (agentshare), so a group-read ACL would
// hand the policed agent pipelock's own detection/block/receipt evidence —
// evasion intel and a capability-separation break. The parent data dir gets
// traverse-only (--x), never read, so siblings like captures/ are not broadly
// exposed. If the operator cannot be resolved, the step fails CLOSED (skips
// with a logged reason) rather than falling back to a group or world grant.

// evidenceReadPerms is the operator access ACL on the evidence dirs and their
// files: read + traverse (directory execute). Mirrors workspace ACL "rX".
const evidenceReadPerms = "rX"

// evidenceTraversePerms grants directory traversal only (no read/list) on the
// data-dir parent, so the operator can descend into the evidence dirs without
// gaining read/list of the whole tree (captures/, quarantine/, ...).
const evidenceTraversePerms = "--x"

// logsDir is the operator-evidence log directory (audit.log lives here).
func (e *installEnv) logsDir() string {
	return filepath.Join(e.dataDir, "logs")
}

// recorderDir is the flight-recorder directory holding the signed receipt
// chain (flight_recorder.dir default). Mirrors config_migrate.go's default.
func (e *installEnv) recorderDir() string {
	return filepath.Join(e.dataDir, "recorder")
}

// evidenceACLDirs returns the evidence directories that receive an operator
// read+traverse ACL: the logs dir (audit log) and the recorder dir (receipt
// chain). Both hold operator evidence the product pitch says operators verify
// offline with the public key.
func (e *installEnv) evidenceACLDirs() []string {
	return []string{e.logsDir(), e.recorderDir()}
}

// evidenceACLInventory tracks the operator evidence ACL grant so rollback can
// revoke it (mirrors workspaceInventory). It records the resolved operator user
// and the dirs that received the grant.
type evidenceACLInventory struct {
	Operator string   `json:"operator"`
	Dirs     []string `json:"dirs"`
}

// evidenceACLCommands builds the operator-only setfacl plan:
//   - traverse-only (--x) on the data-dir parent (no read/list),
//   - recursive read+traverse (rX) access ACL on each evidence dir + its files,
//   - a default ACL (d:) on each evidence dir (and its existing subdirs) so
//     rotated logs and newly-written receipt files inherit operator-read.
//
// Every entry is u:<operator>: scoped. No group, no other, no agent.
func evidenceACLCommands(operator, dataDir string, dirs []string) []workspaceCommand {
	var commands []workspaceCommand

	// Parent: traverse-only. The operator must be able to descend INTO the
	// evidence dirs, but must not gain read/list of the whole data tree.
	commands = append(commands, workspaceCommand{
		name: "setfacl",
		args: []string{"-m", "u:" + operator + ":" + evidenceTraversePerms, dataDir},
	})

	for _, dir := range dirs {
		// Recursive access ACL: read+traverse on the dir and every existing
		// file/subdir within it (so the current audit.log and receipt files
		// become readable immediately).
		commands = append(commands, workspaceCommand{
			name: "setfacl",
			args: []string{"-R", "-m", "u:" + operator + ":" + evidenceReadPerms, dir},
		})
		// Default ACL on the dir so NEW files (rotated logs, new receipts)
		// inherit operator-read automatically.
		commands = append(commands, workspaceCommand{
			name: "setfacl",
			args: []string{"-m", "d:u:" + operator + ":" + evidenceReadPerms, dir},
		})
		// Default ACL on existing subdirs too, so receipts written into nested
		// recorder subdirs also inherit operator-read.
		commands = append(commands, workspaceCommand{
			name: "find",
			args: []string{dir, "-mindepth", "1", "-type", "d", "-exec", "setfacl", "-m", "d:u:" + operator + ":" + evidenceReadPerms, "{}", "+"},
		})
	}
	return commands
}

// evidenceACLRevokeCommands removes the operator ACL from the evidence dirs and
// the traverse-only grant from the data-dir parent. Best-effort: dirs that no
// longer exist are simply skipped by the caller.
func evidenceACLRevokeCommands(operator, dataDir string, dirs []string) []workspaceCommand {
	var commands []workspaceCommand
	for _, dir := range dirs {
		commands = append(commands,
			workspaceCommand{name: "setfacl", args: []string{"-R", "-x", "u:" + operator, dir}},
			workspaceCommand{name: "setfacl", args: []string{"-x", "d:u:" + operator, dir}},
			workspaceCommand{name: "find", args: []string{dir, "-mindepth", "1", "-type", "d", "-exec", "setfacl", "-x", "d:u:" + operator, "{}", "+"}},
		)
	}
	commands = append(commands, workspaceCommand{
		name: "setfacl",
		args: []string{"-x", "u:" + operator, dataDir},
	})
	return commands
}

// stepGrantEvidenceACLs is the install step that grants the resolved operator
// user a durable read+traverse ACL on the evidence dirs. It runs after the data
// dir is created and chowned to pipelock-proxy. Idempotent: re-running
// re-asserts the same ACL and preserves any existing inventory entries.
func stepGrantEvidenceACLs() step {
	// granted is the grant this attempt started applying, kept in memory so
	// undo can revoke it even when the on-disk inventory was never written.
	var granted *evidenceACLInventory
	inventoryWritten := false
	var priorInventory evidenceACLInventory
	priorInventoryExisted := false
	return step{
		name: "grant-evidence-acls",
		desc: "grant operator read+traverse ACL on logs + recorder evidence dirs",
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			granted = nil
			inventoryWritten = false
			priorInventory = evidenceACLInventory{}
			priorInventoryExisted = false
			operator, ok := resolveEvidenceOperator(env)
			if !ok {
				// FAIL CLOSED: never fall back to a group or world grant.
				return false, nil
			}
			if info, err := env.lstat(env.evidenceACLInvPath); err == nil {
				if info.Mode()&os.ModeSymlink != 0 {
					return false, fmt.Errorf("evidence ACL inventory %s is a symlink", env.evidenceACLInvPath)
				}
				priorInventoryExisted = true
			} else if !errors.Is(err, os.ErrNotExist) {
				return false, fmt.Errorf("stat evidence ACL inventory %s: %w", env.evidenceACLInvPath, err)
			}
			var err error
			priorInventory, err = loadEvidenceACLInventory(env)
			if err != nil {
				return false, err
			}

			dirs := env.evidenceACLDirs()
			uid, gid, err := uidGidFor(env, env.proxyUserName)
			if err != nil {
				return false, err
			}
			// Ensure the evidence dirs exist before applying ACLs. They are
			// created lazily by the running proxy otherwise, which would leave
			// the operator without read access until the first write. Because
			// this step runs after chown-data, dirs created here must be
			// explicitly re-owned by pipelock-proxy or the service cannot write
			// its own evidence on a fresh install.
			for _, dir := range dirs {
				if err := ensureEvidenceDir(env, dir); err != nil {
					return false, err
				}
				if err := walkAndChown(env, dir, uid, gid); err != nil {
					return false, err
				}
			}

			// A reinstall re-asserts a grant that already exists. Remember that,
			// so a rollback of this install does not strip operator access the
			// host had before it started.
			env.evidenceACLPreexisting = evidenceACLInventoryValueCovers(priorInventory, operator, dirs)
			commands := evidenceACLCommands(operator, env.dataDir, dirs)
			// From here on some ACLs may be applied, so every error reports
			// applied and undo revokes the grant.
			granted = &evidenceACLInventory{Operator: operator, Dirs: dirs}
			if err := runWorkspaceCommands(ctx, env, commands); err != nil {
				return true, fmt.Errorf("apply operator evidence ACL: %w", err)
			}
			if priorInventory.Operator != "" && priorInventory.Operator != operator {
				if err := revokeEvidenceACLDirs(ctx, env, priorInventory); err != nil {
					return true, fmt.Errorf("revoke prior operator evidence ACL: %w", err)
				}
			}
			if env.evidenceACLPreexisting {
				return true, nil
			}
			inventory := *granted
			if priorInventory.Operator == operator {
				inventory.Dirs = append(append([]string{}, priorInventory.Dirs...), dirs...)
			}
			if err := writeEvidenceACLInventory(env, inventory); err != nil {
				return true, fmt.Errorf("record evidence ACL inventory: %w", err)
			}
			inventoryWritten = true
			return true, nil
		},
		undo: func(ctx context.Context, env *installEnv) error {
			if env.evidenceACLPreexisting {
				return nil
			}
			if granted == nil {
				return nil
			}
			// Restore the previous operator even if removing the new grant fails.
			// Keep the current inventory on any error: a new ACL may still exist.
			rollbackErr := revokeEvidenceACLDirs(ctx, env, *granted)
			if priorInventory.Operator != "" && len(priorInventory.Dirs) > 0 {
				var existingDirs []string
				for _, dir := range priorInventory.Dirs {
					if _, err := env.stat(dir); err == nil {
						existingDirs = append(existingDirs, dir)
					} else if !errors.Is(err, os.ErrNotExist) {
						rollbackErr = errors.Join(rollbackErr, fmt.Errorf("stat prior evidence dir %s: %w", dir, err))
					}
				}
				if len(existingDirs) > 0 {
					if err := runWorkspaceCommands(ctx, env, evidenceACLCommands(priorInventory.Operator, env.dataDir, existingDirs)); err != nil {
						rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore prior evidence ACLs: %w", err))
					}
				}
			}
			if rollbackErr != nil {
				return rollbackErr
			}
			if !inventoryWritten {
				// backupAndWrite restored a failed write inline (or recorded it
				// for retry), so there is no successful inventory to undo here.
				return nil
			}
			if priorInventoryExisted {
				return restoreBackup(env, env.evidenceACLInvPath)
			}
			if err := env.removeFile(env.evidenceACLInvPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove evidence ACL inventory: %w", err)
			}
			return nil
		},
	}
}

// evidenceACLInventoryCovers reports whether the recorded inventory already
// grants operator every dir in dirs. An unreadable or malformed inventory
// counts as not covered, so rollback revokes what this install applied.
func evidenceACLInventoryCovers(env *installEnv, operator string, dirs []string) bool {
	inv, err := loadEvidenceACLInventory(env)
	if err != nil {
		return false
	}
	return evidenceACLInventoryValueCovers(inv, operator, dirs)
}

func evidenceACLInventoryValueCovers(inv evidenceACLInventory, operator string, dirs []string) bool {
	if inv.Operator != operator {
		return false
	}
	for _, dir := range dirs {
		if !slices.Contains(inv.Dirs, dir) {
			return false
		}
	}
	return true
}

// resolveEvidenceOperator returns the operator username if it is set AND
// resolvable to a real account. A clear skip reason is logged when it cannot be
// resolved; the caller treats !ok as a fail-closed skip (no group/world grant).
func resolveEvidenceOperator(env *installEnv) (string, bool) {
	if env.operatorUser == "" {
		_, _ = fmt.Fprintln(env.out, "  [SKIP] operator evidence ACL: operator user not set (no group/world fallback)")
		return "", false
	}
	if _, err := env.lookupUser(env.operatorUser); err != nil {
		_, _ = fmt.Fprintf(env.out, "  [SKIP] operator evidence ACL: cannot resolve operator %q: %v (no group/world fallback)\n", env.operatorUser, err)
		return "", false
	}
	return env.operatorUser, true
}

// ensureEvidenceDir creates dir (private mode) if it does not already exist,
// refusing to follow a symlink in its place.
func ensureEvidenceDir(env *installEnv, dir string) error {
	info, err := env.lstat(dir)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; refusing to apply operator evidence ACL", dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", dir)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if err := env.mkdirAll(dir, modeDirPrivate); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := env.chmod(dir, modeDirPrivate); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return nil
}

// revokeEvidenceACLs removes the operator evidence ACL recorded in the
// inventory. keepData preserves the inventory file (parallels the workspace ACL
// revoke). It is safe to call when nothing was granted.
func revokeEvidenceACLs(ctx context.Context, env *installEnv, keepData bool) error {
	// A failed operator rotation can restore the prior ACL while the current
	// inventory still names the new operator. The backup records that prior
	// grant, so a later full rollback must revoke both.
	paths := []string{env.evidenceACLInvPath, env.evidenceACLInvPath + ".bak"}
	var revokeErr error
	for _, path := range paths {
		inv, err := loadEvidenceACLInventoryPath(env, path)
		if err != nil {
			revokeErr = errors.Join(revokeErr, err)
			continue
		}
		if err := revokeEvidenceACLDirs(ctx, env, inv); err != nil {
			revokeErr = errors.Join(revokeErr, fmt.Errorf("revoke evidence ACLs from %s: %w", path, err))
		}
	}
	if revokeErr != nil {
		return revokeErr
	}
	if keepData {
		return nil
	}
	for _, path := range paths {
		if err := env.removeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}
	return nil
}

// revokeEvidenceACLDirs removes inv's operator ACL from the dirs that still
// exist, skipping removed ones to avoid erroring on a half-removed install.
func revokeEvidenceACLDirs(ctx context.Context, env *installEnv, inv evidenceACLInventory) error {
	if inv.Operator == "" || len(inv.Dirs) == 0 {
		return nil
	}
	var dirs []string
	for _, dir := range inv.Dirs {
		if _, statErr := env.stat(dir); statErr == nil {
			dirs = append(dirs, dir)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", dir, statErr)
		}
	}
	if len(dirs) > 0 {
		commands := evidenceACLRevokeCommands(inv.Operator, env.dataDir, dirs)
		if err := runWorkspaceCommands(ctx, env, commands); err != nil {
			return err
		}
	}
	return nil
}

func loadEvidenceACLInventory(env *installEnv) (evidenceACLInventory, error) {
	return loadEvidenceACLInventoryPath(env, env.evidenceACLInvPath)
}

func loadEvidenceACLInventoryPath(env *installEnv, path string) (evidenceACLInventory, error) {
	data, err := env.readFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return evidenceACLInventory{}, nil
		}
		return evidenceACLInventory{}, err
	}
	var inv evidenceACLInventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return evidenceACLInventory{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return inv, nil
}

func writeEvidenceACLInventory(env *installEnv, inv evidenceACLInventory) error {
	if err := env.mkdirAll(filepath.Dir(env.evidenceACLInvPath), modeDirTraversable); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(env.evidenceACLInvPath), err)
	}
	if err := env.chmod(filepath.Dir(env.evidenceACLInvPath), modeDirTraversable); err != nil {
		return fmt.Errorf("chmod %s: %w", filepath.Dir(env.evidenceACLInvPath), err)
	}
	// De-dupe and sort dirs so a re-run produces stable, non-duplicated output.
	inv.Dirs = slices.Compact(slices.Sorted(slices.Values(inv.Dirs)))
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal evidence ACL inventory: %w", err)
	}
	data = append(data, '\n')
	return backupAndWrite(env, env.evidenceACLInvPath, data, modePinSecret)
}
