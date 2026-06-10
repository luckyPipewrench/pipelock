// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// TestEvidenceACLCommands_OperatorOnly proves the evidence ACL plan grants the
// resolved operator user read+traverse on the logs and recorder dirs, grants
// only traverse on the data-dir parent, and NEVER references a group or the
// contained agent user.
func TestEvidenceACLCommands_OperatorOnly(t *testing.T) {
	dataDir := "/var/lib/pipelock"
	logs := filepath.Join(dataDir, "logs")
	recorder := filepath.Join(dataDir, "recorder")
	commands := evidenceACLCommands(containInstallOperatorUser, dataDir, []string{logs, recorder})

	if len(commands) == 0 {
		t.Fatal("evidenceACLCommands returned no commands")
	}

	joined := make([]string, 0, len(commands))
	for _, c := range commands {
		// Commands are either a direct setfacl, or a `find ... -exec setfacl`
		// that applies the default ACL to existing nested subdirs.
		if c.name != testSetfaclCmd && (c.name != "find" || !containsArg(c.args, testSetfaclCmd)) {
			t.Fatalf("unexpected command %q (want setfacl or find -exec setfacl); cmd=%+v", c.name, c)
		}
		joined = append(joined, strings.Join(c.args, " "))
	}
	all := strings.Join(joined, "\n")

	// SAFETY: no group ACL, no agent user, no world/other entry.
	for _, banned := range []string{
		"g:",             // group ACL
		"d:g:",           // default group ACL
		"pipelock-agent", // the policed agent
		"u::",            // would touch owner perms unexpectedly
		"o:",             // other/world
	} {
		if strings.Contains(all, banned) {
			t.Fatalf("evidence ACL plan contains banned entry %q:\n%s", banned, all)
		}
	}

	// Parent (data dir) must be traverse-only (--x), never read (r-x/rX).
	var sawParentTraverse bool
	for _, c := range commands {
		argv := strings.Join(c.args, " ")
		if containsArg(c.args, dataDir) && !containsArg(c.args, "-R") && strings.Contains(argv, "u:"+containInstallOperatorUser+":--x") {
			sawParentTraverse = true
		}
		// The parent dir must NOT be granted read in any command.
		if argTargetsDir(c.args, dataDir) && (strings.Contains(argv, ":r-x") || strings.Contains(argv, ":rX") || strings.Contains(argv, ":r--")) {
			t.Fatalf("data-dir parent must be traverse-only, got read grant: %s", argv)
		}
	}
	if !sawParentTraverse {
		t.Fatalf("missing traverse-only (--x) grant on data-dir parent:\n%s", all)
	}

	// Logs + recorder must each get a recursive read+traverse access ACL and a
	// default ACL for inheritance, scoped to the operator user.
	for _, dir := range []string{logs, recorder} {
		if !planHasAccessACL(commands, dir, containInstallOperatorUser) {
			t.Fatalf("missing recursive operator read+traverse access ACL for %s:\n%s", dir, all)
		}
		if !planHasDefaultACL(commands, dir, containInstallOperatorUser) {
			t.Fatalf("missing default (inheritance) operator ACL for %s:\n%s", dir, all)
		}
	}
}

// TestEvidenceACLCommands_NonOperatorIdentityNotGranted proves the plan is
// scoped strictly to the resolved operator user. A different (non-operator /
// agent) username must not appear anywhere in the plan.
func TestEvidenceACLCommands_NonOperatorIdentityNotGranted(t *testing.T) {
	dataDir := "/var/lib/pipelock"
	logs := filepath.Join(dataDir, "logs")
	recorder := filepath.Join(dataDir, "recorder")
	commands := evidenceACLCommands(containInstallOperatorUser, dataDir, []string{logs, recorder})

	all := joinCommands(commands)
	for _, identity := range []string{"pipelock-agent", "pipelock-proxy", "root", "nobody"} {
		if strings.Contains(all, "u:"+identity+":") || strings.Contains(all, "d:u:"+identity+":") {
			t.Fatalf("plan grants access to non-operator identity %q:\n%s", identity, all)
		}
	}
}

// TestStepGrantEvidenceACLs_Apply exercises the install step end-to-end against
// the fake env: it ensures the evidence dirs exist, runs the operator-only
// setfacl commands, and records the inventory.
func TestStepGrantEvidenceACLs_Apply(t *testing.T) {
	if _, err := os.Stat("/usr/bin/setfacl"); err != nil {
		// The step shells out via env.runCmd which is faked in tests, so we do
		// NOT need a real setfacl here. This guard only documents that the
		// production path requires it; the fake runner records argv regardless.
		_ = err
	}
	env, runner, _ := newFakeEnv(t)
	var chowned []string
	env.chown = func(path string, uid, gid int) error {
		if uid != 988 || gid != 988 {
			t.Fatalf("evidence dir chown = %d:%d, want pipelock-proxy 988:988", uid, gid)
		}
		chowned = append(chowned, filepath.Clean(path))
		return nil
	}

	applied, err := stepGrantEvidenceACLs().apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatalf("expected step to apply on first run")
	}

	// Evidence dirs must now exist.
	for _, dir := range []string{env.logsDir(), env.recorderDir()} {
		info, statErr := os.Stat(dir)
		if statErr != nil {
			t.Fatalf("evidence dir %s not created: %v", dir, statErr)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", dir)
		}
		if !containsString(chowned, filepath.Clean(dir)) {
			t.Fatalf("evidence dir %s was not chowned to pipelock-proxy; chowned=%v", dir, chowned)
		}
	}

	// setfacl must have been invoked for the operator user only.
	var sawSetfacl bool
	for _, call := range runner.calls {
		if call.name != testSetfaclCmd {
			continue
		}
		sawSetfacl = true
		argv := strings.Join(call.args, " ")
		if strings.Contains(argv, "pipelock-agent") || strings.Contains(argv, "g:") || strings.Contains(argv, "o:") {
			t.Fatalf("setfacl call leaked group/agent access: %s", argv)
		}
	}
	if !sawSetfacl {
		t.Fatal("no setfacl call recorded")
	}

	// Inventory must be recorded with the operator user.
	inv, loadErr := loadEvidenceACLInventory(env)
	if loadErr != nil {
		t.Fatalf("load evidence inventory: %v", loadErr)
	}
	if inv.Operator != containInstallOperatorUser {
		t.Fatalf("inventory operator = %q, want %q", inv.Operator, containInstallOperatorUser)
	}
	for _, dir := range []string{env.logsDir(), env.recorderDir()} {
		if !containsString(inv.Dirs, dir) {
			t.Fatalf("inventory dirs = %v, missing %s", inv.Dirs, dir)
		}
	}
	info, err := os.Stat(env.evidenceACLInvPath)
	if err != nil {
		t.Fatalf("stat evidence ACL inventory: %v", err)
	}
	if got := info.Mode().Perm(); got != modePinSecret {
		t.Fatalf("inventory mode = %s, want %s", got, modePinSecret)
	}
	parentInfo, err := os.Stat(filepath.Dir(env.evidenceACLInvPath))
	if err != nil {
		t.Fatalf("stat evidence ACL inventory parent: %v", err)
	}
	if got := parentInfo.Mode().Perm(); got != modeDirTraversable {
		t.Fatalf("inventory parent mode = %s, want %s", got, modeDirTraversable)
	}
}

// TestStepGrantEvidenceACLs_Idempotent re-runs the step and confirms it does not
// error and does not duplicate inventory entries.
func TestStepGrantEvidenceACLs_Idempotent(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	step := stepGrantEvidenceACLs()
	if _, err := step.apply(context.Background(), env); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if _, err := step.apply(context.Background(), env); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	inv, err := loadEvidenceACLInventory(env)
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	seen := map[string]bool{}
	for _, d := range inv.Dirs {
		if seen[d] {
			t.Fatalf("duplicate dir in inventory after re-run: %s", d)
		}
		seen[d] = true
	}
}

// TestStepGrantEvidenceACLs_FailClosedOnUnresolvedOperator proves the ACL step
// is skipped (no setfacl, no group/world fallback) when the operator user
// cannot be resolved.
func TestStepGrantEvidenceACLs_FailClosedOnUnresolvedOperator(t *testing.T) {
	t.Run("empty operator user", func(t *testing.T) {
		env, runner, buf := newFakeEnv(t)
		env.operatorUser = ""
		applied, err := stepGrantEvidenceACLs().apply(context.Background(), env)
		if err != nil {
			t.Fatalf("apply must not error on unresolved operator, got %v", err)
		}
		if applied {
			t.Fatal("step must not report applied when operator unresolved")
		}
		for _, call := range runner.calls {
			if call.name == testSetfaclCmd {
				t.Fatalf("setfacl must not run when operator unresolved: %+v", call)
			}
		}
		if !strings.Contains(buf.String(), "operator") {
			t.Fatalf("expected a logged skip reason mentioning operator:\n%s", buf.String())
		}
	})

	t.Run("unknown operator user", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.operatorUser = "ghost"
		applied, err := stepGrantEvidenceACLs().apply(context.Background(), env)
		if err != nil {
			t.Fatalf("apply must not error on unknown operator, got %v", err)
		}
		if applied {
			t.Fatal("step must not report applied when operator unknown")
		}
		for _, call := range runner.calls {
			if call.name == testSetfaclCmd {
				t.Fatalf("setfacl must not run when operator unknown: %+v", call)
			}
		}
	})
}

// TestInstallSteps_IncludesEvidenceACLStep proves the install pipeline wires the
// evidence ACL step after the data-dir is created and chowned to the proxy.
func TestInstallSteps_IncludesEvidenceACLStep(t *testing.T) {
	steps := installSteps(installOpts{})
	dataChown, evidence := -1, -1
	for i, s := range steps {
		if s.name == "chown-data" {
			dataChown = i
		}
		if s.name == "grant-evidence-acls" {
			evidence = i
		}
	}
	if evidence == -1 {
		t.Fatal("install steps missing grant-evidence-acls")
	}
	if dataChown == -1 || evidence < dataChown {
		t.Fatalf("evidence ACL step (%d) must run after data chown (%d)", evidence, dataChown)
	}
}

// TestRollbackActions_RevokesEvidenceACLs proves rollback revokes the operator
// evidence ACLs and runs before the data dir removal / user deletion.
func TestRollbackActions_RevokesEvidenceACLs(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	// Seed an inventory as if install had granted the ACLs.
	if err := writeEvidenceACLInventory(env, evidenceACLInventory{
		Operator: containInstallOperatorUser,
		Dirs:     []string{env.logsDir(), env.recorderDir()},
	}); err != nil {
		t.Fatalf("seed evidence inventory: %v", err)
	}
	if err := os.MkdirAll(env.logsDir(), 0o750); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	if err := os.MkdirAll(env.recorderDir(), 0o750); err != nil {
		t.Fatalf("mkdir recorder: %v", err)
	}

	actions := rollbackActions(rollbackOpts{keepData: false})
	revokeIdx := stepIndex(actions, "revoke-evidence-acls")
	if revokeIdx == -1 {
		t.Fatal("rollback actions missing revoke-evidence-acls")
	}
	for _, blocker := range []string{"remove-dir-data", "delete-proxy-user", "delete-agent-user"} {
		blockerIdx := stepIndex(actions, blocker)
		if blockerIdx == -1 {
			t.Fatalf("rollback actions missing %s", blocker)
		}
		if revokeIdx <= blockerIdx {
			t.Fatalf("revoke-evidence-acls index %d must be greater than %s index %d so reverse rollback runs revoke first", revokeIdx, blocker, blockerIdx)
		}
	}

	for i := len(actions) - 1; i >= 0; i-- {
		if actions[i].undo == nil {
			continue
		}
		if err := actions[i].undo(context.Background(), env); err != nil {
			t.Fatalf("undo %s: %v", actions[i].name, err)
		}
	}

	var sawRevoke bool
	for _, call := range runner.calls {
		if call.name != testSetfaclCmd {
			continue
		}
		argv := strings.Join(call.args, " ")
		if strings.Contains(argv, "-x") && strings.Contains(argv, "u:"+containInstallOperatorUser) {
			sawRevoke = true
		}
	}
	if !sawRevoke {
		t.Fatalf("rollback did not revoke operator evidence ACLs; calls=%+v", runner.calls)
	}

	// Inventory removed when keepData=false.
	if _, err := os.Stat(env.evidenceACLInvPath); err == nil {
		t.Fatal("evidence ACL inventory must be removed with keep-data=false")
	}
}

func TestRollbackActions_KeepsEvidenceInventoryWithKeepData(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := writeEvidenceACLInventory(env, evidenceACLInventory{
		Operator: containInstallOperatorUser,
		Dirs:     []string{env.logsDir()},
	}); err != nil {
		t.Fatalf("seed evidence inventory: %v", err)
	}
	if err := os.MkdirAll(env.logsDir(), 0o750); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	env.lookupUser = func(name string) (*user.User, error) {
		return &user.User{Uid: "1000", Gid: "1000", Username: name}, nil
	}

	actions := rollbackActions(rollbackOpts{keepData: true})
	for i := len(actions) - 1; i >= 0; i-- {
		if actions[i].undo == nil {
			continue
		}
		if err := actions[i].undo(context.Background(), env); err != nil {
			t.Fatalf("undo %s: %v", actions[i].name, err)
		}
	}
	if _, err := os.Stat(env.evidenceACLInvPath); err != nil {
		t.Fatalf("evidence ACL inventory must be preserved with keep-data=true: %v", err)
	}
}

func stepIndex(actions []step, name string) int {
	for i, action := range actions {
		if action.name == name {
			return i
		}
	}
	return -1
}

// TestEvidenceACL_DefaultInheritsToNewFile uses the REAL setfacl/getfacl to
// prove (1) the operator gains read+traverse on the evidence dir, (2) a NEW
// file created after the grant inherits the operator-read default ACL, and
// (3) no group or agent entry is added. Skips cleanly if the platform lacks
// ACL support.
func TestEvidenceACL_DefaultInheritsToNewFile(t *testing.T) {
	if _, err := exec.LookPath("setfacl"); err != nil {
		t.Skip("setfacl not available; skipping real-ACL inheritance test")
	}
	if _, err := exec.LookPath("getfacl"); err != nil {
		t.Skip("getfacl not available; skipping real-ACL inheritance test")
	}

	root := t.TempDir()
	dataDir := filepath.Join(root, "var", "lib", "pipelock")
	logs := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(logs, 0o750); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}

	operator, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}

	// Probe: does this filesystem support ACLs at all?
	if _, _, perr := realRunCommand(context.Background(), "setfacl", "-m", "u:"+operator.Username+":rX", dataDir); perr != nil {
		t.Skipf("filesystem does not support ACLs: %v", perr)
	}

	commands := evidenceACLCommands(operator.Username, dataDir, []string{logs})
	for _, c := range commands {
		out, code, runErr := realRunCommand(context.Background(), c.name, c.args...)
		if runErr != nil || code != 0 {
			t.Skipf("ACL command %s %v failed (likely unsupported FS): code=%d err=%v out=%s", c.name, c.args, code, runErr, out)
		}
	}

	// New file written into the logs dir AFTER the default ACL was applied.
	newFile := filepath.Join(logs, "audit.log")
	if err := os.WriteFile(newFile, []byte("entry\n"), 0o600); err != nil {
		t.Fatalf("write new audit log: %v", err)
	}

	facl, _, err := realRunCommand(context.Background(), "getfacl", "-p", newFile)
	if err != nil {
		t.Fatalf("getfacl: %v", err)
	}
	if !strings.Contains(facl, "user:"+operator.Username+":r") {
		t.Fatalf("new file did not inherit operator read ACL:\n%s", facl)
	}
	// Adversarial: our plan must not add a NAMED group ACL ("group:<name>:").
	// The owning-group entry ("group::...") is normal and not our doing.
	for _, line := range strings.Split(facl, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "group:") && !strings.HasPrefix(trimmed, "group::") {
			t.Fatalf("unexpected named-group ACL on inherited file: %q\nfull:\n%s", trimmed, facl)
		}
	}
}

// TestEnsureEvidenceDir_RejectsSymlink proves the dir-ensure step refuses to
// apply an ACL through a symlink standing in for the evidence dir.
func TestEnsureEvidenceDir_RejectsSymlink(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.MkdirAll(target, 0o750); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := ensureEvidenceDir(env, link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v, want symlink rejection", err)
	}
}

// TestEnsureEvidenceDir_RejectsNonDir proves a non-directory in the dir's place
// is rejected.
func TestEnsureEvidenceDir_RejectsNonDir(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	root := t.TempDir()
	file := filepath.Join(root, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := ensureEvidenceDir(env, file); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("err = %v, want non-directory rejection", err)
	}
}

// TestStepGrantEvidenceACLs_PropagatesSetfaclFailure proves a failing setfacl
// surfaces as an apply error (fail-closed, not silently applied).
func TestStepGrantEvidenceACLs_PropagatesSetfaclFailure(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor("setfacl", "-m", "u:"+containInstallOperatorUser+":"+evidenceTraversePerms, env.dataDir), "boom", 1, nil)
	applied, err := stepGrantEvidenceACLs().apply(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "operator evidence ACL") {
		t.Fatalf("err = %v, want apply failure", err)
	}
	if applied {
		t.Fatal("step must not report applied when setfacl fails")
	}
}

// TestLoadEvidenceACLInventory_Malformed proves a corrupt inventory is a clear
// parse error (not a silent empty).
func TestLoadEvidenceACLInventory_Malformed(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.evidenceACLInvPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.evidenceACLInvPath, []byte("{nope"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadEvidenceACLInventory(env); err == nil || !strings.Contains(err.Error(), "evidence-acls.json") {
		t.Fatalf("err = %v, want parse error", err)
	}
}

// TestRevokeEvidenceACLs_SkipsRemovedDirs proves revoke tolerates a dir that no
// longer exists (half-removed install) and still revokes the surviving one.
func TestRevokeEvidenceACLs_SkipsRemovedDirs(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	gone := filepath.Join(env.dataDir, "recorder") // never created
	present := env.logsDir()
	if err := os.MkdirAll(present, 0o750); err != nil {
		t.Fatalf("mkdir present: %v", err)
	}
	if err := writeEvidenceACLInventory(env, evidenceACLInventory{
		Operator: containInstallOperatorUser,
		Dirs:     []string{gone, present},
	}); err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	if err := revokeEvidenceACLs(context.Background(), env, true); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	for _, call := range runner.calls {
		if call.name == testSetfaclCmd && containsArg(call.args, gone) {
			t.Fatalf("revoke touched a removed dir: %+v", call)
		}
	}
}

// TestWriteEvidenceACLInventory_DedupesAndSorts proves repeated/unsorted dirs
// are normalized on write.
func TestWriteEvidenceACLInventory_DedupesAndSorts(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := writeEvidenceACLInventory(env, evidenceACLInventory{
		Operator: containInstallOperatorUser,
		Dirs:     []string{env.recorderDir(), env.logsDir(), env.recorderDir()},
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	inv, err := loadEvidenceACLInventory(env)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(inv.Dirs) != 2 {
		t.Fatalf("dirs = %v, want 2 deduped", inv.Dirs)
	}
	if inv.Dirs[0] >= inv.Dirs[1] {
		t.Fatalf("dirs not sorted: %v", inv.Dirs)
	}
}

// --- test helpers -----------------------------------------------------------

func joinCommands(commands []workspaceCommand) string {
	parts := make([]string, 0, len(commands))
	for _, c := range commands {
		parts = append(parts, c.name+" "+strings.Join(c.args, " "))
	}
	return strings.Join(parts, "\n")
}

// argTargetsDir reports whether dir is the last (target) positional argument of
// the setfacl invocation, i.e. the command acts ON dir (not merely names it as
// an ancestor in a -R recursion rooted elsewhere).
func argTargetsDir(args []string, dir string) bool {
	if len(args) == 0 {
		return false
	}
	return args[len(args)-1] == dir
}

func planHasAccessACL(commands []workspaceCommand, dir, operator string) bool {
	for _, c := range commands {
		argv := strings.Join(c.args, " ")
		if containsArg(c.args, "-R") && containsArg(c.args, dir) &&
			(strings.Contains(argv, "u:"+operator+":rX") || strings.Contains(argv, "u:"+operator+":r-x")) {
			return true
		}
	}
	return false
}

func planHasDefaultACL(commands []workspaceCommand, dir, operator string) bool {
	for _, c := range commands {
		argv := strings.Join(c.args, " ")
		if containsArg(c.args, dir) &&
			(strings.Contains(argv, "d:u:"+operator+":rX") || strings.Contains(argv, "d:u:"+operator+":r-x")) {
			return true
		}
	}
	return false
}
