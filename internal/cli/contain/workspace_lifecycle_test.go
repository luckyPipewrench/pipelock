// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func TestWorkspaceGrant_ExpiredAndStatus(t *testing.T) {
	cases := []struct {
		name       string
		grant      workspaceGrant
		wantExpErr bool
		wantExp    bool
		wantStatus string
	}{
		{"never", workspaceGrant{Path: "/p", Mode: "read-only", Owner: "josh", Created: "x"}, false, false, "active"},
		{"future", workspaceGrant{Path: "/p", Owner: "josh", Expires: "2026-07-01T00:00:00Z"}, false, false, "active"},
		{"past", workspaceGrant{Path: "/p", Owner: "josh", Expires: "2026-05-01T00:00:00Z"}, false, true, "expired"},
		{"exact-boundary", workspaceGrant{Path: "/p", Owner: "josh", Expires: "2026-06-01T12:00:00Z"}, false, true, "expired"},
		{"malformed", workspaceGrant{Path: "/p", Owner: "josh", Expires: "not-a-time"}, true, false, "invalid-expiry"},
		{"legacy", workspaceGrant{Path: "/p", Mode: "read-only"}, false, false, "legacy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exp, err := tc.grant.expired(testNow)
			if tc.wantExpErr != (err != nil) {
				t.Fatalf("expired err = %v, wantErr %v", err, tc.wantExpErr)
			}
			if err == nil && exp != tc.wantExp {
				t.Fatalf("expired = %v, want %v", exp, tc.wantExp)
			}
			if got := tc.grant.grantStatus(testNow); got != tc.wantStatus {
				t.Fatalf("status = %q, want %q", got, tc.wantStatus)
			}
		})
	}
}

func TestParseGrantExpiry(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t.Run("duration", func(t *testing.T) {
		got, err := parseGrantExpiry("720h", created)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if want := created.Add(720 * time.Hour); !got.Equal(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("rfc3339", func(t *testing.T) {
		got, err := parseGrantExpiry("2026-03-01T00:00:00Z", created)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if want := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	for _, bad := range []string{"0s", "-1h", "2025-01-01T00:00:00Z", "garbage", ""} {
		t.Run("reject_"+bad, func(t *testing.T) {
			if _, err := parseGrantExpiry(bad, created); err == nil {
				t.Fatalf("parseGrantExpiry(%q) = nil err, want rejection", bad)
			}
		})
	}
}

// TestLegacyGrantInventoryLoadsUnchanged proves an inventory written by the OLD
// struct (path+mode only) parses without error and is recognized as legacy.
func TestLegacyGrantInventoryLoadsUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "workspaces.json")
	legacy := `{"workspaces":[{"path":"/home/dev/proj","mode":"read-only"}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	inv, err := loadWorkspaceInventoryFrom(os.ReadFile, path)
	if err != nil {
		t.Fatalf("load legacy inventory: %v", err)
	}
	if len(inv.Workspaces) != 1 {
		t.Fatalf("workspaces len = %d, want 1", len(inv.Workspaces))
	}
	g := inv.Workspaces[0]
	if g.Path != "/home/dev/proj" || g.Mode != "read-only" {
		t.Fatalf("legacy grant fields lost: %+v", g)
	}
	if !g.isLegacyGrant() {
		t.Fatalf("grant with no metadata should be legacy: %+v", g)
	}
	if g.grantStatus(testNow) != "legacy" {
		t.Fatalf("status = %q, want legacy", g.grantStatus(testNow))
	}
}

func TestRunGrantWorkspace_RecordsMetadata(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.now = func() time.Time { return testNow }
	env.runCmd = func(context.Context, string, ...string) (string, int, error) { return "", 0, nil }
	ws := t.TempDir()

	err := runGrantWorkspace(context.Background(), env, ws, workspaceOpts{
		mode:    workspaceModeReadWrite,
		reason:  "sprint work",
		expires: "720h",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	inv, err := loadWorkspaceInventory(env)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(inv.Workspaces) != 1 {
		t.Fatalf("grants = %d, want 1", len(inv.Workspaces))
	}
	g := inv.Workspaces[0]
	if g.Owner != containInstallOperatorUser {
		t.Errorf("owner = %q, want %q", g.Owner, containInstallOperatorUser)
	}
	if g.Reason != "sprint work" {
		t.Errorf("reason = %q", g.Reason)
	}
	if g.Created != testNow.Format(time.RFC3339) {
		t.Errorf("created = %q, want %q", g.Created, testNow.Format(time.RFC3339))
	}
	wantExp := testNow.Add(720 * time.Hour).UTC().Format(time.RFC3339)
	if g.Expires != wantExp {
		t.Errorf("expires = %q, want %q", g.Expires, wantExp)
	}
	if g.isLegacyGrant() {
		t.Errorf("recorded grant should carry metadata: %+v", g)
	}
}

// TestWorkspaceMetadataSurvivesRevokeAndRegrant proves inventory rewrites keep
// metadata on unaffected grants while a re-grant records fresh metadata.
func TestWorkspaceMetadataSurvivesRevokeAndRegrant(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.now = func() time.Time { return testNow }
	env.runCmd = func(context.Context, string, ...string) (string, int, error) { return "", 0, nil }
	keptPath := t.TempDir()
	regrantPath := t.TempDir()
	kept := workspaceGrant{
		Path:    keptPath,
		Mode:    workspaceModeReadOnly,
		Owner:   "alice",
		Reason:  "keep this grant",
		Created: "2026-05-01T00:00:00Z",
		Expires: "2026-07-01T00:00:00Z",
	}
	if err := recordWorkspaceGrant(env, kept); err != nil {
		t.Fatalf("record kept grant: %v", err)
	}
	if err := recordWorkspaceGrant(env, workspaceGrant{
		Path:    regrantPath,
		Mode:    workspaceModeReadOnly,
		Owner:   "bob",
		Reason:  "old reason",
		Created: "2026-05-01T00:00:00Z",
		Expires: "2026-07-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("record initial grant: %v", err)
	}
	if err := runRevokeWorkspace(context.Background(), env, regrantPath, workspaceOpts{}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := runGrantWorkspace(context.Background(), env, regrantPath, workspaceOpts{
		mode:    workspaceModeReadWrite,
		reason:  "new reason",
		expires: "720h",
	}); err != nil {
		t.Fatalf("re-grant: %v", err)
	}

	inv := readWorkspaceInventory(env)
	if len(inv.Workspaces) != 2 {
		t.Fatalf("grants = %d, want 2: %+v", len(inv.Workspaces), inv.Workspaces)
	}
	var gotKept, gotRegrant workspaceGrant
	for _, grant := range inv.Workspaces {
		switch grant.Path {
		case keptPath:
			gotKept = grant
		case regrantPath:
			gotRegrant = grant
		}
	}
	if gotKept != kept {
		t.Fatalf("unaffected grant metadata changed: got %+v, want %+v", gotKept, kept)
	}
	if gotRegrant.Mode != workspaceModeReadWrite || gotRegrant.Owner != containInstallOperatorUser ||
		gotRegrant.Reason != "new reason" || gotRegrant.Created != testNow.Format(time.RFC3339) ||
		gotRegrant.Expires != testNow.Add(720*time.Hour).Format(time.RFC3339) {
		t.Fatalf("re-grant metadata = %+v, want fresh recorded metadata", gotRegrant)
	}
}

func TestRunListWorkspaces_RendersRowsAndStatus(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.now = func() time.Time { return testNow }
	if err := writeWorkspaceInventory(env, workspaceInventory{Workspaces: []workspaceGrant{
		{Path: "/a/active", Mode: "read-write", Owner: "josh", Created: "2026-05-01T00:00:00Z", Expires: "2026-07-01T00:00:00Z"},
		{Path: "/b/expired", Mode: "read-only", Owner: "josh", Created: "2026-04-01T00:00:00Z", Expires: "2026-05-01T00:00:00Z"},
		{Path: "/c/legacy", Mode: "read-only"},
	}}); err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	var buf bytes.Buffer
	env.out = &buf
	if err := runListWorkspaces(env); err != nil {
		t.Fatalf("list: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"PATH", "/a/active", "active", "/b/expired", "expired", "/c/legacy", "legacy"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}
}

func TestRunListWorkspaces_EmptyInventory(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	var buf bytes.Buffer
	env.out = &buf
	if err := runListWorkspaces(env); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(buf.String(), "no workspace grants recorded") {
		t.Fatalf("empty inventory message missing: %q", buf.String())
	}
}

func TestExpiredWorkspaceGrants(t *testing.T) {
	grants := []workspaceGrant{
		{Path: "/ok", Expires: "2026-07-01T00:00:00Z"},
		{Path: "/gone", Expires: "2026-05-01T00:00:00Z"},
		{Path: "/never"},
	}
	got, err := expiredWorkspaceGrants(grants, testNow)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 1 || got[0] != "/gone" {
		t.Fatalf("expired = %v, want [/gone]", got)
	}
	if _, err := expiredWorkspaceGrants([]workspaceGrant{{Path: "/bad", Expires: "nope"}}, testNow); err == nil {
		t.Fatal("malformed expiry should error (fail closed)")
	}
}

// TestRunContainRun_RefusesExpiredGrant proves an expired grant fails the launch
// closed, including a dry-run that must report the same refusal without launching.
func TestRunContainRun_RefusesExpiredGrant(t *testing.T) {
	seedExpired := func(env *probeEnv) {
		env.now = func() time.Time { return testNow }
		base := env.readFile
		env.readFile = func(path string) ([]byte, error) {
			if path == env.workspaceInvPath {
				return []byte(`{"workspaces":[{"path":"/x/expired","mode":"read-only","owner":"josh","expires":"2026-05-01T00:00:00Z"}]}`), nil
			}
			return base(path)
		}
	}

	t.Run("launch refused", func(t *testing.T) {
		env := allPassEnv(t)
		seedExpired(env)
		var launched bool
		runEnv := containRunEnv{
			probe: env,
			launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error {
				launched = true
				return nil
			},
			emitPosture: func(string, string, *probeEnv, []string) (string, error) { return "/unused", nil },
		}
		err := runContainRun(context.Background(), nil, io.Discard, io.Discard, runEnv, containRunOptions{}, []string{"claude"})
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("err = %v, want expired-grant refusal", err)
		}
		if launched {
			t.Fatal("launched despite an expired grant")
		}
	})

	t.Run("dry-run reports refusal", func(t *testing.T) {
		env := allPassEnv(t)
		seedExpired(env)
		var buf bytes.Buffer
		var launched, posture bool
		runEnv := containRunEnv{
			probe: env,
			launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error {
				launched = true
				return nil
			},
			emitPosture: func(string, string, *probeEnv, []string) (string, error) {
				posture = true
				return "/unused", nil
			},
		}
		err := runContainRun(context.Background(), nil, &buf, io.Discard, runEnv, containRunOptions{dryRun: true}, []string{"claude"})
		// The recorded grants are checked by the workspace probe during
		// preflight, so a dry run refuses at the same point a real launch does
		// and names the remedy; the contract is never rendered for a boundary
		// that already failed.
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("dry-run err = %v, want expired-grant refusal", err)
		}
		if !strings.Contains(buf.String(), "[FAIL] probe 15") || !strings.Contains(buf.String(), "revoke-workspace") {
			t.Fatalf("dry-run did not surface the expired grant through the workspace probe:\n%s", buf.String())
		}
		if launched || posture {
			t.Fatalf("dry-run launched=%v posture=%v, want neither", launched, posture)
		}
	})
}

func TestProbeWorkspaceAccess_FailsOnExpiredGrant(t *testing.T) {
	env := makeProbeEnv(t)
	env.now = func() time.Time { return testNow }
	env.workspaceGrants = []workspaceGrant{{Path: "/x/expired", Expires: "2026-05-01T00:00:00Z"}}
	status, detail := probeWorkspaceAccess(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "expired") {
		t.Fatalf("status=%s detail=%q, want fail on expiry", status, detail)
	}
}

// TestMultiAgentGrantsOnOnePathStayIndependent covers the case a host that
// contains two agent users actually occupies: both hold a live ACL on the same
// directory. Grant identity is (Path, AgentUser), so neither one's record may
// overwrite, revoke, or gate the other's.
func TestMultiAgentGrantsOnOnePathStayIndependent(t *testing.T) {
	shared := t.TempDir()
	alphaGrant := workspaceGrant{
		Path: shared, Mode: workspaceModeReadOnly, Owner: "josh",
		Reason: "alpha reads it", Created: "2026-05-01T00:00:00Z",
		Expires: "2026-07-01T00:00:00Z", AgentUser: "agent-alpha",
	}
	betaGrant := workspaceGrant{
		Path: shared, Mode: workspaceModeReadWrite, Owner: "josh",
		Reason: "beta writes it", Created: "2026-05-02T00:00:00Z",
		Expires: "2026-08-01T00:00:00Z", AgentUser: "agent-beta",
	}

	t.Run("a second agent's grant does not overwrite the first", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.now = func() time.Time { return testNow }
		if err := recordWorkspaceGrant(env, alphaGrant); err != nil {
			t.Fatalf("record alpha: %v", err)
		}
		if err := recordWorkspaceGrant(env, betaGrant); err != nil {
			t.Fatalf("record beta: %v", err)
		}
		inv := readWorkspaceInventory(env)
		if len(inv.Workspaces) != 2 {
			t.Fatalf("grants = %d, want 2 (one per agent user): %+v", len(inv.Workspaces), inv.Workspaces)
		}
		for _, want := range []workspaceGrant{alphaGrant, betaGrant} {
			if !slices.Contains(inv.Workspaces, want) {
				t.Fatalf("inventory lost %+v: %+v", want, inv.Workspaces)
			}
		}
	})

	t.Run("re-granting one agent leaves the other's metadata intact", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.now = func() time.Time { return testNow }
		if err := recordWorkspaceGrant(env, alphaGrant); err != nil {
			t.Fatalf("record alpha: %v", err)
		}
		updated := betaGrant
		updated.Reason = "beta re-granted"
		if err := recordWorkspaceGrant(env, betaGrant); err != nil {
			t.Fatalf("record beta: %v", err)
		}
		if err := recordWorkspaceGrant(env, updated); err != nil {
			t.Fatalf("re-record beta: %v", err)
		}
		inv := readWorkspaceInventory(env)
		if len(inv.Workspaces) != 2 {
			t.Fatalf("grants = %d, want 2: %+v", len(inv.Workspaces), inv.Workspaces)
		}
		if !slices.Contains(inv.Workspaces, alphaGrant) {
			t.Fatalf("alpha's grant changed when beta was re-granted: %+v", inv.Workspaces)
		}
		if !slices.Contains(inv.Workspaces, updated) {
			t.Fatalf("beta's re-grant not recorded: %+v", inv.Workspaces)
		}
	})

	t.Run("revoking one agent leaves the other's ACL recorded", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.now = func() time.Time { return testNow }
		env.runCmd = func(context.Context, string, ...string) (string, int, error) { return "", 0, nil }
		env.agentUserName = "agent-beta"
		if err := recordWorkspaceGrant(env, alphaGrant); err != nil {
			t.Fatalf("record alpha: %v", err)
		}
		if err := recordWorkspaceGrant(env, betaGrant); err != nil {
			t.Fatalf("record beta: %v", err)
		}
		if err := runRevokeWorkspace(context.Background(), env, shared, workspaceOpts{}); err != nil {
			t.Fatalf("revoke beta: %v", err)
		}
		inv := readWorkspaceInventory(env)
		if len(inv.Workspaces) != 1 || inv.Workspaces[0] != alphaGrant {
			t.Fatalf("revoking beta must leave alpha's grant alone, got %+v", inv.Workspaces)
		}
	})

	t.Run("one agent's expired grant does not gate another's launch", func(t *testing.T) {
		stale := alphaGrant
		stale.Expires = "2026-05-01T00:00:00Z" // before testNow
		grants := []workspaceGrant{stale, betaGrant}

		betaScoped := grantsForAgent(grants, "agent-beta")
		expired, err := expiredWorkspaceGrants(betaScoped, testNow)
		if err != nil {
			t.Fatalf("beta expiry check: %v", err)
		}
		if len(expired) != 0 {
			t.Fatalf("alpha's expired grant gated beta: %v", expired)
		}

		alphaScoped := grantsForAgent(grants, "agent-alpha")
		expired, err = expiredWorkspaceGrants(alphaScoped, testNow)
		if err != nil {
			t.Fatalf("alpha expiry check: %v", err)
		}
		if len(expired) != 1 || expired[0] != shared {
			t.Fatalf("alpha's own expired grant must still gate alpha, got %v", expired)
		}
	})

	t.Run("a legacy grant is honoured for every agent user", func(t *testing.T) {
		legacy := workspaceGrant{Path: shared, Mode: workspaceModeReadOnly}
		for _, user := range []string{"agent-alpha", "agent-beta"} {
			if got := grantsForAgent([]workspaceGrant{legacy}, user); len(got) != 1 {
				t.Fatalf("legacy grant hidden from %s: %+v", user, got)
			}
		}
		if got := grantsForAgent([]workspaceGrant{betaGrant}, "agent-alpha"); len(got) != 0 {
			t.Fatalf("beta's grant leaked into alpha's scope: %+v", got)
		}
	})
}

// TestRevokeScopesAncestorACLCleanupToTheRevokedAgent pins the authorization
// boundary in ancestor cleanup. Traversal (--x) ACLs on a shared ancestor are
// per agent user, so only the revoked user's OWN remaining grants may keep one
// open. Passing every agent's grants to the ancestor calculation would let a
// second agent's grant under the same parent preserve the revoked agent's
// traversal, leaving a path walkable after its grant was revoked.
func TestRevokeScopesAncestorACLCleanupToTheRevokedAgent(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.now = func() time.Time { return testNow }
	env.agentUserName = "agent-alpha"

	var ran []workspaceCommand
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		ran = append(ran, workspaceCommand{name: name, args: args})
		return "", 0, nil
	}

	parent := t.TempDir()
	alphaPath := filepath.Join(parent, "alpha")
	betaPath := filepath.Join(parent, "beta")
	for _, dir := range []string{alphaPath, betaPath} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	// Two agents, two workspaces, one shared ancestor.
	if err := recordWorkspaceGrant(env, workspaceGrant{
		Path: alphaPath, Mode: workspaceModeReadOnly, Owner: "josh",
		Created: "2026-05-01T00:00:00Z", AgentUser: "agent-alpha",
	}); err != nil {
		t.Fatalf("record alpha: %v", err)
	}
	if err := recordWorkspaceGrant(env, workspaceGrant{
		Path: betaPath, Mode: workspaceModeReadOnly, Owner: "josh",
		Created: "2026-05-01T00:00:00Z", AgentUser: "agent-beta",
	}); err != nil {
		t.Fatalf("record beta: %v", err)
	}

	ran = nil
	if err := runRevokeWorkspace(context.Background(), env, alphaPath, workspaceOpts{}); err != nil {
		t.Fatalf("revoke alpha: %v", err)
	}

	// agent-alpha holds no other grant, so its traversal ACL on the shared
	// parent must be removed. agent-beta's grant lives under the same parent
	// and must not keep alpha's traversal alive.
	// Match the ancestor path EXACTLY as an argument. A substring match would
	// be satisfied by the workspace command itself, since alphaPath has parent
	// as a prefix - which made an earlier version of this test pass with the
	// guard removed.
	var cleared bool
	for _, c := range ran {
		if c.name != "setfacl" {
			continue
		}
		joined := strings.Join(c.args, " ")
		if strings.Contains(joined, "u:agent-beta") {
			t.Fatalf("revoking agent-alpha touched agent-beta's ACL: setfacl %s", joined)
		}
		if !slices.Contains(c.args, "-x") || !slices.Contains(c.args, "u:agent-alpha") {
			continue
		}
		if slices.Contains(c.args, parent) {
			cleared = true
		}
	}
	if !cleared {
		var got []string
		for _, c := range ran {
			got = append(got, c.name+" "+strings.Join(c.args, " "))
		}
		t.Fatalf("agent-alpha's traversal ACL on the shared ancestor %s was not removed; another agent's grant kept it open.\ncommands:\n%s",
			parent, strings.Join(got, "\n"))
	}
}
