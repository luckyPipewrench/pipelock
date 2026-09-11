// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
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
		if err == nil || !strings.Contains(err.Error(), "refusing to launch") {
			t.Fatalf("dry-run err = %v, want expired-grant refusal", err)
		}
		if !strings.Contains(buf.String(), "[expired]") {
			t.Fatalf("dry-run did not surface expired grant status:\n%s", buf.String())
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
