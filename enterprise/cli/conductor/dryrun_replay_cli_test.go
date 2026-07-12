//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
)

func TestConductorDryRunFlagsAndReplayCommandRegistered(t *testing.T) {
	root := Cmd()
	for _, path := range [][]string{{"publish"}, {"kill"}, {"resume"}, {"rollback"}} {
		cmd := findCommandPath(t, root, path...)
		flag := cmd.Flags().Lookup("dry-run")
		if flag == nil {
			t.Fatalf("%s missing --dry-run flag", strings.Join(path, " "))
		}
		if flag.Value.Type() != "bool" {
			t.Fatalf("%s --dry-run type = %q, want bool", strings.Join(path, " "), flag.Value.Type())
		}
	}
	if cmd := findCommandPath(t, root, "replay"); cmd == nil {
		t.Fatal("conductor replay command is not registered")
	}
}

func findCommandPath(t *testing.T, root *cobra.Command, path ...string) *cobra.Command {
	t.Helper()
	cmd := root
	for _, name := range path {
		next, _, err := cmd.Find([]string{name})
		if err != nil {
			t.Fatalf("find %s: %v", strings.Join(path, " "), err)
		}
		if next == nil || next.Name() != name {
			t.Fatalf("find %s returned %v", name, next)
		}
		cmd = next
	}
	return cmd
}

func TestRunPublishDryRunSendsDryRunAndRendersEvaluation(t *testing.T) {
	dir := t.TempDir()
	opts := publishDryRunTestOptions(t, dir)
	var gotDryRun bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != controlplane.PublishPolicyBundlePath {
			t.Fatalf("path = %q, want %q", r.URL.Path, controlplane.PublishPolicyBundlePath)
		}
		if r.Method != http.MethodPut {
			t.Fatalf("method = %s, want PUT", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer "+testPubToken {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		var body struct {
			Bundle conductorcore.PolicyBundle `json:"bundle"`
			DryRun bool                       `json:"dry_run"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		gotDryRun = body.DryRun
		if body.Bundle.BundleID == "" || body.Bundle.Signatures == nil {
			t.Fatalf("request bundle not built/signed: %+v", body.Bundle)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controlplane.PublishEvaluation{
			DryRun:         true,
			Valid:          true,
			WouldCreate:    true,
			ResultVersion:  7,
			ResultHash:     strings.Repeat("a", 64),
			HasCurrentHead: false,
			Preflight: controlplane.PublishPreflightSummary{
				CanApply: 1,
			},
		})
	}))
	defer srv.Close()
	opts.conductorURL = srv.URL

	var out bytes.Buffer
	if err := runPublish(t.Context(), &out, opts); err != nil {
		t.Fatalf("runPublish dry-run: %v", err)
	}
	if !gotDryRun {
		t.Fatal("publish request dry_run = false, want true")
	}
	gotOut := out.String()
	for _, want := range []string{"dry-run policy bundle", "valid=true", "would_create=true", "result_version=7", "fleet preflight"} {
		if !strings.Contains(gotOut, want) {
			t.Fatalf("output %q missing %q", gotOut, want)
		}
	}
}

func TestPostBundleDryRunErrorPaths(t *testing.T) {
	bundle := minimalBundle(t)
	t.Run("malformed json", func(t *testing.T) {
		url := newStubStatusServer(t, http.StatusOK, "not json")
		_, err := postBundleDryRun(t.Context(), &http.Client{Timeout: time.Second}, url, "tok", bundle, postBundleOptions{})
		if err == nil || !strings.Contains(err.Error(), "decode publish dry-run response") {
			t.Fatalf("error = %v, want dry-run decode error", err)
		}
	})
	t.Run("server error", func(t *testing.T) {
		url := newStubStatusServer(t, http.StatusInternalServerError, `{"error":"boom"}`)
		_, err := postBundleDryRun(t.Context(), &http.Client{Timeout: time.Second}, url, "tok", bundle, postBundleOptions{})
		if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("error = %v, want HTTP 500", err)
		}
	})
	t.Run("oversized success response", func(t *testing.T) {
		validPrefix, err := json.Marshal(controlplane.PublishEvaluation{
			DryRun:        true,
			Valid:         true,
			WouldCreate:   true,
			ResultVersion: 7,
			ResultHash:    strings.Repeat("a", 64),
		})
		if err != nil {
			t.Fatalf("marshal valid prefix: %v", err)
		}
		url := newStubStatusServer(t, http.StatusOK, string(validPrefix)+strings.Repeat(" ", publishMaxResponseBytes))
		_, err = postBundleDryRun(t.Context(), &http.Client{Timeout: time.Second}, url, "tok", bundle, postBundleOptions{})
		if err == nil || !strings.Contains(err.Error(), "response exceeds") {
			t.Fatalf("error = %v, want oversized response error", err)
		}
	})
}

func TestPostBundleNonDryRunOmitsDryRun(t *testing.T) {
	var sawDryRun bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_, sawDryRun = body["dry_run"]
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(publishResult{
			BundleID:   "bundle-1",
			BundleHash: strings.Repeat("c", 64),
			Version:    7,
			Created:    true,
		})
	}))
	defer srv.Close()

	if _, err := postBundle(t.Context(), srv.Client(), srv.URL, "tok", minimalBundle(t), postBundleOptions{}); err != nil {
		t.Fatalf("postBundle: %v", err)
	}
	if sawDryRun {
		t.Fatal("normal publish request included dry_run; want omitted")
	}
}

func TestRunRemoteKillDryRunSendsDryRunAndDoesNotApply(t *testing.T) {
	rig := newKillRig(t, 0)
	rig.opts.dryRun = true
	cmd, out := newCobraForRun(t)
	if err := runRemoteKill(cmd, rig.opts, conductorcore.KillSwitchActive); err != nil {
		t.Fatalf("runRemoteKill dry-run: %v", err)
	}
	gotOut := out.String()
	for _, want := range []string{"dry-run remote-kill", "valid=true", "would_create=true", "counter=100"} {
		if !strings.Contains(gotOut, want) {
			t.Fatalf("output %q missing %q", gotOut, want)
		}
	}

	follower := controlplane.FollowerIdentity{OrgID: testOrgID, FleetID: testFleetID, InstanceID: testInstanceID, Environment: testEnvironment}
	if _, err := rig.srv.emergency.LatestRemoteKill(t.Context(), follower, rig.now); !errors.Is(err, controlplane.ErrEmergencyNotFound) {
		t.Fatalf("remote-kill dry-run stored a kill: err=%v, want ErrEmergencyNotFound", err)
	}

	realOpts := rig.opts
	realOpts.dryRun = false
	cmd2, out2 := newCobraForRun(t)
	if err := runRemoteKill(cmd2, realOpts, conductorcore.KillSwitchActive); err != nil {
		t.Fatalf("runRemoteKill after dry-run: %v", err)
	}
	if !strings.Contains(out2.String(), "remote-kill published") {
		t.Fatalf("non-dry-run output = %q, want publish", out2.String())
	}

	stored, err := rig.srv.emergency.LatestRemoteKill(t.Context(), follower, rig.now)
	if err != nil {
		t.Fatalf("latest remote kill after real publish: %v", err)
	}
	if stored.Message.State != conductorcore.KillSwitchActive || stored.Message.Counter != rig.opts.counter {
		t.Fatalf("latest remote kill = state %s counter %d, want active counter %d", stored.Message.State, stored.Message.Counter, rig.opts.counter)
	}

	resumeOpts := rig.opts
	resumeOpts.counter = rig.opts.counter + 1
	resumeOpts.dryRun = true
	cmd3, out3 := newCobraForRun(t)
	if err := runRemoteKill(cmd3, resumeOpts, conductorcore.KillSwitchInactive); err != nil {
		t.Fatalf("runRemoteKill resume dry-run: %v", err)
	}
	if !strings.Contains(out3.String(), "dry-run remote-kill") {
		t.Fatalf("resume dry-run output = %q, want dry-run", out3.String())
	}
	stored, err = rig.srv.emergency.LatestRemoteKill(t.Context(), follower, rig.now)
	if err != nil {
		t.Fatalf("latest remote kill after resume dry-run: %v", err)
	}
	if stored.Message.State != conductorcore.KillSwitchActive || stored.Message.Counter != rig.opts.counter {
		t.Fatalf("resume dry-run mutated latest remote kill: state %s counter %d, want active counter %d", stored.Message.State, stored.Message.Counter, rig.opts.counter)
	}
}

func TestRunRollbackDryRunSendsDryRunAndDoesNotApply(t *testing.T) {
	opts := newRollbackRig(t, 0)
	opts.dryRun = true
	cmd, out := rollbackCobra(t)
	if err := runRollback(cmd, opts); err != nil {
		t.Fatalf("runRollback dry-run: %v", err)
	}
	gotOut := out.String()
	for _, want := range []string{"dry-run rollback", "valid=true", "would_create=true", "would_roll_to_version=41"} {
		if !strings.Contains(gotOut, want) {
			t.Fatalf("output %q missing %q", gotOut, want)
		}
	}

	srv, ok := opts.transport.(*testServer)
	if !ok {
		t.Fatalf("rollback test transport = %T, want *testServer", opts.transport)
	}
	follower := controlplane.FollowerIdentity{OrgID: testOrgID, FleetID: testFleetID, InstanceID: testInstanceID, Environment: testEnvironment}
	if _, active, err := srv.emergency.ActiveRollbackForFollower(t.Context(), follower, opts.now()); err != nil || active {
		t.Fatalf("rollback dry-run active rollback = %t err=%v, want none", active, err)
	}
	head, err := srv.store.Latest(t.Context(), follower, opts.now())
	if err != nil {
		t.Fatalf("latest bundle after rollback dry-run: %v", err)
	}
	if head.Bundle.Version != opts.currentVersion || head.Bundle.BundleID != opts.currentBundleID {
		t.Fatalf("rollback dry-run moved stream head to %s v%d, want %s v%d", head.Bundle.BundleID, head.Bundle.Version, opts.currentBundleID, opts.currentVersion)
	}

	realOpts := opts
	realOpts.dryRun = false
	cmd2, out2 := rollbackCobra(t)
	if err := runRollback(cmd2, realOpts); err != nil {
		t.Fatalf("runRollback after dry-run: %v", err)
	}
	if !strings.Contains(out2.String(), "rollback published") {
		t.Fatalf("non-dry-run output = %q, want publish", out2.String())
	}
	if _, active, err := srv.emergency.ActiveRollbackForFollower(t.Context(), follower, opts.now()); err != nil || !active {
		t.Fatalf("rollback real publish active rollback = %t err=%v, want active", active, err)
	}
	head, err = srv.store.Latest(t.Context(), follower, opts.now())
	if err != nil {
		t.Fatalf("latest bundle after rollback publish: %v", err)
	}
	if head.Bundle.Version != opts.targetVersion || head.Bundle.BundleID != opts.targetBundleID {
		t.Fatalf("rollback real publish stream head = %s v%d, want %s v%d", head.Bundle.BundleID, head.Bundle.Version, opts.targetBundleID, opts.targetVersion)
	}
}

func TestRunReplayPostsBundleAndRendersResult(t *testing.T) {
	dir := t.TempDir()
	opts := replayOptions{publish: publishDryRunTestOptions(t, dir)}
	snapshotPath := filepath.Join(dir, "snapshot.json")
	writeClientFile(t, snapshotPath, []byte(`{"followers":[],"runtime_statuses":[]}`))
	opts.stateSnapshot = snapshotPath
	var gotPath string
	var gotSnapshot bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer "+testPubToken {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		requestBody := readRequestBody(t, r)
		var body struct {
			Bundle        *conductorcore.PolicyBundle `json:"bundle"`
			StateSnapshot json.RawMessage             `json:"state_snapshot"`
		}
		if err := json.NewDecoder(bytes.NewReader(requestBody)).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body.Bundle == nil || body.Bundle.BundleID == "" || len(body.Bundle.Signatures) == 0 {
			t.Fatalf("request missing signed bundle: %+v", body.Bundle)
		}
		gotSnapshot = len(body.StateSnapshot) > 0
		var raw map[string]json.RawMessage
		if err := json.NewDecoder(bytes.NewReader(requestBody)).Decode(&raw); err != nil {
			t.Fatalf("decode raw request: %v", err)
		}
		for key := range raw {
			if key != "bundle" && key != "state_snapshot" {
				t.Fatalf("replay request included unexpected key %q", key)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controlplane.DecisionReplayResult{
			ActionKind:        "publish",
			ArtifactHash:      strings.Repeat("b", 64),
			UsedStateSnapshot: true,
			ReplayedAt:        testFixedNow(t),
			PublishEvaluation: &controlplane.PublishEvaluation{
				Valid:          false,
				Conflict:       controlplane.PublishConflictFleetSkew,
				WouldCreate:    false,
				ResultVersion:  7,
				HasCurrentHead: true,
			},
			Divergence:       true,
			DivergenceReason: "recorded as accepted but re-derived decision would reject (fleet_skew)",
		})
	}))
	defer srv.Close()
	opts.publish.conductorURL = srv.URL

	cmd, out := replayCobra(t)
	if err := runReplay(cmd, opts); err != nil {
		t.Fatalf("runReplay: %v", err)
	}
	if gotPath != controlplane.DecisionReplayPath {
		t.Fatalf("path = %q, want %q", gotPath, controlplane.DecisionReplayPath)
	}
	if !gotSnapshot {
		t.Fatal("replay request omitted state_snapshot")
	}
	gotOut := out.String()
	for _, want := range []string{"decision replay action=publish", "divergence=true", "conflict=fleet_skew", "used_state_snapshot=true"} {
		if !strings.Contains(gotOut, want) {
			t.Fatalf("output %q missing %q", gotOut, want)
		}
	}
}

func TestRunReplayErrorPaths(t *testing.T) {
	dir := t.TempDir()
	opts := replayOptions{publish: publishDryRunTestOptions(t, dir)}
	cmd, _ := replayCobra(t)
	opts.publish.publisherTok = ""
	if err := runReplay(cmd, opts); err == nil || !strings.Contains(err.Error(), "--publisher-token-file") {
		t.Fatalf("missing token error = %v, want publisher token required", err)
	}

	opts = replayOptions{publish: publishDryRunTestOptions(t, dir)}
	opts.stateSnapshot = writeFile(t, dir, "bad-snapshot.json", "{not json")
	cmd, _ = replayCobra(t)
	if err := runReplay(cmd, opts); err == nil || !strings.Contains(err.Error(), "parse --state-snapshot") {
		t.Fatalf("bad snapshot error = %v, want parse error", err)
	}

	opts = replayOptions{publish: publishDryRunTestOptions(t, dir)}
	url := newStubStatusServer(t, http.StatusBadGateway, `{"error":"upstream unavailable"}`)
	opts.publish.conductorURL = url
	cmd, _ = replayCobra(t)
	if err := runReplay(cmd, opts); err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("server error = %v, want HTTP 502", err)
	}

	opts = replayOptions{publish: publishDryRunTestOptions(t, dir)}
	opts.stateSnapshot = filepath.Join(dir, "oversized-snapshot.json")
	if err := os.WriteFile(opts.stateSnapshot, []byte(`{"padding":"`+strings.Repeat("x", replayMaxStateSnapshotBytes)+`"}`), 0o600); err != nil {
		t.Fatalf("write oversized snapshot: %v", err)
	}
	cmd, _ = replayCobra(t)
	if err := runReplay(cmd, opts); err == nil || !strings.Contains(err.Error(), "--state-snapshot exceeds") {
		t.Fatalf("oversized snapshot error = %v, want size cap error", err)
	}

	opts = replayOptions{publish: publishDryRunTestOptions(t, dir)}
	resultPrefix, err := json.Marshal(controlplane.DecisionReplayResult{
		ActionKind:   "publish",
		ArtifactHash: strings.Repeat("b", 64),
		ReplayedAt:   testFixedNow(t),
		PublishEvaluation: &controlplane.PublishEvaluation{
			Valid:       true,
			WouldCreate: true,
		},
	})
	if err != nil {
		t.Fatalf("marshal replay prefix: %v", err)
	}
	url = newStubStatusServer(t, http.StatusOK, string(resultPrefix)+strings.Repeat(" ", publishMaxResponseBytes))
	opts.publish.conductorURL = url
	cmd, _ = replayCobra(t)
	if err := runReplay(cmd, opts); err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("oversized replay response error = %v, want size cap error", err)
	}
}

func publishDryRunTestOptions(t *testing.T, dir string) publishOptions {
	t.Helper()
	keyPath, _ := writePolicyKeyFile(t, dir, wantPurposeFlag, "policy-key-dryrun")
	return publishOptions{
		configFile:     writeFile(t, dir, "policy.yaml", testConfigYAML),
		orgID:          testOrg,
		fleetID:        testFleet,
		environment:    testEnv,
		audience:       []string{"*"},
		version:        7,
		validity:       time.Hour,
		minVersion:     "1.2.3",
		signingKey:     keyPath,
		publisherTok:   writeFile(t, dir, "publisher.token", testPubToken),
		insecure:       true,
		dryRun:         true,
		allowFleetSkew: false,
	}
}

func replayCobra(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	return cmd, out
}

func readRequestBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body
}
