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
	"github.com/luckyPipewrench/pipelock/internal/license"
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

func TestReplayCommandRunELicenseGateAndRunReplay(t *testing.T) {
	t.Run("without license", func(t *testing.T) {
		t.Setenv(license.EnvLicenseKey, "")
		t.Setenv(license.EnvLicensePublicKey, "")
		t.Setenv(license.EnvLicenseCRLFile, "")
		cmd := replayCmd()
		cmd.SetArgs([]string{})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
			t.Fatalf("replay without license error = %v, want ErrFleetLicenseRequired", err)
		}
	})

	t.Run("with license reaches runReplay", func(t *testing.T) {
		installFleetLicense(t)
		cmd := replayCmd()
		cmd.SetArgs([]string{})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--publisher-token-file") {
			t.Fatalf("licensed replay error = %v, want runReplay publisher token error", err)
		}
	})
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
		if r.URL.Path != controlplane.PublishPolicyEvaluatePath {
			t.Fatalf("path = %q, want %q", r.URL.Path, controlplane.PublishPolicyEvaluatePath)
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
	t.Run("created response rejected", func(t *testing.T) {
		url := newStubStatusServer(t, http.StatusCreated, `{"bundle_id":"bundle-1","created":true}`)
		_, err := postBundleDryRun(t.Context(), &http.Client{Timeout: time.Second}, url, "tok", bundle, postBundleOptions{})
		if err == nil || !strings.Contains(err.Error(), "201 Created") {
			t.Fatalf("error = %v, want created-response rejection", err)
		}
	})
	t.Run("missing dry run marker", func(t *testing.T) {
		url := newStubStatusServer(t, http.StatusOK, `{"valid":true,"would_create":true}`)
		_, err := postBundleDryRun(t.Context(), &http.Client{Timeout: time.Second}, url, "tok", bundle, postBundleOptions{})
		if err == nil || !strings.Contains(err.Error(), "missing dry_run=true") {
			t.Fatalf("error = %v, want missing dry_run marker error", err)
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

func TestPostEmergencyJSONStatusConstructionAndReadErrors(t *testing.T) {
	t.Run("marshal request", func(t *testing.T) {
		_, err := postEmergencyJSONStatus(t.Context(), &staticEmergencyTransport{}, "https://conductor.example", "/ok", "tok", make(chan int), nil)
		if err == nil || !strings.Contains(err.Error(), "marshal request") {
			t.Fatalf("error = %v, want marshal request error", err)
		}
	})

	t.Run("build request", func(t *testing.T) {
		_, err := postEmergencyJSONStatus(t.Context(), &staticEmergencyTransport{}, "https://conductor.example", "/bad%zz", "tok", map[string]string{"ok": "yes"}, nil)
		if err == nil || !strings.Contains(err.Error(), "build request") {
			t.Fatalf("error = %v, want build request error", err)
		}
	})

	t.Run("read capped body", func(t *testing.T) {
		_, err := readCappedResponseBody(errReader{}, 16)
		if err == nil || !strings.Contains(err.Error(), "read conductor response") {
			t.Fatalf("error = %v, want read conductor response error", err)
		}
	})
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

func TestRunRemoteKillDryRunErrorAndConflictPathsDoNotApply(t *testing.T) {
	follower := controlplane.FollowerIdentity{OrgID: testOrgID, FleetID: testFleetID, InstanceID: testInstanceID, Environment: testEnvironment}
	validEval, err := json.Marshal(controlplane.RemoteKillEvaluation{
		DryRun:      true,
		Valid:       true,
		WouldCreate: true,
		Counter:     100,
		MessageHash: strings.Repeat("d", 64),
	})
	if err != nil {
		t.Fatalf("marshal valid remote-kill eval: %v", err)
	}
	conflictEval, err := json.Marshal(controlplane.RemoteKillEvaluation{
		DryRun:   true,
		Valid:    false,
		Conflict: controlplane.EmergencyConflictStaleCounter,
		Counter:  100,
	})
	if err != nil {
		t.Fatalf("marshal conflict remote-kill eval: %v", err)
	}
	createdResponse, err := json.Marshal(publishRemoteKillResponse{
		MessageID: "old-server-mutated",
		Created:   true,
	})
	if err != nil {
		t.Fatalf("marshal created remote-kill response: %v", err)
	}

	cases := []struct {
		name     string
		status   int
		body     string
		wantErr  string
		wantOut  string
		wantPath string
	}{
		{name: "malformed json", status: http.StatusOK, body: "not json", wantErr: "decode conductor response"},
		{name: "server error", status: http.StatusInternalServerError, body: `{"error":"boom"}`, wantErr: "status=500"},
		{name: "created response rejected", status: http.StatusCreated, body: string(createdResponse), wantErr: "201 Created"},
		{name: "missing dry run marker", status: http.StatusOK, body: `{"valid":true,"would_create":true,"counter":100}`, wantErr: "missing dry_run=true"},
		{name: "oversized response", status: http.StatusOK, body: string(validEval) + strings.Repeat(" ", maxEmergencyResponseBytes), wantErr: "response exceeds"},
		{name: "conflict evaluation", status: http.StatusOK, body: string(conflictEval), wantOut: "valid=false"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newKillRig(t, 0)
			rig.opts.dryRun = true
			transport := &staticEmergencyTransport{status: tc.status, body: tc.body}
			rig.opts.transport = transport
			cmd, out := newCobraForRun(t)
			err := runRemoteKill(cmd, rig.opts, conductorcore.KillSwitchActive)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("runRemoteKill conflict dry-run error = %v", err)
			}
			if tc.wantOut != "" && !strings.Contains(out.String(), tc.wantOut) {
				t.Fatalf("output %q missing %q", out.String(), tc.wantOut)
			}
			if transport.path != controlplane.RemoteKillEvaluatePath {
				t.Fatalf("path = %q, want %q", transport.path, controlplane.RemoteKillEvaluatePath)
			}
			if _, err := rig.srv.emergency.LatestRemoteKill(t.Context(), follower, rig.now); !errors.Is(err, controlplane.ErrEmergencyNotFound) {
				t.Fatalf("remote-kill dry-run error path stored a kill: err=%v, want ErrEmergencyNotFound", err)
			}
		})
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

func TestRunRollbackDryRunErrorAndConflictPathsDoNotApply(t *testing.T) {
	validEval, err := json.Marshal(controlplane.RollbackEvaluation{
		DryRun:              true,
		Valid:               true,
		WouldCreate:         true,
		Counter:             100,
		WouldRollToBundleID: "bundle-target",
		WouldRollToVersion:  41,
		WouldRollToHash:     strings.Repeat("e", 64),
	})
	if err != nil {
		t.Fatalf("marshal valid rollback eval: %v", err)
	}
	conflictEval, err := json.Marshal(controlplane.RollbackEvaluation{
		DryRun:   true,
		Valid:    false,
		Conflict: controlplane.EmergencyConflictStaleCounter,
		Counter:  100,
	})
	if err != nil {
		t.Fatalf("marshal conflict rollback eval: %v", err)
	}
	createdResponse, err := json.Marshal(publishRollbackAuthorizationResponse{
		AuthorizationID: "old-server-mutated",
		Created:         true,
	})
	if err != nil {
		t.Fatalf("marshal created rollback response: %v", err)
	}

	cases := []struct {
		name    string
		status  int
		body    string
		wantErr string
		wantOut string
	}{
		{name: "malformed json", status: http.StatusOK, body: "not json", wantErr: "decode conductor response"},
		{name: "server error", status: http.StatusInternalServerError, body: `{"error":"boom"}`, wantErr: "status=500"},
		{name: "created response rejected", status: http.StatusCreated, body: string(createdResponse), wantErr: "201 Created"},
		{name: "missing dry run marker", status: http.StatusOK, body: `{"valid":true,"would_create":true,"counter":100}`, wantErr: "missing dry_run=true"},
		{name: "oversized response", status: http.StatusOK, body: string(validEval) + strings.Repeat(" ", maxEmergencyResponseBytes), wantErr: "response exceeds"},
		{name: "conflict evaluation", status: http.StatusOK, body: string(conflictEval), wantOut: "valid=false"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := newRollbackRig(t, 0)
			opts.dryRun = true
			srv, ok := opts.transport.(*testServer)
			if !ok {
				t.Fatalf("rollback test transport = %T, want *testServer", opts.transport)
			}
			follower := controlplane.FollowerIdentity{OrgID: testOrgID, FleetID: testFleetID, InstanceID: testInstanceID, Environment: testEnvironment}
			headBefore, err := srv.store.Latest(t.Context(), follower, opts.now())
			if err != nil {
				t.Fatalf("latest bundle before rollback dry-run error path: %v", err)
			}
			transport := &staticEmergencyTransport{status: tc.status, body: tc.body}
			opts.transport = transport
			cmd, out := rollbackCobra(t)
			err = runRollback(cmd, opts)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("runRollback conflict dry-run error = %v", err)
			}
			if tc.wantOut != "" && !strings.Contains(out.String(), tc.wantOut) {
				t.Fatalf("output %q missing %q", out.String(), tc.wantOut)
			}
			if transport.path != controlplane.RollbackEvaluatePath {
				t.Fatalf("path = %q, want %q", transport.path, controlplane.RollbackEvaluatePath)
			}
			if _, active, err := srv.emergency.ActiveRollbackForFollower(t.Context(), follower, opts.now()); err != nil || active {
				t.Fatalf("rollback dry-run error path active rollback = %t err=%v, want none", active, err)
			}
			headAfter, err := srv.store.Latest(t.Context(), follower, opts.now())
			if err != nil {
				t.Fatalf("latest bundle after rollback dry-run error path: %v", err)
			}
			if headAfter.BundleHash != headBefore.BundleHash {
				t.Fatalf("rollback dry-run error path moved head from %s to %s", headBefore.BundleHash, headAfter.BundleHash)
			}
		})
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

func TestRunReplayBundleArtifactPostsExactBundle(t *testing.T) {
	dir := t.TempDir()
	buildOpts := publishDryRunTestOptions(t, dir)
	bundle, _, priv, err := buildSignedBundle(buildOpts)
	if err != nil {
		t.Fatalf("buildSignedBundle: %v", err)
	}
	defer zeroizeKey(priv)
	artifact, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle artifact: %v", err)
	}
	artifactPath := filepath.Join(dir, "bundle-artifact.json")
	writeClientFile(t, artifactPath, artifact)

	opts := replayOptions{
		publish: publishDryRunTestOptions(t, dir),
	}
	opts.bundleArtifact = artifactPath
	opts.publish.configFile = ""
	opts.publish.signingKey = ""
	opts.publish.version = 0

	var gotBundleID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody := readRequestBody(t, r)
		var body struct {
			Bundle *conductorcore.PolicyBundle `json:"bundle"`
		}
		if err := json.NewDecoder(bytes.NewReader(requestBody)).Decode(&body); err != nil {
			t.Fatalf("decode replay request: %v", err)
		}
		if body.Bundle == nil {
			t.Fatal("replay request omitted bundle")
		}
		gotBundleID = body.Bundle.BundleID
		if !body.Bundle.CreatedAt.Equal(bundle.CreatedAt) || !body.Bundle.NotBefore.Equal(bundle.NotBefore) || !body.Bundle.ExpiresAt.Equal(bundle.ExpiresAt) {
			t.Fatalf("replay bundle timestamps changed: got created=%s not_before=%s expires=%s want created=%s not_before=%s expires=%s",
				body.Bundle.CreatedAt, body.Bundle.NotBefore, body.Bundle.ExpiresAt, bundle.CreatedAt, bundle.NotBefore, bundle.ExpiresAt)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controlplane.DecisionReplayResult{
			ActionKind:   "publish",
			ArtifactHash: strings.Repeat("b", 64),
			ReplayedAt:   testFixedNow(t),
			PublishEvaluation: &controlplane.PublishEvaluation{
				Valid:       true,
				WouldCreate: true,
			},
		})
	}))
	defer srv.Close()
	opts.publish.conductorURL = srv.URL

	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	if err := runReplay(cmd, opts); err != nil {
		t.Fatalf("runReplay with artifact: %v", err)
	}
	if gotBundleID != bundle.BundleID {
		t.Fatalf("replay posted bundle_id=%q, want exact artifact bundle_id=%q", gotBundleID, bundle.BundleID)
	}
}

func TestRunReplayResolvesPreviousHashAuto(t *testing.T) {
	dir := t.TempDir()
	opts := replayOptions{publish: publishDryRunTestOptions(t, dir)}
	opts.publish.previousHash = previousHashAuto
	resolvedHash := strings.Repeat("f", 64)
	var replayPreviousHash string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case controlplane.StreamStatusPath:
			if r.Method != http.MethodGet {
				t.Fatalf("stream status method = %s, want GET", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"streams": []map[string]any{{
					"environment":      testEnv,
					"audience":         conductorcore.Audience{InstanceIDs: []string{"*"}},
					"head_bundle_hash": resolvedHash,
				}},
			})
		case controlplane.DecisionReplayPath:
			var body struct {
				Bundle conductorcore.PolicyBundle `json:"bundle"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode replay request: %v", err)
			}
			replayPreviousHash = body.Bundle.PreviousBundleHash
			_ = json.NewEncoder(w).Encode(controlplane.DecisionReplayResult{
				ActionKind:   "publish",
				ArtifactHash: strings.Repeat("b", 64),
				ReplayedAt:   testFixedNow(t),
				PublishEvaluation: &controlplane.PublishEvaluation{
					Valid:       true,
					WouldCreate: true,
				},
			})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()
	opts.publish.conductorURL = srv.URL

	cmd, out := replayCobra(t)
	if err := runReplay(cmd, opts); err != nil {
		t.Fatalf("runReplay auto previous hash: %v", err)
	}
	if replayPreviousHash != resolvedHash {
		t.Fatalf("replay previous hash = %q, want %q", replayPreviousHash, resolvedHash)
	}
	if !strings.Contains(out.String(), "resolved --previous-bundle-hash auto to "+resolvedHash) {
		t.Fatalf("output %q missing resolved hash", out.String())
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

	opts = replayOptions{publish: publishDryRunTestOptions(t, dir)}
	opts.bundleArtifact = writeFile(t, dir, "bad-bundle-artifact.json", "{not json")
	opts.publish.conductorURL = newStubStatusServer(t, http.StatusOK, `{}`)
	cmd, _ = replayCobra(t)
	if err := runReplay(cmd, opts); err == nil || !strings.Contains(err.Error(), "parse --bundle-artifact") {
		t.Fatalf("bad bundle artifact error = %v, want parse error", err)
	}
}

func TestReadReplayBundleArtifactErrorPaths(t *testing.T) {
	dir := t.TempDir()
	if _, err := readReplayBundleArtifact(filepath.Join(dir, "missing.json")); err == nil || !strings.Contains(err.Error(), "read --bundle-artifact") {
		t.Fatalf("missing artifact error = %v, want read error", err)
	}
	if _, err := readReplayBundleArtifact(dir); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory artifact error = %v, want regular file error", err)
	}
	oversized := filepath.Join(dir, "oversized.json")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", replayMaxBundleArtifactBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized artifact: %v", err)
	}
	if _, err := readReplayBundleArtifact(oversized); err == nil || !strings.Contains(err.Error(), "--bundle-artifact exceeds") {
		t.Fatalf("oversized artifact error = %v, want size error", err)
	}
	invalid := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalid, []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatalf("write invalid artifact: %v", err)
	}
	if _, err := readReplayBundleArtifact(invalid); err == nil || !strings.Contains(err.Error(), "validate --bundle-artifact") {
		t.Fatalf("invalid artifact error = %v, want validation error", err)
	}
	trailing := filepath.Join(dir, "trailing.json")
	if err := os.WriteFile(trailing, []byte(`{} {}`), 0o600); err != nil {
		t.Fatalf("write trailing artifact: %v", err)
	}
	if _, err := readReplayBundleArtifact(trailing); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("trailing artifact error = %v, want trailing JSON error", err)
	}
}

func TestReadReplayStateSnapshotErrorPaths(t *testing.T) {
	dir := t.TempDir()
	if snapshot, err := readReplayStateSnapshot("  "); err != nil || snapshot != nil {
		t.Fatalf("empty snapshot path = (%s, %v), want nil nil", snapshot, err)
	}
	if _, err := readReplayStateSnapshot(filepath.Join(dir, "missing.json")); err == nil || !strings.Contains(err.Error(), "read --state-snapshot") {
		t.Fatalf("missing snapshot error = %v, want read error", err)
	}
	if _, err := readReplayStateSnapshot(dir); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory snapshot error = %v, want regular file error", err)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(" \n\t"), 0o600); err != nil {
		t.Fatalf("write empty snapshot: %v", err)
	}
	if _, err := readReplayStateSnapshot(empty); err == nil || !strings.Contains(err.Error(), "--state-snapshot is empty") {
		t.Fatalf("empty snapshot error = %v, want empty error", err)
	}
}

type staticEmergencyTransport struct {
	status int
	body   string
	path   string
}

func (s *staticEmergencyTransport) Do(req *http.Request) (*http.Response, error) {
	s.path = req.URL.Path
	return &http.Response{
		StatusCode: s.status,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
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
