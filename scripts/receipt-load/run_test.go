// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func smallOptions(t *testing.T, binary string) options {
	t.Helper()
	return options{
		binary: binary, out: t.TempDir(), rules: rulesEmpty, requests: 40, warmup: 10, concurrency: 4,
		chains: 1, seed: 1, window: 50 * time.Millisecond, shutdownTimeout: 20 * time.Second,
	}
}

func readResult(t *testing.T, dir string) result {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "result.json")))
	if err != nil {
		t.Fatalf("result.json was not written: %v", err)
	}
	var r result
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("result.json is not valid: %v", err)
	}
	return r
}

func hasReason(reasons []string, substr string) bool {
	for _, r := range reasons {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}

func TestShutdownFailureStillWritesResult(t *testing.T) {
	opt := smallOptions(t, newFakePipelock(t, "shutdownfail"))
	res, err := runMode(context.Background(), opt, modeOff)
	if err != nil {
		t.Fatalf("runMode: %v", err)
	}
	got := readResult(t, filepath.Join(opt.out, modeOff))
	if got.Integrity.Verdict != verdictFail || got.Integrity.Shutdown.Clean || !hasReason(got.Integrity.Reasons, "shutdown") {
		t.Fatalf("integrity = %+v, want a failed verdict naming the shutdown", got.Integrity)
	}
	// The two verdicts are independent: the load itself was sound.
	if got.Performance.Verdict != perfMeasured || got.Performance.RequestsPerSecond <= 0 {
		t.Fatalf("performance = %+v, want a valid measurement despite the shutdown failure", got.Performance)
	}
	if res.Integrity.Verdict != got.Integrity.Verdict {
		t.Fatal("returned result differs from result.json")
	}
	if code := runModes(context.Background(), smallOptions(t, newFakePipelock(t, "shutdownfail")), []string{modeOff}); code != exitIntegrity {
		t.Fatalf("exit code = %d, want %d", code, exitIntegrity)
	}
}

func TestShutdownHangIsKilledAndReported(t *testing.T) {
	opt := smallOptions(t, newFakePipelock(t, "hang"))
	opt.shutdownTimeout = 300 * time.Millisecond
	if _, err := runMode(context.Background(), opt, modeOff); err != nil {
		t.Fatal(err)
	}
	got := readResult(t, filepath.Join(opt.out, modeOff))
	if got.Integrity.Verdict != verdictFail || !hasReason(got.Integrity.Reasons, "ignored SIGTERM") {
		t.Fatalf("integrity = %+v, want a hung proxy to be killed and reported", got.Integrity)
	}
}

func TestSetupFailureStillWritesResult(t *testing.T) {
	opt := smallOptions(t, newFakePipelock(t, "initfail"))
	res, err := runMode(context.Background(), opt, modeBest)
	if err == nil || res == nil {
		t.Fatalf("runMode = %v, %v, want a result and an error", res, err)
	}
	got := readResult(t, filepath.Join(opt.out, modeBest))
	if got.Integrity.Verdict != verdictFail || got.Performance.Verdict != perfInvalid || !hasReason(got.Integrity.Reasons, "pipelock init") {
		t.Fatalf("result after setup failure = %+v", got)
	}
}

func TestVerificationFailureStillWritesResult(t *testing.T) {
	opt := smallOptions(t, newFakePipelock(t, "verifyfail"))
	if _, err := runMode(context.Background(), opt, modeBest); err != nil {
		t.Fatal(err)
	}
	got := readResult(t, filepath.Join(opt.out, modeBest))
	if got.Integrity.Verdict != verdictFail || !got.Integrity.Verify.Ran || got.Integrity.Verify.Exit != 1 || !hasReason(got.Integrity.Reasons, "verify-receipt exited 1") {
		t.Fatalf("integrity = %+v, want the verifier failure recorded", got.Integrity)
	}
}

// A proxy that records nothing must fail integrity in the modes that require a
// recorder, even though it served every request perfectly.
func TestSilentRecorderFailsIntegrityNotPerformance(t *testing.T) {
	opt := smallOptions(t, newFakePipelock(t, "ok"))
	if _, err := runMode(context.Background(), opt, modeBest); err != nil {
		t.Fatal(err)
	}
	got := readResult(t, filepath.Join(opt.out, modeBest))
	if got.Integrity.Verdict != verdictFail || got.Performance.Verdict != perfMeasured {
		t.Fatalf("integrity=%s performance=%s, want fail and measured", got.Integrity.Verdict, got.Performance.Verdict)
	}
	if code := runModes(context.Background(), smallOptions(t, newFakePipelock(t, "ok")), []string{modeBest}); code != exitIntegrity {
		t.Fatalf("exit code = %d, want %d", code, exitIntegrity)
	}
}

func TestCleanOffRunPassesBothVerdicts(t *testing.T) {
	opt := smallOptions(t, newFakePipelock(t, "ok"))
	if code := runModes(context.Background(), opt, []string{modeOff}); code != exitOK {
		t.Fatalf("exit code = %d, want 0", code)
	}
	got := readResult(t, filepath.Join(opt.out, modeOff))
	if got.Integrity.Verdict != verdictPass || got.Performance.Verdict != perfMeasured {
		t.Fatalf("result = %+v", got)
	}
	if got.Requests != 40 || got.WarmupRequests != 10 || got.Performance.Allowed+got.Performance.Blocked != 40 {
		t.Fatalf("warmup must not count toward the measured requests: %+v", got.Performance)
	}
	if got.Performance.Latency.Samples != 40 || len(got.Performance.Windows.Rates) == 0 {
		t.Fatalf("performance = %+v", got.Performance)
	}
}

func TestPerformanceFailureHasItsOwnExitCode(t *testing.T) {
	opt := smallOptions(t, newFakePipelock(t, "badbody"))
	code := runModes(context.Background(), opt, []string{modeOff})
	got := readResult(t, filepath.Join(opt.out, modeOff))
	if got.Performance.Verdict != perfInvalid || got.Performance.BodyReadErrors == 0 {
		t.Fatalf("performance = %+v, want body read errors to invalidate it", got.Performance)
	}
	if got.Integrity.Verdict != verdictPass || code != exitPerf {
		t.Fatalf("integrity=%s exit=%d, want pass and %d", got.Integrity.Verdict, code, exitPerf)
	}
}

func TestInterruptedRunFailsClosed(t *testing.T) {
	opt := smallOptions(t, newFakePipelock(t, "ok"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runMode(ctx, opt, modeOff); err != nil {
		t.Logf("runMode: %v", err)
	}
	got := readResult(t, filepath.Join(opt.out, modeOff))
	if got.Integrity.Verdict != verdictFail && got.Performance.Verdict != perfInvalid {
		t.Fatalf("an interrupted run reported success: %+v", got)
	}
}

// real proxy ----------------------------------------------------------------

func TestRealRunHoldsIntegrity(t *testing.T) {
	bin := realPipelock(t)
	for _, chains := range []int{1, 2} {
		for _, mode := range []string{modeOff, modeBest, modeRequired} {
			t.Run(mode+"-chains-"+strconv.Itoa(chains), func(t *testing.T) {
				opt := smallOptions(t, bin)
				opt.requests, opt.warmup, opt.concurrency, opt.chains = 100, 20, 8, chains
				res, err := runMode(context.Background(), opt, mode)
				if err != nil {
					t.Fatal(err)
				}
				if res.Integrity.Verdict != verdictPass || res.Integrity.ReceiptMissing != 0 {
					t.Fatalf("integrity = %+v", res.Integrity)
				}
				if res.Performance.Verdict != perfMeasured {
					t.Fatalf("performance = %+v", res.Performance)
				}
				name := mode
				if chains > 1 {
					name = "chains-2-" + mode
				}
				got := readResult(t, filepath.Join(opt.out, name))
				if got.Inputs.Config.SHA256 == "" || got.Inputs.Binary.SHA256 == "" || got.Inputs.Rules.Mode != rulesEmpty || len(got.Inputs.Rules.Files) != 0 {
					t.Fatalf("inputs not pinned: %+v", got.Inputs)
				}
				if len(got.Inputs.Config.ExternalPaths) != 0 {
					t.Fatalf("config points outside the run directory: %v", got.Inputs.Config.ExternalPaths)
				}
				if len(got.Performance.Windows.Rates) == 0 || got.Performance.Windows.MedianRPS <= 0 {
					t.Fatalf("no window rates: %+v", got.Performance.Windows)
				}
				if mode == modeRequired {
					allowed := got.Performance.Allowed + res.WarmupRequests - warmupBlocked(res)
					if k := got.Integrity.Kinds["v1_intent"]; k.Observed != allowed || got.Integrity.Kinds["v1_outcome"].Observed != allowed {
						t.Fatalf("intent=%+v outcome=%+v, want %d each", k, got.Integrity.Kinds["v1_outcome"], allowed)
					}
				}
			})
		}
	}
}

func warmupBlocked(r *result) int {
	plan := newWorkload(r.Inputs.Workload.Seed, r.WarmupRequests, r.Requests)
	n := 0
	for slot := range r.WarmupRequests {
		if plan.blocked(slot) {
			n++
		}
	}
	return n
}

// The key must be readable in the receipts the real proxy writes, and the
// credential that rides along with blocked requests must not be.
func TestWorkloadKeySurvivesTheRealProxy(t *testing.T) {
	bin := realPipelock(t)
	opt := smallOptions(t, bin)
	opt.requests, opt.warmup = 60, 10
	res, err := runMode(context.Background(), opt, modeBest)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(opt.out, modeBest, "recorder")
	var text strings.Builder
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "evidence-") {
			raw, err := os.ReadFile(filepath.Clean(filepath.Join(dir, e.Name())))
			if err != nil {
				t.Fatal(err)
			}
			text.Write(raw)
		}
	}
	evidence := text.String()
	plan := newWorkload(opt.seed, opt.warmup, opt.requests)
	plan.runNonce = strings.TrimPrefix(res.Inputs.Workload.Tag, plan.tag()+"-r")
	for slot := range plan.total() {
		if !strings.Contains(evidence, workloadKeyParam+"="+plan.key(slot)) {
			t.Fatalf("key %s was not found in any receipt", plan.key(slot))
		}
	}
	if strings.Contains(evidence, fakeToken) {
		t.Fatal("the synthetic credential reached the evidence files")
	}
	obs, err := scanRecorder(dir, plan, strings.SplitN(extractSinkHost(t, evidence), "/", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	for slot := range plan.total() {
		want := expectedFor(modeBest, plan.blocked(slot))
		if obs.slots[slot].counts != want {
			t.Fatalf("slot %d (%s): receipts %v, want %v", slot, plan.key(slot), obs.slots[slot].counts, want)
		}
	}
}

// extractSinkHost finds the sink address a recorded workload target points at.
func extractSinkHost(t *testing.T, evidence string) string {
	t.Helper()
	i := strings.Index(evidence, `"target":"http://`)
	if i < 0 {
		t.Fatal("no request target in the evidence")
	}
	rest := evidence[i+len(`"target":"http://`):]
	return rest[:strings.IndexAny(rest, `/"`)]
}

// A bundle in the default per-user locations must not load: the harness pins
// HOME and every XDG variable, and rules_dir is explicit.
func TestHostileHomeBundlesDoNotLoad(t *testing.T) {
	bin := realPipelock(t)
	root := t.TempDir()
	home := filepath.Join(root, "hostile-home")
	xdgData := filepath.Join(root, "hostile-xdg-data")
	for _, bundle := range []string{
		filepath.Join(home, ".local", "share", "pipelock", "rules", "hostile-home-bundle"),
		filepath.Join(xdgData, "pipelock", "rules", "hostile-xdg-bundle"),
	} {
		if err := os.MkdirAll(bundle, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundle, "bundle.yaml"), []byte("format_version: 1\nname: x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", xdgData)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "hostile-xdg-config"))
	t.Setenv("PIPELOCK_HOME", filepath.Join(root, "hostile-pipelock-home"))
	t.Setenv("RECEIPT_LOAD_CANARY_SECRET", "hostile-canary-secret")

	opt := smallOptions(t, bin)
	opt.requests, opt.warmup = 30, 5
	res, err := runMode(context.Background(), opt, modeOff)
	if err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(opt.out, modeOff)
	log, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "proxy.log")))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"hostile-home-bundle", "hostile-xdg-bundle", "DEGRADED", "hostile-home", "hostile-xdg"} {
		if strings.Contains(string(log), leak) {
			t.Fatalf("proxy.log mentions %q: the host profile leaked into the run\n%s", leak, log)
		}
	}
	if res.Integrity.Verdict != verdictPass || len(res.Inputs.Rules.ProxyLogLines) != 0 {
		t.Fatalf("integrity=%+v rules=%+v", res.Integrity, res.Inputs.Rules)
	}
	if !strings.HasPrefix(res.Inputs.Env.Pinned["HOME"], "home") || res.Inputs.Env.Passed["RECEIPT_LOAD_CANARY_SECRET"] != "" {
		t.Fatalf("env = %+v", res.Inputs.Env)
	}

	// Control: the same config with rules_dir left empty, run with the hostile
	// environment, does find the bundle. Without this the test above could pass
	// against a fixture that never tempted the proxy.
	cfgPath := filepath.Join(runDir, "pipelock.yaml")
	cfg, err := os.ReadFile(filepath.Clean(cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	unpinned := strings.ReplaceAll(string(cfg), "rules_dir: "+filepath.Join(runDir, "rules"), `rules_dir: ""`)
	if unpinned == string(cfg) {
		t.Fatal("could not blank rules_dir for the control run")
	}
	controlCfg := filepath.Join(root, "control.yaml")
	if err := os.WriteFile(controlCfg, []byte(unpinned), 0o600); err != nil {
		t.Fatal(err)
	}
	port, err := freePort(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	addr := "127.0.0.1:" + strconv.Itoa(port)
	controlLog, err := os.Create(filepath.Clean(filepath.Join(root, "control.log")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = controlLog.Close() }()
	cmd := exec.CommandContext(context.Background(), bin, "run", "--config", controlCfg, "--home", filepath.Join(root, "control-home"), "--listen", addr) //nolint:gosec // test binary built from this repo
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "XDG_DATA_HOME=" + xdgData}
	cmd.Dir = root
	cmd.Stdout, cmd.Stderr = controlLog, controlLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	if err := awaitProxy(context.Background(), addr, exited); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	<-exited
	control, _ := os.ReadFile(filepath.Clean(filepath.Join(root, "control.log")))
	if !strings.Contains(string(control), "hostile-home-bundle") && !strings.Contains(string(control), "hostile-xdg-bundle") {
		t.Fatalf("the control run did not see the hostile bundle, so the fixture proves nothing:\n%s", control)
	}
}

// A --rules directory is loaded, is recorded file by file, and is not touched.
func TestRulesDirectoryModeRecordsBundleHashes(t *testing.T) {
	bin := realPipelock(t)
	src := filepath.Join(t.TempDir(), "rules")
	bundle := filepath.Join(src, "stub-bundle")
	if err := os.MkdirAll(bundle, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "bundle.yaml"), []byte("format_version: 1\nname: stub-bundle\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opt := smallOptions(t, bin)
	opt.rules, opt.requests, opt.warmup = src, 30, 5
	res, err := runMode(context.Background(), opt, modeOff)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Inputs.Rules
	if r.Mode != "dir" || len(r.Files) != 1 || r.Files[0].Path != "stub-bundle/bundle.yaml" || len(r.Files[0].SHA256) != 64 {
		t.Fatalf("rules = %+v", r)
	}
	// The proxy was pointed at the copy, and said so.
	if len(r.ProxyLogLines) == 0 {
		t.Fatal("proxy.log has no line about the bundle it was given")
	}
	if entries, _ := os.ReadDir(bundle); len(entries) != 1 {
		t.Fatalf("source rules directory was modified: %d entries", len(entries))
	}
}
