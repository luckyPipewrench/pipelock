// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// ErrContainmentNotWired is returned when Contained=true but no containment
// hook has been registered via SetContainmentHook. Task 7 will wire the real
// implementation; until then, contained mode visibly refuses to run rather
// than silently falling back to uncontained.
var ErrContainmentNotWired = errors.New(
	"playground: containment mode requested but no containment hook is wired " +
		"(Task 7 will provide the kernel-containment implementation)")

// ContainmentHook is the interface Task 7 must implement to wire kernel
// containment into the demo orchestrator. The orchestrator calls Setup before
// the live run starts and Teardown during Reset/Close.
//
//	Setup: prepare nft chains, agent user, proxy routing. Returns nil on success.
//	Teardown: remove nft chains, kill agent processes, clean state.
type ContainmentHook interface {
	Setup(ctx context.Context, opts DemoOpts) error
	Teardown(runDir string) error
}

// containmentSetupHook is the pluggable containment seam. Nil means
// containment is not available. Task 7 calls SetContainmentHook to wire it.
// Protected by containmentMu for test-time concurrent access.
var (
	containmentSetupHook ContainmentHook
	containmentMu        sync.RWMutex
)

// SetContainmentHook registers the containment implementation. Call this from
// Task 7's init or setup code. Passing nil unregisters (reverts to uncontained-only).
func SetContainmentHook(hook ContainmentHook) {
	containmentMu.Lock()
	defer containmentMu.Unlock()
	containmentSetupHook = hook
}

// getContainmentHook returns the current containment hook (nil if not wired).
func getContainmentHook() ContainmentHook {
	containmentMu.RLock()
	defer containmentMu.RUnlock()
	return containmentSetupHook
}

// DemoOpts configures a full demo run (run/reset/fallback).
type DemoOpts struct {
	// Contained selects kernel-containment mode. When false, the demo runs
	// in uncontained mode (MCP-wrapped only, no kernel enforcement). When
	// true, the containment hook must be wired via SetContainmentHook.
	Contained bool

	// ScenarioID selects the scenario from DefaultScenarios.
	ScenarioID string

	// RunNonce is the unique identifier for this run. When empty, a fixed
	// demo nonce is used (suitable for demos; real runs should supply a
	// high-entropy nonce).
	RunNonce string

	// RunDir is the directory where the run artifacts (packet, manifest,
	// witness) are written. Must be writable.
	RunDir string

	// Color enables ANSI color in the mediator timeline output.
	Color bool

	// OrchestratorKeyPath, when non-empty, points at a hex-encoded ed25519
	// private key used as the run's orchestrator (trust-root) signer instead of
	// a freshly generated ephemeral key. This is how a run signs under the
	// stable published demo key so "verify with our published key" is real. An
	// empty value keeps the ephemeral per-run key (the dev default).
	OrchestratorKeyPath string
}

// defaultDemoNonce is used when DemoOpts.RunNonce is empty.
const defaultDemoNonce = "playground-demo-run"

// defaultScenarioID is the scenario used when DemoOpts.ScenarioID is empty.
const defaultScenarioID = LiveDemoScenarioID

// RunDemo drives a full live demo: preflight, start infrastructure, run the
// toy agent, collect evidence, render the mediator timeline, assemble the
// audit packet, verify, and print the audience verify command.
//
// In uncontained mode (the default, fully working today), the demo runs the
// toy agent through the proxy without kernel containment. In contained mode,
// it delegates to the containment hook (Task 7) for nft/agent-user setup.
//
// Returns the VerifyReport so the caller can check .OK and set the exit code.
func RunDemo(ctx context.Context, out io.Writer, opts DemoOpts) (VerifyReport, error) {
	// --- Defaults ---
	if opts.RunNonce == "" {
		opts.RunNonce = defaultDemoNonce
	}
	if opts.ScenarioID == "" {
		opts.ScenarioID = defaultScenarioID
	}

	// --- Preflight ---
	if err := Preflight(opts); err != nil {
		return VerifyReport{}, fmt.Errorf("preflight: %w", err)
	}

	// --- Containment setup (Task 7 seam) ---
	if opts.Contained {
		hook := getContainmentHook()
		if hook == nil {
			return VerifyReport{}, ErrContainmentNotWired
		}
		if err := hook.Setup(ctx, opts); err != nil {
			return VerifyReport{}, fmt.Errorf("containment setup: %w", err)
		}
	}

	// --- Build binaries into a temp dir ---
	binDir, err := os.MkdirTemp("", "playground-demo-bins-*")
	if err != nil {
		return VerifyReport{}, fmt.Errorf("bin temp dir: %w", err)
	}
	// Contained mode executes these binaries after dropping to the
	// pipelock-agent user, so the temp dir must be cross-user traversable.
	if err := os.Chmod(binDir, 0o755); err != nil {
		return VerifyReport{}, fmt.Errorf("bin temp dir permissions: %w", err)
	}
	defer func() { _ = os.RemoveAll(binDir) }()

	agentBin, webtoolBin, err := buildDemoBinaries(ctx, binDir)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("build binaries: %w", err)
	}

	// --- Timeline events (narration first) ---
	var timeline []MediatorEvent

	timeline = append(timeline, NarrationEvent(
		fmt.Sprintf("Starting demo run: scenario=%s nonce=%s contained=%v",
			opts.ScenarioID, safeNonce(opts.RunNonce), opts.Contained)))

	// --- Start live run ---
	lr, err := StartLiveRun(ctx, LiveRunOpts{
		Contained:           opts.Contained,
		ScenarioID:          opts.ScenarioID,
		RunNonce:            opts.RunNonce,
		ToyAgentBin:         agentBin,
		WebToolBin:          webtoolBin,
		OrchestratorKeyPath: opts.OrchestratorKeyPath,
	})
	if err != nil {
		return VerifyReport{}, fmt.Errorf("start live run: %w", err)
	}
	defer lr.Close()

	// --- Run agent steps ---
	timeline = append(timeline, NarrationEvent("Step 1: Safe GET request (expect ALLOW)"))

	if err := lr.RunSteps(1); err != nil {
		return VerifyReport{}, fmt.Errorf("step 1: %w", err)
	}

	timeline = append(timeline, NarrationEvent("Step 2: Exfiltration POST with canary (expect BLOCK)"))

	if err := lr.RunSteps(2); err != nil {
		return VerifyReport{}, fmt.Errorf("step 2: %w", err)
	}

	// Under the split-proof model the direct-egress bypass is no longer a single
	// in-band agent step; it is proven separately by the host-containment
	// witness (probes run from the contained network position), which
	// AssembleAndVerify produces for contained runs.

	// --- Assemble + verify ---
	rep, err := lr.AssembleAndVerify(opts.RunDir)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("assemble and verify: %w", err)
	}

	// --- Build evidence-based timeline events ---
	evidenceFile, evidenceErr := singleLiveEvidenceFile(lr.evidenceDir)
	if evidenceErr == nil {
		evEvents, evErr := MediatorEventsFromEvidence(evidenceFile)
		if evErr == nil {
			timeline = append(timeline, evEvents...)
		}
	}

	// --- Witness event ---
	witnessPath := filepath.Join(opts.RunDir, witnessFile)
	cleanWitnessPath := filepath.Clean(witnessPath)
	wData, wErr := os.ReadFile(cleanWitnessPath)
	if wErr == nil {
		var w Witness
		if json.Unmarshal(wData, &w) == nil {
			timeline = append(timeline, WitnessEvent(w))
		}
	}

	// --- Containment event (contained mode only) ---
	// Render the event from the verifier's host-containment checks, not a
	// hardcoded assumption or an unverified parse of the witness file. The raw
	// witness only supplies display detail after verification has accepted it.
	if opts.Contained {
		verified := checksPassed(rep,
			checkHostContainSig,
			checkHostContainBinding,
			checkHostContainEnforced,
		)
		detail := "host-containment witness did not pass offline verification"
		hcwPath := filepath.Clean(filepath.Join(opts.RunDir, hostContainmentWitnessFile))
		if hcwData, hcwErr := os.ReadFile(hcwPath); hcwErr == nil {
			var hcw HostContainmentWitness
			if json.Unmarshal(hcwData, &hcw) == nil && verified {
				detail = fmt.Sprintf("%d direct-egress routes blocked for %s; control target reachable for operator",
					len(hcw.AgentProbes), hcw.AgentUser)
			}
		}
		timeline = append(timeline, ContainmentEvent(verified, detail))
	}

	// --- Render timeline ---
	_, _ = fmt.Fprintln(out)
	RenderMediator(out, timeline, opts.Color)
	_, _ = fmt.Fprintln(out)

	// --- Print verify summary ---
	renderVerifySummary(out, rep, opts.RunDir)

	return rep, nil
}

func checksPassed(rep VerifyReport, names ...string) bool {
	passed := make(map[string]bool, len(rep.Checks))
	for _, check := range rep.Checks {
		passed[check.Name] = check.OK
	}
	for _, name := range names {
		if !passed[name] {
			return false
		}
	}
	return true
}

// renderVerifySummary prints the VerifyReport checks and the audience verify
// command to out.
func renderVerifySummary(out io.Writer, rep VerifyReport, runDir string) {
	_, _ = fmt.Fprintln(out, strings.Repeat("=", 72))
	_, _ = fmt.Fprintln(out, "VERIFICATION RESULTS")
	_, _ = fmt.Fprintln(out, strings.Repeat("-", 72))

	for _, c := range rep.Checks {
		status := "PASS"
		if !c.OK {
			status = "FAIL"
		}
		_, _ = fmt.Fprintf(out, "[%s] %s", status, c.Name)
		if c.Reason != "" {
			_, _ = fmt.Fprintf(out, " -- %s", c.Reason)
		}
		_, _ = fmt.Fprintln(out)
	}

	_, _ = fmt.Fprintln(out)
	if rep.OK {
		_, _ = fmt.Fprintf(out, "VERIFY OK  run_nonce=%s observed=%d\n", rep.RunNonce, rep.ObservedCount)
	} else {
		_, _ = fmt.Fprintln(out, "VERIFY FAILED: one or more checks did not pass")
	}

	// Print the audience verify command so anyone can re-check offline.
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "To verify this run independently:")
	_, _ = fmt.Fprintf(out, "  pipelock-playground-demo verify %s --orchestrator-key %s\n",
		filepath.Clean(runDir), rep.OrchestratorKey)
}

// Reset clears all state from a previous run in runDir, making it safe to
// reuse for a new run. It is idempotent: calling Reset on an empty or
// nonexistent dir succeeds. Calling it 3x in a row before new runs must
// produce 3 clean runs.
//
// Containment teardown (nft chains, agent processes) is a Task 7 concern;
// a marked hook is called when wired.
func Reset(runDir string) error {
	cleanDir := filepath.Clean(runDir)

	// If the dir exists, remove its contents entirely. This is the simplest
	// way to guarantee no stale state (evidence, packets, manifests, witnesses)
	// bleeds into a new run.
	if _, err := os.Stat(cleanDir); err == nil {
		if err := os.RemoveAll(cleanDir); err != nil {
			return fmt.Errorf("reset: cannot remove %q: %w", runDir, err)
		}
	}

	// Recreate the dir fresh.
	if err := os.MkdirAll(cleanDir, 0o750); err != nil {
		return fmt.Errorf("reset: cannot create %q: %w", runDir, err)
	}

	// Containment teardown hook (Task 7).
	if hook := getContainmentHook(); hook != nil {
		if err := hook.Teardown(runDir); err != nil {
			return fmt.Errorf("reset: containment teardown: %w", err)
		}
	}

	return nil
}

// Fallback replays a pre-recorded run directory with a visible REPLAY
// watermark, the packet hash, and the verifier command. It re-runs
// VerifyRun to confirm the recorded evidence is still valid.
//
// The output is clearly labeled as a replay so the audience knows they are
// not watching a live run.
func Fallback(out io.Writer, recordedRunDir, orchestratorKeyHex string) (VerifyReport, error) {
	cleanDir := filepath.Clean(recordedRunDir)

	// --- REPLAY watermark ---
	_, _ = fmt.Fprintln(out, strings.Repeat("*", 72))
	_, _ = fmt.Fprintln(out, "***                    REPLAY MODE                              ***")
	_, _ = fmt.Fprintln(out, "*** This is a replay of a pre-recorded run, NOT a live demo.    ***")
	_, _ = fmt.Fprintln(out, strings.Repeat("*", 72))
	_, _ = fmt.Fprintln(out)

	// --- Compute and print packet hash ---
	packetDir := filepath.Join(cleanDir, packetSubdir)
	packetHash, err := hashDir(packetDir)
	if err != nil {
		_, _ = fmt.Fprintf(out, "WARNING: cannot compute packet hash: %v\n", err)
	} else {
		_, _ = fmt.Fprintf(out, "Packet hash: %s\n", packetHash)
	}
	_, _ = fmt.Fprintln(out)

	// --- Rebuild mediator timeline from evidence ---
	evidencePattern := filepath.Join(packetDir, "evidence.jsonl")
	if _, statErr := os.Stat(evidencePattern); statErr == nil {
		evEvents, evErr := MediatorEventsFromEvidence(evidencePattern)
		if evErr == nil && len(evEvents) > 0 {
			RenderMediator(out, evEvents, false)
			_, _ = fmt.Fprintln(out)
		}
	}

	// --- Verify ---
	rep, err := VerifyRun(cleanDir, orchestratorKeyHex)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("fallback verify: %w", err)
	}

	// --- Print verify summary ---
	renderVerifySummary(out, rep, recordedRunDir)

	return rep, nil
}

// buildDemoBinaries compiles the toy agent and webtool into binDir.
// This is the orchestrator's internal build step; the LiveRun itself
// receives the paths.
func buildDemoBinaries(ctx context.Context, binDir string) (agentBin, webtoolBin string, err error) {
	agentBin = filepath.Join(binDir, "toyagent")
	webtoolBin = filepath.Join(binDir, "webtool")

	// Find repo root by walking up from the current working directory.
	repoRoot, err := findRepoRoot()
	if err != nil {
		return "", "", fmt.Errorf("find repo root: %w", err)
	}

	// Build toy agent.
	if err := goBuild(ctx, repoRoot, "./cmd/pipelock-playground-toyagent", agentBin); err != nil {
		return "", "", fmt.Errorf("build toyagent: %w", err)
	}

	// Build web tool.
	if err := goBuild(ctx, repoRoot, "./cmd/pipelock-playground-webtool", webtoolBin); err != nil {
		return "", "", fmt.Errorf("build webtool: %w", err)
	}

	return agentBin, webtoolBin, nil
}

// findRepoRoot walks up from cwd looking for go.mod.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find go.mod walking up from cwd")
		}
		dir = parent
	}
}

// goBuild runs `go build -o outPath pkg` in the given dir.
func goBuild(ctx context.Context, dir, pkg, outPath string) error {
	// All arguments are operator-controlled paths from DemoOpts, not untrusted input.
	args := []string{"build", "-o", outPath, pkg}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w\n%s", pkg, err, out)
	}
	return nil
}

// hashDir computes a sha256 hash over the concatenated contents of all files
// in dir (sorted by path), producing a stable content fingerprint.
func hashDir(dir string) (string, error) {
	cleanDir := filepath.Clean(dir)
	h := sha256.New()
	err := filepath.Walk(cleanDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		cleanPath := filepath.Clean(path)
		data, err := os.ReadFile(cleanPath)
		if err != nil {
			return err
		}
		_, _ = h.Write([]byte(path))
		_, _ = h.Write(data)
		return nil
	})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
