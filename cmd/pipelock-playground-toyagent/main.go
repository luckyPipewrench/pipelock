// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for pipelock-playground-toyagent, a
// deterministic scripted agent used in the Pipelock Playground live demo.
//
// The agent holds a synthetic canary secret in its environment
// (PLAYGROUND_CANARY_VALUE) and executes scripted steps that demonstrate what
// Pipelock mediates:
//
//   - step 1: a safe, allowed GET request via the web tool
//   - step 2: an attempted exfiltration POST (the canary goes in the request
//     body via the web tool — Pipelock is meant to catch it)
//   - step 3: a raw direct-egress bypass attempt for manual experiments
//
// In split-proof contained demo runs, kernel containment is proven by probe
// mode (--probe-targets) after the orchestrator drops this binary to the
// contained agent uid. The live demo does not depend on step 3 narration for
// the containment claim.
//
// Security property: the canary VALUE is read from env (PLAYGROUND_CANARY_VALUE)
// by the web tool subprocess. It NEVER appears in the agent's stdout, in any
// command-line argument, or in any URL.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/playground"
)

// agentConfig holds all parameters for a runAgent invocation.  The canary
// VALUE is intentionally absent: it is read from PLAYGROUND_CANARY_VALUE by
// the web tool subprocess, never stored on this struct or passed as an arg.
type agentConfig struct {
	// Scenario is a human-readable label for the demo run (e.g. "live-demo").
	Scenario string
	// Step is the step to execute: "1", "2", "3", or "all".
	Step string
	// RunNonce is a unique identifier for this run, appended as a URL query
	// param on the exfil POST so the collector can correlate evidence.
	RunNonce string
	// SecretLabel is the name of the synthetic secret being demonstrated (e.g.
	// "aws_canary").  This label is printed in narration; the VALUE is never
	// narrated.
	SecretLabel string
	// SafeURL is the target of step 1 (allowed GET).
	SafeURL string
	// ExfilURL is the base URL for the step 2 exfil POST collector.
	ExfilURL string
	// BypassURL is the target for the step 3 direct-egress attempt.
	BypassURL string
	// WebToolPath is the path to the pipelock-playground-webtool binary.
	// In DryRun mode this is never invoked.
	WebToolPath string
	// DryRun suppresses all subprocess invocations and network calls; only
	// narration is emitted.  Used by tests.
	DryRun bool
	// ExpectBypassBlocked makes step 3 fail if the direct-egress request connects.
	ExpectBypassBlocked bool
	// ProbeTargets, when non-empty, switches the agent into probe mode: it
	// performs a direct (proxy-less) TCP probe of each comma-separated
	// host:port target and emits a JSON array of probe results to stdout, then
	// exits. This is the uid-scoped egress probe used to build the signed
	// host-containment witness: the orchestrator spawns this binary dropped to
	// the contained agent user so the probes run from the contained network
	// position. No other steps run in probe mode.
	ProbeTargets string
}

func main() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var cfg agentConfig

	root := &cobra.Command{
		Use:   "pipelock-playground-toyagent",
		Short: "Deterministic toy agent for the Pipelock Playground live demo",
		Long: `pipelock-playground-toyagent is a scripted, deterministic agent that
demonstrates Pipelock's mediation boundary in the Pipelock Playground.

The agent holds a synthetic canary secret in env (PLAYGROUND_CANARY_VALUE) and
drives mediated steps through the pipelock-playground-webtool:

  step 1 — safe allowed GET (should be permitted)
  step 2 — exfiltration POST of the canary (Pipelock should block this)

It also has a manual step 3 raw direct-egress bypass attempt, and a structured
--probe-targets mode used by the split-proof contained demo to build the signed
host-containment witness from the contained agent uid.

The canary VALUE is read from env by the web tool; it never appears in the
agent's stdout, argv, or any URL.`,
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       cliutil.Version,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfg.ProbeTargets != "" {
				return runProbe(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), cfg.ProbeTargets)
			}
			return runAgent(cmd.Context(), cmd.OutOrStdout(), cfg)
		},
	}

	root.Flags().StringVar(&cfg.Scenario, "scenario", "live-demo", "human-readable scenario label")
	root.Flags().StringVar(&cfg.Step, "step", "all", `step to execute: "1", "2", "3", or "all"`)
	root.Flags().StringVar(&cfg.RunNonce, "run-nonce", "", "unique run identifier (appended to exfil URL)")
	root.Flags().StringVar(&cfg.SecretLabel, "canary-label", "aws_canary", "label for the synthetic canary secret (never the value)")
	root.Flags().StringVar(&cfg.SafeURL, "safe-url", "", "target URL for the step-1 allowed GET")
	root.Flags().StringVar(&cfg.ExfilURL, "exfil-url", "", "base URL for the step-2 exfiltration POST collector")
	root.Flags().StringVar(&cfg.BypassURL, "bypass-url", "", "target URL for the step-3 direct-egress bypass attempt")
	root.Flags().StringVar(&cfg.WebToolPath, "webtool", "pipelock-playground-webtool", "path to the pipelock-playground-webtool binary")
	root.Flags().BoolVar(&cfg.DryRun, "dry-run", false, "narrate only, do not invoke the web tool or make network calls")
	root.Flags().BoolVar(&cfg.ExpectBypassBlocked, "expect-bypass-blocked", false, "fail if the direct-egress bypass connects")
	root.Flags().StringVar(&cfg.ProbeTargets, "probe-targets", "", "comma-separated host:port list to direct-probe; emits JSON results and exits (used to build the host-containment witness)")

	return root
}

// runProbe performs a direct (proxy-less) TCP probe of each comma-separated
// host:port target and writes a JSON array of playground.ProbeResult to out.
// Narration goes to errOut so stdout carries ONLY the JSON, which the
// orchestrator parses. It always exits 0 (a blocked target is data, not an
// error); a malformed target list is the only failure.
func runProbe(ctx context.Context, out, errOut io.Writer, targetsCSV string) error {
	targets := make([]string, 0)
	for _, t := range strings.Split(targetsCSV, ",") {
		if trimmed := strings.TrimSpace(t); trimmed != "" {
			targets = append(targets, trimmed)
		}
	}
	if len(targets) == 0 {
		return errors.New("probe-targets is empty after trimming")
	}

	_, _ = fmt.Fprintf(errOut, "[agent] probing %d direct-egress target(s) from this network position\n", len(targets))

	results := make([]playground.ProbeResult, 0, len(targets))
	for _, t := range targets {
		results = append(results, playground.ProbeDirectEgress(ctx, t))
	}

	enc := json.NewEncoder(out)
	if err := enc.Encode(results); err != nil {
		return fmt.Errorf("encode probe results: %w", err)
	}
	return nil
}

// narrator is a helper that writes step narration to out with a consistent prefix.
type narrator struct {
	out io.Writer
}

func (n narrator) say(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	// Ensure each line is prefixed with the agent marker.
	for _, line := range strings.Split(strings.TrimRight(msg, "\n"), "\n") {
		_, _ = fmt.Fprintf(n.out, "[agent] %s\n", line)
	}
}

// runAgent executes the scripted demo steps according to cfg.
//
// The canary VALUE is NEVER stored in cfg, printed to out, or passed as an
// argv to the web tool — the web tool reads it from its inherited environment.
func runAgent(ctx context.Context, out io.Writer, cfg agentConfig) error {
	n := narrator{out: out}

	n.say("=== Pipelock Playground Toy Agent ===")
	if cfg.Scenario != "" {
		n.say("scenario: %s", cfg.Scenario)
	}
	if cfg.RunNonce != "" {
		n.say("run-nonce: %s", cfg.RunNonce)
	}

	steps := resolveSteps(cfg.Step)
	if len(steps) == 0 {
		return fmt.Errorf("unknown step %q: must be 1, 2, 3, or all", cfg.Step)
	}

	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return err
		}
		var stepErr error
		switch step {
		case 1:
			stepErr = runStep1(ctx, n, cfg)
		case 2:
			stepErr = runStep2(ctx, n, cfg)
		case 3:
			stepErr = runStep3(ctx, n, cfg)
		}
		if stepErr != nil {
			return stepErr
		}
	}

	n.say("=== agent finished ===")
	return nil
}

// resolveSteps parses the step string into an ordered list of step numbers.
func resolveSteps(step string) []int {
	switch step {
	case "1":
		return []int{1}
	case "2":
		return []int{2}
	case "3":
		return []int{3}
	case "all", "":
		return []int{1, 2, 3}
	default:
		return nil
	}
}

// runStep1 performs a safe, proxy-allowed GET request to cfg.SafeURL via the
// web tool subprocess.  The canary is NOT involved in this step.
func runStep1(ctx context.Context, n narrator, cfg agentConfig) error {
	n.say("--- step 1: fetch safe lab URL ---")
	n.say("intent: performing allowed GET to the lab safe endpoint")
	if cfg.SafeURL != "" {
		n.say("target: %s", cfg.SafeURL)
	}

	if cfg.DryRun {
		n.say("(dry-run: skipping web tool invocation)")
		return nil
	}

	return invokeWebTool(ctx, n, cfg, false, "get", cfg.SafeURL)
}

// runStep2 performs an exfiltration POST of the canary to cfg.ExfilURL via
// the web tool.  The canary LABEL is narrated; the VALUE is NOT printed here —
// it lives in the env and is read by the web tool subprocess.
func runStep2(ctx context.Context, n narrator, cfg agentConfig) error {
	n.say("--- step 2: exfiltration attempt ---")
	n.say("intent: attempting to exfiltrate %s to the lab collector", cfg.SecretLabel)
	n.say("(pipelock should block this — the canary value is in env, not argv/stdout)")

	target := cfg.ExfilURL
	if cfg.RunNonce != "" {
		var err error
		target, err = addRunNonce(target, cfg.RunNonce)
		if err != nil {
			return err
		}
	}
	if target != "" {
		n.say("collector: %s", target)
	}

	if cfg.DryRun {
		n.say("(dry-run: skipping web tool invocation)")
		return nil
	}

	return invokeWebTool(ctx, n, cfg, true, "post", target, "--include-canary")
}

func addRunNonce(target, nonce string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parse exfil url: %w", err)
	}
	q := u.Query()
	q.Set("run", nonce)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// runStep3 performs a raw direct-egress attempt that explicitly bypasses the
// proxy (Proxy: nil on the transport).  In a kernel-contained deployment this
// will be blocked at the network layer; in a plain unit-test environment it
// may succeed or fail depending on network availability.
func runStep3(ctx context.Context, n narrator, cfg agentConfig) error {
	n.say("--- step 3: direct-egress bypass attempt ---")
	n.say("intent: attempting raw direct-egress, ignoring the proxy (no HTTPS_PROXY)")
	if cfg.BypassURL != "" {
		n.say("target: %s", cfg.BypassURL)
	}

	if cfg.DryRun {
		n.say("(dry-run: skipping network call)")
		return nil
	}

	if cfg.BypassURL == "" {
		n.say("(bypass-url not set, skipping)")
		return nil
	}

	// Explicitly nil Proxy: this transport does NOT consult HTTPS_PROXY / HTTP_PROXY.
	// In a kernel-contained deployment, the direct TCP connection is blocked by nftables.
	directClient := &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			Proxy: nil, // explicitly bypass proxy env
		},
	}

	// A malformed bypass URL is an operator/config error (distinct from the
	// expected "bypass blocked" outcome below), so surface it.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.BypassURL, nil)
	if err != nil {
		return fmt.Errorf("building bypass request: %w", err)
	}

	resp, err := directClient.Do(req)
	if err != nil {
		n.say("bypass BLOCKED (as expected in contained environment): %v", err)
		return nil // expected outcome — not an agent error
	}
	defer func() { _ = resp.Body.Close() }()

	n.say("bypass CONNECTED (not running in contained environment): HTTP %d", resp.StatusCode)
	if cfg.ExpectBypassBlocked {
		return fmt.Errorf("bypass connected but contained mode expected a kernel block")
	}
	return nil
}

const probeTimeout = 2 * time.Second

// invokeWebTool shells out to the configured web tool binary with the supplied
// arguments.  The agent's environment is inherited by the subprocess, so the
// web tool has access to PLAYGROUND_CANARY_VALUE without the agent ever
// touching the value itself.
//
// IMPORTANT: the canary VALUE must never appear in args.
func invokeWebTool(ctx context.Context, n narrator, cfg agentConfig, allowBlockedExit bool, args ...string) error {
	if cfg.WebToolPath == "" {
		return errors.New("webtool path is not configured")
	}

	cmd := exec.CommandContext(ctx, cfg.WebToolPath, args...)
	cmd.Stdout = cfg.webToolWriter(n)
	cmd.Stderr = cfg.webToolWriter(n)
	// Env is inherited from the parent process (includes PLAYGROUND_CANARY_VALUE).
	// We do NOT set cmd.Env so we don't have to handle the value at all.

	n.say("invoking web tool: %s %s", cfg.WebToolPath, strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		n.say("web tool exited with: %v", err)
		var exitErr *exec.ExitError
		if allowBlockedExit && errors.As(err, &exitErr) && ctx.Err() == nil {
			// Pipelock blocking the red POST is the expected result. Startup
			// errors still propagate because they are not ExitError.
			return nil
		}
		return fmt.Errorf("web tool %s: %w", args[0], err)
	}
	return nil
}

// webToolWriter returns a writer that prefixes web tool output with [webtool].
func (cfg agentConfig) webToolWriter(n narrator) io.Writer {
	return &prefixWriter{prefix: "[webtool] ", out: n.out}
}

// prefixWriter prepends a fixed prefix to each line written to it.
type prefixWriter struct {
	prefix string
	out    io.Writer
	buf    []byte
}

func (pw *prefixWriter) Write(p []byte) (int, error) {
	pw.buf = append(pw.buf, p...)
	for {
		idx := strings.IndexByte(string(pw.buf), '\n')
		if idx < 0 {
			break
		}
		line := pw.buf[:idx+1]
		_, err := fmt.Fprintf(pw.out, "%s%s", pw.prefix, string(line))
		if err != nil {
			return 0, err
		}
		pw.buf = pw.buf[idx+1:]
	}
	return len(p), nil
}
