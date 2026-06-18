// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for pipelock-playground-live, the gated
// live-chat playground server. A visitor redeems an invite code for a
// short-lived session, types to a deterministic agent, and watches Pipelock
// mediate the agent's actual requests in real time over a signed-decision SSE
// stream. Every control is fail-closed: no code -> no session; over capacity ->
// refuse; if kernel containment cannot be established, the session is refused
// rather than run uncontained while presenting as live.
//
// Subcommands:
//
//	serve        Run the live-chat HTTP/SSE server.
//	gen-secret   Print a fresh gate-signing secret.
//	gen-code     Print a fresh random invite code.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "pipelock-playground-live",
		Short:         "Gated live-chat playground server",
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       cliutil.Version,
	}
	root.AddCommand(newServeCmd(), newGenSecretCmd(), newGenCodeCmd())
	return root
}

type serveFlags struct {
	listen                string
	codes                 []string
	maxPerCode            int
	concurrency           int
	requireContainment    bool
	dev                   bool
	orchestratorKey       string
	toyAgentBin           string
	webToolBin            string
	sessionTTL            time.Duration
	maxInputBytes         int
	ipRate                float64
	ipBurst               float64
	codeRate              float64
	codeBurst             float64
	allowOrigin           string
	trustForwardedFor     bool
	secretB64             string
	secretFile            string
	staticDir             string
	llmAgentBin           string
	modelBaseURL          string
	model                 string
	modelSecretFile       string
	modelMaxSteps         int
	modelTimeout          time.Duration
	dailyTurnBudget       int
	maxMessagesPerSession int
}

// defaultMaxPerCode is the safe default lifetime session budget per invite code.
// Unlimited reuse (0) must be opted into explicitly so a leaked code cannot mint
// sessions forever.
const defaultMaxPerCode = 25

func newServeCmd() *cobra.Command {
	f := &serveFlags{}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the live-chat server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.listen, "listen", "127.0.0.1:8099", "address to listen on (use 0.0.0.0:PORT for LAN/Tailscale)")
	fl.StringArrayVar(&f.codes, "code", nil, "invite code (repeatable); in --dev one is generated if omitted")
	fl.IntVar(&f.maxPerCode, "max-per-code", defaultMaxPerCode, "max sessions per invite code (0 = unlimited, opt-in)")
	fl.IntVar(&f.concurrency, "concurrency", 3, "global cap on simultaneous live sessions")
	fl.BoolVar(&f.requireContainment, "require-containment", true, "refuse sessions unless kernel containment is established")
	fl.BoolVar(&f.dev, "dev", false, "DEV ONLY: run uncontained (disables --require-containment); never use for public exposure")
	fl.StringVar(&f.orchestratorKey, "orchestrator-key", "", "path to the published demo signing key (empty = ephemeral per-run key)")
	fl.StringVar(&f.toyAgentBin, "toyagent-bin", "", "toy-agent binary path (needed for the contained host-containment witness)")
	fl.StringVar(&f.webToolBin, "webtool-bin", "", "web-tool binary path (needed for the contained host-containment witness)")
	fl.DurationVar(&f.sessionTTL, "session-ttl", 90*time.Second, "per-session wall-clock cap")
	fl.IntVar(&f.maxInputBytes, "max-input-bytes", 2048, "per-message input size cap")
	fl.Float64Var(&f.ipRate, "ip-rate", 0.5, "per-IP sustained request rate (tokens/sec)")
	fl.Float64Var(&f.ipBurst, "ip-burst", 5, "per-IP burst")
	fl.Float64Var(&f.codeRate, "code-rate", 0.5, "per-code sustained request rate (tokens/sec)")
	fl.Float64Var(&f.codeBurst, "code-burst", 10, "per-code burst")
	fl.StringVar(&f.allowOrigin, "allow-origin", "", "Access-Control-Allow-Origin for the browser (e.g. https://pipelab.org)")
	fl.BoolVar(&f.trustForwardedFor, "trust-forwarded-for", false, "read client IP from X-Forwarded-For (only behind a trusted proxy/CDN)")
	fl.StringVar(&f.secretFile, "secret-file", "", "path to a file holding the base64 gate-signing secret (preferred: keeps it out of argv/shell history)")
	fl.StringVar(&f.secretB64, "secret", "", "base64 gate-signing secret (default: generated; prefer --secret-file to avoid argv exposure)")
	fl.StringVar(&f.staticDir, "static-dir", "", "serve the viewer static files at / from this dir (same-origin demo; no CORS needed)")
	fl.StringVar(&f.llmAgentBin, "llm-agent-bin", "", "model-agent binary path; setting it (with the model flags) drives sessions with a real model-backed agent instead of the deterministic one")
	fl.StringVar(&f.modelBaseURL, "model-base-url", "", "model API base URL (OpenAI-compatible /chat/completions); required to enable the model-backed agent")
	fl.StringVar(&f.model, "model", "", "model name; required to enable the model-backed agent")
	fl.StringVar(&f.modelSecretFile, "model-secret-file", "", "path to a file holding the model API key (kept out of argv); required to enable the model-backed agent")
	fl.IntVar(&f.modelMaxSteps, "model-max-steps", 0, "max model/tool steps per turn (0 = default)")
	fl.DurationVar(&f.modelTimeout, "model-timeout", 0, "per model/tool request timeout (0 = default)")
	fl.IntVar(&f.dailyTurnBudget, "daily-turn-budget", 0, "hard global ceiling on total visitor turns (model calls) per UTC day, the spend kill switch (0 = unlimited; set a positive value for public exposure)")
	fl.IntVar(&f.maxMessagesPerSession, "max-messages-per-session", 0, "max messages one session may send (0 = default of 40)")
	return cmd
}

func runServe(cmd *cobra.Command, f *serveFlags) error {
	srv, handler, err := buildServer(cmd.OutOrStdout(), f)
	if err != nil {
		return err
	}
	defer srv.Close()

	httpSrv := &http.Server{
		Addr:              f.listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	return httpSrv.ListenAndServe()
}

// buildServer assembles the live-chat server and its HTTP handler from the
// flags, without binding a port. Split out from runServe so the wiring
// (containment posture, secret, codes, gate, static-dir mux) is testable
// without a blocking ListenAndServe. The caller owns srv.Close().
func buildServer(out io.Writer, f *serveFlags) (*livechat.Server, http.Handler, error) {
	// Containment posture. --dev turns off the requirement and shouts about it.
	requireContainment := f.requireContainment
	if f.dev {
		requireContainment = false
		_, _ = fmt.Fprintln(out, "WARNING: --dev set: running UNCONTAINED. Visitors are not kernel-isolated. Never use for public exposure.")
	}

	secret, err := resolveSecret(f.secretB64, f.secretFile)
	if err != nil {
		return nil, nil, err
	}

	codes, err := resolveCodes(out, f)
	if err != nil {
		return nil, nil, err
	}

	gate, err := livechat.NewGate(livechat.GateConfig{
		Secret:   secret,
		Codes:    codes,
		TokenTTL: f.sessionTTL,
	})
	if err != nil {
		return nil, nil, err
	}

	var verifier playground.ContainmentVerifier
	if requireContainment {
		verifier = containVerifier{}
	}

	llmAgent, err := buildLLMAgentConfig(f)
	if err != nil {
		return nil, nil, err
	}
	if err := validateServeSafety(f, llmAgent != nil); err != nil {
		return nil, nil, err
	}

	srv, err := livechat.NewServer(livechat.ServerConfig{
		Gate:                  gate,
		Limits:                livechat.Limits{MaxInputBytes: f.maxInputBytes, SessionTTL: f.sessionTTL},
		IPRate:                livechat.RateConfig{RefillPerSec: f.ipRate, Burst: f.ipBurst},
		CodeRate:              livechat.RateConfig{RefillPerSec: f.codeRate, Burst: f.codeBurst},
		MaxConcurrent:         f.concurrency,
		RequireContainment:    requireContainment,
		Containment:           verifier,
		OrchestratorKeyPath:   f.orchestratorKey,
		ToyAgentBin:           f.toyAgentBin,
		WebToolBin:            f.webToolBin,
		TrustForwardedFor:     f.trustForwardedFor,
		AllowOrigin:           f.allowOrigin,
		LLMAgent:              llmAgent,
		DailyTurnBudget:       f.dailyTurnBudget,
		MaxMessagesPerSession: f.maxMessagesPerSession,
	})
	if err != nil {
		return nil, nil, err
	}

	if llmAgent != nil {
		_, _ = fmt.Fprintf(out, "model-backed agent enabled (model %s)\n", llmAgent.Model)
	}

	posture := "CONTAINED"
	if !requireContainment {
		posture = "DEV (uncontained)"
	}
	_, _ = fmt.Fprintf(out, "pipelock-playground-live serving on %s · %s · %d code(s) · concurrency %d\n",
		f.listen, posture, len(codes), f.concurrency)

	handler := srv.Handler()
	if f.staticDir != "" {
		// Same-origin demo: API under /api/live/, viewer at /. No CORS needed.
		mux := http.NewServeMux()
		mux.Handle("/api/live/", srv.Handler())
		mux.Handle("/", http.FileServer(http.Dir(f.staticDir)))
		handler = mux
		_, _ = fmt.Fprintf(out, "serving viewer from %s at /\n", f.staticDir)
	}
	return srv, handler, nil
}

func validateServeSafety(f *serveFlags, modelBacked bool) error {
	if f.maxPerCode < 0 {
		return errors.New("--max-per-code must be >= 0")
	}
	if f.dailyTurnBudget < 0 {
		return errors.New("--daily-turn-budget must be >= 0")
	}
	if f.maxMessagesPerSession < 0 {
		return errors.New("--max-messages-per-session must be >= 0")
	}
	if !f.dev && !f.requireContainment {
		return errors.New("non-dev serve requires containment; use --dev for local uncontained testing")
	}
	if modelBacked && !f.dev && f.dailyTurnBudget <= 0 {
		return errors.New("model-backed public serve requires --daily-turn-budget > 0 (or --dev for local testing)")
	}
	if err := validateAllowOrigin(f.allowOrigin, f.dev); err != nil {
		return fmt.Errorf("--allow-origin: %w", err)
	}
	return nil
}

func validateAllowOrigin(raw string, dev bool) error {
	if raw == "" {
		return nil
	}
	if strings.TrimSpace(raw) != raw {
		return errors.New("must not contain surrounding whitespace")
	}
	if raw == "*" {
		if dev {
			return nil
		}
		return errors.New("wildcard is only allowed with --dev")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("must be an http(s) origin")
	}
	if u.Host == "" {
		return errors.New("host is required")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return errors.New("must be an origin only, like https://pipelab.org")
	}
	return nil
}

// buildLLMAgentConfig assembles the model-backed agent config from the model
// flags, or returns nil to leave the deterministic agent in place. It is enabled
// when ANY model flag is set, and then requires the full set, so a partial config
// fails loudly instead of silently falling back to the deterministic agent.
func buildLLMAgentConfig(f *serveFlags) (*playground.LLMAgentConfig, error) {
	if f.llmAgentBin == "" &&
		f.modelBaseURL == "" &&
		f.model == "" &&
		f.modelSecretFile == "" &&
		f.modelMaxSteps == 0 &&
		f.modelTimeout == 0 {
		return nil, nil
	}
	var missing []string
	if f.llmAgentBin == "" {
		missing = append(missing, "--llm-agent-bin")
	}
	if f.modelBaseURL == "" {
		missing = append(missing, "--model-base-url")
	}
	if f.model == "" {
		missing = append(missing, "--model")
	}
	if f.modelSecretFile == "" {
		missing = append(missing, "--model-secret-file")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("model-backed agent requires %s", strings.Join(missing, ", "))
	}
	if _, err := playground.ValidatePlainHTTPURL(f.modelBaseURL); err != nil {
		return nil, fmt.Errorf("--model-base-url: %w", err)
	}
	return &playground.LLMAgentConfig{
		Bin:          f.llmAgentBin,
		ModelBaseURL: f.modelBaseURL,
		Model:        f.model,
		SecretFile:   f.modelSecretFile,
		MaxSteps:     f.modelMaxSteps,
		Timeout:      f.modelTimeout,
	}, nil
}

// resolveSecret picks the gate-signing secret. A --secret-file (base64 contents)
// takes precedence and keeps the secret out of argv; then --secret (base64); then
// a freshly generated secret. The file is the preferred path for any non-dev run.
func resolveSecret(b64, file string) ([]byte, error) {
	if file != "" {
		data, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			return nil, fmt.Errorf("read --secret-file: %w", err)
		}
		secret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("decode --secret-file: %w", err)
		}
		return secret, nil
	}
	if b64 == "" {
		return livechat.NewSecret()
	}
	secret, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode --secret: %w", err)
	}
	return secret, nil
}

func resolveCodes(out interface{ Write([]byte) (int, error) }, f *serveFlags) ([]livechat.CodeSpec, error) {
	specs := make([]livechat.CodeSpec, 0, len(f.codes))
	for _, c := range f.codes {
		if strings.TrimSpace(c) == "" {
			return nil, errors.New("invite code cannot be empty or whitespace")
		}
		specs = append(specs, livechat.CodeSpec{Code: c, MaxSessions: f.maxPerCode})
	}
	if len(specs) == 0 {
		if !f.dev {
			return nil, errors.New("no invite codes: pass --code CODE (or --dev to auto-generate one)")
		}
		gen, err := livechat.NewRandomCode(18)
		if err != nil {
			return nil, err
		}
		specs = append(specs, livechat.CodeSpec{Code: gen, MaxSessions: f.maxPerCode})
		_, _ = fmt.Fprintf(out, "DEV invite code (use this to start a session): %s\n", gen)
	}
	return specs, nil
}

func newGenSecretCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gen-secret",
		Short: "Print a fresh base64 gate-signing secret",
		RunE: func(cmd *cobra.Command, _ []string) error {
			secret, err := livechat.NewSecret()
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), base64.StdEncoding.EncodeToString(secret))
			return nil
		},
	}
}

func newGenCodeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gen-code",
		Short: "Print a fresh random invite code",
		RunE: func(cmd *cobra.Command, _ []string) error {
			code, err := livechat.NewRandomCode(18)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), code)
			return nil
		},
	}
}

// containVerifier proves kernel containment is in place before a public session
// starts. It requires root (the contained drop is a privileged operation) and
// confirms `pipelock contain verify` passes (via playground.ContainmentAvailable).
// The per-session CRYPTOGRAPHIC proof is the signed host-containment witness
// produced at session finalize; this is the start-time gate that refuses to even
// begin if the kernel drop is not active.
type containVerifier struct{}

func (containVerifier) Verify(_ context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("containment requires root (run the server as root, or use --dev to run uncontained)")
	}
	if !playground.ContainmentAvailable() {
		return errors.New("'pipelock contain verify' did not pass; containment is not installed")
	}
	return nil
}
