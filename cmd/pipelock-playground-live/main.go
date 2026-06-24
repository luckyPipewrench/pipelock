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
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain"
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
	root.AddCommand(newServeCmd(), newGenSecretCmd(), newGenCodeCmd(), newPrintNFTCmd(), newVerifyContainmentCmd())
	return root
}

type serveFlags struct {
	listen                 string
	codes                  []string
	maxPerCode             int
	concurrency            int
	requireContainment     bool
	requireModel           bool
	selfManagedContainment bool
	dev                    bool
	orchestratorKey        string
	toyAgentBin            string
	webToolBin             string
	proxyPort              int
	sessionTTL             time.Duration
	maxInputBytes          int
	ipRate                 float64
	ipBurst                float64
	codeRate               float64
	codeBurst              float64
	allowOrigin            string
	trustForwardedFor      bool
	secretB64              string
	secretFile             string
	staticDir              string
	llmAgentBin            string
	modelBaseURL           string
	model                  string
	modelSecretFile        string
	modelMaxSteps          int
	modelTimeout           time.Duration
	dailyTurnBudget        int
	perIPDailyBudget       int
	perCodeDailyBudget     int
	maxMessagesPerSession  int
	verifierBinLinux       string
	verifierBinMacOS       string
	verifierBinWindows     string
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
	fl.BoolVar(&f.requireModel, "require-model", false, "refuse to serve unless the real model-backed agent is fully configured (public demo guard)")
	fl.BoolVar(&f.selfManagedContainment, "self-managed-containment", false, "the deployment sets the nft owner-match egress rule itself (e.g. a per-visitor microVM boot entrypoint) instead of `pipelock contain install`; the server proves the agent-uid egress/local escape drops empirically at start and via the signed witness, and does NOT require `pipelock contain verify`")
	fl.BoolVar(&f.dev, "dev", false, "DEV ONLY: run uncontained (disables --require-containment); never use for public exposure")
	fl.StringVar(&f.orchestratorKey, "orchestrator-key", "", "path to the published demo signing key (required outside --dev; empty = ephemeral per-run key in --dev)")
	fl.StringVar(&f.toyAgentBin, "toyagent-bin", "", "toy-agent binary path (needed for the contained host-containment witness)")
	fl.StringVar(&f.webToolBin, "webtool-bin", "", "web-tool binary path (needed for the contained host-containment witness)")
	fl.IntVar(&f.proxyPort, "proxy-port", 0, "fixed loopback port the in-process proxy binds; must match `pipelock contain install --proxy-port` (defaults to 8888 in contained mode). 0 = ephemeral, dev/test only")
	fl.DurationVar(&f.sessionTTL, "session-ttl", 600*time.Second, "per-session wall-clock cap")
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
	fl.IntVar(&f.dailyTurnBudget, "daily-turn-budget", 0, "hard global ceiling on total model round trips per UTC day, the spend kill switch (each visitor message reserves up to --model-max-steps round trips; 0 = unlimited; set a positive value for public exposure)")
	fl.IntVar(&f.perIPDailyBudget, "per-ip-daily-budget", 0, "per client-IP ceiling on model round trips per UTC day so one client cannot drain the global budget (0 = no per-IP cap)")
	fl.IntVar(&f.perCodeDailyBudget, "per-code-daily-budget", 0, "per invite-code ceiling on model round trips per UTC day so one code cannot drain the global budget (0 = no per-code cap)")
	fl.IntVar(&f.maxMessagesPerSession, "max-messages-per-session", 0, "max messages one session may send (0 = default of 40)")
	fl.StringVar(&f.verifierBinLinux, "verifier-bin-linux", "", "Linux pipelock-verifier binary path for live verify-kit downloads")
	fl.StringVar(&f.verifierBinMacOS, "verifier-bin-macos", "", "macOS pipelock-verifier binary path for live verify-kit downloads")
	fl.StringVar(&f.verifierBinWindows, "verifier-bin-windows", "", "Windows pipelock-verifier.exe binary path for live verify-kit downloads")
	return cmd
}

func runServe(cmd *cobra.Command, f *serveFlags) error {
	srv, handler, err := buildServer(cmd.OutOrStdout(), f)
	if err != nil {
		return err
	}
	defer srv.Close()

	// Operator kill switch: on Unix, SIGUSR1 terminates active sessions and
	// refuses new ones; SIGUSR2 resumes. No-op where those signals are absent.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchKillSwitch(ctx, srv)

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
		if f.selfManagedContainment {
			// Self-managed (in-VM/Fly) containment: the deployment set the nft
			// owner-match rule; verify the egress drop empirically rather than
			// asking `pipelock contain verify` whether `pipelock contain install`
			// ran on this host.
			verifier = inVMContainVerifier{toyAgentBin: f.toyAgentBin}
		} else {
			verifier = containVerifier{}
		}
	}

	llmAgent, err := buildLLMAgentConfig(f)
	if err != nil {
		return nil, nil, err
	}
	if err := validateServeSafety(f, llmAgent != nil); err != nil {
		return nil, nil, err
	}
	if !f.dev {
		if _, err := playground.LoadOrchestratorSigningKey(f.orchestratorKey); err != nil {
			return nil, nil, fmt.Errorf("--orchestrator-key: %w", err)
		}
		if err := validateModelAgentRuntime(llmAgent); err != nil {
			return nil, nil, err
		}
		// Contained serve binds a fixed proxy port to match the kernel owner-match
		// rule. Default it to the stock `pipelock contain install` port; an
		// operator who installed containment on a custom port passes --proxy-port.
		f.proxyPort = containedProxyPort(f.proxyPort)
		if f.concurrency != 1 {
			// One fixed proxy port can host one contained session at a time; the
			// second concurrent session fails its bind and returns 503. Warn rather
			// than block (the runtime is fail-safe), and point at the fix.
			_, _ = fmt.Fprintf(out, "warning: contained serve binds one fixed proxy port (%d); concurrent sessions past the first fail to start. Set --concurrency 1 to avoid 503s.\n", f.proxyPort)
		}
	}

	srv, err := livechat.NewServer(livechat.ServerConfig{
		Gate:                gate,
		Limits:              livechat.Limits{MaxInputBytes: f.maxInputBytes, SessionTTL: f.sessionTTL},
		IPRate:              livechat.RateConfig{RefillPerSec: f.ipRate, Burst: f.ipBurst},
		CodeRate:            livechat.RateConfig{RefillPerSec: f.codeRate, Burst: f.codeBurst},
		MaxConcurrent:       f.concurrency,
		RequireContainment:  requireContainment,
		Containment:         verifier,
		OrchestratorKeyPath: f.orchestratorKey,
		ToyAgentBin:         f.toyAgentBin,
		WebToolBin:          f.webToolBin,
		ProxyPort:           f.proxyPort,
		TrustForwardedFor:   f.trustForwardedFor,
		AllowOrigin:         f.allowOrigin,
		LLMAgent:            llmAgent,
		VerifierBinaries: playground.VerifyKitBinaries{
			Linux:   f.verifierBinLinux,
			MacOS:   f.verifierBinMacOS,
			Windows: f.verifierBinWindows,
		},
		DailyTurnBudget:       f.dailyTurnBudget,
		PerIPDailyBudget:      f.perIPDailyBudget,
		PerCodeDailyBudget:    f.perCodeDailyBudget,
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
		mux.Handle(livechat.RouteAPIPrefix, srv.Handler())
		mux.Handle("/", http.FileServer(http.Dir(f.staticDir)))
		handler = mux
		_, _ = fmt.Fprintf(out, "serving viewer from %s at /\n", f.staticDir)
	}
	return srv, handler, nil
}

// containedProxyPort resolves the proxy port for a contained serve: an unset
// port (0) becomes the stock containment proxy port so a default contained
// install works without --proxy-port; an explicit port is kept as-is so an
// operator on a custom `contain install --proxy-port` can match it.
func containedProxyPort(port int) int {
	if port == 0 {
		return playground.DefaultContainedProxyPort
	}
	return port
}

func validateServeSafety(f *serveFlags, modelBacked bool) error {
	if f.maxPerCode < 0 {
		return errors.New("--max-per-code must be >= 0")
	}
	if f.perIPDailyBudget < 0 {
		return errors.New("--per-ip-daily-budget must be >= 0")
	}
	if f.perCodeDailyBudget < 0 {
		return errors.New("--per-code-daily-budget must be >= 0")
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
	if f.selfManagedContainment {
		if f.dev {
			return errors.New("--self-managed-containment cannot be combined with --dev (it IS a contained mode)")
		}
		if strings.TrimSpace(f.toyAgentBin) == "" {
			return errors.New("--self-managed-containment requires --toyagent-bin (the start-gate egress probe binary)")
		}
	}
	if f.proxyPort < 0 || f.proxyPort > 65535 {
		return errors.New("--proxy-port must be 0-65535")
	}
	if !f.dev && strings.TrimSpace(f.orchestratorKey) == "" {
		return errors.New("non-dev serve requires --orchestrator-key so bundles verify against the published demo key")
	}
	if f.requireModel && !modelBacked {
		return errors.New("--require-model set but model-backed agent is not configured")
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

func validateModelAgentRuntime(cfg *playground.LLMAgentConfig) error {
	if cfg == nil {
		return nil
	}
	if err := requireExecutableFile("--llm-agent-bin", cfg.Bin); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Clean(cfg.SecretFile))
	if err != nil {
		return fmt.Errorf("--model-secret-file: %w", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return errors.New("--model-secret-file is empty")
	}
	return nil
}

func requireExecutableFile(name, path string) error {
	info, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s: is a directory", name)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s: file is not executable", name)
	}
	return nil
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

// newPrintNFTCmd prints the canonical Pipelock containment nftables ruleset for
// the self-managed (in-VM/Fly) containment model. A per-visitor microVM boot
// entrypoint pipes it to `nft -f -` so the kernel owner-match egress rule the
// contained agent uid is held to is generated by the SHIPPED renderer (single
// source of truth), not a drift-prone hand-copied rule. operator and proxy
// default to uid 0 (the playground server and its in-process proxy run as root
// in the disposable VM); only the agent uid is dropped to proxy-only egress.
func newPrintNFTCmd() *cobra.Command {
	var (
		agentUID    int
		proxyPort   int
		operatorUID int
		proxyUID    int
	)
	cmd := &cobra.Command{
		Use:   "print-containment-nft",
		Short: "Print the containment nftables ruleset (for `nft -f -` in a self-managed/in-VM deployment)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if agentUID <= 0 {
				return errors.New("--agent-uid must be a positive non-root uid (the contained agent user)")
			}
			if proxyPort < 1 || proxyPort > 65535 {
				return errors.New("--proxy-port must be 1-65535")
			}
			_, _ = fmt.Fprint(cmd.OutOrStdout(), contain.RenderNFTRules(operatorUID, proxyUID, agentUID, proxyPort))
			return nil
		},
	}
	cmd.Flags().IntVar(&agentUID, "agent-uid", 0, "uid of the contained agent user (required; only this uid is dropped to proxy-only egress)")
	cmd.Flags().IntVar(&proxyPort, "proxy-port", playground.DefaultContainedProxyPort, "loopback port the in-process proxy binds; the agent uid may reach only 127.0.0.1:this")
	cmd.Flags().IntVar(&operatorUID, "operator-uid", 0, "operator uid allowed full egress (default 0/root)")
	cmd.Flags().IntVar(&proxyUID, "proxy-uid", 0, "proxy uid allowed full egress (default 0/root; the in-process proxy runs in the server process)")
	return cmd
}

// newVerifyContainmentCmd runs the install-agnostic in-VM containment start gate
// (playground.VerifyInVMContainment) and exits non-zero if the contained agent
// uid's direct egress is not proven blocked. A per-visitor microVM boot
// entrypoint runs this AFTER loading the nft rule and BEFORE starting the
// server, so a VM that failed to establish containment aborts (fail-closed)
// rather than serving an uncontained agent. The same proof runs per-session at
// serve time and is recorded cryptographically in the signed bundle.
func newVerifyContainmentCmd() *cobra.Command {
	var (
		toyAgentBin string
		agentUser   string
	)
	cmd := &cobra.Command{
		Use:   "verify-containment",
		Short: "Prove the contained agent uid's egress/local escape surfaces are blocked (fail-closed boot gate for self-managed containment)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := playground.VerifyInVMContainment(cmd.Context(), toyAgentBin, agentUser); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "containment verified: contained agent egress/local escape surfaces are blocked; operator + proxy paths intact")
			return nil
		},
	}
	cmd.Flags().StringVar(&toyAgentBin, "toyagent-bin", "", "probe binary (the pipelock-playground-toyagent path); required")
	cmd.Flags().StringVar(&agentUser, "agent-user", "pipelock-agent", "contained agent username")
	return cmd
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
// confirms `pipelock contain verify --enforcement-only` passes (via
// playground.ContainmentEnforced).
// The per-session CRYPTOGRAPHIC proof is the signed host-containment witness
// produced at session finalize; this is the start-time gate that refuses to even
// begin if the kernel drop is not active.
type containVerifier struct{}

func (containVerifier) Verify(_ context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("containment requires root (run the server as root, or use --dev to run uncontained)")
	}
	if !playground.ContainmentEnforced() {
		return errors.New("'pipelock contain verify --enforcement-only' did not pass; containment enforcement is not installed")
	}
	return nil
}

// inVMContainVerifier is the start gate for the self-managed (in-VM/Fly)
// containment model: the deployment (e.g. a per-visitor microVM boot entrypoint)
// sets the kernel owner-match egress rule itself, so there is no
// `pipelock contain install` to verify. Instead of trusting the installer, it
// proves the contained agent uid's direct egress is actually dropped, empirically
// and fail-closed, before any session starts. The per-session cryptographic proof
// is still the signed host-containment witness produced at finalize.
type inVMContainVerifier struct {
	toyAgentBin string
	agentUser   string
}

func (v inVMContainVerifier) Verify(ctx context.Context) error {
	return playground.VerifyInVMContainment(ctx, v.toyAgentBin, v.agentUser)
}
