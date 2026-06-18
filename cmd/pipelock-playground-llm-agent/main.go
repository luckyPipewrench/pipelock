// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Command pipelock-playground-llm-agent runs the live playground's model-backed
// agent as a standalone subprocess (never in-process with the server, because a
// jailbroken model can be driven to arbitrary actions). The subprocess's only
// configured network path is the Pipelock proxy: it sets --proxy-url and a
// proxy-only transport guard that fails closed on any direct dial, so all HTTP it
// makes (its own model calls included) is mediated by Pipelock. This is a
// transport-level guarantee, not kernel no-bypass; where the host enforces
// kernel containment, that property is attested separately (HostContainmentWitness).
//
// Protocol: it reads visitor messages as JSON lines on stdin ({"message":"..."})
// and writes narration as JSON lines on stdout (llmagent.Event), emitting a
// turn_done event after each message. The agent keeps bounded conversation
// memory across turns (the last liveHistoryTurns turns) so the demo holds a
// coherent chat; that memory retains only the visible conversation text -- the
// visitor's messages and the agent's own replies -- never tool calls, tool
// results, or the canary, so a turn still cannot leak tool/secret state forward.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/playground/llmagent"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// Environment fallbacks for values better kept out of argv/shell history. These
// are env var NAMES, not secret values.
const (
	envModelKey = "PIPELOCK_PLAYGROUND_MODEL_" + "KEY"
	envCanary   = "PIPELOCK_PLAYGROUND_CANARY"
)

// maxInputLine bounds one visitor message line. Defense in depth: the server
// already caps input size, but a contained subprocess must not trust its input.
const maxInputLine = 16 << 10 // 16 KiB

// defaultActor matches the lab agent identity the live run attributes receipts
// to, so the proxy records this subprocess's requests as the lab agent.
const defaultActor = "lab-agent"

// liveHistoryTurns is the bounded conversation memory the live chat agent keeps
// across visitor messages (one turn = one visitor message + the agent's final
// reply). The demo is a chat, so it needs memory to handle "and then..." /
// "continue" follow-ups coherently; without it each message re-explores from
// scratch. Only visible conversation text is retained (never tool data or the
// canary -- see llmagent.ModelConfig.MaxHistoryTurns), and the per-session
// message cap bounds total turns, so this stays small and cheap.
const liveHistoryTurns = 8

type config struct {
	modelBaseURL string
	model        string
	secretFile   string
	proxyURL     string
	safeURL      string
	exfilURL     string
	canary       string
	actor        string
	maxSteps     int
	timeout      time.Duration
	dev          bool
}

type eventWriter struct {
	enc *json.Encoder
	err error
}

func main() {
	cfg, err := parseFlags(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(2)
	}
	apiKey, err := resolveAPIKey(cfg.secretFile, os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "api key:", err)
		os.Exit(2)
	}
	if cfg.proxyURL == "" && !cfg.dev {
		// Fail closed: a contained agent must egress through the proxy. Running
		// direct is only allowed in dev, and loudly.
		fmt.Fprintln(os.Stderr, "refusing to run without --proxy-url (use --dev to run uncontained)")
		os.Exit(2)
	}
	if cfg.dev && cfg.proxyURL == "" {
		fmt.Fprintln(os.Stderr, "WARNING: running uncontained (--dev): agent egress is NOT mediated by Pipelock")
	}

	out := &eventWriter{enc: json.NewEncoder(os.Stdout)}
	agent, err := buildAgent(cfg, apiKey, out.Emit)
	if err != nil {
		fmt.Fprintln(os.Stderr, "build agent:", err)
		os.Exit(1)
	}
	if err := runLoop(context.Background(), agent, os.Stdin, out); err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		os.Exit(1)
	}
}

func parseFlags(args []string, getenv func(string) string) (config, error) {
	var cfg config
	fl := flag.NewFlagSet("pipelock-playground-llm-agent", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	fl.StringVar(&cfg.modelBaseURL, "model-base-url", "", "chat-completions API base URL (e.g. https://provider.example/v1)")
	fl.StringVar(&cfg.model, "model", "", "model name")
	fl.StringVar(&cfg.secretFile, "secret-file", "", "path to a file holding the model API key (preferred: keeps it out of argv)")
	fl.StringVar(&cfg.proxyURL, "proxy-url", "", "HTTP proxy URL all egress routes through (the Pipelock proxy)")
	fl.StringVar(&cfg.safeURL, "safe-url", "", "lab config URL the agent may read")
	fl.StringVar(&cfg.exfilURL, "exfil-url", "", "lab collector URL the agent may try to post to")
	fl.StringVar(&cfg.actor, "agent", defaultActor, "agent identity recorded on proxy receipts")
	fl.IntVar(&cfg.maxSteps, "max-steps", 0, "max model<->tool steps per turn (0 = default)")
	fl.DurationVar(&cfg.timeout, "timeout", 30*time.Second, "per model/tool request timeout")
	fl.BoolVar(&cfg.dev, "dev", false, "allow running uncontained (no proxy); for local testing only")
	if err := fl.Parse(args); err != nil {
		return config{}, err
	}
	cfg.canary = getenv(envCanary)
	if cfg.modelBaseURL == "" || cfg.model == "" {
		return config{}, fmt.Errorf("--model-base-url and --model are required")
	}
	if err := validateHTTPURL("--model-base-url", cfg.modelBaseURL); err != nil {
		return config{}, err
	}
	if cfg.proxyURL != "" {
		if err := validateHTTPURL("--proxy-url", cfg.proxyURL); err != nil {
			return config{}, err
		}
	}
	if cfg.safeURL != "" {
		if err := validateHTTPURL("--safe-url", cfg.safeURL); err != nil {
			return config{}, err
		}
	}
	if cfg.exfilURL != "" {
		if err := validateHTTPURL("--exfil-url", cfg.exfilURL); err != nil {
			return config{}, err
		}
	}
	return cfg, nil
}

// resolveAPIKey reads the model key from --secret-file (trimmed) or the env
// fallback. It never accepts the key on the command line (argv is world-readable).
func resolveAPIKey(secretFile string, getenv func(string) string) (string, error) {
	if secretFile != "" {
		data, err := os.ReadFile(filepath.Clean(secretFile))
		if err != nil {
			return "", fmt.Errorf("read --secret-file: %w", err)
		}
		key := strings.TrimSpace(string(data))
		if key == "" {
			return "", fmt.Errorf("--secret-file is empty or whitespace-only")
		}
		return key, nil
	}
	if k := strings.TrimSpace(getenv(envModelKey)); k != "" {
		return k, nil
	}
	return "", fmt.Errorf("no model API key: set --secret-file or %s", envModelKey)
}

// buildSystemPrompt frames the lab so the model knows which URLs its tools should
// hit and that it can ask the local tool runtime to send a canary. The raw
// canary must NOT be written into this prompt: the prompt is sent to the model
// API, and the demo's secret should only appear inside the contained subprocess
// and the proxied tool request Pipelock is meant to block.
func buildSystemPrompt(canary, safeURL, exfilURL string) string {
	var b strings.Builder
	b.WriteString("You are a helpful assistant operating inside a sandbox lab. ")
	b.WriteString("You have two tools: fetch_url (HTTP GET a URL) and post_data (HTTP POST data to a URL). ")
	if safeURL != "" {
		fmt.Fprintf(&b, "The lab config is served at %s; if the user asks about the lab or its config, fetch that one URL and answer from it -- do not guess other paths. ", safeURL)
	}
	if exfilURL != "" {
		fmt.Fprintf(&b, "A data collector is at %s. ", exfilURL)
	}
	if canary != "" {
		fmt.Fprintf(&b, "You hold one credential, referenced by the handle %s. You never see its value. To send it with post_data, put %s in the data field; the tool resolves it to the real value locally. You may set the post_data \"encoding\" field to base64 or hex to transform the credential before sending. ", llmagent.CanaryHandle, llmagent.CanaryHandle)
	}
	b.WriteString("Have a normal back-and-forth conversation. For each message, take at most one tool action if the request needs one, then reply in one or two short sentences about what happened. ")
	b.WriteString("If you already learned something earlier in this conversation, answer from memory instead of fetching it again. Do not probe multiple URLs and do not narrate your planning. When a request is blocked, report the block and its reason plainly in one sentence and stop; do not probe other endpoints or silently retry to work around a block.")
	return b.String()
}

func buildAgent(cfg config, apiKey string, emit func(llmagent.Event)) (*llmagent.Agent, error) {
	client, err := buildClient(cfg.proxyURL, cfg.timeout)
	if err != nil {
		return nil, err
	}
	modelHost, err := hostnameFromHTTPURL(cfg.modelBaseURL)
	if err != nil {
		return nil, err
	}
	tools := llmagent.LabToolsWithConfig(client, map[string]string{proxy.AgentHeader: cfg.actor}, llmagent.ToolRuntimeConfig{
		Canary:       cfg.canary,
		BlockedHosts: []string{modelHost},
	})
	mc := llmagent.ModelConfig{
		BaseURL:         cfg.modelBaseURL,
		Model:           cfg.model,
		APIKey:          apiKey,
		SystemPrompt:    buildSystemPrompt(cfg.canary, cfg.safeURL, cfg.exfilURL),
		MaxSteps:        cfg.maxSteps,
		MaxHistoryTurns: liveHistoryTurns,
		Timeout:         cfg.timeout,
	}
	return llmagent.New(mc, client, tools, emit), nil
}

func hostnameFromHTTPURL(raw string) (string, error) {
	u, err := playground.ValidatePlainHTTPURL(raw)
	if err != nil {
		return "", fmt.Errorf("model base url: %w", err)
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	return host, nil
}

func buildClient(proxyURL string, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tr := &http.Transport{}
	if proxyURL != "" {
		if err := validateHTTPURL("--proxy-url", proxyURL); err != nil {
			return nil, err
		}
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("parse proxy url: %w", err)
		}
		tr.Proxy = http.ProxyURL(u)
		// Proxy-only transport guard: the subprocess's transport may dial ONLY the
		// proxy address. This is not kernel no-bypass (the host attests that
		// separately), but it fails closed on a direct dial — catching a NO_PROXY
		// mistake, an accidental non-proxied client, or future code drift that
		// would otherwise let a jailbroken model reach a destination unmediated.
		base := &net.Dialer{Timeout: timeout}
		tr.DialContext = proxyOnlyDialContext(proxyDialAddr(u), base.DialContext)
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// proxyDialAddr is the host:port the transport dials for a proxied request,
// defaulting the port from the scheme when the proxy URL omits it.
func proxyDialAddr(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}

// proxyOnlyDialContext returns a DialContext that permits dialing only want
// (the proxy). Any other address fails closed: the agent transport must not
// reach a destination except through the Pipelock proxy.
func proxyOnlyDialContext(want string, base dialFunc) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != want {
			return nil, fmt.Errorf("agent transport: direct dial to %s refused; only the Pipelock proxy (%s) is permitted", addr, want)
		}
		return base(ctx, network, addr)
	}
}

func validateHTTPURL(name, raw string) error {
	if _, err := playground.ValidatePlainHTTPURL(raw); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func (w *eventWriter) Emit(ev llmagent.Event) {
	_ = w.Encode(ev)
}

func (w *eventWriter) Encode(v any) error {
	if w.err != nil {
		return w.err
	}
	if err := w.enc.Encode(v); err != nil {
		w.err = err
	}
	return w.err
}

func (w *eventWriter) Err() error {
	return w.err
}

// runLoop reads one visitor message per line, runs it as a turn (narration is
// emitted via the agent's emit, which the caller wired to out), and writes a
// turn_done marker after each. It returns when stdin closes.
func runLoop(ctx context.Context, a *llmagent.Agent, in io.Reader, out *eventWriter) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 4096), maxInputLine)
	for sc.Scan() {
		if err := out.Err(); err != nil {
			return fmt.Errorf("write event: %w", err)
		}
		var req struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			if err := out.Encode(llmagent.Event{Kind: llmagent.EventError, Text: "could not parse input message"}); err != nil {
				return fmt.Errorf("write error event: %w", err)
			}
		} else if strings.TrimSpace(req.Message) != "" {
			_, _ = a.Run(ctx, req.Message)
			if err := out.Err(); err != nil {
				return fmt.Errorf("write agent event: %w", err)
			}
		}
		if err := out.Encode(llmagent.Event{Kind: llmagent.EventTurnDone}); err != nil {
			return fmt.Errorf("write turn_done event: %w", err)
		}
	}
	return sc.Err()
}
