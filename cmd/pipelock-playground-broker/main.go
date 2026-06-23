// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for pipelock-playground-broker, the public
// playground front door that leases one private per-visitor VM and reverse
// proxies the /api/live/* session API to it.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/playground/broker"
	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

const (
	defaultListen      = "127.0.0.1:8100"
	defaultConcurrency = 3
	defaultMaxPerCode  = 25
	defaultSessionTTL  = 10 * time.Minute
	defaultGrace       = 30 * time.Second
	defaultIPRate      = 0.5
	defaultIPBurst     = 5
	defaultCodeRate    = 0.5
	defaultCodeBurst   = 10
	cfAccessJWTHeader  = "Cf-Access-Jwt-Assertion"
	cfAccessKeysTTL    = 5 * time.Minute

	envModelKey        = "PLAYGROUND_MODEL_" + "KEY"
	envOrchestratorKey = "PLAYGROUND_ORCHESTRATOR_" + "KEY"
)

type serveFlags struct {
	listen                string
	staticDir             string
	provider              string
	flyApp                string
	flyTokenFile          string
	flyTokenEnv           string
	image                 string
	region                string
	memoryMB              int
	cpus                  int
	internalPort          int
	concurrency           int
	codes                 []string
	maxPerCode            int
	gateSecretFile        string
	gateSecretEnv         string
	ipRate                float64
	ipBurst               float64
	codeRate              float64
	codeBurst             float64
	perIPDailyBudget      int
	perCodeDailyBudget    int
	globalDailyBudget     int
	sessionTTL            time.Duration
	deadlineGrace         time.Duration
	allowOrigin           string
	publicHosts           []string
	cfAccessTeamDomain    string
	cfAccessAUD           string
	cfAccessCertsURL      string
	trustForwardedFor     bool
	modelKeyFile          string
	modelKeyEnv           string
	orchestratorKeyFile   string
	orchestratorKeyEnv    string
	requireSessionSecrets bool
	// VM model/session config, passed into each per-visitor VM via PLAYGROUND_*
	// env (consumed by deploy/fly-playground/entrypoint.sh).
	vmModelBaseURL    string
	vmModel           string
	vmModelMaxSteps   int
	vmDailyTurnBudget int
	vmSessionTTL      time.Duration
	vmMaxMessages     int
}

type providerFactory func(context.Context, *serveFlags, string) (broker.MachineProvider, error)

var newMachineProvider providerFactory = defaultMachineProvider

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "pipelock-playground-broker",
		Short:         "Public playground broker front door",
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       cliutil.Version,
	}
	root.AddCommand(newServeCmd())
	return root
}

func newServeCmd() *cobra.Command {
	f := &serveFlags{}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the playground broker HTTP server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.listen, "listen", defaultListen, "address to listen on")
	fl.StringVar(&f.staticDir, "static-dir", "", "directory of static UI files to serve at / (the /api/live/* API is unaffected); empty disables static serving")
	fl.StringVar(&f.provider, "provider", "fly", "machine provider")
	fl.StringVar(&f.flyApp, "fly-app", "", "Fly app that owns per-visitor machines")
	fl.StringVar(&f.flyTokenFile, "fly-token-file", "", "path to the Fly API token file")
	fl.StringVar(&f.flyTokenEnv, "fly-token-env", "", "environment variable holding the Fly API token (for Fly secrets; alternative to --fly-token-file)")
	fl.StringVar(&f.image, "image", "", "per-visitor VM image")
	fl.StringVar(&f.region, "region", "", "provider region")
	fl.IntVar(&f.memoryMB, "memory-mb", 512, "per-visitor VM memory in MiB")
	fl.IntVar(&f.cpus, "cpus", 1, "per-visitor VM shared CPUs")
	fl.IntVar(&f.internalPort, "internal-port", 8080, "per-visitor VM internal HTTP port")
	fl.IntVar(&f.concurrency, "concurrency", defaultConcurrency, "global cap on live per-visitor machines")
	fl.StringArrayVar(&f.codes, "code", nil, "public invite code (repeatable)")
	fl.IntVar(&f.maxPerCode, "max-per-code", defaultMaxPerCode, "max broker sessions per invite code (0 = unlimited)")
	fl.StringVar(&f.gateSecretFile, "gate-secret-file", "", "path to base64 broker gate secret")
	fl.StringVar(&f.gateSecretEnv, "gate-secret-env", "", "environment variable containing base64 broker gate secret")
	fl.Float64Var(&f.ipRate, "ip-rate", defaultIPRate, "per-IP sustained request rate (tokens/sec)")
	fl.Float64Var(&f.ipBurst, "ip-burst", defaultIPBurst, "per-IP burst")
	fl.Float64Var(&f.codeRate, "code-rate", defaultCodeRate, "per-code sustained request rate (tokens/sec)")
	fl.Float64Var(&f.codeBurst, "code-burst", defaultCodeBurst, "per-code burst")
	fl.IntVar(&f.perIPDailyBudget, "per-ip-daily-budget", 0, "per-IP session starts per UTC day (0 = unlimited)")
	fl.IntVar(&f.perCodeDailyBudget, "per-code-daily-budget", 0, "per-code session starts per UTC day (0 = unlimited)")
	fl.IntVar(&f.globalDailyBudget, "global-daily-budget", 0, "global session starts per UTC day (0 = unlimited)")
	fl.DurationVar(&f.sessionTTL, "session-ttl", defaultSessionTTL, "VM session token TTL")
	fl.DurationVar(&f.deadlineGrace, "deadline-grace", defaultGrace, "lease teardown grace after VM session expiry")
	fl.StringVar(&f.allowOrigin, "allow-origin", "", "Access-Control-Allow-Origin for the browser")
	fl.StringArrayVar(&f.publicHosts, "public-host", nil, "allowed public Host header for the broker (repeatable); defaults to the --allow-origin host when set")
	fl.StringVar(&f.cfAccessTeamDomain, "cf-access-team-domain", "", "Cloudflare Access team domain, e.g. https://team.cloudflareaccess.com; enables origin-side Access JWT validation when set with --cf-access-aud")
	fl.StringVar(&f.cfAccessAUD, "cf-access-aud", "", "Cloudflare Access application AUD tag expected in Cf-Access-Jwt-Assertion")
	fl.StringVar(&f.cfAccessCertsURL, "cf-access-certs-url", "", "override Cloudflare Access JWKS URL (tests/dev only; defaults to <team-domain>/cdn-cgi/access/certs)")
	fl.BoolVar(&f.trustForwardedFor, "trust-forwarded-for", false, "read client IP from X-Forwarded-For behind a trusted proxy")
	fl.StringVar(&f.modelKeyFile, "model-key-file", "", "path to the model key file passed to the VM env")
	fl.StringVar(&f.modelKeyEnv, "model-key-env", "", "environment variable holding the model key passed to the VM env")
	fl.StringVar(&f.orchestratorKeyFile, "orchestrator-key-file", "", "path to the orchestrator key file passed to the VM env")
	fl.StringVar(&f.orchestratorKeyEnv, "orchestrator-key-env", "", "environment variable holding the orchestrator key passed to the VM env")
	fl.BoolVar(&f.requireSessionSecrets, "require-session-secrets", true, "require model and orchestrator keys from file/env")
	fl.StringVar(&f.vmModelBaseURL, "vm-model-base-url", "", "model API base URL passed to each VM (enables the model-backed agent)")
	fl.StringVar(&f.vmModel, "vm-model", "", "model name passed to each VM")
	fl.IntVar(&f.vmModelMaxSteps, "vm-model-max-steps", 0, "max model/tool steps per turn in each VM (0 = VM default)")
	fl.IntVar(&f.vmDailyTurnBudget, "vm-daily-turn-budget", 0, "per-VM model round-trip ceiling per UTC day (the in-VM spend kill switch; required by the VM when a model is set)")
	fl.DurationVar(&f.vmSessionTTL, "vm-session-ttl", 0, "per-VM session wall-clock cap (0 = VM default)")
	fl.IntVar(&f.vmMaxMessages, "vm-max-messages-per-session", 0, "per-VM max messages per session (0 = VM default)")
	return cmd
}

func runServe(cmd *cobra.Command, f *serveFlags) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	srv, handler, err := buildServer(ctx, cmd.OutOrStdout(), f)
	if err != nil {
		return err
	}
	defer srv.Close()

	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", f.listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", f.listen, err)
	}
	defer func() { _ = ln.Close() }()
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "pipelock-playground-broker serving on %s with provider %s\n", f.listen, f.provider)
	if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func buildServer(ctx context.Context, out io.Writer, f *serveFlags) (*broker.Server, http.Handler, error) {
	if err := validateFlags(f); err != nil {
		return nil, nil, err
	}
	secret, err := resolveGateSecret(f.gateSecretFile, f.gateSecretEnv)
	if err != nil {
		return nil, nil, err
	}
	codes, err := resolveCodes(f.codes, f.maxPerCode)
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
	token, err := resolveFlyToken(f)
	if err != nil {
		return nil, nil, err
	}
	provider, err := newMachineProvider(ctx, f, token)
	if err != nil {
		return nil, nil, err
	}
	sessionEnv, err := resolveSessionEnv(f)
	if err != nil {
		return nil, nil, err
	}
	lm, err := broker.NewLeaseManager(broker.LeaseConfig{
		Provider:     provider,
		Concurrency:  livechat.NewConcurrencyLimiter(f.concurrency),
		Image:        f.image,
		Region:       f.region,
		MemoryMB:     f.memoryMB,
		CPUs:         f.cpus,
		InternalPort: f.internalPort,
		BaseEnv:      buildVMBaseEnv(f),
	})
	if err != nil {
		return nil, nil, err
	}
	srv, err := broker.NewServer(broker.ServerConfig{
		Leases:             lm,
		Gate:               gate,
		IPRate:             livechat.RateConfig{RefillPerSec: f.ipRate, Burst: f.ipBurst},
		CodeRate:           livechat.RateConfig{RefillPerSec: f.codeRate, Burst: f.codeBurst},
		PerIPDailyBudget:   f.perIPDailyBudget,
		PerCodeDailyBudget: f.perCodeDailyBudget,
		GlobalDailyBudget:  f.globalDailyBudget,
		SessionEnv:         sessionEnv,
		InternalPort:       f.internalPort,
		DeadlineGrace:      f.deadlineGrace,
		TrustForwardedFor:  f.trustForwardedFor,
		AllowOrigin:        f.allowOrigin,
	})
	if err != nil {
		return nil, nil, err
	}
	_, _ = fmt.Fprintf(out, "broker configured: %d code(s), capacity %d, image %s\n", len(codes), f.concurrency, f.image)

	// The broker API lives under /api/live/*. When a static UI directory is
	// configured, serve it at / on the SAME origin so the live viewer's
	// relative /api/live/* calls reach the broker and one CF Access gate covers
	// both. The API mux is mounted at the /api/live/ prefix; everything else is
	// static files. Mirrors the per-VM server's static-dir handling.
	handler := srv.Handler()
	if strings.TrimSpace(f.staticDir) != "" {
		mux := http.NewServeMux()
		mux.Handle(livechat.RouteAPIPrefix, srv.Handler())
		mux.Handle("/", http.FileServer(http.Dir(f.staticDir)))
		handler = mux
		_, _ = fmt.Fprintf(out, "serving static UI from %s at /\n", f.staticDir)
	}
	hosts, err := brokerPublicHosts(f)
	if err != nil {
		return nil, nil, err
	}
	if len(hosts) > 0 {
		handler = hostGuard(handler, hosts)
		_, _ = fmt.Fprintf(out, "broker public host guard enabled for %s\n", strings.Join(hosts, ", "))
	}
	cfAccess, err := newCFAccessVerifier(f)
	if err != nil {
		return nil, nil, err
	}
	if cfAccess != nil {
		handler = cfAccessGuard(handler, cfAccess)
		_, _ = fmt.Fprintf(out, "broker Cloudflare Access JWT guard enabled for %s\n", cfAccess.issuer)
	}
	return srv, handler, nil
}

func defaultMachineProvider(_ context.Context, f *serveFlags, flyToken string) (broker.MachineProvider, error) {
	if f.provider != "fly" {
		return nil, fmt.Errorf("--provider %q is not supported", f.provider)
	}
	return &broker.FlyMachines{
		AppName: f.flyApp,
		Token:   flyToken,
	}, nil
}

func validateFlags(f *serveFlags) error {
	if f == nil {
		return errors.New("nil serve flags")
	}
	if strings.TrimSpace(f.image) == "" {
		return errors.New("--image is required")
	}
	if strings.TrimSpace(f.flyApp) == "" {
		return errors.New("--fly-app is required")
	}
	if strings.TrimSpace(f.flyTokenFile) == "" && strings.TrimSpace(f.flyTokenEnv) == "" {
		return errors.New("a Fly API token is required: pass --fly-token-file or --fly-token-env")
	}
	if f.concurrency <= 0 {
		return errors.New("--concurrency must be > 0")
	}
	if f.maxPerCode < 0 {
		return errors.New("--max-per-code must be >= 0")
	}
	if len(f.codes) == 0 {
		return errors.New("no invite codes: pass --code CODE")
	}
	if f.internalPort < 1 || f.internalPort > 65535 {
		return errors.New("--internal-port must be 1-65535")
	}
	if f.memoryMB < 0 {
		return errors.New("--memory-mb must be >= 0")
	}
	if f.cpus < 0 {
		return errors.New("--cpus must be >= 0")
	}
	if f.perIPDailyBudget < 0 || f.perCodeDailyBudget < 0 || f.globalDailyBudget < 0 {
		return errors.New("daily budgets must be >= 0")
	}
	if f.sessionTTL <= 0 {
		return errors.New("--session-ttl must be > 0")
	}
	if f.deadlineGrace < 0 {
		return errors.New("--deadline-grace must be >= 0")
	}
	if err := validateAllowOrigin(f.allowOrigin); err != nil {
		return fmt.Errorf("--allow-origin: %w", err)
	}
	if err := validateCFAccessFlags(f); err != nil {
		return err
	}
	return nil
}

func validateAllowOrigin(raw string) error {
	if raw == "" {
		return nil
	}
	if strings.TrimSpace(raw) != raw {
		return errors.New("must not contain surrounding whitespace")
	}
	if raw == "*" {
		return errors.New("wildcard is not allowed")
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

func brokerPublicHosts(f *serveFlags) ([]string, error) {
	seen := make(map[string]struct{})
	var hosts []string
	add := func(raw string) error {
		host, err := normalizePublicHost(raw)
		if err != nil {
			return err
		}
		if host == "" {
			return nil
		}
		if _, ok := seen[host]; ok {
			return nil
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
		return nil
	}
	for _, h := range f.publicHosts {
		if err := add(h); err != nil {
			return nil, fmt.Errorf("--public-host: %w", err)
		}
	}
	if len(hosts) == 0 && f.allowOrigin != "" {
		u, err := url.Parse(f.allowOrigin)
		if err != nil {
			return nil, fmt.Errorf("--allow-origin: parse: %w", err)
		}
		if err := add(u.Host); err != nil {
			return nil, fmt.Errorf("--allow-origin host: %w", err)
		}
	}
	return hosts, nil
}

func normalizePublicHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.Contains(raw, "://") {
		return "", errors.New("must be a host, not a URL")
	}
	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSuffix(host, "."), "[]")
	host = strings.ToLower(host)
	if host == "" || strings.ContainsAny(host, "/?# \t\r\n") {
		return "", fmt.Errorf("invalid host %q", raw)
	}
	return host, nil
}

func hostGuard(next http.Handler, allowed []string) http.Handler {
	set := make(map[string]struct{}, len(allowed))
	for _, h := range allowed {
		if norm, err := normalizePublicHost(h); err == nil && norm != "" {
			set[norm] = struct{}{}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, err := normalizePublicHost(r.Host)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if _, ok := set[host]; !ok {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type cfAccessVerifier struct {
	issuer   string
	audience string
	certsURL string
	client   *http.Client
	now      func() time.Time

	mu      sync.RWMutex
	keys    *jose.JSONWebKeySet
	keysExp time.Time
}

func validateCFAccessFlags(f *serveFlags) error {
	team := strings.TrimSpace(f.cfAccessTeamDomain)
	aud := strings.TrimSpace(f.cfAccessAUD)
	if team == "" && aud == "" {
		if strings.TrimSpace(f.cfAccessCertsURL) != "" {
			return errors.New("--cf-access-certs-url requires --cf-access-team-domain and --cf-access-aud")
		}
		return nil
	}
	if team == "" || aud == "" {
		return errors.New("--cf-access-team-domain and --cf-access-aud must be set together")
	}
	if _, err := normalizeCFAccessTeamDomain(team); err != nil {
		return fmt.Errorf("--cf-access-team-domain: %w", err)
	}
	if strings.ContainsAny(aud, " \t\r\n") {
		return errors.New("--cf-access-aud must not contain whitespace")
	}
	if raw := strings.TrimSpace(f.cfAccessCertsURL); raw != "" {
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("--cf-access-certs-url: parse: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return errors.New("--cf-access-certs-url must be http(s)")
		}
		if u.Host == "" {
			return errors.New("--cf-access-certs-url host is required")
		}
	}
	return nil
}

func newCFAccessVerifier(f *serveFlags) (*cfAccessVerifier, error) {
	team := strings.TrimSpace(f.cfAccessTeamDomain)
	aud := strings.TrimSpace(f.cfAccessAUD)
	if team == "" && aud == "" {
		return nil, nil
	}
	issuer, err := normalizeCFAccessTeamDomain(team)
	if err != nil {
		return nil, fmt.Errorf("--cf-access-team-domain: %w", err)
	}
	certsURL := strings.TrimSpace(f.cfAccessCertsURL)
	if certsURL == "" {
		certsURL = issuer + "/cdn-cgi/access/certs"
	}
	return &cfAccessVerifier{
		issuer:   issuer,
		audience: aud,
		certsURL: certsURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		now: time.Now,
	}, nil
}

func normalizeCFAccessTeamDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	if u.Scheme != "https" {
		return "", errors.New("must use https")
	}
	if u.Host == "" {
		return "", errors.New("host is required")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("must be only the Access team domain")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Host, "."))
	return "https://" + host, nil
}

func cfAccessGuard(next http.Handler, verifier *cfAccessVerifier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(r.Header.Get(cfAccessJWTHeader))
		if token == "" {
			http.Error(w, "missing Cloudflare Access JWT", http.StatusForbidden)
			return
		}
		if err := verifier.verify(r.Context(), token); err != nil {
			http.Error(w, "invalid Cloudflare Access JWT", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (v *cfAccessVerifier) verify(ctx context.Context, raw string) error {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return fmt.Errorf("parse access jwt: %w", err)
	}
	keys, err := v.keySet(ctx)
	if err != nil {
		return err
	}
	var claims jwt.Claims
	if err := tok.Claims(keys, &claims); err != nil {
		return fmt.Errorf("verify access jwt signature: %w", err)
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      v.issuer,
		AnyAudience: jwt.Audience{v.audience},
		Time:        v.now(),
	}, 30*time.Second); err != nil {
		return fmt.Errorf("validate access jwt claims: %w", err)
	}
	return nil
}

func (v *cfAccessVerifier) keySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	now := v.now()
	v.mu.RLock()
	if v.keys != nil && now.Before(v.keysExp) {
		defer v.mu.RUnlock()
		return v.keys, nil
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()
	now = v.now()
	if v.keys != nil && now.Before(v.keysExp) {
		return v.keys, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.certsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build Cloudflare Access JWKS request: %w", err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch Cloudflare Access JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch Cloudflare Access JWKS: status %d", resp.StatusCode)
	}
	var keys jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&keys); err != nil {
		return nil, fmt.Errorf("decode Cloudflare Access JWKS: %w", err)
	}
	if len(keys.Keys) == 0 {
		return nil, errors.New("cloudflare access jwks is empty")
	}
	v.keys = &keys
	v.keysExp = now.Add(cfAccessKeysTTL)
	return v.keys, nil
}

// resolveFlyToken reads the Fly API token from the configured file or env var.
// The file path wins when both are set. The token is never logged.
func resolveFlyToken(f *serveFlags) (string, error) {
	if strings.TrimSpace(f.flyTokenFile) != "" {
		return readRequiredFile(f.flyTokenFile, "--fly-token-file")
	}
	v := strings.TrimSpace(os.Getenv(f.flyTokenEnv))
	if v == "" {
		return "", fmt.Errorf("%s is empty or unset", f.flyTokenEnv)
	}
	return v, nil
}

func resolveGateSecret(file, envName string) ([]byte, error) {
	var raw string
	var err error
	switch {
	case file != "":
		raw, err = readRequiredFile(file, "--gate-secret-file")
	case envName != "":
		raw = strings.TrimSpace(os.Getenv(envName))
		if raw == "" {
			err = fmt.Errorf("%s is empty or unset", envName)
		}
	default:
		return livechat.NewSecret()
	}
	if err != nil {
		return nil, err
	}
	secret, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode broker gate secret: %w", err)
	}
	return secret, nil
}

func resolveCodes(codes []string, maxPerCode int) ([]livechat.CodeSpec, error) {
	if len(codes) == 0 {
		return nil, errors.New("no invite codes: pass --code CODE")
	}
	specs := make([]livechat.CodeSpec, 0, len(codes))
	for _, code := range codes {
		if strings.TrimSpace(code) == "" {
			return nil, errors.New("invite code cannot be empty or whitespace")
		}
		specs = append(specs, livechat.CodeSpec{Code: code, MaxSessions: maxPerCode})
	}
	return specs, nil
}

// buildVMBaseEnv assembles the PLAYGROUND_* environment shared by every
// per-visitor VM. The deploy entrypoint (deploy/fly-playground/entrypoint.sh)
// consumes these env vars into `serve` flags — keep the names in sync with it.
// The per-session invite code (PLAYGROUND_CODE) and the secrets
// (PLAYGROUND_MODEL_KEY / PLAYGROUND_ORCHESTRATOR_KEY) are layered in elsewhere
// (broker sessionEnv / resolveSessionEnv), not here.
func buildVMBaseEnv(f *serveFlags) map[string]string {
	env := map[string]string{
		"PLAYGROUND_LISTEN": fmt.Sprintf("0.0.0.0:%d", f.internalPort),
	}
	if f.vmModelBaseURL != "" {
		env["PLAYGROUND_MODEL_BASE_URL"] = f.vmModelBaseURL
	}
	if f.vmModel != "" {
		env["PLAYGROUND_MODEL"] = f.vmModel
	}
	if f.vmModelMaxSteps > 0 {
		env["PLAYGROUND_MODEL_MAX_STEPS"] = strconv.Itoa(f.vmModelMaxSteps)
	}
	if f.vmDailyTurnBudget > 0 {
		env["PLAYGROUND_DAILY_TURN_BUDGET"] = strconv.Itoa(f.vmDailyTurnBudget)
	}
	if f.vmSessionTTL > 0 {
		env["PLAYGROUND_SESSION_TTL"] = f.vmSessionTTL.String()
	}
	if f.vmMaxMessages > 0 {
		env["PLAYGROUND_MAX_MESSAGES"] = strconv.Itoa(f.vmMaxMessages)
	}
	return env
}

func resolveSessionEnv(f *serveFlags) (map[string]string, error) {
	model, err := resolveSessionSecret(f.modelKeyFile, f.modelKeyEnv, "--model-key-file", envModelKey, f.requireSessionSecrets)
	if err != nil {
		return nil, err
	}
	orchestrator, err := resolveSessionSecret(f.orchestratorKeyFile, f.orchestratorKeyEnv, "--orchestrator-key-file", envOrchestratorKey, f.requireSessionSecrets)
	if err != nil {
		return nil, err
	}
	env := make(map[string]string)
	if model != "" {
		env[envModelKey] = model
	}
	if orchestrator != "" {
		env[envOrchestratorKey] = orchestrator
	}
	return env, nil
}

func resolveSessionSecret(file, envName, flagName, defaultEnv string, required bool) (string, error) {
	switch {
	case file != "":
		return readRequiredFile(file, flagName)
	case envName != "":
		v := strings.TrimSpace(os.Getenv(envName))
		if v == "" {
			return "", fmt.Errorf("%s is empty or unset", envName)
		}
		return v, nil
	default:
		v := strings.TrimSpace(os.Getenv(defaultEnv))
		if v != "" {
			return v, nil
		}
		if required {
			return "", fmt.Errorf("%s or --%s-env is required", flagName, strings.TrimPrefix(strings.TrimPrefix(flagName, "--"), "-"))
		}
		return "", nil
	}
}

func readRequiredFile(path, name string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	return value, nil
}
