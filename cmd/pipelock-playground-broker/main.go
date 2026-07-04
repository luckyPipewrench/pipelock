// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for pipelock-playground-broker, the public
// playground front door that leases one private per-visitor VM and reverse
// proxies the /api/live/* session API to it.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
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
	defaultListen         = "127.0.0.1:8100"
	defaultConcurrency    = 3
	defaultMaxPerCode     = 25
	defaultSessionTTL     = 10 * time.Minute
	defaultGrace          = 30 * time.Second
	defaultIPRate         = 0.5
	defaultIPBurst        = 5
	defaultCodeRate       = 0.5
	defaultCodeBurst      = 10
	nonStreamWriteTimeout = 30 * time.Second
	// sessionWriteTimeout bounds the session-create response write. It must exceed
	// the WHOLE cold-path budget, summed across every stage, or a legitimate cold
	// start fails closed mid-response (the 30s default did exactly that: Fly PU02
	// / client 502). On a warm-pool MISS the handler runs, in sequence, three
	// independently-bounded Fly/broker calls before it writes the response:
	//   - CreateMachine  — Fly adapter HTTP client timeout ~65s (waitTimeout+5s)
	//   - WaitReady      — Fly adapter HTTP client timeout ~65s (incl. image pull)
	//   - createVMSession — broker vmReadyTimeout ~60s
	// i.e. a code-level worst case of ~190s. The ceiling is set above that with
	// margin so a cold miss completes, while still CAPPING a slow/non-reading
	// client (a full exemption would leave that goroutine-pin hole open; the
	// concurrency cap bounds how many such pins can exist). The warm-pool common
	// path is ~2-3s; this ceiling only bites on a cold miss.
	sessionWriteTimeout      = 300 * time.Second
	cfAccessJWTHeader        = "Cf-Access-Jwt-Assertion"
	cfAccessKeysTTL          = 5 * time.Minute
	cfAccessNegativeCacheTTL = 30 * time.Second

	envModelKey        = "PLAYGROUND_MODEL_" + "KEY"
	envOrchestratorKey = "PLAYGROUND_ORCHESTRATOR_" + "KEY"

	// warmPoolVMCodeBytes mirrors broker.vmInviteCodeBytes for warm-pool VM
	// code generation. Kept in sync with the broker constant.
	warmPoolVMCodeBytes = 18
)

type serveFlags struct {
	listen                    string
	adminListen               string
	adminTokenFile            string
	adminTokenEnv             string
	unsafeAdminListenPublic   bool
	staticDir                 string
	provider                  string
	flyApp                    string
	flyTokenFile              string
	flyTokenEnv               string
	image                     string
	region                    string
	memoryMB                  int
	cpus                      int
	internalPort              int
	concurrency               int
	codes                     []string
	maxPerCode                int
	gateSecretFile            string
	gateSecretEnv             string
	ipRate                    float64
	ipBurst                   float64
	codeRate                  float64
	codeBurst                 float64
	perIPDailyBudget          int
	perCodeDailyBudget        int
	globalDailyBudget         int
	unsafeUnlimited           bool
	unsafeNoHumanGate         bool
	turnstileSecretFile       string
	turnstileSecretEnv        string
	turnstileVerifyURL        string
	turnstileExpectedHostname string
	turnstileExpectedAction   string
	turnstileMaxAge           time.Duration
	turnstileSitekey          string
	sessionTTL                time.Duration
	deadlineGrace             time.Duration
	allowOrigin               string
	publicHosts               []string
	cfAccessTeamDomain        string
	cfAccessAUD               string
	cfAccessCertsURL          string
	cfAccessDefaultCode       string
	defaultCode               string
	trustForwardedFor         bool
	modelKeyFile              string
	modelKeyEnv               string
	orchestratorKeyFile       string
	orchestratorKeyEnv        string
	requireSessionSecrets     bool
	warmPoolSize              int
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
	fl.StringVar(&f.adminListen, "admin-listen", "", "separate admin listen address for authenticated pause/resume endpoints; empty disables")
	fl.StringVar(&f.adminTokenFile, "admin-token-file", "", "path to bearer token required by --admin-listen")
	fl.StringVar(&f.adminTokenEnv, "admin-token-env", "", "environment variable holding bearer token required by --admin-listen")
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
	fl.BoolVar(&f.unsafeUnlimited, "unsafe-unlimited-budgets", false, "allow unlimited public broker/model budgets; unsafe for public deployments")
	fl.BoolVar(&f.unsafeNoHumanGate, "unsafe-no-human-gate", false, "allow session creation without Turnstile or Cloudflare Access; unsafe for public deployments")
	fl.BoolVar(&f.unsafeAdminListenPublic, "unsafe-admin-listen-public", false, "allow --admin-listen on a public/unspecified address; unsafe outside container netns")
	fl.StringVar(&f.turnstileSecretFile, "turnstile-secret-file", "", "path to the Cloudflare Turnstile secret; enables human verification for session creation")
	fl.StringVar(&f.turnstileSecretEnv, "turnstile-secret-env", "", "environment variable holding the Cloudflare Turnstile secret; enables human verification for session creation")
	fl.StringVar(&f.turnstileVerifyURL, "turnstile-verify-url", "", "Cloudflare Turnstile Siteverify URL override (tests/dev only; empty uses Cloudflare)")
	fl.StringVar(&f.turnstileExpectedHostname, "turnstile-expected-hostname", "", "expected hostname in the Turnstile Siteverify response; required when Turnstile runs against Cloudflare")
	fl.StringVar(&f.turnstileExpectedAction, "turnstile-action", "", "expected action label in the Turnstile Siteverify response; required when Turnstile runs against Cloudflare")
	fl.DurationVar(&f.turnstileMaxAge, "turnstile-max-age", broker.DefaultTurnstileMaxAge, "max age for a Turnstile challenge_ts before it is rejected (0 disables)")
	fl.StringVar(&f.turnstileSitekey, "turnstile-sitekey", "", "public Cloudflare Turnstile site key; reported via /health so the viewer renders the widget (the secret is set separately via --turnstile-secret-*)")
	fl.DurationVar(&f.sessionTTL, "session-ttl", defaultSessionTTL, "VM session token TTL")
	fl.DurationVar(&f.deadlineGrace, "deadline-grace", defaultGrace, "lease teardown grace after VM session expiry")
	fl.StringVar(&f.allowOrigin, "allow-origin", "", "Access-Control-Allow-Origin for the browser")
	fl.StringArrayVar(&f.publicHosts, "public-host", nil, "allowed public Host header for the broker (repeatable); defaults to the --allow-origin host when set")
	fl.StringVar(&f.cfAccessTeamDomain, "cf-access-team-domain", "", "Cloudflare Access team domain, e.g. https://team.cloudflareaccess.com; enables origin-side Access JWT validation when set with --cf-access-aud")
	fl.StringVar(&f.cfAccessAUD, "cf-access-aud", "", "Cloudflare Access application AUD tag expected in Cf-Access-Jwt-Assertion")
	fl.StringVar(&f.cfAccessCertsURL, "cf-access-certs-url", "", "override Cloudflare Access JWKS URL (tests/dev only; defaults to <team-domain>/cdn-cgi/access/certs)")
	fl.StringVar(&f.cfAccessDefaultCode, "cf-access-default-code", "", "invite code used when an Access-gated request sends none, so allowlisted users skip the code prompt; REQUIRES --cf-access-team-domain/--cf-access-aud and must be one of the --code values")
	fl.StringVar(&f.defaultCode, "default-code", "", "invite code auto-applied when a session request sends none, so public visitors skip the code prompt; REQUIRES a human gate (--turnstile-secret-* or Cloudflare Access) and must be one of the --code values. Use this for a public Turnstile-gated demo (no email allowlist)")
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
	fl.IntVar(&f.warmPoolSize, "warm-pool-size", 0, "number of pre-created warm VMs to maintain (0 = disabled)")
	return cmd
}

func runServe(cmd *cobra.Command, f *serveFlags) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	srv, handler, startReaper, pool, err := buildServer(ctx, cmd.OutOrStdout(), f)
	if err != nil {
		return err
	}
	defer srv.Close()

	// Start the orphan-VM reaper under a context that cancels when the serve
	// function returns (server close / shutdown / signal).
	reaperCtx, reaperCancel := context.WithCancel(ctx)
	defer reaperCancel()
	go startReaper(reaperCtx)

	// Start the warm pool maintainer if enabled; drain on shutdown.
	// INVARIANT 4: warm VMs are drained on graceful shutdown.
	if pool != nil {
		poolCtx, poolCancel := context.WithCancel(ctx)
		defer func() {
			poolCancel()
			pool.Drain(context.Background())
		}()
		go pool.Run(poolCtx)
	}

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
	stopSignals := startSignalControlLoop(ctx, cmd.OutOrStdout(), srv, httpSrv)
	defer stopSignals()
	stopAdmin, err := startAdminServer(ctx, cmd.OutOrStdout(), f, srv)
	if err != nil {
		return err
	}
	defer stopAdmin()
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "pipelock-playground-broker serving on %s with provider %s\n", f.listen, f.provider)
	if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func buildServer(ctx context.Context, out io.Writer, f *serveFlags) (*broker.Server, http.Handler, func(context.Context), *broker.Pool, error) {
	if err := validateFlags(f); err != nil {
		return nil, nil, nil, nil, err
	}
	secret, err := resolveGateSecret(f.gateSecretFile, f.gateSecretEnv)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	codes, err := resolveCodes(f.codes, f.maxPerCode)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	gate, err := livechat.NewGate(livechat.GateConfig{
		Secret:   secret,
		Codes:    codes,
		TokenTTL: f.sessionTTL,
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	token, err := resolveFlyToken(f)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	provider, err := newMachineProvider(ctx, f, token)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sessionEnv, err := resolveSessionEnv(f)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	humanVerifier, err := resolveTurnstileVerifier(f)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// The concurrency limiter is shared between the LeaseManager and the
	// optional warm pool so warm + active machines never exceed the cap.
	concLimiter := livechat.NewConcurrencyLimiter(f.concurrency)

	baseEnv := buildVMBaseEnv(f)
	lm, err := broker.NewLeaseManager(broker.LeaseConfig{
		Provider:     provider,
		Concurrency:  concLimiter,
		Image:        f.image,
		Region:       f.region,
		MemoryMB:     f.memoryMB,
		CPUs:         f.cpus,
		InternalPort: f.internalPort,
		BaseEnv:      baseEnv,
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Build the optional warm pool when --warm-pool-size > 0.
	var warmPool *broker.Pool
	if f.warmPoolSize > 0 {
		pool, poolErr := broker.NewPool(broker.PoolConfig{
			Provider:    provider,
			Concurrency: concLimiter,
			NewVMCode: func() (string, error) {
				return livechat.NewRandomCode(warmPoolVMCodeBytes)
			},
			BuildSpec: func(vmCode string) broker.MachineSpec {
				return broker.MachineSpec{
					Image:        f.image,
					Env:          mergeSessionAndBaseEnv(sessionEnv, baseEnv, vmCode),
					Region:       f.region,
					MemoryMB:     f.memoryMB,
					CPUs:         f.cpus,
					InternalPort: f.internalPort,
				}
			},
			Size: f.warmPoolSize,
			Log:  out,
		})
		if poolErr != nil {
			return nil, nil, nil, nil, poolErr
		}
		warmPool = pool
		_, _ = fmt.Fprintf(out, "warm pool enabled: size %d\n", f.warmPoolSize)
	}

	srv, err := broker.NewServer(broker.ServerConfig{
		Leases:             lm,
		WarmPool:           warmPool,
		Gate:               gate,
		DefaultCode:        effectiveDefaultCode(f),
		TurnstileSitekey:   f.turnstileSitekey,
		HumanVerifier:      humanVerifier,
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
		return nil, nil, nil, nil, err
	}

	// The reaper's protected-ID set is (warm pool + in-flight handoffs) UNION
	// (active leases). INVARIANT 2: the reaper MUST NOT destroy warm or
	// handing-off VMs.
	//
	// HAND-OVER-HAND ORDERING (do NOT reorder these two reads): a machine's
	// protection moves from the pool's handoff set to the lease's active set, and
	// the pool clears the handoff marker only AFTER AdoptWarm has registered the
	// active lease (handleSession calls FinishHandoff after AdoptWarm). The two
	// sets are independently locked, so this snapshot is non-atomic. We therefore
	// read the SOURCE (warm + handoff) FIRST and the DESTINATION (active leases)
	// SECOND: if a machine has already left handoff between the reads, it is
	// guaranteed to be in active by the time we read active (and stays there until
	// the session ends). Reading active first would let a machine that adopts +
	// finishes between the two reads fall out of BOTH snapshots, and the reaper
	// could destroy a live VM (TOCTOU).
	activeIDsFn := func() map[string]struct{} {
		if warmPool == nil {
			return lm.ActiveMachineIDs()
		}
		ids := warmPool.WarmMachineIDs()        // source: warm + in-flight handoff, FIRST
		for id := range lm.ActiveMachineIDs() { // destination: active leases, SECOND
			ids[id] = struct{}{}
		}
		return ids
	}
	reaper, err := broker.NewReaper(broker.ReaperConfig{
		Provider:  provider,
		ActiveIDs: activeIDsFn,
		Log:       out,
	})
	if err != nil {
		return nil, nil, nil, nil, err
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
		mux.Handle("/", noCacheStatic(http.FileServer(http.Dir(f.staticDir))))
		handler = mux
		_, _ = fmt.Fprintf(out, "serving static UI from %s at /\n", f.staticDir)
	}
	// Per-route write deadlines. Stream writes indefinitely and the message route
	// is held open for the whole model turn, so both are exempt (deadline 0).
	// Session-create synchronously boots and proves a fresh per-visitor microVM;
	// on a cold start that legitimately exceeds the default 30s (a 30s deadline
	// made cold starts fail closed mid-response: Fly PU02 / client 502), so it
	// gets a longer BOUNDED deadline (sessionWriteTimeout > the 60s vmReadyTimeout)
	// rather than a full exemption — capping a slow reader without cutting off a
	// healthy boot. Everything else gets the default fast deadline.
	handler = writeDeadlineMiddleware(handler, nonStreamWriteTimeout, map[string]time.Duration{
		livechat.RouteStream:  0,
		livechat.RouteMessage: 0,
		livechat.RouteSession: sessionWriteTimeout,
		// The signed bundle / verify kit can be large (one receipt per action — a
		// long session is hundreds of KB) and the VM generates it on demand, so a
		// 30s write deadline truncates the proxied download mid-body (Fly "could
		// not finish reading HTTP body from instance"). Give it the same long
		// bounded budget as session-create.
		livechat.RouteBundle: sessionWriteTimeout,
	})

	hosts, err := brokerPublicHosts(f)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(hosts) > 0 {
		handler = hostGuard(handler, hosts)
		_, _ = fmt.Fprintf(out, "broker public host guard enabled for %s\n", strings.Join(hosts, ", "))
	}
	cfAccess, err := newCFAccessVerifier(f)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if cfAccess != nil {
		handler = cfAccessGuard(handler, cfAccess)
		_, _ = fmt.Fprintf(out, "broker Cloudflare Access JWT guard enabled for %s\n", cfAccess.issuer)
	}
	return srv, handler, reaper.Run, warmPool, nil
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
	if err := validateAdminFlags(f); err != nil {
		return err
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
	if !f.unsafeUnlimited {
		if f.globalDailyBudget <= 0 {
			return errors.New("--global-daily-budget must be > 0 unless --unsafe-unlimited-budgets is set")
		}
		if f.vmDailyTurnBudget <= 0 {
			return errors.New("--vm-daily-turn-budget must be > 0 unless --unsafe-unlimited-budgets is set")
		}
	}
	if err := validateHumanGateFlags(f); err != nil {
		return err
	}
	if f.sessionTTL <= 0 {
		return errors.New("--session-ttl must be > 0")
	}
	if err := validateTurnstileFlags(f); err != nil {
		return err
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
	if err := validateDefaultCode(f); err != nil {
		return err
	}
	return nil
}

// effectiveDefaultCode is the server-side invite code auto-applied when a
// session request sends none. The general --default-code wins; --cf-access-default-code
// remains as the Access-only alias. Empty means "client must send a code".
func effectiveDefaultCode(f *serveFlags) string {
	if dc := strings.TrimSpace(f.defaultCode); dc != "" {
		return dc
	}
	return strings.TrimSpace(f.cfAccessDefaultCode)
}

// validateDefaultCode fails closed on --default-code: like --cf-access-default-code
// it lets visitors skip the invite-code prompt, so it is only safe behind a human
// gate (Turnstile OR Cloudflare Access) — never with no gate / --unsafe-no-human-gate
// alone, which would let ANYONE create sessions code-free. It must also name a real
// --code. (--cf-access-default-code keeps its own Access-only check in validateCFAccessFlags.)
func validateDefaultCode(f *serveFlags) error {
	dc := strings.TrimSpace(f.defaultCode)
	if dc == "" {
		return nil
	}
	if cfdc := strings.TrimSpace(f.cfAccessDefaultCode); cfdc != "" && cfdc != dc {
		return errors.New("set only one of --default-code or --cf-access-default-code")
	}
	hasTurnstile := strings.TrimSpace(f.turnstileSecretFile) != "" || strings.TrimSpace(f.turnstileSecretEnv) != ""
	hasCFAccess := strings.TrimSpace(f.cfAccessTeamDomain) != "" || strings.TrimSpace(f.cfAccessAUD) != ""
	if !hasTurnstile && !hasCFAccess {
		return errors.New("--default-code requires a human gate (--turnstile-secret-file/--turnstile-secret-env or Cloudflare Access); a default code with no human gate would open the broker")
	}
	for _, c := range f.codes {
		if strings.TrimSpace(c) == dc {
			return nil
		}
	}
	return errors.New("--default-code must be one of the --code values")
}

func validateAdminFlags(f *serveFlags) error {
	listen := strings.TrimSpace(f.adminListen)
	tokenFile := strings.TrimSpace(f.adminTokenFile)
	tokenEnv := strings.TrimSpace(f.adminTokenEnv)
	if listen == "" {
		if tokenFile != "" || tokenEnv != "" {
			return errors.New("--admin-token-file/--admin-token-env require --admin-listen")
		}
		return nil
	}
	if tokenFile == "" && tokenEnv == "" {
		return errors.New("--admin-listen requires --admin-token-file or --admin-token-env")
	}
	if err := validateAdminListenScope(listen, f.unsafeAdminListenPublic); err != nil {
		return err
	}
	return nil
}

// validateAdminListenScope rejects admin listen addresses that bind to public
// or unspecified IPs unless the operator explicitly opts in with
// --unsafe-admin-listen-public. Loopback and RFC1918/ULA/link-local are safe.
func validateAdminListenScope(listen string, unsafePublic bool) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		// May be a bare port like ":9090" — host is empty.
		host = listen
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		// Empty host = unspecified address (binds all interfaces).
		if unsafePublic {
			return nil
		}
		return errors.New("--admin-listen binds to all interfaces (unspecified address); use a loopback/private address or pass --unsafe-admin-listen-public")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Not a numeric IP — could be a hostname. Allow loopback names.
		lower := strings.ToLower(host)
		if lower == "localhost" {
			return nil
		}
		if unsafePublic {
			return nil
		}
		return fmt.Errorf("--admin-listen host %q is not a recognized private address; use a loopback/private address or pass --unsafe-admin-listen-public", host)
	}
	if addr.IsUnspecified() {
		if unsafePublic {
			return nil
		}
		return errors.New("--admin-listen binds to all interfaces (unspecified address); use a loopback/private address or pass --unsafe-admin-listen-public")
	}
	if isPrivateOrLoopback(addr) {
		return nil
	}
	if unsafePublic {
		return nil
	}
	return fmt.Errorf("--admin-listen address %s is public; use a loopback/private address or pass --unsafe-admin-listen-public", addr)
}

// isPrivateOrLoopback returns true for loopback, link-local, RFC1918, and ULA
// addresses — the address classes safe for an admin listener without explicit
// opt-in.
func isPrivateOrLoopback(addr netip.Addr) bool {
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()
}

func validateHumanGateFlags(f *serveFlags) error {
	hasTurnstile := strings.TrimSpace(f.turnstileSecretFile) != "" || strings.TrimSpace(f.turnstileSecretEnv) != ""
	hasCFAccess := strings.TrimSpace(f.cfAccessTeamDomain) != "" || strings.TrimSpace(f.cfAccessAUD) != ""
	if hasTurnstile || hasCFAccess || f.unsafeNoHumanGate {
		return nil
	}
	return errors.New("--turnstile-secret-file/--turnstile-secret-env or Cloudflare Access is required unless --unsafe-no-human-gate is set")
}

func validateTurnstileFlags(f *serveFlags) error {
	configured := strings.TrimSpace(f.turnstileSecretFile) != "" || strings.TrimSpace(f.turnstileSecretEnv) != ""
	if f.turnstileMaxAge < 0 {
		return errors.New("--turnstile-max-age must be >= 0")
	}
	if !configured && strings.TrimSpace(f.turnstileVerifyURL) != "" {
		return errors.New("--turnstile-verify-url requires --turnstile-secret-file or --turnstile-secret-env")
	}
	// The endpoint is Cloudflare's production Siteverify when no override is set
	// OR the override explicitly points at challenges.cloudflare.com. In that
	// case the hostname + action bindings are mandatory, not advisory: without
	// them a token solved for another page/action could be replayed against this
	// broker. Only a non-Cloudflare override (a local dev/test stub) is exempt.
	cloudflareEndpoint := strings.TrimSpace(f.turnstileVerifyURL) == ""
	if v := strings.TrimSpace(f.turnstileVerifyURL); v != "" {
		if u, err := url.Parse(v); err == nil && strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), "challenges.cloudflare.com") {
			cloudflareEndpoint = true
		}
	}
	if configured && cloudflareEndpoint {
		if strings.TrimSpace(f.turnstileExpectedHostname) == "" || strings.TrimSpace(f.turnstileExpectedAction) == "" {
			return errors.New("--turnstile-expected-hostname and --turnstile-action are required when Turnstile is enabled against Cloudflare (use a non-Cloudflare --turnstile-verify-url for dev/test only)")
		}
	}
	if strings.TrimSpace(f.turnstileVerifyURL) == "" {
		return nil
	}
	u, err := url.Parse(f.turnstileVerifyURL)
	if err != nil {
		return fmt.Errorf("--turnstile-verify-url: parse: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("--turnstile-verify-url must be http(s)")
	}
	if u.Host == "" {
		return errors.New("--turnstile-verify-url host is required")
	}
	return nil
}

func startSignalControlLoop(ctx context.Context, out io.Writer, srv *broker.Server, httpSrv *http.Server) func() {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, controlSignals()...)
	stopCh := make(chan struct{})
	done := make(chan struct{})
	var shutdownOnce sync.Once
	shutdown := func(reason string) {
		shutdownOnce.Do(func() {
			_, _ = fmt.Fprintf(out, "broker shutting down: %s\n", reason)
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = httpSrv.Shutdown(shutdownCtx)
		})
	}
	go func() {
		defer close(done)
		for {
			select {
			case sig := <-sigCh:
				if applyControlSignal(out, srv, sig) {
					shutdown(sig.String())
					return
				}
			case <-ctx.Done():
				shutdown("context canceled")
				return
			case <-stopCh:
				return
			}
		}
	}()
	return func() {
		signal.Stop(sigCh)
		close(stopCh)
		<-done
	}
}

func startAdminServer(ctx context.Context, out io.Writer, f *serveFlags, srv *broker.Server) (func(), error) {
	if strings.TrimSpace(f.adminListen) == "" {
		return func() {}, nil
	}
	token, err := resolveAdminToken(f)
	if err != nil {
		return nil, err
	}
	httpSrv := &http.Server{
		Handler:           adminHandler(srv, token),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", f.adminListen)
	if err != nil {
		return nil, fmt.Errorf("admin listen %s: %w", f.adminListen, err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			_, _ = fmt.Fprintf(out, "admin server error: %v\n", err)
		}
	}()
	_, _ = fmt.Fprintf(out, "broker admin serving on %s\n", f.adminListen)
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		_ = ln.Close()
		<-done
	}, nil
}

func resolveAdminToken(f *serveFlags) (string, error) {
	if strings.TrimSpace(f.adminTokenFile) != "" {
		return readRequiredFile(f.adminTokenFile, "--admin-token-file")
	}
	v := strings.TrimSpace(os.Getenv(f.adminTokenEnv))
	if v == "" {
		return "", fmt.Errorf("%s is empty or unset", f.adminTokenEnv)
	}
	return v, nil
}

func adminHandler(srv *broker.Server, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/health", func(w http.ResponseWriter, r *http.Request) {
		if !adminAuthorized(r, token) {
			writeAdminAuthErr(w, r)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeAdminJSON(w, http.StatusOK, map[string]any{"killed": srv.Killed()})
	})
	mux.HandleFunc("/admin/pause", func(w http.ResponseWriter, r *http.Request) {
		if !adminAuthorized(r, token) {
			writeAdminAuthErr(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srv.Kill()
		writeAdminJSON(w, http.StatusOK, map[string]any{"killed": true})
	})
	mux.HandleFunc("/admin/resume", func(w http.ResponseWriter, r *http.Request) {
		if !adminAuthorized(r, token) {
			writeAdminAuthErr(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srv.Resume()
		writeAdminJSON(w, http.StatusOK, map[string]any{"killed": false})
	})
	return mux
}

func adminAuthorized(r *http.Request, token string) bool {
	got := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if !strings.HasPrefix(got, prefix) {
		return false
	}
	got = strings.TrimSpace(strings.TrimPrefix(got, prefix))
	if got == "" || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func writeAdminAuthErr(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get("Authorization")) == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	http.Error(w, "invalid bearer token", http.StatusForbidden)
}

func writeAdminJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func applyControlSignal(out io.Writer, srv *broker.Server, sig os.Signal) bool {
	if isPauseSignal(sig) {
		srv.Kill()
		_, _ = fmt.Fprintln(out, "broker paused by SIGUSR1")
		return false
	}
	if isResumeSignal(sig) {
		srv.Resume()
		_, _ = fmt.Fprintln(out, "broker resumed by SIGUSR2")
		return false
	}
	if isShutdownSignal(sig) {
		return true
	}
	return false
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
	if len(hosts) == 0 && f.turnstileExpectedHostname != "" {
		if err := add(f.turnstileExpectedHostname); err != nil {
			return nil, fmt.Errorf("--turnstile-expected-hostname: %w", err)
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

// writeDeadlineMiddleware sets a per-request write deadline on bounded,
// fast-completing routes so a slow reader cannot pin a goroutine, WITHOUT a
// server-level WriteTimeout (which would kill the long-lived routes). The
// exemptPaths are left with NO write deadline because they legitimately exceed
// it: the SSE stream writes indefinitely, and the message route is held open
// for the entire model turn (a multi-step agent turn routinely takes longer
// than the deadline) before the response is written. Those long-lived routes
// are bounded instead by the session TTL and the upstream/edge connection
// timeouts, not by this deadline.
// noCacheStatic sets Cache-Control: no-cache on static viewer assets so the
// browser revalidates them (via ETag/Last-Modified) on every load instead of
// serving a stale copy from disk cache. The demo updates the viewer (HTML/JS/CSS)
// in place behind the same paths, so without revalidation a redeploy leaves
// visitors on a stale viewer — e.g. old example prompts after the assets change.
// no-cache (revalidate), not no-store, keeps 304s cheap when nothing changed.
func noCacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func writeDeadlineMiddleware(next http.Handler, defaultTimeout time.Duration, overrides map[string]time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		d, ok := overrides[r.URL.Path]
		switch {
		case ok && d <= 0:
			// Exempt long-lived route: clear any inherited deadline.
			_ = rc.SetWriteDeadline(time.Time{})
		case ok:
			// Route-specific bounded deadline (e.g. session-create's long
			// cold-start budget). Still bounded so a slow reader can't pin us.
			_ = rc.SetWriteDeadline(time.Now().Add(d))
		default:
			_ = rc.SetWriteDeadline(time.Now().Add(defaultTimeout))
		}
		next.ServeHTTP(w, r)
	})
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

	mu        sync.RWMutex
	keys      *jose.JSONWebKeySet
	keysExp   time.Time
	nextRetry time.Time // negative-cache: skip refetch until this time after a failure
}

func validateCFAccessFlags(f *serveFlags) error {
	team := strings.TrimSpace(f.cfAccessTeamDomain)
	aud := strings.TrimSpace(f.cfAccessAUD)
	// --cf-access-default-code lets Access-gated users skip the invite code.
	// Fail closed: it is only safe behind the Access JWT gate (without it, a
	// default code would let ANYONE create sessions code-free), and it must name
	// a real configured code so the gate can redeem it.
	if dc := strings.TrimSpace(f.cfAccessDefaultCode); dc != "" {
		if team == "" || aud == "" {
			return errors.New("--cf-access-default-code requires --cf-access-team-domain and --cf-access-aud (a default code without a human gate would open the broker)")
		}
		found := false
		for _, c := range f.codes {
			if strings.TrimSpace(c) == dc {
				found = true
				break
			}
		}
		if !found {
			return errors.New("--cf-access-default-code must be one of the --code values")
		}
	}
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

	// Negative-cache: if a previous refetch failed and we have stale keys,
	// serve them until nextRetry to avoid hammering the JWKS endpoint.
	if v.keys != nil && now.Before(v.nextRetry) {
		v.keysExp = now.Add(cfAccessNegativeCacheTTL)
		return v.keys, nil
	}

	keys, fetchErr := v.fetchKeys(ctx)
	if fetchErr != nil {
		// Fail-closed when there are no cached keys at all.
		if v.keys == nil {
			return nil, fetchErr
		}
		// Stale keys exist: serve them and set a negative-cache window.
		v.nextRetry = now.Add(cfAccessNegativeCacheTTL)
		v.keysExp = v.nextRetry
		return v.keys, nil
	}
	v.keys = keys
	v.keysExp = now.Add(cfAccessKeysTTL)
	v.nextRetry = time.Time{}
	return v.keys, nil
}

func (v *cfAccessVerifier) fetchKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
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
	return &keys, nil
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

// mergeSessionAndBaseEnv builds the full VM environment for a warm-pool VM:
// baseEnv (shared config) + sessionEnv (per-session secrets) + the per-VM
// invite code. Mirrors the layering that handleSession does for cold-path VMs.
func mergeSessionAndBaseEnv(sessionEnv, baseEnv map[string]string, vmCode string) map[string]string {
	out := make(map[string]string, len(baseEnv)+len(sessionEnv)+1)
	for k, v := range baseEnv {
		out[k] = v
	}
	for k, v := range sessionEnv {
		out[k] = v
	}
	out["PLAYGROUND_CODE"] = vmCode
	return out
}

func resolveTurnstileVerifier(f *serveFlags) (broker.HumanVerifier, error) {
	file := strings.TrimSpace(f.turnstileSecretFile)
	envName := strings.TrimSpace(f.turnstileSecretEnv)
	if file == "" && envName == "" {
		return nil, nil
	}
	var secretValue string
	var err error
	if file != "" {
		secretValue, err = readRequiredFile(file, "--turnstile-secret-file")
	} else {
		secretValue = strings.TrimSpace(os.Getenv(envName))
		if secretValue == "" {
			err = fmt.Errorf("%s is empty or unset", envName)
		}
	}
	if err != nil {
		return nil, err
	}
	inner := broker.TurnstileVerifier{
		Secret:           secretValue,
		VerifyURL:        strings.TrimSpace(f.turnstileVerifyURL),
		Client:           &http.Client{Timeout: 5 * time.Second},
		ExpectedHostname: strings.TrimSpace(f.turnstileExpectedHostname),
		ExpectedAction:   strings.TrimSpace(f.turnstileExpectedAction),
		MaxAge:           f.turnstileMaxAge,
	}
	return &broker.ReplayGuardVerifier{
		Inner:  inner,
		Seen:   broker.NewSeenTokens(0, nil),
		Failed: broker.NewSeenTokens(broker.DefaultFailedTokenTTL, nil),
	}, nil
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
