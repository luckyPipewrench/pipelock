// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package playground

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/replaycapture"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// .test hostnames used by the live run. RFC 6761 reserved, safe to publish.
// liveRunExfilHost is the collector (the exfil target) the agent posts to; the
// identifier names that role, but the VALUE is deliberately neutral so the
// agent-discovered config and the signed receipt never broadcast "exfil" to a
// visitor on the public find-a-bypass page (the visitor supplies the intent).
const (
	liveRunSafeHost  = "safe.target.test"
	liveRunExfilHost = "intake.lab.test"
)

// liveRunPrincipal and liveRunActor use the same values as the replaycapture
// lab so that the assembled audit packet passes the public-safe field
// allowlist. These are synthetic, non-identifying labels.
const (
	liveRunPrincipal = "pipelock-lab"
	liveRunActor     = "lab-agent"
)

// canaryEnvVar is the env var the toy agent/webtool reads.
const canaryEnvVar = "PLAYGROUND_CANARY_VALUE"

// DefaultContainedProxyPort is the fixed loopback port a contained run should
// bind the in-process proxy to. It mirrors the `pipelock contain install
// --proxy-port` default (internal/cli/contain), so the stock owner-match rule
// (allow agent uid -> 127.0.0.1:8888, drop everything else) lets the contained
// agent reach exactly this proxy and nothing else on loopback. It is the
// command layer's default for contained serves; the library never auto-applies
// it (ProxyPort 0 is always ephemeral). Keep in sync with that contain default;
// an operator who changes one must change both, and the HostContainmentWitness
// fails closed if they diverge.
const DefaultContainedProxyPort = 8888

// LiveRunOpts configures a live playground run.
type LiveRunOpts struct {
	// Contained selects kernel-containment mode (requires sudo). When true, the
	// mediated demo steps still run through the proxy as the operator, and a
	// separate uid-dropped probe phase builds the host-containment witness.
	Contained bool
	// ScenarioID selects the scenario from DefaultScenarios.
	ScenarioID string
	// RunNonce is the unique identifier for this run.
	RunNonce string
	// ToyAgentBin and WebToolBin are paths to the compiled binaries. When
	// empty, StartLiveRun builds them into a temp dir.
	ToyAgentBin string
	WebToolBin  string
	// AgentUser is the OS user used for contained-mode toy-agent execution.
	// Empty means pipelock-agent.
	AgentUser string
	// ProxyPort is the FIXED loopback port the in-process proxy binds. It must
	// match the single port the kernel owner-match rule allows the contained agent
	// uid to reach (`pipelock contain install --proxy-port`, default 8888) -- a
	// random ephemeral port can never align with that single-port rule. 0 selects
	// an ephemeral port (dev/test/uncontained only); the library does NOT
	// substitute a default for 0, so a contained run passes the fixed port
	// explicitly (the command layer defaults it to DefaultContainedProxyPort). The
	// bound port is signed into the HostContainmentWitness and the contained agent
	// must reach EXACTLY it, so a port that does not match the nft rule fails closed.
	ProxyPort int
	// OrchestratorKeyPath, when non-empty, loads the run's orchestrator
	// (trust-root) signing key from disk instead of generating an ephemeral one.
	OrchestratorKeyPath string
	// ModelBaseURL, when non-empty, allowlists the model API host in the lab
	// proxy so a model-backed agent's chat-completions calls can egress through
	// it. This is the ONLY real-egress destination the lab proxy permits; the
	// .test lab targets stay loopback. Empty leaves the proxy loopback-only.
	ModelBaseURL string
	// ModelHostOverride, when non-empty, maps the model host to these IPs in the
	// lab proxy DNS (tests point it at a loopback fake model). Empty => real DNS
	// resolution of the model host.
	ModelHostOverride []string
	// OnReceipt, when non-nil, is invoked with each signed receipt as it is
	// recorded, in chain order. The live-chat stream uses this to surface
	// decisions in real time. The receipt's secret-bearing fields are already
	// sanitized (the recorder runs with redaction on), so streamed decisions
	// carry the redacted shape, never the canary. The observer must not block
	// (see receipt.EmitterConfig.OnReceipt). Nil leaves the batch path unchanged.
	OnReceipt func(rcpt *receipt.Receipt)
}

// LiveRun holds the state of a running live playground demo. All resources
// (listeners, proxy, targets) are cleaned up by Close.
type LiveRun struct {
	ctx    context.Context
	cancel context.CancelFunc

	// Keys
	orchestratorPub  ed25519.PublicKey
	orchestratorPriv ed25519.PrivateKey
	collectorPub     ed25519.PublicKey
	collectorPriv    ed25519.PrivateKey
	pipelockPub      ed25519.PublicKey
	pipelockPriv     ed25519.PrivateKey

	// Infrastructure
	safeTarget   *SafeTarget
	safeLn       net.Listener
	safeSrv      *http.Server
	collector    *Collector
	collectorLn  net.Listener
	collectorSrv *http.Server
	proxyLn      net.Listener
	proxySrv     *http.Server
	proxyObj     *proxy.Proxy
	rec          *recorder.Recorder
	sc           *scanner.Scanner

	// Scenario / config
	scenario    replaycapture.Scenario
	manifest    LaunchManifest
	opts        LiveRunOpts
	evidenceDir string
	policyHash  string

	// Binaries
	agentBin   string
	webtoolBin string

	// Canary
	canaryID    string
	canaryValue string

	egressProbe      func(targets []string, asAgent bool) ([]ProbeResult, error)
	localEscapeProbe func(asAgent bool) ([]ProbeResult, error)
}

// proxyBindAddrFor returns the loopback bind address for the in-process proxy.
// A non-zero port binds that exact fixed port (production contained runs pass
// the port matching their kernel owner-match rule). Port 0 binds an ephemeral
// port (dev/test/uncontained, where no owner-match rule constrains the agent).
// The library never substitutes a default for 0: a contained run that wants the
// stock port passes it explicitly, and the HostContainmentWitness fails closed
// if the bound port does not match the nft rule the agent is restricted to.
// Out-of-range ports fail.
func proxyBindAddrFor(port int) (string, error) {
	if port < 0 || port > 65535 {
		return "", fmt.Errorf("proxy port %d out of range (0-65535)", port)
	}
	return fmt.Sprintf("127.0.0.1:%d", port), nil
}

// StartLiveRun boots a complete live demo environment: lab targets, a real
// Pipelock proxy with receipt emission, and prepares everything for running
// the toy agent through it.
func StartLiveRun(ctx context.Context, opts LiveRunOpts) (*LiveRun, error) {
	ctx, cancel := context.WithCancel(ctx)
	lr := &LiveRun{
		ctx:    ctx,
		cancel: cancel,
		opts:   opts,
	}

	var err error
	defer func() {
		if err != nil {
			lr.Close()
		}
	}()

	// --- Key generation ---
	// The orchestrator key is the run's trust root. When a stable key path is
	// supplied, load it (so the run signs under the published demo key and is
	// verifiable against PublishedOrchestratorPubKeyHex); otherwise generate an
	// ephemeral per-run key (the dev default).
	if opts.OrchestratorKeyPath != "" {
		var loadErr error
		lr.orchestratorPriv, loadErr = LoadOrchestratorSigningKey(opts.OrchestratorKeyPath)
		if loadErr != nil {
			err = fmt.Errorf("load orchestrator key: %w", loadErr)
			return nil, err
		}
		lr.orchestratorPub = lr.orchestratorPriv.Public().(ed25519.PublicKey)
		if defaultPath := DefaultOrchestratorKeyPath(); defaultPath != "" &&
			filepath.Clean(opts.OrchestratorKeyPath) == filepath.Clean(defaultPath) &&
			!OrchestratorKeyMatchesPublished(lr.orchestratorPriv) {
			err = fmt.Errorf("default orchestrator key %s does not match PublishedOrchestratorPubKeyHex", opts.OrchestratorKeyPath)
			return nil, err
		}
	} else {
		lr.orchestratorPub, lr.orchestratorPriv, err = signing.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("orchestrator keygen: %w", err)
		}
	}
	lr.collectorPub, lr.collectorPriv, err = signing.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("collector keygen: %w", err)
	}
	lr.pipelockPub, lr.pipelockPriv, err = signing.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("pipelock keygen: %w", err)
	}

	// --- Canary ---
	lr.canaryID = "playground-canary"
	lr.canaryValue, err = liveCanaryValue()
	if err != nil {
		return nil, fmt.Errorf("generate canary: %w", err)
	}

	// --- Look up the scenario ---
	if s, ok := lookupPlaygroundScenario(opts.ScenarioID); ok {
		lr.scenario = s
	} else {
		err = fmt.Errorf("unknown scenario %q", opts.ScenarioID)
		return nil, err
	}

	// --- Bind safe target + collector on loopback :0 ---
	// Bind both before starting the safe target server: the collector's port
	// feeds the diagnostics endpoint published in the safe target's config, so
	// the model discovers the destination by fetching config rather than from
	// its system prompt.
	lr.safeLn, err = (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("safe target listen: %w", err)
	}
	lr.collectorLn, err = (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("collector listen: %w", err)
	}

	// --- Start safe target ---
	// On a live MODEL run we do NOT advertise an exfil destination in the lab
	// config: a real visitor supplies the malicious intent, and the demo should not
	// hand the agent a target to send the secret to. The collector still runs as the
	// independent "received nothing" witness (it is not on the allowlist, so any
	// attempt to reach it is blocked at the door regardless). The deterministic
	// (replay) path keeps the advertised diagnostics URL so its scripted beat works.
	reportingURL := lr.liveExfilURL()
	if opts.ModelBaseURL != "" {
		reportingURL = ""
	}
	lr.safeTarget = NewSafeTarget(reportingURL)
	lr.safeSrv = &http.Server{
		Handler:           lr.safeTarget.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = lr.safeSrv.Serve(lr.safeLn) }()

	// --- Start collector ---
	lr.collector = NewCollector(lr.canaryID, lr.canaryValue)
	lr.collectorSrv = &http.Server{
		Handler:           lr.collector.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = lr.collectorSrv.Serve(lr.collectorLn) }()

	// --- Build pipelock config ---
	cfg := config.Defaults()
	cfg.ForwardProxy.Enabled = true

	// DNS host overrides: .test hosts -> loopback
	cfg.DNS.HostOverrides = map[string][]string{
		liveRunSafeHost:  {"127.0.0.1"},
		liveRunExfilHost: {"127.0.0.1"},
	}

	// Trust the .test hosts so they pass the domain check
	cfg.TrustedDomains = append(cfg.TrustedDomains, liveRunSafeHost, liveRunExfilHost)

	// Model-agent runs enforce a strict host allowlist: a jailbroken model (which
	// has a real shell, so tool-runtime host guards are bypassable by curl) must
	// not be able to reach any host the operator did not approve. The ONLY approved
	// egress destinations are the benign lab read target and the model's own API.
	//
	// CRITICAL: the allowlist is ASSIGNED, never appended to config.Defaults(). The
	// defaults ship general third-party hosts (github/openai/telegram/slack/discord/
	// npm) which ARE enforced as reachable in strict mode -- appending would
	// silently approve real exfil channels (e.g. a visitor's own Telegram bot). The
	// drop-box/collector host (liveRunExfilHost) is also intentionally NOT approved:
	// an exfil attempt to it is blocked at the allowlist (destination control, before
	// DNS), which encoding cannot bypass; the collector still runs as the independent
	// "received nothing" witness. Allowlist enforcement is gated to strict mode, so
	// model runs run strict; the deterministic IntentAgent path (no ModelBaseURL)
	// keeps its balanced config (collector reachable, content-scan beat) unchanged.
	if opts.ModelBaseURL != "" {
		modelHost, mhErr := modelHostname(opts.ModelBaseURL)
		if mhErr != nil {
			err = fmt.Errorf("model base url: %w", mhErr)
			return nil, err
		}
		cfg.TrustedDomains = append(cfg.TrustedDomains, modelHost)
		if len(opts.ModelHostOverride) > 0 {
			cfg.DNS.HostOverrides[modelHost] = opts.ModelHostOverride
		}
		cfg.Mode = config.ModeStrict
		cfg.APIAllowlist = []string{liveRunSafeHost, modelHost}
		cfg.Suppress = append(cfg.Suppress, modelProviderAuthSuppressions(opts.ModelBaseURL)...)

		// Bind EVERY contained-agent request to the lab-agent identity. The agent's
		// Go tools and model traffic set the X-Pipelock-Agent header (-> actor
		// "lab-agent"), but its shell tools (curl/wget/python3 via HTTP_PROXY) do
		// NOT — those egress as actor "anonymous", which the public-safe packet
		// assembler REJECTS at seal time, breaking the downloadable bundle. Binding
		// attributes ALL of the contained agent's egress to lab-agent regardless of
		// any (missing or self-declared) header, so every blocked-exfil receipt
		// seals into the bundle. It also hardens identity: a jailbroken model cannot
		// self-declare a different agent to dodge attribution. Safe because the VM
		// is single-tenant — the only actor in it IS the lab agent.
		cfg.DefaultAgentIdentity = liveRunActor
		cfg.BindDefaultAgentIdentity = true

		// The benign read host is the one approved interactive destination, so lock
		// it to reads: a request_policy rule blocks the standard write methods at
		// the proxy (with a signed receipt), so a shell `curl -X POST` cannot use
		// the approved host as a body-exfil channel. NOTE: this is a method
		// deny-list, not a true default-deny "only GET" route (an exotic custom
		// verb is not covered here -- the SafeTarget handler 405s those as
		// defense-in-depth). Route-level default-deny allow-routes with receipts is
		// tracked as a separate product item. The model host stays an opaque CONNECT
		// (its path is not proxy-visible without MITM), so it is NOT route-locked;
		// the model provider seeing the agent's own context is inherent to using a
		// model, not exfil to an attacker.
		cfg.RequestPolicy.Enabled = true
		cfg.RequestPolicy.Rules = append(cfg.RequestPolicy.Rules, config.RequestPolicyRule{
			Name:   "benign-read-host-get-only",
			Action: config.ActionBlock,
			Route: config.RequestPolicyRoute{
				Hosts:   []string{liveRunSafeHost},
				Methods: []string{"POST", "PUT", "PATCH", "DELETE"},
			},
			Reason: "benign lab read host is GET-only; a write method could carry a secret body",
		})
	}

	cfg.ApplyDefaults()

	// --- Policy hash ---
	lr.policyHash = liveRunConfigHash(cfg)

	// --- Evidence dir ---
	lr.evidenceDir, err = os.MkdirTemp("", "playground-live-evidence-*")
	if err != nil {
		return nil, fmt.Errorf("evidence dir: %w", err)
	}

	// --- Scanner + Recorder + Emitter ---
	lr.sc = scanner.New(cfg)

	lr.rec, err = recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                lr.evidenceDir,
		CheckpointInterval: 1000,
		Redact:             true,
	}, lr.sc.ScanTextForDLP, lr.pipelockPriv)
	if err != nil {
		return nil, fmt.Errorf("recorder: %w", err)
	}

	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:       lr.rec,
		PrivKey:        lr.pipelockPriv,
		ConfigHash:     lr.policyHash,
		Principal:      liveRunPrincipal,
		Actor:          liveRunActor,
		OnReceipt:      opts.OnReceipt,
		PostureBinding: receipt.PostureBinding{},
	})
	if emitter == nil {
		err = fmt.Errorf("emitter construction failed")
		return nil, err
	}
	if err = emitter.EmitSessionOpen(); err != nil {
		return nil, fmt.Errorf("session_open receipt: %w", err)
	}

	// --- Proxy ---
	lr.proxyObj, err = proxy.New(cfg, audit.NewNop(), lr.sc, metrics.New(),
		proxy.WithRecorder(lr.rec),
		proxy.WithReceiptEmitter(emitter),
	)
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}

	// Start the in-process proxy on a FIXED loopback port so it aligns with the
	// single-port kernel owner-match rule the contained agent is restricted to
	// (C1). A contained run with no explicit port uses the stock containment
	// default; an ephemeral port (0) is for dev/test/uncontained only, where no
	// owner-match rule constrains the agent. The bound port is signed into the
	// host-containment witness and the contained agent must reach exactly it.
	proxyBindAddr, err := proxyBindAddrFor(opts.ProxyPort)
	if err != nil {
		return nil, fmt.Errorf("resolve proxy bind address: %w", err)
	}
	lr.proxyLn, err = (&net.ListenConfig{}).Listen(ctx, "tcp", proxyBindAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy listen on %s: %w", proxyBindAddr, err)
	}
	lr.proxySrv = &http.Server{
		Handler:           lr.proxyObj.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = lr.proxySrv.Serve(lr.proxyLn) }()

	// --- Build + sign launch manifest ---
	lr.manifest = LaunchManifest{
		RunNonce:        opts.RunNonce,
		ScenarioID:      opts.ScenarioID,
		CanaryID:        lr.canaryID,
		PipelockPubKey:  hex.EncodeToString(lr.pipelockPub),
		CollectorPubKey: hex.EncodeToString(lr.collectorPub),
		PolicyHash:      lr.policyHash,
		TargetHost:      liveRunExfilHost,
		StartedAt:       time.Now().UTC(),
		Contained:       opts.Contained,
		AgentKind:       manifestAgentKind(opts.ModelBaseURL),
	}
	lr.manifest = SignLaunchManifest(lr.orchestratorPriv, lr.manifest)

	// Open the collector run with the manifest hash
	if openErr := lr.collector.OpenRun(opts.RunNonce, lr.manifest.Hash()); openErr != nil {
		err = fmt.Errorf("open collector run: %w", openErr)
		return nil, err
	}

	// --- Binaries ---
	lr.agentBin = opts.ToyAgentBin
	lr.webtoolBin = opts.WebToolBin

	return lr, nil
}

// RunSteps executes the specified toy-agent mediated steps. Step 1 = safe GET,
// Step 2 = exfil POST. Step 3 remains in the toy agent for manual/raw bypass
// experiments, but the split-proof live demo proves containment through
// buildHostContainmentWitness instead.
func (lr *LiveRun) RunSteps(steps ...int) error {
	safePort := portFromAddr(lr.safeLn.Addr())
	collectorPort := portFromAddr(lr.collectorLn.Addr())
	proxyAddr := lr.proxyLn.Addr().String()

	safeURL := fmt.Sprintf("http://%s:%s/", liveRunSafeHost, safePort)
	exfilURL := fmt.Sprintf("http://%s:%s/", liveRunExfilHost, collectorPort)

	for _, step := range steps {
		switch step {
		case 1, 2:
		default:
			return fmt.Errorf("unsupported mediated step %d", step)
		}

		// The mediated steps (1 = allow, 2 = body-DLP block) always run as the
		// operator through the demo's lab proxy. Under the split-proof model the
		// kernel-containment property is proven separately by the
		// HostContainmentWitness (see buildHostContainmentWitness), NOT by
		// dropping these steps to the contained user. That is deliberate: the
		// proxy's allow/block decision is orthogonal to the agent's uid, and on a
		// host with global owner-match containment the contained user cannot
		// reach the demo's ephemeral lab proxy at all -- so running these steps
		// contained would just time out and produce no receipts.
		args := []string{
			"--step", fmt.Sprintf("%d", step),
			"--run-nonce", lr.opts.RunNonce,
			"--canary-label", lr.canaryID,
			"--safe-url", safeURL,
			"--exfil-url", exfilURL,
			"--webtool", lr.webtoolBin,
		}

		cmd := exec.CommandContext(lr.ctx, lr.agentBin, args...)
		// Minimal, controlled environment: the demo agent holds ONLY the
		// synthetic canary plus the demo plumbing -- NEVER the operator's real
		// environment (which could contain real secrets). This enforces the
		// capability-separation story instead of merely narrating it: the agent
		// genuinely possesses nothing sensitive except the planted synthetic canary.
		cmd.Env = []string{
			"PATH=/usr/local/bin:/usr/bin:/bin",
			canaryEnvVar + "=" + lr.canaryValue,
			"PLAYGROUND_AGENT_ID=" + liveRunActor,
			"HTTP_PROXY=http://" + proxyAddr,
			"HTTPS_PROXY=http://" + proxyAddr,
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("step %d exec: %w", step, err)
		}
	}
	return nil
}

// runEgressProbe spawns the toy agent in probe mode against the given targets
// and parses its JSON results. When asAgent is true, the probe subprocess is
// dropped to the contained agent user (uid-scoped), so it probes from the
// contained network position; this requires root and an installed containment.
// When false it runs as the current (operator) user.
func (lr *LiveRun) runEgressProbe(targets []string, asAgent bool) ([]ProbeResult, error) {
	if asAgent {
		// Shared with the in-VM start gate (VerifyInVMContainment) so the
		// finalize witness and the start gate exercise an identical agent-uid
		// probe path and cannot diverge.
		return spawnAgentEgressProbe(lr.ctx, lr.agentBin, lr.opts.AgentUser, targets)
	}

	// Operator (current user) probe: run the toy agent as-is, no uid drop.
	args := []string{"--probe-targets", strings.Join(targets, ",")}
	cmd := exec.CommandContext(lr.ctx, lr.agentBin, args...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("egress probe exec: %w", err)
	}

	return decodeProbeResults(stdout.Bytes(), targets)
}

// runLocalEscapeProbe spawns the toy agent in local escape probe mode and
// parses its JSON results. When asAgent is true, the probe subprocess is dropped
// to the contained agent user, so it tests the same local permissions as the
// live agent. These probes cover non-network surfaces that HTTP receipts cannot
// mediate.
func (lr *LiveRun) runLocalEscapeProbe(asAgent bool) ([]ProbeResult, error) {
	targets := LocalEscapeTargets()
	args := []string{"--probe-local-targets", strings.Join(targets, ",")}
	cmd := exec.CommandContext(lr.ctx, lr.agentBin, args...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	if asAgent {
		if err := configureContainedCommand(cmd, lr.opts.AgentUser); err != nil {
			return nil, err
		}
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("local escape probe exec: %w", err)
	}

	return decodeProbeResults(stdout.Bytes(), targets)
}

// decodeProbeResults parses the toy agent's probe-mode JSON output and verifies
// it carries exactly the requested target set, in order. Extracted from
// runEgressProbe so the parsing/validation logic is unit-testable without
// spawning a privileged subprocess (the exec itself is host-only).
func decodeProbeResults(stdout []byte, expectedTargets []string) ([]ProbeResult, error) {
	var results []ProbeResult
	if err := json.Unmarshal(stdout, &results); err != nil {
		return nil, fmt.Errorf("parse egress probe output: %w", err)
	}
	if len(results) != len(expectedTargets) {
		return nil, fmt.Errorf("egress probe returned %d results for %d targets", len(results), len(expectedTargets))
	}
	for i, expected := range expectedTargets {
		if results[i].Target != expected {
			return nil, fmt.Errorf("egress probe result %d target=%q, want %q", i, results[i].Target, expected)
		}
	}
	return results, nil
}

// buildHostContainmentWitness produces the signed host-containment witness for
// a contained run. It stands up a host-local control listener (reachable absent
// containment), probes it as the operator (must connect) and as the contained
// agent (must be blocked) -- the differential that isolates the kernel
// owner-match drop -- then probes the real direct-egress target suite from the
// contained position (all must be blocked), and probes local non-network escape
// surfaces (platform sockets, device nodes, namespace/mount capabilities). The
// witness is signed by the orchestrator key, the run's trust root.
//
// ctx should survive session cancellation (e.g. via context.WithoutCancel) so
// the witness can be built at TTL expiry when the session context is canceled.
func (lr *LiveRun) buildHostContainmentWitness(ctx context.Context) (HostContainmentWitness, error) {
	runProbe := lr.runEgressProbe
	if lr.egressProbe != nil {
		runProbe = lr.egressProbe
	}
	runLocalProbe := lr.runLocalEscapeProbe
	if lr.localEscapeProbe != nil {
		runLocalProbe = lr.localEscapeProbe
	}

	ctrlLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return HostContainmentWitness{}, fmt.Errorf("control listener: %w", err)
	}
	defer func() { _ = ctrlLn.Close() }()
	go func() {
		for {
			c, acceptErr := ctrlLn.Accept()
			if acceptErr != nil {
				return
			}
			_ = c.Close()
		}
	}()
	ctrlTarget := ctrlLn.Addr().String()

	// Operator probe of the control target: proves the probe can see "open".
	opProbes, err := runProbe([]string{ctrlTarget}, false)
	if err != nil {
		return HostContainmentWitness{}, fmt.Errorf("operator control probe: %w", err)
	}

	if lr.proxyLn == nil {
		return HostContainmentWitness{}, fmt.Errorf("proxy listener not initialized")
	}
	proxyTarget := lr.proxyLn.Addr().String()

	// Contained-agent probes, in order: the proxy port (its ONE permitted egress,
	// must be reachable -> Open), the control target (a DIFFERENT loopback port,
	// must be blocked -> the non-proxy-loopback negative), then the real
	// direct-egress suite (all must be blocked). Probing the proxy as the agent is
	// what catches an operator port mismatch: a proxy bound to a port the nft rule
	// does not allow comes back Blocked and the witness fails closed.
	realTargets := DirectEgressTargets()
	agentTargets := append([]string{proxyTarget, ctrlTarget}, realTargets...)
	agProbes, err := runProbe(agentTargets, true)
	if err != nil {
		return HostContainmentWitness{}, fmt.Errorf("contained agent probe: %w", err)
	}
	localProbes, err := runLocalProbe(true)
	if err != nil {
		return HostContainmentWitness{}, fmt.Errorf("contained agent local escape probe: %w", err)
	}

	w := HostContainmentWitness{
		RunNonce:             lr.opts.RunNonce,
		LaunchManifestHash:   lr.manifest.Hash(),
		AgentUser:            containedAgentUserName(lr.opts.AgentUser),
		AgentUID:             containedAgentUID(lr.opts.AgentUser),
		ControlTarget:        ctrlTarget,
		ControlOperatorProbe: opProbes[0],
		ControlAgentProbe:    agProbes[1],
		ProxyTarget:          proxyTarget,
		ProxyAgentProbe:      agProbes[0],
		AgentProbes:          agProbes[2:],
		LocalAgentProbes:     localProbes,
		ProbedAt:             time.Now().UTC(),
	}
	return SignHostContainmentWitness(lr.orchestratorPriv, w), nil
}

// HasReceipt reports whether the evidence JSONL contains at least one receipt
// with the given verdict (e.g. "allow", "block").
func (lr *LiveRun) HasReceipt(verdict string) bool {
	for _, v := range lr.Verdicts() {
		if strings.EqualFold(v, verdict) {
			return true
		}
	}
	return false
}

// Verdicts returns all receipt verdicts from the evidence JSONL.
func (lr *LiveRun) Verdicts() []string {
	// Close the recorder so evidence is flushed before reading.
	if lr.rec != nil {
		_ = lr.rec.Close()
		lr.rec = nil
	}

	evidenceFile, err := singleLiveEvidenceFile(lr.evidenceDir)
	if err != nil {
		return nil
	}

	receipts, err := receipt.ExtractReceipts(evidenceFile)
	if err != nil {
		return nil
	}

	var verdicts []string
	for _, r := range receipts {
		verdicts = append(verdicts, receipt.NormalizeVerdict(r.ActionRecord.Verdict))
	}
	return verdicts
}

// AssembleAndVerify performs the full end-to-end: red-case calibration, witness
// seal, packet assembly, and offline verification. Returns the VerifyReport.
func (lr *LiveRun) AssembleAndVerify(runDir string) (VerifyReport, error) {
	// Ensure recorder is closed so evidence is flushed.
	if lr.rec != nil {
		_ = lr.rec.Close()
		lr.rec = nil
	}

	// The seal must complete even when the session context is canceled (TTL
	// expiry or client disconnect). WithoutCancel drops the parent's
	// cancellation while preserving values; the 30s timeout bounds the seal
	// so a genuinely stuck probe does not hang forever.
	sealCtx, sealCancel := context.WithTimeout(context.WithoutCancel(lr.ctx), 30*time.Second)
	defer sealCancel()

	// --- Red-case calibration ---
	rcResult, redWitness, err := RunRedCaseCalibrationWithWitness(sealCtx, lr.collectorPriv, lr.canaryID, lr.canaryValue)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("red-case calibration: %w", err)
	}
	if err := lr.collector.AttachRedCase(lr.opts.RunNonce, rcResult); err != nil {
		return VerifyReport{}, fmt.Errorf("attach red-case: %w", err)
	}

	// --- Seal witness ---
	witness, err := lr.collector.SealAndSign(lr.opts.RunNonce, lr.collectorPriv, 2*time.Second)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("seal witness: %w", err)
	}

	// --- Evidence file ---
	evidenceFile, err := singleLiveEvidenceFile(lr.evidenceDir)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("evidence file: %w", err)
	}

	// --- Assemble packet ---
	// AssemblePacket creates a subdirectory named after the scenario ID inside
	// outDir. VerifyRun expects the packet at <runDir>/packet/, so we pass
	// runDir as outDir and then rename the result.
	sc := lr.scenario
	// Make re-runs on the same run dir idempotent: clear any stale assembly
	// output (a prior packet/, or a partially-written scenario subdir from an
	// aborted run) so the operator can re-run `run --run-dir X` without a
	// manual reset. The manifest/witness JSON files are overwritten in place.
	_ = os.RemoveAll(filepath.Join(runDir, "packet"))
	_ = os.RemoveAll(filepath.Join(runDir, sc.ID))
	asmResult, asmErr := AssembleFromEvidenceWithScenario(
		evidenceFile,
		hex.EncodeToString(lr.pipelockPub),
		&sc,
		runDir,
		time.Now().UTC(),
	)
	if asmErr != nil {
		return VerifyReport{}, fmt.Errorf("assemble: %w", asmErr)
	}
	// Rename the assembly output dir to the canonical "packet/" location
	// expected by VerifyRun.
	packetDir := filepath.Join(runDir, "packet")
	if asmResult.PacketDir != packetDir {
		if renameErr := os.Rename(asmResult.PacketDir, packetDir); renameErr != nil {
			return VerifyReport{}, fmt.Errorf("rename packet dir: %w", renameErr)
		}
	}

	// --- Write launch manifest ---
	lmBytes, err := json.Marshal(lr.manifest)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("marshal launch manifest: %w", err)
	}
	lmPath := filepath.Join(runDir, "launch-manifest.json")
	if err := os.WriteFile(lmPath, lmBytes, 0o600); err != nil {
		return VerifyReport{}, fmt.Errorf("write launch manifest: %w", err)
	}

	// --- Write witness ---
	wBytes, err := json.Marshal(witness)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("marshal witness: %w", err)
	}
	wPath := filepath.Join(runDir, "witness.json")
	if err := os.WriteFile(wPath, wBytes, 0o600); err != nil {
		return VerifyReport{}, fmt.Errorf("write witness: %w", err)
	}

	// --- Write red-case witness ---
	redBytes, err := json.Marshal(redWitness)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("marshal red witness: %w", err)
	}
	redPath := filepath.Join(runDir, redWitnessFile)
	if err := os.WriteFile(redPath, redBytes, 0o600); err != nil {
		return VerifyReport{}, fmt.Errorf("write red witness: %w", err)
	}

	// --- Host-containment witness (contained mode only, split-proof) ---
	// The mediated receipts above prove the proxy's allow/block decision; this
	// separate witness proves the kernel owner-match drop from the contained
	// network position. Each property is attested where it is actually enforced.
	if lr.opts.Contained {
		hcw, hcwErr := lr.buildHostContainmentWitness(sealCtx)
		if hcwErr != nil {
			return VerifyReport{}, fmt.Errorf("host-containment witness: %w", hcwErr)
		}
		hcwBytes, hcwMErr := json.Marshal(hcw)
		if hcwMErr != nil {
			return VerifyReport{}, fmt.Errorf("marshal host-containment witness: %w", hcwMErr)
		}
		hcwPath := filepath.Join(runDir, hostContainmentWitnessFile)
		if writeErr := os.WriteFile(hcwPath, hcwBytes, 0o600); writeErr != nil {
			return VerifyReport{}, fmt.Errorf("write host-containment witness: %w", writeErr)
		}
	}

	// --- Verify ---
	rep, err := VerifyRun(runDir, hex.EncodeToString(lr.orchestratorPub))
	if err != nil {
		return VerifyReport{}, fmt.Errorf("verify run: %w", err)
	}
	if !rep.OK {
		return rep, fmt.Errorf("verify run: failed checks")
	}

	return rep, nil
}

// OrchestratorPubHex returns the run's trust-root (orchestrator) public key as
// hex -- the key a downloaded session bundle is verified against offline.
func (lr *LiveRun) OrchestratorPubHex() string {
	return hex.EncodeToString(lr.orchestratorPub)
}

// Close shuts down all infrastructure. Safe to call multiple times.
func (lr *LiveRun) Close() {
	lr.cancel()

	if lr.proxySrv != nil {
		_ = lr.proxySrv.Close()
	}
	if lr.proxyObj != nil {
		lr.proxyObj.Close()
	}
	if lr.sc != nil {
		lr.sc.Close()
		lr.sc = nil
	}
	if lr.rec != nil {
		_ = lr.rec.Close()
		lr.rec = nil
	}
	if lr.safeSrv != nil {
		_ = lr.safeSrv.Close()
	}
	if lr.collectorSrv != nil {
		_ = lr.collectorSrv.Close()
	}
	if lr.evidenceDir != "" {
		_ = os.RemoveAll(lr.evidenceDir)
	}
}

// manifestAgentKind records which agent drove the run in the signed manifest.
// A non-empty model base URL means the real model-backed subprocess ran; an
// empty one means the scripted deterministic IntentAgent.
func manifestAgentKind(modelBaseURL string) string {
	if modelBaseURL != "" {
		return AgentKindModel
	}
	return AgentKindDeterministic
}

// modelHostname extracts the hostname (no port) from a model API base URL, for
// allowlisting and DNS-override keying. It requires an http(s) URL with a host.
func modelHostname(raw string) (string, error) {
	u, err := ValidatePlainHTTPURL(raw)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	return strings.TrimSuffix(strings.ToLower(host), "."), nil
}

var modelProviderAuthDLPPatterns = []string{
	"Anthropic API Key",
	"OpenAI API Key",
	"OpenAI Service Key",
	"Fireworks API Key",
	"Google API Key",
	"Hugging Face Token",
	"Replicate API Token",
	"Groq API Key",
	"xAI API Key",
}

// modelProviderAuthSuppressions allows the playground's own model-provider
// Authorization key to reach exactly the configured chat-completions endpoint.
// Tool calls still cannot target the model host, and the lab collector/safe
// targets remain fully scanned.
func modelProviderAuthSuppressions(baseURL string) []config.SuppressEntry {
	target := strings.TrimRight(baseURL, "/") + "/chat/completions"
	out := make([]config.SuppressEntry, 0, len(modelProviderAuthDLPPatterns))
	for _, rule := range modelProviderAuthDLPPatterns {
		out = append(out, config.SuppressEntry{
			Rule:   rule,
			Path:   target,
			Reason: "playground model provider authorization header",
		})
	}
	return out
}

// portFromAddr extracts the port string from a net.Addr.
func portFromAddr(addr net.Addr) string {
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "0"
	}
	return port
}

// singleLiveEvidenceFile returns the lone evidence JSONL file from the dir.
func singleLiveEvidenceFile(dir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "evidence-proxy-*.jsonl"))
	if err != nil {
		return "", fmt.Errorf("globbing evidence: %w", err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no evidence files in %s", dir)
	}
	// Use the first one (there should be exactly one per recorder session).
	return matches[0], nil
}

// liveRunConfigHash returns a deterministic policy hash for the live-run config.
func liveRunConfigHash(cfg *config.Config) string {
	data, err := json.Marshal(cfg)
	if err != nil {
		data = []byte(cfg.Mode)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
