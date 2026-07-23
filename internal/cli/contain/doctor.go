// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// `pipelock contain doctor` is a live self-test for the contained agent's
// runtime contract. Where `verify` proves the boundary is *installed*, doctor
// proves common tooling can actually *work through* it — and, crucially, makes
// the four failure classes distinguishable so a compatibility failure does not
// read as "the agent is broken":
//
//	policy        — blocked because the request is dangerous (DLP/policy)
//	proxy-compat  — the tool isn't proxy-compatible (ignores HTTPS_PROXY)
//	local-context — Pipelock misclassified harmless local context
//	infra         — infra protection tripped (DNS failure, gateway down)
//
// Each check reports pass/fail/skip/unknown plus an operator-readable remediation.
const (
	classNone        = ""
	classPolicy      = "policy"
	classProxyCompat = "proxy-compat"
	classLocalCtx    = "local-context"
	classInfra       = "infra"
)

// doctorEnv carries everything the checks need. Function fields are injectable
// so tests exercise the logic without spawning real processes or touching the
// network, mirroring verify.go's probeEnv.
type doctorEnv struct {
	port           int
	agentUserName  string
	wrapperDir     string
	caBundlePath   string
	undiciShimPath string
	canaryURL      string
	curlPath       string

	runCmd runCommand
	// dropCounter reads the same managed catch-all nftables counter used by
	// contain verify. Nil means attribution is unavailable, never PASS.
	dropCounter func(ctx context.Context) (uint64, error)
	dialCtx     dialFunc
	readFile    func(path string) ([]byte, error)
	stat        func(path string) (os.FileInfo, error)
}

// doctorEnvFactory builds the live doctor environment. It is a package var so
// tests can substitute an injected environment and exercise the command
// wiring without spawning real processes or touching the network.
var doctorEnvFactory = defaultDoctorEnv

// defaultDoctorEnv builds the production doctor environment and its live
// managed DROP-counter reader.
func defaultDoctorEnv() *doctorEnv {
	platform := detectContainPlatform(os.ReadFile, os.Stat, exec.LookPath)
	counterEnv := defaultProbeEnv()
	env := &doctorEnv{
		port:           defaultProxyPort,
		agentUserName:  defaultAgentUser,
		wrapperDir:     defaultWrapperDir,
		caBundlePath:   defaultCABundlePath,
		undiciShimPath: defaultUndiciShimPath,
		canaryURL:      canaryURL,
		curlPath:       platform.curlPath,
		runCmd:         realRunCommand,
		dialCtx:        realDial,
		readFile:       os.ReadFile,
		stat:           os.Stat,
	}
	env.dropCounter = doctorDropCounterReader(counterEnv, env)
	return env
}

// doctorDropCounterReader binds the verify counter reader to live doctor flag
// values at each read, while retaining an injectable base environment for tests.
func doctorDropCounterReader(base *probeEnv, env *doctorEnv) func(context.Context) (uint64, error) {
	return func(ctx context.Context) (uint64, error) {
		// doctor flags are applied after the factory returns. Copy their live
		// values into the verify environment on each read so a non-default
		// installed proxy port is not mistaken for an unsafe loopback allow.
		probe := doctorCounterProbeEnv(base, env)
		return probe.dropCounter(ctx, &probe)
	}
}

// doctorCounterProbeEnv copies live doctor flag overrides into a probe
// environment without mutating the shared defaults.
func doctorCounterProbeEnv(base *probeEnv, env *doctorEnv) probeEnv {
	probe := *base
	probe.port = env.port
	probe.agentUserName = env.agentUserName
	return probe
}

// doctorResult is one check outcome. remediation is the operator's next step
// on a non-pass; class places the outcome in one of the four block classes.
type doctorResult struct {
	status      string
	detail      string
	remediation string
	class       string
}

func pass(detail string) doctorResult { return doctorResult{status: statusPass, detail: detail} }

func fail(class, detail, remediation string) doctorResult {
	return doctorResult{status: statusFail, detail: detail, remediation: remediation, class: class}
}

func skip(detail, remediation string) doctorResult {
	return doctorResult{status: statusSkip, detail: detail, remediation: remediation}
}

// unknown returns an inconclusive result that must never count as a pass.
func unknown(class, detail, remediation string) doctorResult {
	return doctorResult{
		status:      statusUnknown,
		detail:      detail,
		remediation: remediation,
		class:       class,
	}
}

// unknownInfra returns an inconclusive infrastructure-attribution result.
func unknownInfra(detail string) doctorResult {
	return unknown(classInfra, detail, rawEgressAttributionRemediation)
}

type doctorCheck struct {
	n    int
	name string
	desc string
	fn   func(ctx context.Context, env *doctorEnv) doctorResult
}

func allDoctorChecks() []doctorCheck {
	return []doctorCheck{
		{1, "gateway_health", "pipelock proxy reachable on loopback", checkGatewayHealth},
		{2, "curl_through_proxy", "curl reaches an allowed host through the proxy", checkCurlThroughProxy},
		{3, "python_through_proxy", "python reaches an allowed host through the proxy", checkPythonThroughProxy},
		{4, "node_through_proxy", "node (with undici shim) reaches an allowed host through the proxy", checkNodeThroughProxy},
		{5, "dns_failure_clean", "DNS failures surface as a clean proxy error, not a hang", checkDNSFailure},
		{6, "raw_egress_blocked", "direct (proxy-bypassing) egress is blocked for the agent", checkRawEgressBlocked},
	}
}

// ---------------------------------------------------------------------------
// Shared check helpers
// ---------------------------------------------------------------------------

const remediationRunAsRoot = "re-run as root: sudo pipelock contain doctor"

const remediationInstall = "run `pipelock contain install` first"

const rawEgressAttributionRemediation = "verify the managed nftables owner-match DROP counter is readable and increasing (`pipelock contain verify`)"

// sudoAgent prefixes a command so it runs as the contained agent. doctor is an
// operator/root diagnostic; root can sudo to the agent without a password.
func (env *doctorEnv) sudoAgent(args ...string) (string, []string) {
	return "sudo", append([]string{"-n", "-u", env.agentUserName, "--"}, args...)
}

// classifyAgentRun maps the generic sudo/agent failure modes to a skip result.
// Returns (result, true) when the run could not proceed and the caller should
// return that skip; (zero, false) when the command actually executed.
func classifyAgentRun(out string, err error, tool string) (doctorResult, bool) {
	if err != nil {
		return skip(fmt.Sprintf("%s could not be launched: %v", tool, err), remediationRunAsRoot), true
	}
	if isSudoRefusal(out) {
		return skip("sudo refused without a password", remediationRunAsRoot), true
	}
	if isSudoUserMissing(out) {
		return skip(fmt.Sprintf("agent user %q is not present", "pipelock-agent"), remediationInstall), true
	}
	return doctorResult{}, false
}

// curlProxyArgs builds an explicit through-the-proxy curl invocation. Explicit
// --proxy/--cacert (rather than relying on env) makes the check definitive:
// success means the proxy + CA path itself works, independent of env plumbing.
func (env *doctorEnv) curlProxyArgs(url string) []string {
	return env.curlProxyArgsWithWriteOut(url, "%{http_code}")
}

// curlProxyArgsWithWriteOut builds the explicit proxy curl command with the
// requested curl write-out signal.
func (env *doctorEnv) curlProxyArgsWithWriteOut(url, writeOut string) []string {
	curl := env.curlPath
	if curl == "" {
		curl = defaultCurlPath
	}
	return []string{
		curl,
		"--proxy", proxyURLFor(env.port),
		"--cacert", env.caBundlePath,
		"--connect-timeout", curlConnectTimeout,
		"--max-time", curlMaxTime,
		"-sS",
		"-o", "/dev/null",
		"-w", writeOut,
		url,
	}
}

// trailingHTTPCode extracts curl's `-w %{http_code}` value, which is the last
// whitespace-separated token (sudo/PAM warnings merged from stderr can precede
// it). Returns (code, true) when a numeric code is present.
func trailingHTTPCode(out string) (int, bool) {
	fields := strings.Fields(oneLine(out))
	if len(fields) == 0 {
		return 0, false
	}
	code, err := strconv.Atoi(fields[len(fields)-1])
	if err != nil {
		return 0, false
	}
	return code, true
}

func is2xx3xx(code int) bool { return code >= 200 && code < 400 }

// ---------------------------------------------------------------------------
// Check 1: gateway health
// ---------------------------------------------------------------------------

func checkGatewayHealth(ctx context.Context, env *doctorEnv) doctorResult {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(env.port))
	conn, err := env.dialCtx(ctx, "tcp", addr, probeDialTimeout)
	if err != nil {
		return fail(classInfra,
			fmt.Sprintf("could not connect to the proxy at %s: %v", addr, err),
			"start the service: systemctl status pipelock (or `pipelock contain verify`)")
	}
	_ = conn.Close()
	return pass(fmt.Sprintf("proxy accepting connections on %s", addr))
}

// ---------------------------------------------------------------------------
// Check 2: curl through proxy
// ---------------------------------------------------------------------------

func checkCurlThroughProxy(ctx context.Context, env *doctorEnv) doctorResult {
	name, args := env.sudoAgent(env.curlProxyArgs(env.canaryURL)...)
	out, code, err := env.runCmd(ctx, name, args...)
	if res, done := classifyAgentRun(out, err, "curl"); done {
		return res
	}
	if isSudoTargetCommandMissing(out) {
		return skip("curl not available for the agent", "install curl on the host")
	}
	// curl exit 60/77 == CA problem; the proxy MITM cert isn't trusted.
	if code == 60 || code == 77 {
		return fail(classInfra,
			fmt.Sprintf("curl rejected the proxy TLS certificate (exit %d): %s", code, oneLine(out)),
			"refresh the CA bundle: pipelock contain ca-refresh")
	}
	if code != 0 {
		return fail(classProxyCompat,
			fmt.Sprintf("curl through the proxy failed (exit %d): %s", code, oneLine(out)),
			"confirm the proxy is up (check 1) and the CA bundle at "+env.caBundlePath+" is current")
	}
	httpCode, ok := trailingHTTPCode(out)
	if !ok {
		return fail(classInfra, "curl produced no HTTP status code", "re-run with: curl --proxy "+proxyURLFor(env.port)+" -v "+env.canaryURL)
	}
	if !is2xx3xx(httpCode) {
		return fail(classPolicy,
			fmt.Sprintf("proxy returned HTTP %d for %s", httpCode, env.canaryURL),
			"the proxy reached upstream but returned a non-2xx/3xx status; check pipelock logs for a block decision")
	}
	return pass(fmt.Sprintf("HTTP %d via the proxy", httpCode))
}

// ---------------------------------------------------------------------------
// Check 3: python through proxy (via the pipelock-python wrapper)
// ---------------------------------------------------------------------------

// pythonProbeScript prefers the requests library so the check actually
// exercises REQUESTS_CA_BUNDLE (requests/certifi), which urllib ignores. It
// falls back to urllib (which honors SSL_CERT_FILE) when requests is absent.
const pythonProbeScript = `import sys
url = sys.argv[1]
try:
    import requests
    sys.stdout.write(str(requests.get(url, timeout=5).status_code))
except ImportError:
    import urllib.request
    resp = urllib.request.urlopen(url, timeout=5)
    sys.stdout.write(str(getattr(resp, "status", 0) or resp.getcode()))
`

func checkPythonThroughProxy(ctx context.Context, env *doctorEnv) doctorResult {
	wrapper := filepath.Join(env.wrapperDir, "pipelock-python")
	name, args := env.sudoAgent(wrapper, "-c", pythonProbeScript, env.canaryURL)
	out, code, err := env.runCmd(ctx, name, args...)
	if res, done := classifyAgentRun(out, err, "python"); done {
		return res
	}
	if code == 127 || isSudoTargetCommandMissing(out) {
		return skip("python3 (or the pipelock-python wrapper) is not installed", "install python3, then re-run")
	}
	if code != 0 {
		return fail(classProxyCompat,
			fmt.Sprintf("python through the proxy failed (exit %d): %s", code, oneLine(out)),
			"use the pipelock-python wrapper, which forces HTTPS_PROXY + REQUESTS_CA_BUNDLE + SSL_CERT_FILE")
	}
	httpCode, ok := trailingHTTPCode(out)
	if !ok || !is2xx3xx(httpCode) {
		return fail(classPolicy,
			fmt.Sprintf("python reached the proxy but got an unexpected status: %s", oneLine(out)),
			"check pipelock logs for a block decision on "+env.canaryURL)
	}
	return pass(fmt.Sprintf("HTTP %d via the pipelock-python wrapper", httpCode))
}

// ---------------------------------------------------------------------------
// Check 4: node through proxy (via the pipelock-node wrapper + undici shim)
// ---------------------------------------------------------------------------

const nodeProbeScript = "(async()=>{try{" +
	"const u=process.argv[process.argv.length-1];" +
	"const r=await fetch(u);" +
	"process.stdout.write(String(r.status));process.exit(0);" +
	"}catch(e){process.stderr.write(String((e&&e.message)||e));process.exit(1);}})()"

func checkNodeThroughProxy(ctx context.Context, env *doctorEnv) doctorResult {
	// The shim is what makes node's fetch() honor HTTPS_PROXY; surface a clear
	// remediation if it is missing rather than letting node fail on --require.
	if _, err := env.stat(env.undiciShimPath); err != nil {
		return skip(fmt.Sprintf("undici shim missing at %s", env.undiciShimPath), "re-run `pipelock contain install` to write the shim")
	}
	wrapper := filepath.Join(env.wrapperDir, "pipelock-node")
	name, args := env.sudoAgent(wrapper, "-e", nodeProbeScript, env.canaryURL)
	out, code, err := env.runCmd(ctx, name, args...)
	if res, done := classifyAgentRun(out, err, "node"); done {
		return res
	}
	if code == 127 || isSudoTargetCommandMissing(out) {
		return skip("node (or the pipelock-node wrapper) is not installed", "install node, then re-run")
	}
	if code != 0 {
		return fail(classProxyCompat,
			fmt.Sprintf("node fetch through the proxy failed (exit %d): %s", code, oneLine(out)),
			"node ignores HTTPS_PROXY for fetch() unless the undici shim is loaded; use the pipelock-node wrapper (NODE_OPTIONS=--require "+env.undiciShimPath+")")
	}
	httpCode, ok := trailingHTTPCode(out)
	if !ok || !is2xx3xx(httpCode) {
		return fail(classPolicy,
			fmt.Sprintf("node reached the proxy but got an unexpected status: %s", oneLine(out)),
			"check pipelock logs for a block decision on "+env.canaryURL)
	}
	return pass(fmt.Sprintf("HTTP %d via the pipelock-node wrapper (undici shim active)", httpCode))
}

// ---------------------------------------------------------------------------
// Check 5: DNS-failure behavior
// ---------------------------------------------------------------------------

// dnsFailureHost is a name guaranteed not to resolve (RFC 6761 reserves
// .invalid). A request to it through the proxy must produce a clean, bounded
// error — not a hang, and not a success (which would mean a bogus host
// resolved or the agent bypassed the proxy).
const dnsFailureHost = "pipelock-doctor-nonexistent.invalid"

// checkDNSFailure proves an invalid hostname is rejected by the proxy rather
// than succeeding, hanging, or failing without proxy attribution.
func checkDNSFailure(ctx context.Context, env *doctorEnv) doctorResult {
	// %{http_connect} is the proxy's CONNECT response. It gives this check a
	// positive attribution signal: a 5xx proves Pipelock handled the request and
	// rejected the unresolvable target. A bare nonzero curl exit could instead be
	// a dead proxy, TLS failure, or unrelated transport error.
	name, args := env.sudoAgent(env.curlProxyArgsWithWriteOut("https://"+dnsFailureHost+"/", "%{http_connect}")...)
	out, code, err := env.runCmd(ctx, name, args...)
	if res, done := classifyAgentRun(out, err, "curl"); done {
		return res
	}
	if isSudoTargetCommandMissing(out) {
		return skip("curl not available for the agent", "install curl on the host")
	}
	connectCode, ok := trailingHTTPCode(out)
	if code != 0 && ok && connectCode >= 500 && connectCode < 600 {
		return pass(fmt.Sprintf("proxy CONNECT returned HTTP %d for the unresolvable host (curl exit %d, clean failure)", connectCode, code))
	}
	if code == 0 && ok && connectCode == 200 {
		return fail(classInfra,
			fmt.Sprintf("an unresolvable host completed proxy CONNECT with HTTP %d — a bogus name resolved or DNS was intercepted", connectCode),
			"investigate DNS interception / captive portal; the agent should never reach "+dnsFailureHost)
	}
	return unknown(classInfra,
		fmt.Sprintf("DNS-failure probe was inconclusive (curl exit %d, proxy CONNECT status %s): %s",
			code, formatObservedHTTPCode(connectCode, ok), oneLine(out)),
		"confirm the proxy is healthy, then inspect Pipelock logs for the "+dnsFailureHost+" resolution failure")
}

// formatObservedHTTPCode renders a parsed status or an explicit parse failure.
func formatObservedHTTPCode(code int, ok bool) string {
	if !ok {
		return "unparseable"
	}
	return strconv.Itoa(code)
}

// ---------------------------------------------------------------------------
// Check 6: raw-egress diagnostics
// ---------------------------------------------------------------------------

// curlDirectArgs builds the bounded DNS-free direct-egress probe.
func (env *doctorEnv) curlDirectArgs() []string {
	return curlDirectCanaryArgsFor(env.curlPath)
}

// checkRawEgressBlocked requires probe-specific time_connect evidence plus a
// positive DROP-counter delta before a dial-level curl failure can pass;
// completed dials and post-connect failures always fail closed.
func checkRawEgressBlocked(ctx context.Context, env *doctorEnv) doctorResult {
	var before uint64
	var beforeErr error
	if env.dropCounter != nil {
		before, beforeErr = env.dropCounter(ctx)
	}

	name, args := env.sudoAgent(env.curlDirectArgs()...)
	out, code, err := env.runCmd(ctx, name, args...)
	if res, done := classifyAgentRun(out, err, "curl"); done {
		return res
	}
	if isSudoTargetCommandMissing(out) {
		return skip("curl not available for the agent", "install curl on the host")
	}
	if code == 0 {
		httpCode, ok := trailingHTTPCode(out)
		detail := "agent completed a direct HTTP request, bypassing the proxy"
		if ok {
			detail = fmt.Sprintf("CONTAINMENT HOLE: agent reached %s directly (HTTP %d), bypassing the proxy", directEgressCanaryURL, httpCode)
		}
		return fail(classInfra, detail,
			"the nftables owner-match egress rule is missing or broken; run `pipelock contain verify` and re-install")
	}
	dialCompletion := parseDirectCurlDialCompletion(out)
	outcome, after, afterErr := classifyDirectEgressAttribution(code, dialCompletion, env.dropCounter != nil, before, beforeErr, func() (uint64, error) {
		return env.dropCounter(ctx)
	})
	switch outcome {
	case egressAttrFailPostConnect:
		return fail(classInfra,
			fmt.Sprintf("CONTAINMENT HOLE: direct egress reached the network before curl failed (exit %d): %s", code, oneLine(out)),
			"verify the nftables owner-match drop is present (`pipelock contain verify`); a post-connect error means the outbound dial escaped containment")
	case egressAttrUnknownDialCompletion:
		return unknownInfra(fmt.Sprintf("direct egress curl failed (exit %d), but probe-specific time_connect was missing or unparseable; refusing to claim containment", code))
	case egressAttrUnknownNoCounter:
		return unknownInfra(fmt.Sprintf("direct egress curl failed (exit %d), but no DROP counter reader is available; containment attribution is inconclusive", code))
	case egressAttrUnknownBeforeErr:
		return unknownInfra(fmt.Sprintf("direct egress curl failed (exit %d), but reading the DROP counter before the probe failed: %v", code, beforeErr))
	case egressAttrUnknownAfterErr:
		return unknownInfra(fmt.Sprintf("direct egress curl failed (exit %d), but reading the DROP counter after the probe failed: %v", code, afterErr))
	case egressAttrUnknownNoDelta:
		return unknownInfra(fmt.Sprintf("direct egress curl failed (exit %d), but the managed DROP counter did not increase (%d -> %d)", code, before, after))
	case egressAttrUnknownUnexpectedExit:
		return unknownInfra(fmt.Sprintf("direct egress curl failed with unexpected exit %d despite a counter delta; the DNS-free HTTP canary expected a connect refusal or timeout", code))
	case egressAttrPass:
		return doctorResult{
			status: statusPass,
			detail: fmt.Sprintf("direct egress dial did not complete (curl exit %d, time_connect=0) and managed nftables DROP counter increased (%d -> %d); proxy-unaware tools fail here", code, before, after),
			remediation: "a tool that 'can't reach the internet' is ignoring the proxy, NOT broken — " +
				"run it via pipelock-curl / pipelock-python / pipelock-node, or export HTTPS_PROXY=" + proxyURLFor(env.port),
			class: classProxyCompat,
		}
	default:
		// Fail closed: an unhandled attribution outcome must never claim PASS.
		return unknownInfra(fmt.Sprintf("unexpected direct-egress attribution outcome %d (exit %d); refusing to claim containment", outcome, code))
	}
}

// ---------------------------------------------------------------------------
// Command wiring + runner
// ---------------------------------------------------------------------------

type doctorOpts struct {
	jsonOutput bool
	port       int
	url        string
}

// doctorCmd builds the live containment-diagnostics command.
func doctorCmd() *cobra.Command {
	var opts doctorOpts

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Live self-test of the contained agent's runtime contract",
		Long: `Run live checks proving common tooling can reach the internet THROUGH the
Pipelock proxy from the contained pipelock-agent user, and that direct egress
is blocked.

Unlike ` + "`verify`" + ` (which proves the boundary is installed), doctor proves the
boundary is USABLE and makes failure classes distinguishable so a
compatibility problem does not look like a broken agent:

  policy        blocked because the request is dangerous
  proxy-compat  the tool isn't proxy-compatible (ignores HTTPS_PROXY)
  local-context Pipelock misclassified harmless local context
  infra         infra protection tripped (DNS failure, gateway down)

Each check reports pass/fail/skip plus the exact remediation. doctor never
mutates state. Run it as root (it sudoes to the agent for the live probes).

Exit codes:
  0  All checks passed.
  1  At least one check failed.
  2  Incomplete (a check was skipped or inconclusive).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validatePort(opts.port); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			env := doctorEnvFactory()
			env.port = opts.port
			if opts.url != "" {
				env.canaryURL = opts.url
			}
			return runDoctor(cmd, env, opts)
		},
	}

	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit newline-delimited JSON instead of text")
	cmd.Flags().IntVar(&opts.port, "port", defaultProxyPort, "pipelock proxy port to test on loopback")
	cmd.Flags().StringVar(&opts.url, "url", canaryURL, "allowed canary URL the agent should be able to reach")

	return cmd
}

// doctorRecord is one JSON record per check in --json output.
type doctorRecord struct {
	Check       int    `json:"check"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	Detail      string `json:"detail,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Class       string `json:"class,omitempty"`
}

// runDoctor executes all checks, writes fail-closed output, and returns the
// aggregate CLI exit contract.
func runDoctor(cmd *cobra.Command, env *doctorEnv, opts doctorOpts) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	w := cmd.OutOrStdout()
	var textWriter *errorTrackingWriter
	if !opts.jsonOutput {
		textWriter = &errorTrackingWriter{w: w}
		w = textWriter
	}
	enc := json.NewEncoder(w)

	if !opts.jsonOutput {
		_, _ = fmt.Fprintln(w, "pipelock contain doctor")
		if err := textWriter.Err(); err != nil {
			return fmt.Errorf("writing doctor header: %w", err)
		}
	}

	var passN, failN, skipN, unknownN int
	for _, c := range allDoctorChecks() {
		res := c.fn(ctx, env)
		switch res.status {
		case statusPass:
			passN++
		case statusFail:
			failN++
		case statusSkip:
			skipN++
		case statusUnknown:
			unknownN++
		default:
			failN++
			res.detail = fmt.Sprintf("invalid status %q (detail: %s)", res.status, res.detail)
			res.status = statusFail
		}

		if opts.jsonOutput {
			if err := enc.Encode(doctorRecord{
				Check:       c.n,
				Name:        c.name,
				Status:      res.status,
				Detail:      res.detail,
				Remediation: res.remediation,
				Class:       res.class,
			}); err != nil {
				return fmt.Errorf("encoding check %d JSON: %w", c.n, err)
			}
			continue
		}
		writeDoctorLine(w, c, res)
		if err := textWriter.Err(); err != nil {
			return fmt.Errorf("writing check %d text: %w", c.n, err)
		}
	}

	exitCode := cliutil.ExitOK
	switch {
	case failN > 0:
		exitCode = cliutil.ExitGeneral
	case skipN > 0 || unknownN > 0:
		exitCode = cliutil.ExitConfig
	}

	if opts.jsonOutput {
		if err := enc.Encode(aggregateRecord{Aggregate: aggregateBody{
			Pass:     passN,
			Fail:     failN,
			Skip:     skipN,
			Unknown:  unknownN,
			Total:    len(allDoctorChecks()),
			ExitCode: exitCode,
		}}); err != nil {
			return fmt.Errorf("encoding aggregate JSON: %w", err)
		}
	} else {
		if unknownN > 0 {
			_, _ = fmt.Fprintf(w, "Result: %d PASS / %d FAIL / %d SKIP / %d UNKNOWN — exit %d\n", passN, failN, skipN, unknownN, exitCode)
		} else {
			_, _ = fmt.Fprintf(w, "Result: %d PASS / %d FAIL / %d SKIP — exit %d\n", passN, failN, skipN, exitCode)
		}
		printEvidencePaths(w)
		if err := textWriter.Err(); err != nil {
			return fmt.Errorf("writing doctor aggregate: %w", err)
		}
	}

	if exitCode == cliutil.ExitOK {
		return nil
	}
	if failN > 0 {
		return cliutil.ExitCodeError(exitCode, fmt.Errorf("%d check(s) failed", failN))
	}
	if unknownN > 0 {
		return cliutil.ExitCodeError(exitCode, fmt.Errorf("%d check(s) inconclusive; diagnosis incomplete", unknownN))
	}
	return cliutil.ExitCodeError(exitCode, fmt.Errorf("%d check(s) skipped; diagnosis incomplete", skipN))
}

// writeDoctorLine renders one check outcome in text mode, including the
// remediation + block class on a non-pass.
func writeDoctorLine(w io.Writer, c doctorCheck, res doctorResult) {
	tag := "[PASS]"
	switch res.status {
	case statusFail:
		tag = "[FAIL]"
	case statusSkip:
		tag = "[SKIP]"
	case statusUnknown:
		tag = "[UNKNOWN]"
	}
	line := fmt.Sprintf("  %s check %d: %s", tag, c.n, c.desc)
	if res.detail != "" {
		line += " — " + res.detail
	}
	_, _ = fmt.Fprintln(w, line)
	if res.remediation != "" {
		if res.class != "" {
			_, _ = fmt.Fprintf(w, "          ↳ [%s] %s\n", res.class, res.remediation)
		} else {
			_, _ = fmt.Fprintf(w, "          ↳ %s\n", res.remediation)
		}
	}
}

// printEvidencePaths emits the resolved evidence/receipts paths after the
// doctor result summary. Operators running doctor are typically debugging
// containment and need to know where to find audit logs and receipts.
func printEvidencePaths(w io.Writer) {
	// Use the same default paths from the install env so there is a single
	// source of truth for the filesystem layout.
	_, _ = fmt.Fprintln(w, "Evidence paths:")
	_, _ = fmt.Fprintf(w, "  logs:     %s\n", filepath.Join(defaultDataDir, "logs"))
	_, _ = fmt.Fprintf(w, "  receipts: %s\n", filepath.Join(defaultDataDir, "recorder"))
}
