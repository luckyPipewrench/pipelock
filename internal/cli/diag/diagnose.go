// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const diagnoseTimeout = 5 * time.Second

var diagnoseClient = &http.Client{Timeout: diagnoseTimeout}

// diagnoseGet performs a GET request with a background context so noctx is satisfied.
func diagnoseGet(url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return diagnoseClient.Do(req)
}

type diagnoseCheck struct {
	Name string
	Run  func(proxyURL, mockURL string, cfg *config.Config) diagnoseResult
}

type diagnoseResult struct {
	Status string `json:"status"` // pass, fail, skip
	Detail string `json:"detail,omitempty"`
}

type diagnoseReport struct {
	ConfigFile string                `json:"config_file"`
	Mode       string                `json:"mode"`
	Total      int                   `json:"total"`
	Passed     int                   `json:"passed"`
	Failed     int                   `json:"failed"`
	Skipped    int                   `json:"skipped"`
	Checks     []diagnoseReportCheck `json:"checks"`
}

type diagnoseReportCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func DiagnoseCmd() *cobra.Command {
	var configFile string
	var jsonOutput bool
	var noColor bool
	var sandboxCheck bool

	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Run end-to-end diagnostic checks against a local proxy",
		Long: `Spin up a temporary proxy with a local mock upstream and run diagnostic
checks to verify your configuration works correctly. No network access required.

Checks:
  health           /health endpoint responds 200
  fetch_allowed    Allowed fetch succeeds and returns content
  fetch_blocked    DLP-triggering fetch is blocked correctly
  fetch_hint       Blocked response includes actionable hint (requires explain_blocks)
  forward_allowed  CONNECT tunnel to allowed host succeeds
  forward_blocked  CONNECT tunnel to blocklisted host is rejected
  rules            Installed rule bundles load and verify correctly

Exit codes:
  0  All checks passed (skipped checks are OK)
  1  One or more checks failed
  2  Config load error`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Sandbox mode: run only sandbox capability checks (no proxy).
			if sandboxCheck {
				return runDiagnoseSandbox(cmd, jsonOutput, !noColor && cliutil.UseColor())
			}

			cfg, cfgLabel, err := loadTestConfig(configFile)
			if err != nil {
				return cliutil.ExitCodeError(2, err)
			}

			// Disable SSRF so mock upstream at 127.0.0.1 is reachable.
			cfg.Internal = nil
			// Disable env scanning for self-test.
			cfg.DLP.ScanEnv = false
			// Enable forward proxy for CONNECT checks.
			cfg.ForwardProxy.Enabled = true

			color := !noColor && cliutil.UseColor()

			return runDiagnose(cmd, cfg, cfgLabel, jsonOutput, color)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file (default: built-in defaults)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output results as JSON")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "disable color output")
	cmd.Flags().BoolVar(&sandboxCheck, "sandbox", false, "run sandbox capability checks instead of proxy diagnostics")

	return cmd
}

func runDiagnose(cmd *cobra.Command, cfg *config.Config, cfgLabel string, jsonOut, color bool) error {
	// Start mock upstream that responds 200 to everything.
	// Use explicit listener to return an error instead of panicking.
	var lc net.ListenConfig
	mockLn, err := lc.Listen(cmd.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("mock upstream listener: %w", err)
	}
	mock := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("mock upstream OK"))
	}))
	mock.Listener = mockLn
	mock.Start()
	defer mock.Close()

	// Add mock hostname (without port) to allowlist so fetch_allowed passes.
	// MatchDomain compares against parsed.Hostname() which strips port.
	mockHostPort := strings.TrimPrefix(mock.URL, "http://")
	mockHost, _, _ := net.SplitHostPort(mockHostPort)
	cfg.APIAllowlist = append(cfg.APIAllowlist, mockHost)

	// Add a known blocklist entry for forward_blocked check.
	cfg.FetchProxy.Monitoring.Blocklist = append(cfg.FetchProxy.Monitoring.Blocklist, "malware.example.com")

	// Nop logger avoids writing to stdout, which would corrupt --json output.
	bundleResult := rules.MergeIntoConfig(cfg, cliutil.Version)
	for _, e := range bundleResult.Errors {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pipelock: warning: bundle %s: %s\n", e.Name, e.Reason)
	}
	sc := scanner.New(cfg)
	defer sc.Close()
	logger := audit.NewNop()
	defer logger.Close()
	m := metrics.New()

	p, pErr := proxy.New(cfg, logger, sc, m)
	if pErr != nil {
		return fmt.Errorf("creating proxy: %w", pErr)
	}

	// Start temp proxy using the composed handler.
	proxyLn, err := lc.Listen(cmd.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("proxy listener: %w", err)
	}
	ts := httptest.NewUnstartedServer(p.Handler())
	ts.Listener = proxyLn
	ts.Start()
	defer ts.Close()

	checks := buildDiagnoseChecks()

	report := diagnoseReport{
		ConfigFile: cfgLabel,
		Mode:       cfg.Mode,
		Total:      len(checks),
	}

	for _, c := range checks {
		result := c.Run(ts.URL, mock.URL, cfg)
		switch result.Status {
		case statusPass:
			report.Passed++
		case statusFail:
			report.Failed++
		case statusSkip:
			report.Skipped++
		}
		report.Checks = append(report.Checks, diagnoseReportCheck{
			Name:   c.Name,
			Status: result.Status,
			Detail: result.Detail,
		})
	}

	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("JSON encode: %w", err)
		}
	} else {
		printDiagnoseTable(cmd.OutOrStdout(), report, color)
	}

	if report.Failed > 0 {
		return cliutil.ExitCodeError(1, fmt.Errorf("%d check(s) failed", report.Failed))
	}
	return nil
}

func buildDiagnoseChecks() []diagnoseCheck {
	return []diagnoseCheck{
		{Name: "health", Run: checkHealth},
		{Name: "fetch_allowed", Run: checkFetchAllowed},
		{Name: "fetch_blocked", Run: checkFetchBlocked},
		{Name: "fetch_hint", Run: checkFetchHint},
		{Name: "forward_allowed", Run: checkForwardAllowed},
		{Name: "forward_blocked", Run: checkForwardBlocked},
		{Name: "rules", Run: checkRules},
	}
}

func checkHealth(proxyURL, _ string, _ *config.Config) diagnoseResult {
	resp, err := diagnoseGet(proxyURL + "/health") //nolint:gosec // diagnostic one-shot to local httptest
	if err != nil {
		return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("health request failed: %v", err)}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("expected 200, got %d", resp.StatusCode)}
	}
	return diagnoseResult{Status: statusPass}
}

func checkFetchAllowed(proxyURL, mockURL string, _ *config.Config) diagnoseResult {
	resp, err := diagnoseGet(proxyURL + "/fetch?url=" + mockURL) //nolint:gosec // diagnostic one-shot to local httptest
	if err != nil {
		return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("fetch request failed: %v", err)}
	}
	defer func() { _ = resp.Body.Close() }()

	var fr proxy.FetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil {
		return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("decode error: %v", err)}
	}
	if fr.Blocked {
		return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("expected allowed, got blocked: %s", fr.BlockReason)}
	}
	if resp.StatusCode != http.StatusOK {
		return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("expected 200, got %d", resp.StatusCode)}
	}
	if fr.Error != "" {
		return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("fetch error: %s", fr.Error)}
	}
	return diagnoseResult{Status: statusPass}
}

func checkFetchBlocked(proxyURL, mockURL string, _ *config.Config) diagnoseResult {
	// Split credential at runtime to avoid gosec G101 (hardcoded credentials).
	fakeKey := "AKIA" + "IOSFODNN7EXAMPLE"
	url := proxyURL + "/fetch?url=" + mockURL + "%3Ftoken%3D" + fakeKey

	resp, err := diagnoseGet(url) //nolint:gosec // diagnostic one-shot to local httptest
	if err != nil {
		return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("fetch request failed: %v", err)}
	}
	defer func() { _ = resp.Body.Close() }()

	var fr proxy.FetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil {
		return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("decode error: %v", err)}
	}
	if !fr.Blocked {
		return diagnoseResult{Status: statusFail, Detail: "expected blocked by DLP, but request was allowed"}
	}
	if !strings.Contains(fr.BlockReason, "DLP") && !strings.Contains(fr.BlockReason, "leak detected") {
		return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("blocked by %q, expected DLP scanner", fr.BlockReason)}
	}
	return diagnoseResult{Status: statusPass, Detail: fmt.Sprintf("reason=%s", fr.BlockReason)}
}

func checkFetchHint(proxyURL, mockURL string, cfg *config.Config) diagnoseResult {
	if !cfg.ExplainBlocksEnabled() {
		return diagnoseResult{
			Status: statusSkip,
			Detail: "explain_blocks not enabled; set explain_blocks: true in config to test",
		}
	}

	fakeKey := "AKIA" + "IOSFODNN7EXAMPLE"
	url := proxyURL + "/fetch?url=" + mockURL + "%3Ftoken%3D" + fakeKey

	resp, err := diagnoseGet(url) //nolint:gosec // diagnostic one-shot to local httptest
	if err != nil {
		return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("fetch request failed: %v", err)}
	}
	defer func() { _ = resp.Body.Close() }()

	var fr proxy.FetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil {
		return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("decode error: %v", err)}
	}
	if !fr.Blocked {
		return diagnoseResult{Status: statusFail, Detail: "expected blocked, but request was allowed"}
	}
	if fr.Hint == "" {
		return diagnoseResult{Status: statusFail, Detail: "expected non-empty hint in blocked response"}
	}
	return diagnoseResult{Status: statusPass, Detail: fmt.Sprintf("hint=%q", fr.Hint)}
}

func checkForwardAllowed(proxyURL, mockURL string, _ *config.Config) diagnoseResult {
	// CONNECT to the mock upstream's host:port.
	mockHost := strings.TrimPrefix(mockURL, "http://")

	conn, err := connectThroughProxy(proxyURL, mockHost)
	if err != nil {
		return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("CONNECT failed: %v", err)}
	}
	_ = conn.Close()
	return diagnoseResult{Status: statusPass}
}

func checkForwardBlocked(proxyURL, _ string, _ *config.Config) diagnoseResult {
	_, err := connectThroughProxy(proxyURL, "malware.example.com:443")
	if err == nil {
		return diagnoseResult{Status: statusFail, Detail: "expected CONNECT to be blocked, but it succeeded"}
	}
	// The error should indicate a 403.
	if strings.Contains(err.Error(), "403") {
		return diagnoseResult{Status: statusPass}
	}
	return diagnoseResult{Status: statusFail, Detail: fmt.Sprintf("unexpected error (expected 403): %v", err)}
}

func checkRules(_, _ string, cfg *config.Config) diagnoseResult {
	rulesDir := rules.ResolveRulesDir(cfg.Rules.RulesDir)
	result := rules.LoadBundles(rulesDir, rules.LoadOptions{
		MinConfidence:   cfg.Rules.MinConfidence,
		TrustedKeys:     cfg.Rules.TrustedKeys,
		PipelockVersion: cliutil.Version,
	})

	if len(result.Loaded) == 0 && len(result.Errors) == 0 {
		return diagnoseResult{Status: statusSkip, Detail: "no bundles installed"}
	}

	var detail strings.Builder
	for _, b := range result.Loaded {
		_, _ = fmt.Fprintf(&detail, "%s v%s (%d rules)", b.Name, b.Version, b.Rules)
		if b.Unsigned {
			detail.WriteString(" [unsigned]")
		}
		detail.WriteString("; ")
	}
	for _, e := range result.Errors {
		_, _ = fmt.Fprintf(&detail, "%s: FAILED (%s); ", e.Name, e.Reason)
	}

	if len(result.Errors) > 0 {
		return diagnoseResult{Status: statusFail, Detail: detail.String()}
	}
	return diagnoseResult{Status: statusPass, Detail: detail.String()}
}

// connectThroughProxy issues a CONNECT request through the proxy and returns
// the hijacked connection on success, or an error if blocked/failed.
func connectThroughProxy(proxyURL, target string) (net.Conn, error) {
	proxyHost := strings.TrimPrefix(proxyURL, "http://")

	ctx, cancel := context.WithTimeout(context.Background(), diagnoseTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(diagnoseTimeout))

	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", http.MethodConnect, target, target)
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}

	//nolint:bodyclose // CONNECT 200 has no body; resp.Body wraps the tunneled conn we return.
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT rejected: %s", resp.Status)
	}

	// Clear deadline for caller use.
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func printDiagnoseTable(w io.Writer, report diagnoseReport, color bool) {
	_, _ = fmt.Fprintf(w, "Pipelock Diagnostics\n")
	_, _ = fmt.Fprintf(w, "Config: %s  Mode: %s\n\n", report.ConfigFile, report.Mode)

	for _, c := range report.Checks {
		icon := statusIcon(c.Status, color)
		line := fmt.Sprintf("  %s  %-20s", icon, c.Name)
		if c.Detail != "" {
			line += "  " + c.Detail
		}
		_, _ = fmt.Fprintln(w, line)
	}

	_, _ = fmt.Fprintf(w, "\n%d passed, %d failed, %d skipped\n", report.Passed, report.Failed, report.Skipped)
}

func statusIcon(status string, color bool) string {
	if color {
		switch status {
		case statusPass:
			return "\033[32mPASS\033[0m"
		case statusFail:
			return "\033[31mFAIL\033[0m"
		case statusSkip:
			return "\033[33mSKIP\033[0m"
		}
	}
	return strings.ToUpper(status)
}

// runDiagnoseSandbox runs sandbox capability checks without starting a proxy.
func runDiagnoseSandbox(cmd *cobra.Command, jsonOut bool, color bool) error {
	caps := sandbox.Detect()

	checks := []diagnoseReportCheck{
		{Name: "sandbox_landlock", Status: statusPass, Detail: fmt.Sprintf("ABI v%d", caps.LandlockABI)},
		{Name: "sandbox_userns", Status: statusPass, Detail: fmt.Sprintf("max %d", caps.MaxUserNS)},
		{Name: "sandbox_seccomp", Status: statusPass, Detail: "available"},
		{Name: "sandbox_selinux", Status: statusPass, Detail: caps.SELinux},
	}
	if caps.LandlockABI <= 0 {
		checks[0].Status = statusFail
		checks[0].Detail = stateUnavailable
	}
	if !caps.UserNamespaces {
		checks[1].Status = statusFail
		checks[1].Detail = stateUnavailable
	}
	if !caps.Seccomp {
		checks[2].Status = statusFail
		checks[2].Detail = stateUnavailable
	}
	if caps.SELinux == "" {
		checks[3].Status = statusSkip
		checks[3].Detail = "not present"
	}

	passed, failed, skipped := 0, 0, 0
	for _, c := range checks {
		switch c.Status {
		case statusPass:
			passed++
		case statusFail:
			failed++
		case statusSkip:
			skipped++
		}
	}

	// Build recommendation.
	active := 0
	if caps.LandlockABI > 0 {
		active++
	}
	if caps.UserNamespaces {
		active++
	}
	if caps.Seccomp {
		active++
	}
	const totalLayers = 3
	recommendation := fmt.Sprintf("All %d/%d capabilities detected (launch may still fail under AppArmor/container restrictions)", active, totalLayers)
	if active < totalLayers {
		recommendation = fmt.Sprintf("Degraded: %d/%d capabilities detected", active, totalLayers)
	}

	report := diagnoseReport{
		ConfigFile: "(sandbox capability check)",
		Mode:       "sandbox",
		Total:      len(checks),
		Passed:     passed,
		Failed:     failed,
		Skipped:    skipped,
		Checks:     checks,
	}

	if jsonOut {
		type sandboxReport struct {
			diagnoseReport
			Sandbox struct {
				LandlockABI    int    `json:"landlock_abi"`
				UserNamespaces bool   `json:"user_namespaces"`
				MaxUserNS      int    `json:"max_user_ns"`
				Seccomp        bool   `json:"seccomp"`
				SELinux        string `json:"selinux"`
				Recommendation string `json:"recommendation"`
			} `json:"sandbox"`
		}
		sr := sandboxReport{diagnoseReport: report}
		sr.Sandbox.LandlockABI = caps.LandlockABI
		sr.Sandbox.UserNamespaces = caps.UserNamespaces
		sr.Sandbox.MaxUserNS = caps.MaxUserNS
		sr.Sandbox.Seccomp = caps.Seccomp
		sr.Sandbox.SELinux = caps.SELinux
		sr.Sandbox.Recommendation = recommendation
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		if err := enc.Encode(sr); err != nil {
			return err
		}
		if failed > 0 {
			return cliutil.ExitCodeError(1, fmt.Errorf("%d sandbox check(s) failed", failed))
		}
		return nil
	}

	// Text output.
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Sandbox Capabilities:\n")
	for _, c := range checks {
		label := statusIcon(c.Status, color)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %-20s %s  %s\n", c.Name, label, c.Detail)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n  Recommendation: %s\n", recommendation)

	if failed > 0 {
		return cliutil.ExitCodeError(1, fmt.Errorf("%d sandbox check(s) failed", failed))
	}
	return nil
}
