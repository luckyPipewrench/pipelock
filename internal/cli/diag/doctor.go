// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

const (
	doctorStatusOK      = "ok"
	doctorStatusWarn    = "warn"
	doctorStatusFail    = "fail"
	doctorStatusInfo    = "info"
	doctorSurfaceHTTP   = "http"
	doctorSurfaceMCP    = "mcp"
	doctorSurfaceHost   = "host"
	doctorSurfaceConfig = "config"
)

const doctorRootBannerText = "running as root: readability checks reflect root's view, not pipelock-proxy's. Re-run as the service user for an accurate readability report."

type doctorReport struct {
	ConfigFile    string              `json:"config_file"`
	Mode          string              `json:"mode"`
	Version       string              `json:"version"`
	RootRunBanner string              `json:"root_run_banner,omitempty"`
	Summary       doctorSummary       `json:"summary"`
	Checks        []doctorReportCheck `json:"checks"`
}

type doctorSummary struct {
	OK       int `json:"ok"`
	Warnings int `json:"warnings"`
	Failures int `json:"failures"`
	Info     int `json:"info"`
}

type doctorReportCheck struct {
	Name       string `json:"name"`
	Surface    string `json:"surface"`
	Status     string `json:"status"`
	Configured bool   `json:"configured"`
	Reachable  bool   `json:"reachable"`
	Enforcing  bool   `json:"enforcing"`
	Detail     string `json:"detail,omitempty"`
	Next       string `json:"next,omitempty"`
}

func DoctorCmd() *cobra.Command {
	var configFile string
	var jsonOutput bool
	var noColor bool
	var checkPorts bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Report whether configured protections are actually enforceable",
		Long: `Report the difference between configured protections and protections that
can actually enforce in the current topology. This command does not perform
network access. It checks local config, filesystem reachability, and known
deployment prerequisites so operators can catch no-op security settings before
claiming production coverage.

Readability checks reflect the calling user's view. When run as root (sudo),
DAC checks are bypassed and any file the kernel can stat will look readable.
Re-run as the pipelock service user for an accurate "can the service read
this" report.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, cfgLabel, err := loadTestConfig(configFile)
			if err != nil {
				return cliutil.ExitCodeError(2, err)
			}
			report := buildDoctorReport(cfg, cfgLabel)
			if checkPorts {
				report.Checks = append(report.Checks, checkPortsReport(cfg)...)
				// Rebuild summary tallies so the appended port checks count
				// against pass/warn/fail exit codes alongside the built-in
				// checks. Re-tally rather than incremental-add so the same
				// code path produces summary either way.
				report.Summary = doctorSummary{}
				for _, check := range report.Checks {
					switch check.Status {
					case doctorStatusOK:
						report.Summary.OK++
					case doctorStatusWarn:
						report.Summary.Warnings++
					case doctorStatusFail:
						report.Summary.Failures++
					default:
						report.Summary.Info++
					}
				}
			}
			if jsonOutput {
				report.RootRunBanner = doctorRootBannerMessage()
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return fmt.Errorf("encode doctor report JSON: %w", err)
				}
			} else {
				printDoctorReport(cmd, report, !noColor && cliutil.UseColor())
			}
			if report.Summary.Failures > 0 {
				return cliutil.ExitCodeError(2, fmt.Errorf("%d doctor failure(s)", report.Summary.Failures))
			}
			if report.Summary.Warnings > 0 {
				return cliutil.ExitCodeError(1, fmt.Errorf("%d doctor warning(s)", report.Summary.Warnings))
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file (default: built-in defaults)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output report as JSON")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "disable color output")
	cmd.Flags().BoolVar(&checkPorts, "check-ports", false, "report which process holds each configured listener port (Linux /proc; run as root for cross-user visibility)")

	return cmd
}

func buildDoctorReport(cfg *config.Config, cfgLabel string) doctorReport {
	report := doctorReport{
		ConfigFile: cfgLabel,
		Mode:       cfg.Mode,
		Version:    cliutil.Version,
	}
	report.Checks = []doctorReportCheck{
		checkDoctorHTTPProxy(cfg),
		checkDoctorTLSInterception(cfg),
		checkDoctorRequestBodyScanning(cfg),
		checkDoctorBrowserShield(cfg),
		checkDoctorMCPWrapperFeatures(cfg),
		checkDoctorMCPBinaryIntegrity(cfg),
		checkDoctorMCPToolProvenance(cfg),
		checkDoctorFileSentry(cfg),
		checkDoctorLicense(cfg),
		checkDoctorSentry(cfg),
		checkDoctorDeploymentBoundary(cfg),
	}
	report.Checks = append(report.Checks, checkDoctorConfigSemantics(cfg)...)
	for _, check := range report.Checks {
		switch check.Status {
		case doctorStatusOK:
			report.Summary.OK++
		case doctorStatusWarn:
			report.Summary.Warnings++
		case doctorStatusFail:
			report.Summary.Failures++
		default:
			report.Summary.Info++
		}
	}
	return report
}

func checkDoctorLicense(cfg *config.Config) doctorReportCheck {
	if cfg.LicenseKey == "" {
		return doctorReportCheck{
			Name:    "license_status",
			Surface: doctorSurfaceConfig,
			Status:  doctorStatusInfo,
			Detail:  "no enterprise license configured",
		}
	}
	lic, verified, err := doctorVerifiedLicense(cfg)
	if err != nil {
		status := doctorStatusWarn
		if errors.Is(err, license.ErrLicenseExpired) || errors.Is(err, license.ErrLicenseRevoked) {
			status = doctorStatusFail
		}
		return doctorReportCheck{
			Name:       "license_status",
			Surface:    doctorSurfaceConfig,
			Status:     status,
			Configured: true,
			Detail:     "license verification failed: " + err.Error(),
			Next:       "run `pipelock license status` for details and install a valid license token",
		}
	}
	if !verified {
		return doctorReportCheck{
			Name:       "license_status",
			Surface:    doctorSurfaceConfig,
			Status:     doctorStatusWarn,
			Configured: true,
			Detail:     fmt.Sprintf("license %s is present but signature could not be verified because no public key is available", lic.ID),
			Next:       "set license_public_key in dev builds or use an official build with an embedded key",
		}
	}
	if cfg.LicenseRevoked {
		return doctorReportCheck{
			Name:       "license_status",
			Surface:    doctorSurfaceConfig,
			Status:     doctorStatusFail,
			Configured: true,
			Detail:     fmt.Sprintf("license %s is revoked: %s", lic.ID, cfg.LicenseRevocationReason),
			Next:       "install a renewed license token before relying on enterprise agent profiles",
		}
	}
	if lic.ExpiresAt > 0 && time.Now().Unix() > lic.ExpiresAt {
		return doctorReportCheck{
			Name:       "license_status",
			Surface:    doctorSurfaceConfig,
			Status:     doctorStatusFail,
			Configured: true,
			Detail:     fmt.Sprintf("license %s expired on %s", lic.ID, time.Unix(lic.ExpiresAt, 0).UTC().Format(time.DateOnly)),
			Next:       "install a renewed license token before relying on enterprise agent profiles",
		}
	}
	warning := license.ExpiryStatus(lic, time.Now())
	if warning.Active {
		status := doctorStatusWarn
		if warning.Severity == license.ExpirySeverityInfo {
			status = doctorStatusInfo
		}
		return doctorReportCheck{
			Name:       "license_status",
			Surface:    doctorSurfaceConfig,
			Status:     status,
			Configured: true,
			Reachable:  true,
			Enforcing:  true,
			Detail: fmt.Sprintf("license %s expires in %d day(s) on %s; %d-day renewal band severity=%s",
				lic.ID, warning.DaysRemaining, warning.ExpiresAt.Format(time.DateOnly), warning.ThresholdDays, warning.Severity),
			Next: "renew or refresh the license before expiry disables enterprise agent profiles",
		}
	}
	detail := "license token is configured"
	if lic.ExpiresAt > 0 {
		detail = fmt.Sprintf("license %s expires on %s", lic.ID, time.Unix(lic.ExpiresAt, 0).UTC().Format(time.DateOnly))
	}
	if cfg.LicenseCRLFile != "" {
		detail += "; signed CRL configured"
	}
	if len(cfg.LicenseIntermediateCert) > 0 {
		detail += "; intermediate certificate configured"
	}
	return doctorReportCheck{
		Name:       "license_status",
		Surface:    doctorSurfaceConfig,
		Status:     doctorStatusOK,
		Configured: true,
		Reachable:  true,
		Enforcing:  true,
		Detail:     detail,
	}
}

func doctorVerifiedLicense(cfg *config.Config) (license.License, bool, error) {
	pubKey, err := doctorLicensePublicKey(cfg)
	if err != nil {
		if cfg.LicensePublicKey != "" {
			return license.License{}, false, err
		}
		lic, decodeErr := license.Decode(cfg.LicenseKey)
		if decodeErr != nil {
			return license.License{}, false, decodeErr
		}
		return lic, false, nil
	}
	var crl *license.CRL
	if cfg.LicenseCRLFile != "" {
		loaded, crlErr := license.LoadAndVerifyCRLMonotonic(cfg.LicenseCRLFile, pubKey, time.Now())
		if crlErr != nil {
			return license.License{}, true, crlErr
		}
		crl = &loaded
	}
	lic, verifyErr := license.VerifyTokenWithOptionalIntermediate(cfg.LicenseKey, cfg.LicenseIntermediateCert, pubKey, crl, time.Now())
	return lic, true, verifyErr
}

func doctorLicensePublicKey(cfg *config.Config) (ed25519.PublicKey, error) {
	if key := license.EmbeddedPublicKey(); key != nil {
		return key, nil
	}
	if cfg.LicensePublicKey == "" {
		return nil, errors.New("no license public key available")
	}
	keyBytes, err := hex.DecodeString(cfg.LicensePublicKey)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return nil, errors.New("invalid license public key")
	}
	return ed25519.PublicKey(keyBytes), nil
}

func checkDoctorHTTPProxy(cfg *config.Config) doctorReportCheck {
	configured := cfg.ForwardProxy.Enabled || cfg.FetchProxy.Listen != "" || cfg.WebSocketProxy.Enabled || cfg.ReverseProxy.Enabled
	if !configured {
		return doctorReportCheck{
			Name:    "http_proxy",
			Surface: doctorSurfaceHTTP,
			Status:  doctorStatusFail,
			Detail:  "no HTTP, forward, WebSocket, or reverse proxy listener is enabled",
			Next:    "enable at least one proxy listener for agent network traffic",
		}
	}
	if !doctorGlobalEnforce(cfg) {
		return doctorReportCheck{
			Name:       "http_proxy",
			Surface:    doctorSurfaceHTTP,
			Status:     doctorStatusWarn,
			Configured: true,
			Reachable:  true,
			Detail:     "proxy listener is configured, but global enforce=false means observation/audit mode",
			Next:       "set enforce=true before claiming blocking enforcement",
		}
	}
	return doctorReportCheck{
		Name:       "http_proxy",
		Surface:    doctorSurfaceHTTP,
		Status:     doctorStatusOK,
		Configured: true,
		Reachable:  true,
		Enforcing:  true,
		Detail:     "proxy listener is configured; OS/container policy must still force agents to use it",
		Next:       "pair this with contain/network-policy checks so direct raw egress is blocked",
	}
}

func checkDoctorTLSInterception(cfg *config.Config) doctorReportCheck {
	if !cfg.TLSInterception.Enabled {
		return doctorReportCheck{
			Name:    "tls_interception",
			Surface: doctorSurfaceHTTP,
			Status:  doctorStatusInfo,
			Detail:  "disabled; HTTPS bodies are not visible unless traffic is plaintext or otherwise terminated",
			Next:    "enable TLS interception and install the Pipelock CA for Browser Shield/body scanning on HTTPS",
		}
	}
	missing := missingReadableFiles(cfg.TLSInterception.CACertPath, cfg.TLSInterception.CAKeyPath)
	if len(missing) > 0 {
		return doctorReportCheck{
			Name:       "tls_interception",
			Surface:    doctorSurfaceHTTP,
			Status:     doctorStatusFail,
			Configured: true,
			Detail:     "configured but CA material is not readable: " + strings.Join(missing, ", "),
			Next:       "fix ca_cert/ca_key paths or rerun TLS/contain CA setup",
		}
	}
	if !doctorGlobalEnforce(cfg) {
		return doctorReportCheck{
			Name:       "tls_interception",
			Surface:    doctorSurfaceHTTP,
			Status:     doctorStatusWarn,
			Configured: true,
			Reachable:  true,
			Detail:     "CA material is readable, but global enforce=false means findings on intercepted bodies are not blocking",
			Next:       "set enforce=true before claiming blocking enforcement on intercepted HTTPS",
		}
	}
	return doctorReportCheck{
		Name:       "tls_interception",
		Surface:    doctorSurfaceHTTP,
		Status:     doctorStatusOK,
		Configured: true,
		Reachable:  true,
		Enforcing:  true,
		Detail:     "CA material is readable; clients still need to trust the CA",
		Next:       "verify agent and browser trust stores use this CA",
	}
}

func checkDoctorRequestBodyScanning(cfg *config.Config) doctorReportCheck {
	if !cfg.RequestBodyScanning.Enabled {
		return doctorReportCheck{
			Name:    "request_body_scanning",
			Surface: doctorSurfaceHTTP,
			Status:  doctorStatusWarn,
			Detail:  "disabled; POST bodies and headers can miss DLP unless another layer sees them",
			Next:    "enable request_body_scanning for agent HTTP/TLS proxy paths",
		}
	}
	if !doctorGlobalEnforce(cfg) {
		return doctorReportCheck{
			Name:       "request_body_scanning",
			Surface:    doctorSurfaceHTTP,
			Status:     doctorStatusWarn,
			Configured: true,
			Reachable:  true,
			Detail:     "enabled, but global enforce=false means request body findings are not blocking",
			Next:       "set enforce=true and request_body_scanning.action=block for blocking enforcement",
		}
	}
	if cfg.RequestBodyScanning.Action != config.ActionBlock {
		return doctorReportCheck{
			Name:       "request_body_scanning",
			Surface:    doctorSurfaceHTTP,
			Status:     doctorStatusWarn,
			Configured: true,
			Reachable:  true,
			Detail:     "enabled with action=" + cfg.RequestBodyScanning.Action + "; this is not blocking enforcement",
			Next:       "set request_body_scanning.action=block before claiming enforcement",
		}
	}
	return doctorReportCheck{
		Name:       "request_body_scanning",
		Surface:    doctorSurfaceHTTP,
		Status:     doctorStatusOK,
		Configured: true,
		Reachable:  true,
		Enforcing:  true,
		Detail:     "configured on proxy paths; CONNECT HTTPS bodies require TLS interception",
	}
}

func checkDoctorBrowserShield(cfg *config.Config) doctorReportCheck {
	if !cfg.BrowserShield.Enabled {
		return doctorReportCheck{
			Name:    "browser_shield",
			Surface: doctorSurfaceHTTP,
			Status:  doctorStatusInfo,
			Detail:  "disabled",
			Next:    "enable browser_shield where agent browser responses should be rewritten",
		}
	}
	status := doctorStatusOK
	detail := "enabled; only enforces on response bodies visible to Pipelock"
	next := "prove with a shieldable HTTPS response through the proxy"
	enforcing := cfg.TLSInterception.Enabled
	switch {
	case !cfg.TLSInterception.Enabled:
		status = doctorStatusWarn
		detail = "enabled, but HTTPS Browser Shield coverage needs TLS interception or plaintext response bodies"
		next = "enable TLS interception or limit the claim to plaintext/fetch-visible bodies"
		enforcing = false
	case !doctorGlobalEnforce(cfg):
		status = doctorStatusWarn
		detail = "enabled with TLS interception, but global enforce=false means findings are not blocking"
		next = "set enforce=true before claiming blocking enforcement on browser responses"
		enforcing = false
	}
	return doctorReportCheck{
		Name:       "browser_shield",
		Surface:    doctorSurfaceHTTP,
		Status:     status,
		Configured: true,
		Reachable:  cfg.TLSInterception.Enabled,
		Enforcing:  enforcing,
		Detail:     detail,
		Next:       next,
	}
}

func checkDoctorMCPWrapperFeatures(cfg *config.Config) doctorReportCheck {
	enabled := []string{}
	if cfg.MCPInputScanning.Enabled {
		enabled = append(enabled, "mcp_input_scanning")
	}
	if cfg.MCPToolScanning.Enabled {
		enabled = append(enabled, "mcp_tool_scanning")
	}
	if cfg.MCPToolPolicy.Enabled {
		enabled = append(enabled, "mcp_tool_policy")
	}
	if cfg.MCPSessionBinding.Enabled {
		enabled = append(enabled, "mcp_session_binding")
	}
	if len(enabled) == 0 {
		return doctorReportCheck{
			Name:    "mcp_wrapper_scanning",
			Surface: doctorSurfaceMCP,
			Status:  doctorStatusInfo,
			Detail:  "MCP wrapper-dependent scanning features are disabled",
			Next:    "enable MCP scanning where tools are launched through pipelock mcp proxy or an MCP listener",
		}
	}
	return doctorReportCheck{
		Name:       "mcp_wrapper_scanning",
		Surface:    doctorSurfaceMCP,
		Status:     doctorStatusWarn,
		Configured: true,
		Detail:     "configured features: " + strings.Join(enabled, ", "),
		Next:       "prove the agent launches MCP servers through pipelock mcp proxy -- or a Pipelock MCP listener",
	}
}

func checkDoctorMCPBinaryIntegrity(cfg *config.Config) doctorReportCheck {
	if !cfg.MCPBinaryIntegrity.Enabled {
		return doctorReportCheck{
			Name:    "mcp_binary_integrity",
			Surface: doctorSurfaceMCP,
			Status:  doctorStatusInfo,
			Detail:  "disabled",
			Next:    "enable after generating a real manifest for wrapped MCP server binaries",
		}
	}
	check := doctorReportCheck{
		Name:       "mcp_binary_integrity",
		Surface:    doctorSurfaceMCP,
		Configured: true,
		Detail:     "configured; enforcement only runs before pipelock-spawned MCP subprocesses",
		Next:       "generate/mount the manifest and prove MCP servers are launched through the wrapper",
	}
	if cfg.MCPBinaryIntegrity.ManifestPath == "" {
		check.Status = doctorStatusFail
		check.Detail = "enabled but manifest_path is empty"
		return check
	}
	if pathReadableFile(cfg.MCPBinaryIntegrity.ManifestPath) {
		check.Status = doctorStatusWarn
		check.Reachable = true
		check.Detail = "manifest is readable, but wrapper invocation still must be proven"
		return check
	}
	check.Status = doctorStatusFail
	check.Detail = "enabled but manifest is not readable: " + cfg.MCPBinaryIntegrity.ManifestPath
	return check
}

func checkDoctorMCPToolProvenance(cfg *config.Config) doctorReportCheck {
	if !cfg.MCPToolProvenance.Enabled {
		return doctorReportCheck{
			Name:    "mcp_tool_provenance",
			Surface: doctorSurfaceMCP,
			Status:  doctorStatusInfo,
			Detail:  "disabled",
			Next:    "enable where signed tools/list provenance should be required",
		}
	}
	return doctorReportCheck{
		Name:       "mcp_tool_provenance",
		Surface:    doctorSurfaceMCP,
		Status:     doctorStatusWarn,
		Configured: true,
		Detail:     "configured in " + cfg.MCPToolProvenance.Mode + " mode; enforcement only runs on tools/list traffic through MCP wrapper/listener paths",
		Next:       "prove signed and unsigned tools/list fixtures through the live MCP path",
	}
}

func checkDoctorFileSentry(cfg *config.Config) doctorReportCheck {
	if !cfg.FileSentry.Enabled {
		return doctorReportCheck{
			Name:    "file_sentry",
			Surface: doctorSurfaceMCP,
			Status:  doctorStatusInfo,
			Detail:  "disabled",
			Next:    "enable with reachable watch_paths where workspace drift should be detected",
		}
	}
	// Split required vs optional paths so the doctor exit code aligns with
	// runtime behavior: optional (required:false) misses degrade at startup,
	// they should not turn doctor into a hard failure. Required misses still
	// fail.
	var requiredPaths, optionalPaths []string
	for _, wp := range cfg.FileSentry.WatchPaths {
		if wp.Required {
			requiredPaths = append(requiredPaths, wp.Path)
		} else {
			optionalPaths = append(optionalPaths, wp.Path)
		}
	}
	check := doctorReportCheck{
		Name:       "file_sentry",
		Surface:    doctorSurfaceMCP,
		Configured: true,
		Detail:     "configured; current implementation is tied to MCP proxy lifecycle",
		Next:       "prove the watched workspace is reachable from the process that arms file_sentry",
	}
	if len(cfg.FileSentry.WatchPaths) == 0 {
		check.Status = doctorStatusFail
		check.Detail = "enabled but no watch_paths are configured"
		return check
	}
	requiredMissing := missingReadablePaths(requiredPaths...)
	optionalMissing := missingReadablePaths(optionalPaths...)
	if len(requiredMissing) > 0 {
		check.Status = doctorStatusFail
		check.Detail = "required watch path(s) not readable: " + strings.Join(requiredMissing, ", ")
		return check
	}
	if len(optionalMissing) > 0 {
		check.Status = doctorStatusWarn
		check.Reachable = true
		check.Detail = "optional watch path(s) not readable (will degrade at startup, not fail): " + strings.Join(optionalMissing, ", ")
		check.Next = "either mark these required:true to fail-fast, or remove them from watch_paths"
		return check
	}
	check.Status = doctorStatusWarn
	check.Reachable = true
	check.Detail = "watch paths are readable, but wrapper/sidecar lifecycle still must be proven"
	return check
}

func checkDoctorSentry(cfg *config.Config) doctorReportCheck {
	dsnConfigured := cfg.Sentry.DSN != "" || os.Getenv("SENTRY_DSN") != ""
	if !cfg.Sentry.IsEnabled() {
		return doctorReportCheck{
			Name:    "sentry",
			Surface: doctorSurfaceHost,
			Status:  doctorStatusWarn,
			Detail:  "disabled",
			Next:    "enable Sentry or equivalent alerting before production claims",
		}
	}
	if !dsnConfigured {
		return doctorReportCheck{
			Name:       "sentry",
			Surface:    doctorSurfaceHost,
			Status:     doctorStatusWarn,
			Configured: true,
			Detail:     "enabled but no DSN is configured via YAML or SENTRY_DSN",
			Next:       "configure DSN without printing it in logs/docs, then emit a scrubbed test event",
		}
	}
	return doctorReportCheck{
		Name:       "sentry",
		Surface:    doctorSurfaceHost,
		Status:     doctorStatusOK,
		Configured: true,
		Reachable:  true,
		Enforcing:  true,
		Detail:     "enabled and DSN is present (value redacted)",
		Next:       "verify one scrubbed breadcrumb/error path",
	}
}

func checkDoctorDeploymentBoundary(_ *config.Config) doctorReportCheck {
	return doctorReportCheck{
		Name:    "direct_egress_boundary",
		Surface: doctorSurfaceHost,
		Status:  doctorStatusInfo,
		Detail:  "proxy env vars only steer cooperative clients; launch agents through plk/containment or cluster network policy so raw egress is blocked",
		Next:    "run contain verify or cluster topology smoke tests; agents launched outside that boundary can still use the operator's normal network",
	}
}

func missingReadablePaths(paths ...string) []string {
	return missingByPredicate(pathReadable, paths...)
}

func missingReadableFiles(paths ...string) []string {
	return missingByPredicate(pathReadableFile, paths...)
}

func missingByPredicate(pred func(string) bool, paths ...string) []string {
	missing := []string{}
	for _, path := range paths {
		if path == "" {
			missing = append(missing, "<empty>")
			continue
		}
		if !pred(path) {
			missing = append(missing, path)
		}
	}
	return missing
}

func pathReadableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return openReadable(path)
}

func pathReadable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return false
	}
	return openReadable(path)
}

func openReadable(path string) bool {
	f, err := os.Open(filepath.Clean(path)) //nolint:gosec // doctor checks operator-visible config paths from local configuration.
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func doctorGlobalEnforce(cfg *config.Config) bool {
	return cfg.Enforce == nil || *cfg.Enforce
}

// doctorRootBannerMessage returns a non-empty advisory string when the
// process is running with euid 0. Doctor's readability checks reflect the
// caller's view, and root bypasses DAC, so paths that pipelock-proxy cannot
// read still look readable. Surfacing this in both human and JSON output
// keeps "configured ≠ enforcing" honest in the most common invocation.
func doctorRootBannerMessage() string {
	if os.Geteuid() != 0 {
		return ""
	}
	return doctorRootBannerText
}

func printDoctorReport(cmd *cobra.Command, report doctorReport, color bool) {
	w := cmd.OutOrStdout()
	_, _ = fmt.Fprintln(w, "Pipelock Enforcement Doctor")
	_, _ = fmt.Fprintln(w, "===========================")
	_, _ = fmt.Fprintf(w, "Config: %s\n", report.ConfigFile)
	_, _ = fmt.Fprintf(w, "Mode:   %s\n", report.Mode)
	if banner := doctorRootBannerMessage(); banner != "" {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintf(w, "%s %s\n", doctorStatusTag(doctorStatusWarn, color), banner)
	}
	_, _ = fmt.Fprintln(w)
	for _, check := range report.Checks {
		_, _ = fmt.Fprintf(w, "%s %-24s [%s]\n", doctorStatusTag(check.Status, color), check.Name, check.Surface)
		if check.Detail != "" {
			_, _ = fmt.Fprintf(w, "  %s\n", check.Detail)
		}
		if check.Next != "" {
			_, _ = fmt.Fprintf(w, "  next: %s\n", check.Next)
		}
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "Summary: %d ok, %d warning, %d failure, %d info\n",
		report.Summary.OK, report.Summary.Warnings, report.Summary.Failures, report.Summary.Info)
}

func doctorStatusTag(status string, color bool) string {
	if !color {
		return "[" + strings.ToUpper(status) + "]"
	}
	switch status {
	case doctorStatusOK:
		return "\033[32m[OK]\033[0m"
	case doctorStatusWarn:
		return "\033[33m[WARN]\033[0m"
	case doctorStatusFail:
		return "\033[31m[FAIL]\033[0m"
	default:
		return "\033[36m[INFO]\033[0m"
	}
}
