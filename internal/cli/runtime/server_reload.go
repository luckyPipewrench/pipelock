// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/cli/runtimeconfig"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Reload applies a single hot-reload cycle against newCfg. Mirrors the
// goroutine body the pre-refactor RunCmd launched from reloader.Changes():
// gates restart-only fields, resolves runtime policy on a clone, runs
// ValidateReload, blocks strict-mode downgrades, swaps scanner + emit
// sinks + kill switch state, and dedups fsnotify + SIGHUP event stacking.
//
// Errors returned here correspond to the reload-rejected branches the
// original code logged via logger.LogError and then `return`-ed on, plus the
// "proxy kept the previous config" fail-safe path when proxy.Reload aborts its
// internal swap. Silent no-ops (dedup, restart-only field changes) return nil.
func (s *Server) Reload(newCfg *config.Config) (err error) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			ReloadPanicHandler(r, s.sentry, s.logger, s.opts.ConfigFile)
			err = fmt.Errorf("scanner construction panic during config reload: %v", r)
		}
	}()

	oldCfg := s.proxy.CurrentConfig()
	if oldCfg != nil {
		// Block fetch_proxy.listen changes via reload. The listener binds at
		// startup and cannot rebind at runtime; preserve the live address so the
		// config object does not drift from the actual socket.
		if oldCfg.FetchProxy.Listen != newCfg.FetchProxy.Listen {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: fetch_proxy.listen changed from %q to %q - requires restart, ignoring\n",
				oldCfg.FetchProxy.Listen, newCfg.FetchProxy.Listen)
			newCfg.FetchProxy.Listen = oldCfg.FetchProxy.Listen
		}
		// Block enabling forward proxy via reload. WriteTimeout is set
		// at server start and cannot change at runtime; tunnels would
		// be killed prematurely. Restart to enable.
		if !oldCfg.ForwardProxy.Enabled && newCfg.ForwardProxy.Enabled {
			rejectErr := fmt.Errorf("rejected: forward proxy cannot be enabled via reload (requires restart)")
			s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile), rejectErr)
			return rejectErr
		}
		// Block enabling WebSocket proxy via reload for the same
		// reason: WriteTimeout must be 0 at server start.
		if !oldCfg.WebSocketProxy.Enabled && newCfg.WebSocketProxy.Enabled {
			rejectErr := fmt.Errorf("rejected: WebSocket proxy cannot be enabled via reload (requires restart)")
			s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile), rejectErr)
			return rejectErr
		}
		// Block api_listen changes via reload. The API server binds at
		// startup and can't rebind at runtime.
		if oldCfg.KillSwitch.APIListen != newCfg.KillSwitch.APIListen {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: kill_switch.api_listen changed from %q to %q — requires restart, ignoring\n",
				oldCfg.KillSwitch.APIListen, newCfg.KillSwitch.APIListen)
			newCfg.KillSwitch.APIListen = oldCfg.KillSwitch.APIListen
		}
		// Block metrics_listen changes via reload. The metrics server
		// binds at startup and can't rebind at runtime.
		if oldCfg.MetricsListen != newCfg.MetricsListen {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: metrics_listen changed from %q to %q — requires restart, ignoring\n",
				oldCfg.MetricsListen, newCfg.MetricsListen)
			newCfg.MetricsListen = oldCfg.MetricsListen
		}
		// Block scan_api listener setting changes via reload. The Scan
		// API server binds at startup and cannot rebind or reconfigure
		// connection limits / deadlines at runtime.
		if oldCfg.ScanAPI.Listen != newCfg.ScanAPI.Listen ||
			oldCfg.ScanAPI.ConnectionLimit != newCfg.ScanAPI.ConnectionLimit ||
			oldCfg.ScanAPI.Timeouts.Read != newCfg.ScanAPI.Timeouts.Read ||
			oldCfg.ScanAPI.Timeouts.Write != newCfg.ScanAPI.Timeouts.Write {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: scan_api listener settings changed — requires restart, ignoring\n")
			newCfg.ScanAPI.Listen = oldCfg.ScanAPI.Listen
			newCfg.ScanAPI.ConnectionLimit = oldCfg.ScanAPI.ConnectionLimit
			newCfg.ScanAPI.Timeouts = oldCfg.ScanAPI.Timeouts
		}
		if conductorRuntimeChanged(oldCfg, newCfg) {
			attemptedHash := newCfg.Hash()
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: conductor settings changed — requires restart, ignoring\n")
			// Surface to the audit channel as well as stderr. Conductor
			// settings sit on the trust boundary with Boss: silently
			// preserving them on reload is the right choice, but an
			// operator (or attacker with config write) attempting the
			// change should leave a record an SOC tool can find.
			s.logger.LogConfigReload("ignored", "conductor settings restart-only", attemptedHash)
			newCfg.Conductor = oldCfg.Conductor
		}
		// Block recorder-binding changes via reload. The recorder (and its
		// receipt/audit chain) is built once at Start; reload swaps config and
		// scanner but never rebuilds the recorder, so path/key/retention/etc.
		// changes would leave the live config disagreeing with the running
		// recorder. require_receipts is the exception: it changes only whether
		// an emit failure escalates an otherwise-allowed request to a block, so
		// it is safe and intentionally reloadable.
		//
		// This also keeps Conductor policy-bundle apply working: a signed bundle
		// carries enforcement-only config (flight_recorder is not an allowlisted
		// bundle section), so the bundle's loaded config omits flight_recorder.
		// Preserving the follower's existing block means conductor.enabled - which
		// requires a signed flight recorder - still validates after the apply.
		oldFR := oldCfg.FlightRecorder
		newFR := newCfg.FlightRecorder
		oldFR.RequireReceipts = newFR.RequireReceipts
		oldFR.EvidenceHealth.SelfAuditInterval = newFR.EvidenceHealth.SelfAuditInterval
		oldFR.EvidenceHealth.MaxAnchorLag = newFR.EvidenceHealth.MaxAnchorLag
		if !reflect.DeepEqual(oldFR, newFR) {
			if oldCfg.FlightRecorder.SigningKeyPath != newCfg.FlightRecorder.SigningKeyPath {
				_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: flight_recorder.signing_key_path changed from %q to %q — receipt chain cannot rotate at runtime, ignoring (restart required)\n",
					oldCfg.FlightRecorder.SigningKeyPath, newCfg.FlightRecorder.SigningKeyPath)
			} else if !boolPtrEqual(oldCfg.FlightRecorder.EvidenceHealth.Enabled, newCfg.FlightRecorder.EvidenceHealth.Enabled) {
				_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: flight_recorder.evidence_health.enabled changed — evidence health loop is built at startup and cannot rebind at runtime, ignoring (restart required)\n")
			} else {
				_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: flight_recorder settings changed — recorder is built at startup and cannot rebind at runtime, ignoring (restart required)\n")
			}
			requireReceipts := newCfg.FlightRecorder.RequireReceipts
			evidenceHealth := newCfg.FlightRecorder.EvidenceHealth
			newCfg.FlightRecorder = oldCfg.FlightRecorder
			newCfg.FlightRecorder.RequireReceipts = requireReceipts
			newCfg.FlightRecorder.EvidenceHealth.SelfAuditInterval = evidenceHealth.SelfAuditInterval
			newCfg.FlightRecorder.EvidenceHealth.MaxAnchorLag = evidenceHealth.MaxAnchorLag
		}
		// require_receipts reloads freely, but it only has a live emitter to
		// gate on when one was built at Start (the recorder is restart-only).
		// Enabling it without one fails every request closed with
		// receipt_emission_failed. Warn loudly; the value still applies so the
		// posture is honest (fail-closed), but restart with a configured
		// recorder is the real fix.
		if newCfg.FlightRecorder.RequireReceipts && !s.liveReceiptEmitterReady() {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: flight_recorder.require_receipts is enabled but no healthy live signed receipt emitter exists — every request will fail closed with receipt_emission_failed. Configure flight_recorder.dir + signing_key_path, fix any receipt-chain resume error, and restart.\n")
		}
		// Block file_sentry changes via reload. The watcher is built
		// once at Start from the startup snapshot; reloading would
		// leave the old watcher armed on stale paths while the live
		// config reported the new ones. Restart to apply.
		if !reflect.DeepEqual(oldCfg.FileSentry, newCfg.FileSentry) {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: file_sentry settings changed — watcher cannot rebind at runtime, ignoring (restart required)\n")
			newCfg.FileSentry = oldCfg.FileSentry
		}
		if !reflect.DeepEqual(oldCfg.DashboardSnapshot, newCfg.DashboardSnapshot) {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: dashboard_snapshot settings changed — writer is built at startup and cannot rebind at runtime, ignoring (restart required)\n")
			newCfg.DashboardSnapshot = oldCfg.DashboardSnapshot
		}

		// Dedupe identical-hash reload EVENTS within a short window.
		// fsnotify + SIGHUP stack up so a single `echo cfg > path;
		// kill -HUP` sequence triggers two reload Changes() events in
		// quick succession; the second is pure noise. Switch to a
		// time-windowed dedup keyed on the LAST EMITTED reload event:
		// the first of a stacked pair still logs, any event with the
		// same hash inside 2s skips silently.
		if s.shouldSkipReload(newCfg.Hash()) {
			return nil
		}

		// Block ALL reverse proxy changes via reload. The listener binds at
		// startup, the upstream is pinned in the handler, and the submit-profile
		// SSRF-safe dialer is installed on the transport at init - none of these
		// rebind at runtime. A field-by-field check missed profile, allowed
		// methods/paths, trusted_upstream, body cap, and timeout; flipping
		// profile on reload would activate the submit gate while the dial path
		// stayed startup-frozen (a real security weakening). Compare the whole
		// struct so any change is preserved until restart, matching the
		// restart-required warning in reloadwarn.go.
		if !reflect.DeepEqual(oldCfg.ReverseProxy, newCfg.ReverseProxy) {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: reverse_proxy settings changed — requires restart, ignoring\n")
			newCfg.ReverseProxy = oldCfg.ReverseProxy
		}
		// Block agent listener changes via reload. Listener sockets
		// are bound at startup and cannot be rebound at runtime. Warn
		// and preserve old listener config.
		//
		// Respect the license gate: if EnforceLicenseGate disabled
		// agents on reload, do not re-add them via listener
		// preservation.
		// EnforceLicenseGate strips named agents but intentionally preserves
		// _default. Detect loss of non-default profiles instead of a nil agents
		// map so reload cannot re-add stripped named agents when _default remains.
		agentsRevokedByLicense := hasNamedAgentProfiles(oldCfg.Agents) && !hasNamedAgentProfiles(newCfg.Agents)
		licenseInputsChanged := oldCfg.LicenseKey != newCfg.LicenseKey ||
			oldCfg.LicensePublicKey != newCfg.LicensePublicKey ||
			oldCfg.LicenseFile != newCfg.LicenseFile ||
			oldCfg.LicenseCRLFile != newCfg.LicenseCRLFile ||
			oldCfg.LicenseIntermediateFile != newCfg.LicenseIntermediateFile ||
			!bytes.Equal(oldCfg.LicenseIntermediateCert, newCfg.LicenseIntermediateCert) ||
			oldCfg.LicenseIntermediateLoadError != newCfg.LicenseIntermediateLoadError ||
			// A require-intermediate flip is a license-trust change: compare the
			// MATERIALIZED value so a reload that turns require on/off (via config
			// or env) re-verifies and can tear down a surface that no longer
			// satisfies the required trust tier.
			oldCfg.LicenseRequireIntermediateResolved != newCfg.LicenseRequireIntermediateResolved ||
			// A CRL freshness-window change is also a license-trust change: shrinking
			// it can make a previously-fresh CRL stale, which under require mode is
			// proven loss. Compare the materialized window.
			oldCfg.LicenseCRLMaxAgeResolved != newCfg.LicenseCRLMaxAgeResolved

		// Re-verify the NEW license inputs ONCE and classify the result so both
		// paid surfaces — agent listeners and the Conductor follower — make the
		// SAME decision. License inputs are restart-only: a reload never
		// activates a new license. So an UNVERIFIABLE new input (unreadable or
		// malformed CRL, intermediate, public key, or token) leaves the effective
		// entitlement intact and must NOT tear down a running surface — that would
		// be a denial-of-service on an operator typo, not fail-closed security.
		// Only PROVEN loss (revoked, expired, or a cleanly-verified token that no
		// longer carries the feature) tears a surface down. Genuine runtime
		// revocation/expiry of the ACTIVE license is still enforced independently
		// by the CRL watcher and the expiry timer, against the effective license
		// state. EnforceLicenseGate (run during Load) stays strictly fail-closed
		// because at startup there is no prior entitlement to preserve; this
		// reload-only precision is the only place an old-vs-new baseline exists.
		reloadLicenseChecked := agentsRevokedByLicense || licenseInputsChanged
		var (
			reloadLic   license.License
			reloadClass = license.ReloadVerified
		)
		if reloadLicenseChecked {
			reloadLic, reloadClass = license.ClassifyReloadWithOptions(license.FleetVerifyInputs{
				LicenseKey:       newCfg.LicenseKey,
				PublicKeyHex:     newCfg.LicensePublicKey,
				CRLFile:          newCfg.LicenseCRLFile,
				IntermediateFile: newCfg.LicenseIntermediateFile,
				IntermediateCert: newCfg.LicenseIntermediateCert,
				RequireSet:       true,
				Require:          newCfg.LicenseRequireIntermediateResolved,
				MaxAge:           newCfg.LicenseCRLMaxAgeResolved,
			})
		}
		conductorFleetLost := oldCfg.Conductor.Enabled && reloadLicenseChecked &&
			reloadClass.ProvesLoss(reloadLic, license.FeatureFleet)

		switch {
		case agentsRevokedByLicense && reloadClass.ProvesLoss(reloadLic, license.FeatureAgents):
			// License gate disabled agents on reload and the loss is PROVEN
			// (revoked / expired / downgraded). Shut down already-bound listener
			// servers so the agent ports stop accepting traffic.
			s.proxy.ShutdownAgentServers()
			_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: license revoked agents, shutting down agent listeners\n")
		case agentsRevokedByLicense || licenseInputsChanged:
			// Either the new license inputs are UNVERIFIABLE (agents were stripped
			// at Load but the effective entitlement is unchanged — a fat-fingered
			// path must not DoS a licensed surface) or the inputs simply changed.
			// Both are restart-only: preserve ALL old license state and the old
			// agents so a reload can neither activate nor deactivate licensed
			// features without a restart. Preserving the input fields themselves is
			// mandatory; otherwise the new values commit to the live config and a
			// later unrelated reload sees no diff and silently applies the staged
			// license.
			preserveLicenseInputsRestartOnly(newCfg, oldCfg)
			if agentsRevokedByLicense {
				_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: new license inputs could not be verified (unreadable/malformed CRL, intermediate, or token); effective license unchanged, preserving licensed surfaces — requires restart for license re-verification\n")
			} else {
				_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: license key inputs changed (license_key, license_file, license_crl_file, license_intermediate_file, or license_public_key) - requires restart for license re-verification\n")
			}
		case AgentListenersChanged(oldCfg, newCfg):
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: agents[*].listeners changed — requires restart, ignoring listener changes\n")
			PreserveAgentListeners(oldCfg, newCfg)
		}

		if conductorFleetLost {
			// New license inputs PROVE the fleet entitlement is gone: stop the
			// running Conductor follower fail-closed. Detection keeps running;
			// Conductor stays down until restart.
			s.teardownConductor("reload revoked fleet entitlement")
		} else if oldCfg.Conductor.Enabled && reloadLicenseChecked && reloadClass == license.ReloadUnverifiable {
			// Conductor stays up: unverifiable new inputs cannot PROVE the fleet
			// entitlement was lost, so tearing the follower down here would be a
			// DoS on an operator typo. Warn for SOC visibility — the conductor
			// analogue of the agents preserve path above.
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: new license inputs could not be verified; Conductor fleet entitlement unchanged, follower stays running — requires restart for license re-verification\n")
		}
		// Carry forward runtime-derived license expiry.
		// LicenseExpiresAt is set by EnforceLicenseGate at startup,
		// not parsed from YAML. Always preserve the old value until
		// restart.
		newCfg.LicenseExpiresAt = oldCfg.LicenseExpiresAt
		newCfg.LicenseID = oldCfg.LicenseID
		newCfg.LicenseCRLExpiresAt = oldCfg.LicenseCRLExpiresAt
		newCfg.LicenseCRLSHA256 = oldCfg.LicenseCRLSHA256
		newCfg.LicenseRevoked = oldCfg.LicenseRevoked
		newCfg.LicenseRevocationReason = oldCfg.LicenseRevocationReason
		newCfg.LicenseAgentsFeature = oldCfg.LicenseAgentsFeature
		if !hasNamedAgentProfiles(newCfg.Agents) {
			newCfg.LicenseAgentsFeature = false
		}
	}

	// Surface advisory warnings on reload the same way NewServer does at
	// startup. The Reloader discards warnings from Load()'s internal
	// Validate() call, so re-run the idempotent validator after deduping
	// stacked reload events and after preserving restart-only fields.
	if reloadWarns, _ := newCfg.ValidateWithWarnings(); len(reloadWarns) > 0 {
		for _, wn := range reloadWarns {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: %s: %s\n", wn.Field, wn.Message)
		}
	}

	// Resolve runtime policy on a clone of the newly loaded config so
	// the reloaded cfg stored in the proxy reflects the same
	// bundle-merge + auto-enable pipeline startup uses and its
	// canonical hash is computed fresh. The live runtime mode tracks
	// the startup flags: reload cannot toggle MCP listener or forward
	// proxy enablement (both gated above).
	var reloadBundleResult *rules.LoadResult
	newCfg, _ = runtimeconfig.ResolveAndReportConfig(newCfg, config.RuntimeResolveOpts{
		Mode: s.runtimeMode,
		MergeBundles: func(c *config.Config) {
			reloadBundleResult = rules.MergeIntoConfig(c, cliutil.Version)
		},
		DefaultToolPolicyRules: policy.DefaultToolPolicyRules,
	}, s.opts.Stderr, reloadRuntimeModeLabel(s.runtimeMode))
	for _, e := range reloadBundleResult.Errors {
		_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: bundle %s: %s\n", e.Name, e.Reason)
	}
	for _, w := range reloadBundleResult.Warnings {
		_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: %s\n", w)
	}
	if reloadBundleResult.Degraded {
		_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: DEGRADED — standard pack failed after reload, running core patterns only\n")
	}
	if oldCfg != nil {
		// Compare resolved-vs-resolved configs so bundle merges and
		// MCP listener auto-enable do not look like policy downgrades
		// during hot reload.
		if reasons := implausibleReloadTeardownReasons(oldCfg, newCfg); len(reasons) > 0 {
			rejectErr := fmt.Errorf("rejected: implausibly empty config reload would weaken security posture: %s", strings.Join(reasons, ", "))
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload rejected: %v\n", rejectErr)
			s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile), rejectErr)
			return rejectErr
		}
		warnings := config.ValidateReload(oldCfg, newCfg)
		for _, w := range warnings {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: %s - %s\n", w.Field, w.Message)
		}
		// Block downgrades from strict mode and from explicit "required"
		// security contracts. A required evidence/signature mode should not
		// keep forwarding under a warning-only weakening reload.
		if reason := reloadDowngradeRejectReason(oldCfg, warnings); reason != "" {
			rejectErr := fmt.Errorf("rejected: security downgrade from %s", reason)
			s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile), rejectErr)
			return rejectErr
		}
		// Bundle load failures are warning-only at startup because there is no
		// previous live bundle coverage to preserve. At reload there is: a fresh
		// config that fails bundle resolution must not activate if it would drop
		// currently-live bundle rules. This gate is mode-independent so balanced
		// and audit deployments fail closed for the real weakening without
		// rejecting unrelated bundle errors that do not remove live coverage.
		if reason := bundleResolutionRejectReason(oldCfg, newCfg, reloadBundleResult, s.currentMCPToolExtraPoison()); reason != "" {
			rejectErr := fmt.Errorf("rejected: bundle resolution error would drop live detection rules: %s", reason)
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload rejected: %v\n", rejectErr)
			s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile), rejectErr)
			return rejectErr
		}
	}
	newSc := scanner.New(newCfg)
	newSc.SetDLPWarnHook(func(ctx context.Context, patternName, severity string) {
		emitDLPWarn(s.logger, s.metrics, s.liveReceiptEmitter(), ctx, patternName, severity)
	})
	if !s.proxy.Reload(newCfg, newSc) {
		return errors.New("reload failed: proxy kept previous config")
	}
	fireReloadAfterProxySwapHook(s)
	s.refreshRuntimeState(oldCfg, newCfg, reloadBundleResult, s.proxy.ScannerPtr().Load())
	if reloadErr := s.proxy.LoadCertCache(newCfg); reloadErr != nil {
		s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile),
			fmt.Errorf("TLS cert cache reload failed: %w", reloadErr))
	}
	s.killswitch.Reload(newCfg)

	// Reload emit sinks: build new sinks from config, swap into
	// emitter, close old sinks.
	newSinks, sinkErr := BuildEmitSinks(newCfg, s.metrics)
	if sinkErr != nil {
		s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile),
			fmt.Errorf("emit sink rebuild failed: %w", sinkErr))
	} else {
		oldSinks := s.emitter.ReloadSinks(newSinks)
		for _, old := range oldSinks {
			if closeErr := old.Close(); closeErr != nil {
				s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile),
					fmt.Errorf("closing old emit sink: %w", closeErr))
			}
		}
		activateEmitSinks(newSinks)
	}

	if needsHITLApprover(newCfg) && !s.hasApprover {
		_, _ = fmt.Fprintln(s.opts.Stderr, "WARNING: config reloaded to HITL ask mode but approver was not initialized at startup; detections will be blocked")
	}
	reloadHash := newCfg.Hash()
	s.logger.LogConfigReload("success", fmt.Sprintf("mode=%s", newCfg.Mode), reloadHash)
	s.recordReloadSuccess(reloadHash)
	return nil
}

func boolPtrEqual(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func reloadRuntimeModeLabel(mode config.RuntimeMode) string {
	switch mode {
	case config.RuntimeForwardWithMCPListener:
		return "listener"
	case config.RuntimeMCPProxy:
		return "proxy"
	case config.RuntimeMCPScan:
		return "scan"
	default:
		return "forward"
	}
}

func implausibleReloadTeardownReasons(oldCfg, newCfg *config.Config) []string {
	if oldCfg == nil {
		return nil
	}
	if newCfg == nil {
		return []string{"new config is nil"}
	}

	var reasons []string
	appendCleared := func(field, oldValue, newValue string) {
		if oldValue != "" && newValue == "" {
			reasons = append(reasons, field+" cleared")
		}
	}
	appendDisabled := func(field string, oldEnabled, newEnabled bool) {
		if oldEnabled && !newEnabled {
			reasons = append(reasons, field+" disabled")
		}
	}

	appendCleared("mode", oldCfg.Mode, newCfg.Mode)
	appendCleared("fetch_proxy.listen", oldCfg.FetchProxy.Listen, newCfg.FetchProxy.Listen)
	appendCleared("license_file", oldCfg.LicenseFile, newCfg.LicenseFile)
	if oldCfg.EnforceEnabled() && !newCfg.EnforceEnabled() {
		reasons = append(reasons, "enforce disabled")
	}
	if len(oldCfg.Internal) > 0 && len(newCfg.Internal) == 0 {
		reasons = append(reasons, "internal CIDR list emptied")
	}

	appendDisabled("dlp.scan_env", oldCfg.DLP.ScanEnv, newCfg.DLP.ScanEnv)
	appendDisabled("forward_proxy.enabled", oldCfg.ForwardProxy.Enabled, newCfg.ForwardProxy.Enabled)
	appendDisabled("websocket_proxy.enabled", oldCfg.WebSocketProxy.Enabled, newCfg.WebSocketProxy.Enabled)
	appendDisabled("tls_interception.enabled", oldCfg.TLSInterception.Enabled, newCfg.TLSInterception.Enabled)
	appendDisabled("mcp_input_scanning.enabled", oldCfg.MCPInputScanning.Enabled, newCfg.MCPInputScanning.Enabled)
	appendDisabled("mcp_tool_scanning.enabled", oldCfg.MCPToolScanning.Enabled, newCfg.MCPToolScanning.Enabled)
	appendDisabled("mcp_tool_policy.enabled", oldCfg.MCPToolPolicy.Enabled, newCfg.MCPToolPolicy.Enabled)
	appendDisabled("session_profiling.enabled", oldCfg.SessionProfiling.Enabled, newCfg.SessionProfiling.Enabled)
	appendDisabled("adaptive_enforcement.enabled", oldCfg.AdaptiveEnforcement.Enabled, newCfg.AdaptiveEnforcement.Enabled)
	appendDisabled("behavioral_baseline.enabled", oldCfg.BehavioralBaseline.Enabled, newCfg.BehavioralBaseline.Enabled)
	appendDisabled("mcp_session_binding.enabled", oldCfg.MCPSessionBinding.Enabled, newCfg.MCPSessionBinding.Enabled)
	appendDisabled("a2a_scanning.enabled", oldCfg.A2AScanning.Enabled, newCfg.A2AScanning.Enabled)
	appendDisabled("tool_chain_detection.enabled", oldCfg.ToolChainDetection.Enabled, newCfg.ToolChainDetection.Enabled)
	appendDisabled("cross_request_detection.enabled", oldCfg.CrossRequestDetection.Enabled, newCfg.CrossRequestDetection.Enabled)
	appendDisabled("address_protection.enabled", oldCfg.AddressProtection.Enabled, newCfg.AddressProtection.Enabled)
	appendDisabled("taint.enabled", oldCfg.Taint.Enabled, newCfg.Taint.Enabled)
	appendDisabled("response_scanning.enabled", oldCfg.ResponseScanning.Enabled, newCfg.ResponseScanning.Enabled)
	appendDisabled("request_body_scanning.enabled", oldCfg.RequestBodyScanning.Enabled, newCfg.RequestBodyScanning.Enabled)
	// Configurable/default DLP patterns vanishing is a teardown even though the
	// compiled-in core DLP floor (scanner/core.go) still runs. ValidateReload
	// only WARNS on this, which strict rejects but balanced does not.
	if len(oldCfg.DLP.Patterns) > 0 && len(newCfg.DLP.Patterns) == 0 {
		reasons = append(reasons, "dlp.patterns emptied")
	}
	if oldCfg.BehavioralBaseline.Enabled && newCfg.BehavioralBaseline.Enabled &&
		config.ActionDowngraded(oldCfg.BehavioralBaseline.DeviationAction, newCfg.BehavioralBaseline.DeviationAction) {
		reasons = append(reasons, "behavioral_baseline.deviation_action downgraded")
	}

	// A live profile_dir change is a posture teardown: Reconfigure swaps the
	// dir in memory without loading profiles from it, so locked profiles are
	// silently orphaned on the next restart (fail-open). Require a full restart
	// to move the profile store instead of a hot reload.
	if oldCfg.BehavioralBaseline.Enabled && newCfg.BehavioralBaseline.Enabled &&
		oldCfg.BehavioralBaseline.ProfileDir != newCfg.BehavioralBaseline.ProfileDir {
		reasons = append(reasons, "behavioral_baseline.profile_dir changed")
	}

	return reasons
}

func reloadDowngradeRejectReason(oldCfg *config.Config, warnings []config.ReloadWarning) string {
	if oldCfg == nil || len(warnings) == 0 {
		return ""
	}
	if oldCfg.Mode == config.ModeStrict {
		return "strict mode"
	}
	if !hasRejectableDowngradeWarning(warnings) {
		return ""
	}

	var required []string
	if oldCfg.FlightRecorder.RequireReceipts {
		required = append(required, "flight_recorder.require_receipts")
	}
	if oldCfg.LicenseRequireIntermediateResolved {
		required = append(required, "license_require_intermediate")
	}
	if oldCfg.A2AScanning.Enabled && oldCfg.A2AScanning.RequireSignedAgentCards {
		required = append(required, "a2a_scanning.require_signed_agent_cards")
	}
	if oldCfg.MCPBinaryIntegrity.Enabled && oldCfg.MCPBinaryIntegrity.RequireSignature {
		required = append(required, "mcp_binary_integrity.require_signature")
	}
	if oldCfg.MediationEnvelope.VerifyInbound.Enabled {
		required = append(required, "mediation_envelope.verify_inbound.enabled")
	}
	if len(required) == 0 {
		return ""
	}
	return "required security mode (" + strings.Join(required, ", ") + ")"
}

func bundleResolutionRejectReason(
	oldCfg, newCfg *config.Config,
	result *rules.LoadResult,
	oldToolPoison []*tools.ExtraPoisonPattern,
) string {
	if oldCfg == nil || newCfg == nil || result == nil || len(result.Errors) == 0 {
		return ""
	}

	// Enforce by comparing the live bundle-sourced rules against the resolved
	// candidate directly, independent of whether ValidateReload emitted a
	// warning for the same drop. Coupling enforcement to warning generation
	// would be brittle: a suppressed, renamed, or missed warning must not be
	// able to bypass this coverage-drop check.
	var reasons []string
	if dropped := removedBundleDLPPatterns(oldCfg.DLP.Patterns, newCfg.DLP.Patterns); len(dropped) > 0 {
		reasons = append(reasons, "dlp.patterns: "+strings.Join(dropped, ", "))
	}
	if dropped := removedBundleResponsePatterns(oldCfg.ResponseScanning.Patterns, newCfg.ResponseScanning.Patterns); len(dropped) > 0 {
		reasons = append(reasons, "response_scanning.patterns: "+strings.Join(dropped, ", "))
	}
	if dropped := removedBundleToolPoisonPatterns(oldToolPoison, rules.ConvertToolPoison(result.ToolPoison)); len(dropped) > 0 {
		reasons = append(reasons, "mcp_tool_scanning.tool_poison: "+strings.Join(dropped, ", "))
	}
	if len(reasons) == 0 {
		return ""
	}

	// The dropped patterns above name exactly what was lost per surface. The
	// suffix lists the bundle load errors observed during this reload as
	// context; it is not a causal attribution (an unrelated bundle can error in
	// the same reload without dropping any live rule), so it is labelled as
	// such to avoid pointing an operator at the wrong bundle.
	names := make([]string, 0, len(result.Errors))
	for _, e := range result.Errors {
		names = append(names, e.Name)
	}
	return strings.Join(reasons, "; ") + " (bundle load errors this reload: " + strings.Join(names, ", ") + ")"
}

func removedBundleDLPPatterns(old, updated []config.DLPPattern) []string {
	return removedBundleNamedRegexPatterns(old, updated,
		func(p config.DLPPattern) string { return p.Name },
		func(p config.DLPPattern) string { return p.Regex },
		func(p config.DLPPattern) string { return p.Bundle })
}

func removedBundleResponsePatterns(old, updated []config.ResponseScanPattern) []string {
	return removedBundleNamedRegexPatterns(old, updated,
		func(p config.ResponseScanPattern) string { return p.Name },
		func(p config.ResponseScanPattern) string { return p.Regex },
		func(p config.ResponseScanPattern) string { return p.Bundle })
}

func removedBundleNamedRegexPatterns[T any](
	old, updated []T,
	nameOf func(T) string,
	regexOf func(T) string,
	bundleOf func(T) string,
) []string {
	updatedByName := make(map[string]string, len(updated))
	for _, p := range updated {
		updatedByName[nameOf(p)] = regexOf(p)
	}

	var removed []string
	for _, p := range old {
		if bundleOf(p) == "" {
			continue
		}
		name := nameOf(p)
		newRegex, ok := updatedByName[name]
		switch {
		case !ok:
			removed = append(removed, name)
		case newRegex != regexOf(p):
			removed = append(removed, name+" (regex changed)")
		}
	}
	return removed
}

func removedBundleToolPoisonPatterns(old, updated []*tools.ExtraPoisonPattern) []string {
	updatedByName := make(map[string]string, len(updated))
	for _, p := range updated {
		if p == nil {
			continue
		}
		updatedByName[p.Name] = toolPoisonPatternIdentity(p)
	}

	var removed []string
	for _, p := range old {
		if p == nil || p.Bundle == "" {
			continue
		}
		identity, ok := updatedByName[p.Name]
		switch {
		case !ok:
			removed = append(removed, p.Name)
		case identity != toolPoisonPatternIdentity(p):
			removed = append(removed, p.Name+" (regex or scan_field changed)")
		}
	}
	return removed
}

func toolPoisonPatternIdentity(p *tools.ExtraPoisonPattern) string {
	if p == nil {
		return ""
	}
	regex := ""
	if p.Re != nil {
		regex = p.Re.String()
	}
	return regex + "\x00" + p.ScanField
}

func hasRejectableDowngradeWarning(warnings []config.ReloadWarning) bool {
	for _, w := range warnings {
		if reloadWarningIsAdvisory(w) {
			continue
		}
		return true
	}
	return false
}

func reloadWarningIsAdvisory(w config.ReloadWarning) bool {
	msg := strings.ToLower(w.Message)
	if strings.Contains(msg, "requires restart") ||
		strings.Contains(msg, "require restart") ||
		strings.Contains(msg, "ignored on reload") ||
		strings.Contains(msg, "uses init-time") ||
		strings.Contains(msg, "cannot change at runtime") {
		return true
	}

	switch w.Field {
	case "mediation_envelope.key_id":
		return true
	case "dlp.secrets_file":
		return !strings.Contains(msg, "removed")
	default:
		return false
	}
}

func hasNamedAgentProfiles(agents map[string]config.AgentProfile) bool {
	for name := range agents {
		if name != "_default" {
			return true
		}
	}
	return false
}

// preserveLicenseInputsRestartOnly copies the old license inputs and agent
// profiles onto newCfg so a reload cannot activate OR deactivate licensed
// surfaces without a restart. Used for both a plain license-input change and an
// unverifiable new input: in both cases the effective entitlement is the old,
// already-verified one, and committing the new input fields would let a later
// unrelated reload see no diff and silently apply the staged license.
func preserveLicenseInputsRestartOnly(newCfg, oldCfg *config.Config) {
	newCfg.Agents = oldCfg.Agents
	newCfg.LicenseKey = oldCfg.LicenseKey
	newCfg.LicenseFile = oldCfg.LicenseFile
	newCfg.LicenseCRLFile = oldCfg.LicenseCRLFile
	newCfg.LicenseIntermediateFile = oldCfg.LicenseIntermediateFile
	newCfg.LicenseIntermediateCert = append([]byte(nil), oldCfg.LicenseIntermediateCert...)
	newCfg.LicenseIntermediateLoadError = oldCfg.LicenseIntermediateLoadError
	newCfg.LicensePublicKey = oldCfg.LicensePublicKey
	// Require-intermediate is restart-only too: preserve both the YAML pointer and
	// the materialized value so a later unrelated reload sees no diff and cannot
	// silently apply a staged require-mode change without a restart.
	newCfg.LicenseRequireIntermediate = oldCfg.LicenseRequireIntermediate
	newCfg.LicenseRequireIntermediateResolved = oldCfg.LicenseRequireIntermediateResolved
	newCfg.LicenseRequireIntermediateEnvError = oldCfg.LicenseRequireIntermediateEnvError
	// The CRL freshness window is part of the restart-only license input set.
	newCfg.LicenseCRLMaxAge = oldCfg.LicenseCRLMaxAge
	newCfg.LicenseCRLMaxAgeResolved = oldCfg.LicenseCRLMaxAgeResolved
	newCfg.LicenseCRLMaxAgeError = oldCfg.LicenseCRLMaxAgeError
}

// cleanup closes all owned resources. Safe to call multiple times: each
// field is niled after its close so repeat calls are no-ops. LIFO order
// mirrors the original RunCmd deferred closures so shutdown sequencing is
// preserved.
func (s *Server) cleanup() {
	if s.recorder != nil {
		_ = s.recorder.Close()
		s.recorder = nil
	}
	if s.conductorProducer != nil {
		_ = s.conductorProducer.Close()
		s.conductorProducer = nil
	}
	closeConductorAuditQueue(s.conductorAuditQueue)
	s.conductorAuditQueue = nil
	if s.captureWriter != nil {
		_ = s.captureWriter.Close()
		s.captureWriter = nil
	}
	if s.approver != nil {
		s.approver.Close()
		s.approver = nil
	}
	liveScanner := s.scanner
	if s.proxy != nil {
		if current := s.proxy.ScannerPtr().Load(); current != nil {
			liveScanner = current
		}
	}
	if liveScanner != nil {
		liveScanner.Close()
		s.scanner = nil
	}
	if s.emitter != nil {
		_ = s.emitter.Close()
		s.emitter = nil
	}
	if s.logger != nil {
		s.logger.Close()
		s.logger = nil
	}
	if s.sentry != nil {
		s.sentry.Close()
		s.sentry = nil
	}
}
