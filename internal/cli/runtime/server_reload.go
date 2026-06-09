// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
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
	defer func() {
		if r := recover(); r != nil {
			ReloadPanicHandler(r, s.sentry, s.logger, s.opts.ConfigFile)
			err = fmt.Errorf("scanner construction panic during config reload: %v", r)
		}
	}()

	oldCfg := s.proxy.CurrentConfig()
	if oldCfg != nil {
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
		// Block flight_recorder changes via reload. The recorder (and its
		// receipt/audit chain) is built once at Start; reload swaps config and
		// scanner but never rebuilds the recorder, so any flight_recorder change
		// would leave the live config disagreeing with the running recorder.
		// Signing-key rotation is the sharpest case - the receipt chain is
		// anchored to the current key, and rotating mid-chain breaks tail-
		// signature verification on resume - but every field is restart-only for
		// the same build-once reason. Preserve the whole block and warn.
		//
		// This also keeps Conductor policy-bundle apply working: a signed bundle
		// carries enforcement-only config (flight_recorder is not an allowlisted
		// bundle section), so the bundle's loaded config omits flight_recorder.
		// Preserving the follower's existing block means conductor.enabled - which
		// requires a signed flight recorder - still validates after the apply.
		if !reflect.DeepEqual(oldCfg.FlightRecorder, newCfg.FlightRecorder) {
			if oldCfg.FlightRecorder.SigningKeyPath != newCfg.FlightRecorder.SigningKeyPath {
				_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: flight_recorder.signing_key_path changed from %q to %q — receipt chain cannot rotate at runtime, ignoring (restart required)\n",
					oldCfg.FlightRecorder.SigningKeyPath, newCfg.FlightRecorder.SigningKeyPath)
			} else {
				_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: flight_recorder settings changed — recorder is built at startup and cannot rebind at runtime, ignoring (restart required)\n")
			}
			newCfg.FlightRecorder = oldCfg.FlightRecorder
		}
		// Block file_sentry changes via reload. The watcher is built
		// once at Start from the startup snapshot; reloading would
		// leave the old watcher armed on stale paths while the live
		// config reported the new ones. Restart to apply.
		if !reflect.DeepEqual(oldCfg.FileSentry, newCfg.FileSentry) {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: file_sentry settings changed — watcher cannot rebind at runtime, ignoring (restart required)\n")
			newCfg.FileSentry = oldCfg.FileSentry
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
			oldCfg.LicenseIntermediateLoadError != newCfg.LicenseIntermediateLoadError

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
			reloadLic, reloadClass = license.ClassifyReload(
				newCfg.LicenseKey, newCfg.LicensePublicKey, newCfg.LicenseCRLFile, newCfg.LicenseIntermediateFile)
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
	newCfg, _ = newCfg.ResolveRuntime(config.RuntimeResolveOpts{
		Mode: s.runtimeMode,
		MergeBundles: func(c *config.Config) {
			reloadBundleResult = rules.MergeIntoConfig(c, cliutil.Version)
		},
		DefaultToolPolicyRules: policy.DefaultToolPolicyRules,
	})
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
		warnings := config.ValidateReload(oldCfg, newCfg)
		for _, w := range warnings {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: %s - %s\n", w.Field, w.Message)
		}
		// Block downgrades from strict mode (security-critical).
		if oldCfg.Mode == config.ModeStrict && len(warnings) > 0 {
			rejectErr := fmt.Errorf("rejected: security downgrade from strict mode")
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
	s.refreshRuntimeState(oldCfg, newCfg, reloadBundleResult, s.proxy.ScannerPtr().Load())
	if reloadErr := s.proxy.LoadCertCache(newCfg); reloadErr != nil {
		s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile),
			fmt.Errorf("TLS cert cache reload failed: %w", reloadErr))
	}
	s.killswitch.Reload(newCfg)

	// Reload emit sinks: build new sinks from config, swap into
	// emitter, close old sinks.
	newSinks, sinkErr := BuildEmitSinks(newCfg)
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
	}

	if newCfg.ResponseScanning.Action == config.ActionAsk && !s.hasApprover {
		_, _ = fmt.Fprintln(s.opts.Stderr, "WARNING: config reloaded to ask mode but HITL approver was not initialized at startup; detections will be blocked")
	}
	reloadHash := newCfg.Hash()
	s.logger.LogConfigReload("success", fmt.Sprintf("mode=%s", newCfg.Mode), reloadHash)
	s.recordReloadSuccess(reloadHash)
	return nil
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
