// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
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
		// Block signing key rotation via reload. The receipt chain
		// state is anchored to the current signing key; rotation
		// mid-chain causes tail-signature verification to fail on
		// resume, which in turn drops receipt persistence for every
		// subsequent action. Proper chain rollover with a key-rotation
		// marker is tracked for v2.2.1. Until then, preserve the old
		// key and warn — operators must restart pipelock to rotate the
		// receipt signing key.
		if oldCfg.FlightRecorder.SigningKeyPath != newCfg.FlightRecorder.SigningKeyPath {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: flight_recorder.signing_key_path changed from %q to %q — receipt chain cannot rotate at runtime, ignoring (restart required)\n",
				oldCfg.FlightRecorder.SigningKeyPath, newCfg.FlightRecorder.SigningKeyPath)
			newCfg.FlightRecorder.SigningKeyPath = oldCfg.FlightRecorder.SigningKeyPath
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

		// Block reverse proxy listener/upstream changes via reload.
		// The listener binds at startup and the upstream is pinned in
		// the handler. Requires restart.
		if oldCfg.ReverseProxy.Listen != newCfg.ReverseProxy.Listen ||
			oldCfg.ReverseProxy.Enabled != newCfg.ReverseProxy.Enabled ||
			oldCfg.ReverseProxy.Upstream != newCfg.ReverseProxy.Upstream {
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
		agentsRevokedByLicense := oldCfg.Agents != nil && newCfg.Agents == nil
		licenseInputsChanged := oldCfg.LicenseKey != newCfg.LicenseKey ||
			oldCfg.LicensePublicKey != newCfg.LicensePublicKey ||
			oldCfg.LicenseFile != newCfg.LicenseFile ||
			oldCfg.LicenseCRLFile != newCfg.LicenseCRLFile

		if agentsRevokedByLicense {
			// License gate disabled agents on reload. Shut down
			// already-bound listener servers so the agent ports
			// stop accepting traffic.
			s.proxy.ShutdownAgentServers()
			_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: license revoked agents, shutting down agent listeners\n")
		} else if licenseInputsChanged {
			// License inputs changed but agents were not revoked.
			// Preserve ALL old license state so a reload cannot
			// activate licensed features without a restart. We
			// must also preserve the old license input fields
			// themselves; otherwise the new values get committed
			// to the live config and a subsequent unrelated reload
			// would see no diff, silently applying the staged
			// license.
			newCfg.Agents = oldCfg.Agents
			newCfg.LicenseKey = oldCfg.LicenseKey
			newCfg.LicenseFile = oldCfg.LicenseFile
			newCfg.LicenseCRLFile = oldCfg.LicenseCRLFile
			newCfg.LicensePublicKey = oldCfg.LicensePublicKey
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: license key inputs changed (license_key, license_file, license_crl_file, or license_public_key) - requires restart for license re-verification\n")
		} else if AgentListenersChanged(oldCfg, newCfg) {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: agents[*].listeners changed — requires restart, ignoring listener changes\n")
			PreserveAgentListeners(oldCfg, newCfg)
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

// cleanup closes all owned resources. Safe to call multiple times: each
// field is niled after its close so repeat calls are no-ops. LIFO order
// mirrors the original RunCmd deferred closures so shutdown sequencing is
// preserved.
func (s *Server) cleanup() {
	if s.recorder != nil {
		_ = s.recorder.Close()
		s.recorder = nil
	}
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
