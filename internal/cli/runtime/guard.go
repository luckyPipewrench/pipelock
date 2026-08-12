// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/destination"
	guardfs "github.com/luckyPipewrench/pipelock/internal/guard"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/posturebinding"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// GuardLaunchOptions is the fully resolved operator request.
type GuardLaunchOptions struct {
	Context   context.Context
	Config    *config.Config
	Profile   string
	Workspace string
	Command   []string
	Stderr    io.Writer
}

// GuardPreflight validates the runtime contract and probes every required
// phase-0 capability without launching the command.
func GuardPreflight(cfg *config.Config, profile, workspace string, command []string) (sandbox.PreflightResult, error) {
	if err := validateGuardRuntime(cfg); err != nil {
		return sandbox.PreflightResult{}, err
	}
	resolved, err := filepath.Abs(workspace)
	if err != nil {
		return sandbox.PreflightResult{}, fmt.Errorf("resolving guard workspace: %w", err)
	}
	if err := validateGuardRuntimeObjects(cfg, profile); err != nil {
		return sandbox.PreflightResult{}, err
	}
	executable, err := resolveGuardExecutable(command, resolved)
	if err != nil {
		return sandbox.PreflightResult{}, err
	}
	if err := guardfs.ValidateExecutionPaths(resolved, resolved, executable); err != nil {
		return sandbox.PreflightResult{}, err
	}
	policy, err := guardSandboxPolicy(cfg, profile, resolved)
	if err != nil {
		return sandbox.PreflightResult{}, err
	}
	policy.AllowRWDirs = existingGuardPreflightDirs(policy.AllowRWDirs)
	return sandbox.PreflightWithRequirements(resolved, command, &policy, sandbox.PreflightRequirements{
		RequireNetNS:        true,
		RequireProxyHandler: true,
		RequireLandlock:     true,
		MinimumLandlockABI:  guardfs.MinimumABI,
	}), nil
}

// LaunchGuard runs an operator command under the Linux HTTP/HTTPS preview.
func LaunchGuard(opts GuardLaunchOptions) error {
	return launchGuard(opts, sandbox.LaunchStandalone)
}

func launchGuard(opts GuardLaunchOptions, launchStandalone func(sandbox.StandaloneLaunchConfig) error) error {
	if opts.Config == nil {
		return errors.New("guard config is nil")
	}
	if len(opts.Command) == 0 {
		return errors.New("guard command is empty")
	}
	if err := validateGuardRuntime(opts.Config); err != nil {
		return err
	}
	workspace, err := filepath.Abs(opts.Workspace)
	if err != nil {
		return fmt.Errorf("resolving guard workspace: %w", err)
	}
	if err := sandbox.ValidateWorkspace(workspace); err != nil {
		return fmt.Errorf("guard workspace: %w", err)
	}
	if err := validateGuardRuntimeObjects(opts.Config, opts.Profile); err != nil {
		return err
	}
	executable, err := resolveGuardExecutable(opts.Command, workspace)
	if err != nil {
		return err
	}
	prepared, err := guardfs.PrepareExecution(opts.Config, opts.Profile, workspace, workspace, executable, os.Getuid())
	if err != nil {
		return fmt.Errorf("prepare Guard manifest before sandbox launch: %w", err)
	}
	if !prepared.Complete() {
		outcomes := prepared.Outcomes()
		_ = prepared.Close()
		return fmt.Errorf("prepare Guard manifest before sandbox launch: incomplete grants: %+v", outcomes)
	}
	if err := prepared.Close(); err != nil {
		return fmt.Errorf("close prepared Guard manifest: %w", err)
	}

	runtimeCfg := opts.Config.Clone()
	runtimeCfg.ForwardProxy.Enabled = true
	grants, err := guardDestinationGrants(runtimeCfg.Guard.Services)
	if err != nil {
		return err
	}
	sc, err := scanner.NewWithOptions(runtimeCfg, scanner.Options{DestinationGrants: grants})
	if err != nil {
		return fmt.Errorf("create guard scanner: %w", err)
	}
	defer sc.Close()

	logger, err := audit.NewWithStream(
		runtimeCfg.Logging.Format,
		runtimeCfg.Logging.Output,
		runtimeCfg.Logging.File,
		runtimeCfg.Logging.IncludeAllowed,
		runtimeCfg.Logging.IncludeBlocked,
		opts.Stderr,
	)
	if err != nil {
		return fmt.Errorf("create guard audit logger: %w", err)
	}
	defer logger.Close()

	guardMetrics := metrics.New()
	baseCtx := ctxOrBackground(opts.Context)
	evidence, err := newGuardEvidence(baseCtx, runtimeCfg, sc, guardMetrics, opts.Stderr)
	if err != nil {
		return err
	}
	defer evidence.close()
	ctx, cancel := signal.NotifyContext(baseCtx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	guardReady := make(chan struct{})
	var guardReadyOnce sync.Once

	p, err := proxy.New(runtimeCfg, logger, sc, guardMetrics, evidence.proxyOptions...)
	if err != nil {
		return fmt.Errorf("create guard proxy: %w", err)
	}
	defer p.Close()
	handler := p.Handler()
	proxyHandler := func(conn net.Conn) {
		select {
		case <-guardReady:
		case <-ctx.Done():
			_ = conn.Close()
			return
		}
		srv := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		_ = srv.Serve(&singleConnListener{conn: conn})
	}

	policy, err := guardSandboxPolicy(runtimeCfg, opts.Profile, workspace)
	if err != nil {
		return err
	}
	declaration := runtimeCfg.Guard
	configPolicyHash := runtimeCfg.CanonicalPolicyHash()
	return launchStandalone(sandbox.StandaloneLaunchConfig{
		Ctx:                     ctx,
		Command:                 opts.Command,
		Workspace:               workspace,
		Policy:                  &policy,
		RequireNetNS:            true,
		DeveloperEnvironment:    os.Environ(),
		UseDeveloperEnvironment: true,
		ProxyHandler:            proxyHandler,
		RequireProxyHandler:     true,
		GuardDeclaration:        &declaration,
		GuardProfile:            opts.Profile,
		GuardPolicyHash:         configPolicyHash,
		GuardAppliedPreExec: func(encoded []byte) error {
			var proof guardfs.ExecutionProof
			if err := json.Unmarshal(encoded, &proof); err != nil {
				return fmt.Errorf("decoding child enforcement proof: %w", err)
			}
			if err := proof.Verify(configPolicyHash); err != nil {
				return err
			}
			if err := evidence.activate(proof); err != nil {
				return err
			}
			guardReadyOnce.Do(func() { close(guardReady) })
			return nil
		},
	})
}

func resolveGuardExecutable(command []string, workspace string) (string, error) {
	if len(command) == 0 || command[0] == "" {
		return "", errors.New("guard command is empty")
	}
	resolved, err := sandbox.ResolveCommandInDir(command[0], os.Environ(), workspace)
	if err != nil {
		return "", fmt.Errorf("resolving guard command %q: %w", command[0], err)
	}
	return resolved, nil
}

type guardEvidence struct {
	proxyOptions []proxy.Option
	recorder     *recorder.Recorder
	stop         func()
	emitter      *receipt.Emitter
	ctx          context.Context
	heartbeat    time.Duration
	stderr       io.Writer
	require      bool
	activateOnce sync.Once
	activateErr  error
}

func (e *guardEvidence) close() {
	if e == nil {
		return
	}
	if e.stop != nil {
		e.stop()
	}
	if e.recorder != nil {
		_ = e.recorder.Close()
	}
}

func (e *guardEvidence) activate(proof guardfs.ExecutionProof) error {
	if e == nil || e.emitter == nil {
		return nil
	}
	e.activateOnce.Do(func() {
		e.activateErr = e.activateReceipts(proof)
	})
	return e.activateErr
}

func (e *guardEvidence) activateReceipts(proof guardfs.ExecutionProof) error {
	e.emitter.UpdateConfigHash(proof.ConfigPolicyHash)
	if err := emitStartupSessionOpen(e.emitter); err != nil {
		if e.require {
			return fmt.Errorf("emitting Guard session_open receipt: %w", err)
		}
		_, _ = fmt.Fprintf(e.stderr,
			"  Receipts: ERROR - Guard session_open could not be emitted: %v\n"+
				"            Receipt emission for this run is UNVERIFIED until resolved.\n", err)
	}
	if err := e.emitter.EmitDurable(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Layer: "guard", Pattern: "landlock_applied_pre_exec", Transport: "guard_exec",
		Method: "EXEC", Target: proof.Binary, PolicyHash: proof.ConfigPolicyHash,
		// RequestID is the signed per-action correlation field. Guard uses it to
		// carry the effective invocation digest without mislabeling that digest
		// as the canonical configuration policy hash.
		RequestID: "guard-exec:" + proof.EffectivePolicyHash,
	}); err != nil {
		if e.require {
			return fmt.Errorf("emitting Guard pre-exec enforcement receipt: %w", err)
		}
		_, _ = fmt.Fprintf(e.stderr, "  Receipts: ERROR - Guard pre-exec enforcement could not be emitted: %v\n", err)
	}
	e.stop = startStandaloneReceiptLifecycle(e.ctx, e.heartbeat, e.emitter, e.stderr, e.require, nil)
	return nil
}

func newGuardEvidence(ctx context.Context, cfg *config.Config, sc *scanner.Scanner, m *metrics.Metrics, stderr io.Writer) (*guardEvidence, error) {
	evidence := &guardEvidence{
		stop: func() {}, ctx: ctx, heartbeat: cfg.FlightRecorder.HeartbeatIntervalDuration(),
		stderr: stderr, require: cfg.FlightRecorder.RequireReceipts,
	}
	if !cfg.FlightRecorder.Enabled || cfg.FlightRecorder.Dir == "" {
		if cfg.FlightRecorder.RequireReceipts {
			return nil, errors.New("flight_recorder.require_receipts is enabled but Guard has no configured recorder directory")
		}
		if cfg.FlightRecorder.Enabled {
			_, _ = fmt.Fprintln(stderr, "  Recorder: enabled but inert; set flight_recorder.dir and signing_key_path for signed Guard receipts")
		}
		return evidence, nil
	}

	recorderConfig := recorder.Config{
		Enabled:            true,
		Dir:                cfg.FlightRecorder.Dir,
		CheckpointInterval: cfg.FlightRecorder.CheckpointInterval,
		RetentionDays:      cfg.FlightRecorder.RetentionDays,
		Redact:             cfg.FlightRecorder.Redact,
		SignCheckpoints:    cfg.FlightRecorder.SignCheckpoints,
		MaxEntriesPerFile:  cfg.FlightRecorder.MaxEntriesPerFile,
		FileMode:           cfg.FlightRecorder.FileMode,
		RawEscrow:          cfg.FlightRecorder.RawEscrow,
		EscrowPublicKey:    cfg.FlightRecorder.EscrowPublicKey,
		Metrics:            m,
	}
	var redactFn recorder.RedactFunc
	if cfg.FlightRecorder.Redact {
		redactFn = sc.ScanTextForDLP
	}
	var privateKey ed25519.PrivateKey
	if cfg.FlightRecorder.SigningKeyPath != "" {
		key, err := signing.LoadPrivateKeyFile(cfg.FlightRecorder.SigningKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading Guard receipt signing key: %w", err)
		}
		privateKey = key
	}
	rec, err := recorder.New(recorderConfig, redactFn, privateKey)
	if err != nil {
		return nil, fmt.Errorf("creating Guard flight recorder: %w", err)
	}
	evidence.recorder = rec
	evidence.proxyOptions = append(evidence.proxyOptions, proxy.WithRecorder(rec))

	binding, err := posturebinding.LoadRuntime()
	if err != nil {
		evidence.close()
		return nil, fmt.Errorf("loading Guard posture binding: %w", err)
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rec, PrivKey: privateKey, ConfigHash: cfg.CanonicalPolicyHash(),
		Principal: "local", Actor: "pipelock", Metrics: m, PostureBinding: binding,
		HeartbeatSeconds: cfg.FlightRecorder.HeartbeatIntervalSecondsForReceipt(),
	})
	if !receiptEmitterReady(emitter) {
		if cfg.FlightRecorder.RequireReceipts {
			evidence.close()
			return nil, errors.New("flight_recorder.require_receipts is enabled but no healthy signed Guard receipt emitter is active")
		}
		_, _ = fmt.Fprintln(stderr, "  Receipts: disabled; set a healthy flight_recorder.signing_key_path to enable signed Guard receipts")
		return evidence, nil
	}
	evidence.emitter = emitter
	evidence.proxyOptions = append(evidence.proxyOptions,
		proxy.WithReceiptEmitter(emitter),
		proxy.WithReceiptKeyPath(cfg.FlightRecorder.SigningKeyPath),
	)
	if v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{
		Recorder: rec, Signer: proxydecision.NewKeyedSigner(privateKey),
		Sanitize:  proxydecision.SanitizeFromRedactor(rec.ReceiptRedactor()),
		Principal: "local", Actor: "pipelock",
	}); v2 != nil {
		evidence.proxyOptions = append(evidence.proxyOptions, proxy.WithV2ReceiptEmitter(v2))
	}
	_, _ = fmt.Fprintf(stderr, "  Recorder: %s (Guard receipts armed; awaiting child enforcement proof)\n", cfg.FlightRecorder.Dir)
	return evidence, nil
}

func ctxOrBackground(ctx context.Context) context.Context {
	if ctx != nil {
		return ctx
	}
	return context.Background()
}

func validateGuardRuntime(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("guard config is nil")
	}
	if cfg.Sandbox.BestEffort {
		return errors.New("guard refuses sandbox.best_effort:true; network namespace isolation is required")
	}
	if !cfg.EnforceEnabled() {
		return errors.New("guard refuses enforce:false; an egress guard cannot run audit-only")
	}
	if !cfg.DLP.ScanEnv {
		return errors.New("guard refuses dlp.scan_env:false because the preserved developer environment contains secret-bearing values")
	}
	return cfg.ValidateGuardDeclaration()
}

func guardDestinationGrants(services []config.GuardService) (destination.GrantSet, error) {
	grants := make([]destination.Grant, 0, len(services))
	for _, service := range services {
		grant, err := destination.NewGrant(destination.Network(service.Protocol), service.Host, service.Port)
		if err != nil {
			return destination.GrantSet{}, fmt.Errorf("guard service %q: %w", service.Name, err)
		}
		grants = append(grants, grant)
	}
	return destination.NewGrantSet(grants...)
}

func guardSandboxPolicy(cfg *config.Config, profileName, workspace string) (sandbox.Policy, error) {
	policy := sandbox.DefaultPolicy(workspace)
	if profileName == "" {
		if len(cfg.Guard.Profiles) != 0 {
			return sandbox.Policy{}, errors.New("guard profile is required when profiles are declared")
		}
		return policy, nil
	}
	var selected *config.GuardProfile
	for i := range cfg.Guard.Profiles {
		if cfg.Guard.Profiles[i].Name == profileName {
			selected = &cfg.Guard.Profiles[i]
			break
		}
	}
	if selected == nil {
		return sandbox.Policy{}, fmt.Errorf("guard profile %q not found", profileName)
	}
	byName := make(map[string]config.GuardManifest, len(cfg.Guard.Manifests))
	for _, manifest := range cfg.Guard.Manifests {
		byName[manifest.Name] = manifest
	}
	for _, name := range selected.Manifests {
		manifest := byName[name]
		policy.AllowReadFiles = append(policy.AllowReadFiles, manifest.ReadOnly...)
		policy.AllowReadDirs = append(policy.AllowReadDirs, manifest.ReadOnlyDirectories...)
		policy.AllowRWFiles = append(policy.AllowRWFiles, manifest.ReadWrite...)
		policy.AllowRWDirs = append(policy.AllowRWDirs, manifest.ReadWriteDirectories...)
	}
	return policy, nil
}

func validateGuardRuntimeObjects(cfg *config.Config, profileName string) error {
	selected := make(map[string]struct{})
	profileFound := false
	if profileName == "" {
		if len(cfg.Guard.Profiles) != 0 {
			return errors.New("guard profile is required when profiles are declared")
		}
		return nil
	}
	for _, profile := range cfg.Guard.Profiles {
		if profile.Name == profileName {
			profileFound = true
			for _, name := range profile.Manifests {
				selected[name] = struct{}{}
			}
			break
		}
	}
	if !profileFound {
		return fmt.Errorf("guard profile %q not found", profileName)
	}
	check := func(path string, wantDirectory, allowMissingLeaf bool) error {
		resolved, err := filepath.EvalSymlinks(path)
		if errors.Is(err, os.ErrNotExist) {
			if !allowMissingLeaf {
				return fmt.Errorf("guard path %q does not exist", path)
			}
			parent, parentErr := filepath.EvalSymlinks(filepath.Dir(filepath.Clean(path)))
			if parentErr != nil {
				return fmt.Errorf("guard writable directory parent for %q does not exist: %w", path, parentErr)
			}
			// EvalSymlinks proved this was a directory, but the path may be
			// replaced before the grant is prepared. Re-stat it so that race
			// fails closed instead of creating state beneath a non-directory.
			info, statErr := os.Stat(parent)
			if statErr != nil || !info.IsDir() {
				return fmt.Errorf("guard writable directory parent for %q is not a directory", path)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("resolve Guard path %q: %w", path, err)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return fmt.Errorf("stat Guard path %q: %w", path, err)
		}
		if wantDirectory && !info.IsDir() {
			return fmt.Errorf("guard path %q is not a directory", path)
		}
		if !wantDirectory && !info.Mode().IsRegular() {
			return fmt.Errorf("guard path %q is not a regular file; sockets, FIFOs, and devices cannot be granted", path)
		}
		return nil
	}
	for _, manifest := range cfg.Guard.Manifests {
		if _, ok := selected[manifest.Name]; !ok {
			continue
		}
		for _, path := range append(append([]string{}, manifest.ReadOnly...), manifest.ReadWrite...) {
			if err := check(path, false, false); err != nil {
				return err
			}
		}
		for _, path := range manifest.ReadOnlyDirectories {
			if err := check(path, true, false); err != nil {
				return err
			}
		}
		for _, path := range manifest.ReadWriteDirectories {
			if err := check(path, true, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func existingGuardPreflightDirs(paths []string) []string {
	existing := make([]string, 0, len(paths))
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			existing = append(existing, path)
		}
	}
	return existing
}
