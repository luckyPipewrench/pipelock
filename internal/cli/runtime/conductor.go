//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/emergency"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/policysync"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	conductorHTTPTimeout           = 30 * time.Second
	conductorTLSHandshakeTimeout   = 10 * time.Second
	conductorResponseHeaderTimeout = 30 * time.Second
	conductorIdleConnTimeout       = 90 * time.Second
	conductorExpectContinueTimeout = time.Second
	// conductorAppliedStateHandshakeTimeout bounds the best-effort capabilities
	// handshake used to decide whether the follower may emit signed
	// applied-state. Kept short so a slow/absent conductor does not stall
	// producer startup; a timeout fails safe (no applied-state).
	conductorAppliedStateHandshakeTimeout = 5 * time.Second
	// conductorMaxResponseHeaderBytes caps Boss response headers. The default
	// Go ceiling is 1 MiB, which is wasteful for an ingest endpoint that
	// returns small JSON receipts; a tight cap also bounds memory under a
	// hostile or misbehaving Boss.
	conductorMaxResponseHeaderBytes = 64 * 1024
)

type ConductorApplyOptions struct {
	Resolver      conductor.SignatureKeyResolver
	Labels        map[string]string
	Rollback      *conductor.RollbackAuthorization
	AllowRollback bool
}

// conductorFollowerLabels returns a defensive copy of the follower's
// self-declared audience labels from config. Both the forward bundle applier and
// the rollback applier source the follower's labels here so leader-side
// label/audience targeting can match this follower (conductor.Audience.Matches).
// A copy is returned so the captured applier never shares a map with a config
// that a later (no-op for conductor) reload could replace; conductor settings
// are restart-only, but the copy keeps the apply path independent of config
// mutation regardless. Returns nil for nil/empty labels, which fails closed:
// a label-scoped bundle simply will not match a follower that declares none.
func conductorFollowerLabels(cfg *config.Config) map[string]string {
	if cfg == nil || len(cfg.Conductor.Labels) == 0 {
		return nil
	}
	labels := make(map[string]string, len(cfg.Conductor.Labels))
	for k, v := range cfg.Conductor.Labels {
		labels[k] = v
	}
	return labels
}

func buildConductorApplyCache(cfg *config.Config) (*applycache.Cache, error) {
	if cfg == nil || !cfg.Conductor.Enabled {
		return nil, nil
	}
	cache, err := applycache.Open(applycache.Config{Dir: cfg.Conductor.BundleCacheDir})
	if err != nil {
		return nil, fmt.Errorf("opening conductor apply cache: %w", err)
	}
	return cache, nil
}

func (s *Server) applyCache() *applycache.Cache {
	if s == nil {
		return nil
	}
	cache, _ := s.conductorApply.(*applycache.Cache)
	return cache
}

func (s *Server) ApplyConductorPolicyBundle(bundle conductor.PolicyBundle, opts ConductorApplyOptions) (applycache.AppliedBundle, error) {
	if s == nil {
		return applycache.AppliedBundle{}, errors.New("nil runtime server")
	}
	// Fail closed once the fleet entitlement has been revoked/expired/downgraded
	// at runtime: teardownConductor sets conductorDown, after which no further
	// policy bundles may be applied.
	if s.conductorDown.Load() {
		return applycache.AppliedBundle{}, applycache.ErrCacheRequired
	}
	cache := s.applyCache()
	if cache == nil {
		return applycache.AppliedBundle{}, applycache.ErrCacheRequired
	}
	// Serialize the whole stage -> reload -> activate sequence: the durable
	// last-known-good pointer must never diverge from the running config.
	s.conductorApplyMu.Lock()
	defer s.conductorApplyMu.Unlock()
	// Re-check under the apply lock: teardownConductor runs concurrently (CRL
	// watcher / expiry timer / reload) and sets conductorDown without taking
	// this lock (taking it would deadlock the poller's own
	// apply -> reload -> teardown path). Re-checking here means any teardown
	// observed before stage/reload/activate aborts the apply; the only residual
	// window is a single bundle already past this point when teardown fires, and
	// the poller is cancelled so no further bundles follow.
	if s.conductorDown.Load() {
		return applycache.AppliedBundle{}, applycache.ErrCacheRequired
	}
	cfg := s.currentConfig()
	if cfg == nil && s.proxy != nil {
		cfg = s.proxy.CurrentConfig()
	}
	if cfg == nil {
		return applycache.AppliedBundle{}, errors.New("runtime config unavailable")
	}
	boundary := applycache.Boundary{
		Cache: cache,
		Identity: applycache.Identity{
			OrgID:      cfg.Conductor.OrgID,
			FleetID:    cfg.Conductor.FleetID,
			InstanceID: cfg.Conductor.InstanceID,
			Labels:     opts.Labels,
		},
		Resolver:     opts.Resolver,
		LocalVersion: cliutil.Version,
		LoadConfig:   config.Load,
		Reload: func(newCfg *config.Config) error {
			preserveConductorBundleLocalRuntimeState(cfg, newCfg)
			return s.Reload(newCfg)
		},
		// Close the in-flight apply window: teardownConductor sets conductorDown
		// without taking conductorApplyMu (that would deadlock the poller's own
		// apply -> reload -> teardown path), so a bundle already past the
		// under-lock conductorDown re-check could otherwise complete its Reload
		// after a concurrent revocation/expiry teardown. Re-checking right before
		// the boundary's live-config swap aborts that last bundle fail-closed.
		StillEntitled: func() bool { return !s.conductorDown.Load() },
	}
	return boundary.Apply(bundle, applycache.ApplyOptions{
		Rollback:      opts.Rollback,
		AllowRollback: opts.AllowRollback,
	})
}

func preserveConductorBundleLocalRuntimeState(oldCfg, newCfg *config.Config) {
	config.PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg)
}

func buildConductorAuditTransport(cfg *config.Config, m *metrics.Metrics) (*auditbatcher.Queue, *auditbatcher.Transport, error) {
	if cfg == nil || !cfg.Conductor.Enabled {
		return nil, nil, nil
	}
	q, err := auditbatcher.Open(auditbatcher.Config{
		Dir:             cfg.Conductor.DurableAuditQueueDir,
		MaxPayloadBytes: conductor.MaxAuditPayloadBytes,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("opening conductor audit queue: %w", err)
	}
	opened := false
	defer func() {
		if !opened {
			_ = q.Close()
		}
	}()
	stats, err := q.Stats()
	if err != nil {
		return nil, nil, fmt.Errorf("reading conductor audit queue stats: %w", err)
	}
	if m != nil {
		m.RecordConductorAuditQueue(stats)
	}

	client, err := newConductorMTLSClient(cfg.Conductor)
	if err != nil {
		return nil, nil, err
	}
	tr, err := auditbatcher.NewTransport(auditbatcher.TransportConfig{
		BaseURL: cfg.Conductor.ConductorURL,
		Client:  client,
		Queue:   q,
		Metrics: m,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating conductor audit transport: %w", err)
	}
	opened = true
	return q, tr, nil
}

func buildConductorRemoteKillPoller(cfg *config.Config, ks emergency.KillSwitchSetter, logWriter io.Writer) (*emergency.RemoteKillPoller, error) {
	if cfg == nil || !cfg.Conductor.Enabled {
		return nil, nil
	}
	client, err := newConductorMTLSClient(cfg.Conductor)
	if err != nil {
		return nil, err
	}
	var resolver conductor.SignatureKeyResolver
	if cfg.Conductor.HonorRemoteKillSwitch {
		resolver, err = buildConductorTrustResolver(cfg.Conductor, time.Now)
		if err != nil {
			return nil, err
		}
	} else {
		resolver = func(string) (conductor.SignatureKey, error) {
			return conductor.SignatureKey{}, conductor.ErrSignatureVerification
		}
	}
	interval, err := time.ParseDuration(cfg.Conductor.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("parsing conductor remote kill poll interval: %w", err)
	}
	if logWriter == nil {
		logWriter = io.Discard
	}
	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "pipelock", "component", "conductor_remote_kill")
	applier := buildConductorRemoteKillApplier(cfg, ks, resolver, logger)
	if !applier.DisableRemoteKill {
		if err := applier.RestorePersistedState(); err != nil {
			return nil, fmt.Errorf("restoring conductor remote kill state: %w", err)
		}
	}
	return emergency.NewRemoteKillPoller(emergency.RemoteKillPollerConfig{
		BaseURL:      cfg.Conductor.ConductorURL,
		Client:       client,
		Applier:      applier,
		PollInterval: interval,
		Logger:       logger,
	})
}

func buildConductorRemoteKillApplier(cfg *config.Config, ks emergency.KillSwitchSetter, resolver conductor.SignatureKeyResolver, logger *slog.Logger) *emergency.RemoteKillApplier {
	return &emergency.RemoteKillApplier{
		OrgID:             cfg.Conductor.OrgID,
		FleetID:           cfg.Conductor.FleetID,
		InstanceID:        cfg.Conductor.InstanceID,
		Labels:            conductorFollowerLabels(cfg),
		Resolver:          resolver,
		KillSwitch:        ks,
		StatePath:         filepath.Join(cfg.Conductor.BundleCacheDir, emergency.RemoteKillStateFileName),
		DisableRemoteKill: !cfg.Conductor.HonorRemoteKillSwitch,
		Now:               time.Now,
		Logger:            logger,
	}
}

// buildConductorBundlePoller wires the follower-side policy-bundle poller. It is
// a method so the applier closure can call s.ApplyConductorPolicyBundle, which
// owns the verify -> reload -> activate boundary. Unlike the remote-kill poller,
// the bundle poller ALWAYS builds the real trust resolver: applying a policy
// bundle mutates the running config, so it must be signature-verified regardless
// of honor_remote_kill_switch. A missing/unloadable roster fails closed here.
func (s *Server) buildConductorBundlePoller(cfg *config.Config, logWriter io.Writer) (*policysync.Poller, error) {
	if cfg == nil || !cfg.Conductor.Enabled {
		return nil, nil
	}
	cache := s.applyCache()
	client, err := newConductorMTLSClient(cfg.Conductor)
	if err != nil {
		return nil, err
	}
	resolver, err := buildConductorTrustResolver(cfg.Conductor, time.Now)
	if err != nil {
		return nil, fmt.Errorf("building conductor policy bundle trust resolver: %w", err)
	}
	interval, err := time.ParseDuration(cfg.Conductor.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("parsing conductor policy bundle poll interval: %w", err)
	}
	if logWriter == nil {
		logWriter = io.Discard
	}
	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "pipelock", "component", "conductor_policy_bundle")
	// Capture the follower's self-declared audience labels so the leader can
	// target this follower by label (e.g. ring=canary). Without this the
	// applier passes empty labels and a label-scoped bundle would never match.
	// Conductor config is restart-only, so capturing at build time is correct.
	labels := conductorFollowerLabels(cfg)
	applier := policysync.ApplierFunc(func(bundle conductor.PolicyBundle) error {
		_, applyErr := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: resolver, Labels: labels})
		return applyErr
	})
	reporter, err := newConductorPolicyStatusReporter(cfg, client, cache)
	if err != nil {
		return nil, err
	}
	// Stash the reporter so the audit producer (built in a later init phase) can
	// reuse its cache + latest-poll view as the signed applied-state provider.
	// nil reporter (no enrollment marker) leaves conductorStatusReporter nil.
	if reporter != nil {
		s.conductorStatusReporter = reporter
	}
	return policysync.NewPoller(policysync.PollerConfig{
		BaseURL:      cfg.Conductor.ConductorURL,
		Client:       client,
		Applier:      applier,
		Reporter:     reporter,
		PollInterval: interval,
		Logger:       logger,
	})
}

// initConductorBundlePoller stores the policy-bundle poller on the Server so the
// lifecycle can launch its Run loop alongside the remote-kill poller and audit
// transport. Mirrors initConductorRemoteKill.
func (s *Server) initConductorBundlePoller(cfg *config.Config, stderr io.Writer) error {
	poller, err := s.buildConductorBundlePoller(cfg, stderr)
	if err != nil {
		return err
	}
	if poller != nil {
		s.conductorBundle = poller
	}
	return nil
}

// conductorRollbackContextProvider reports the active bundle and its on-disk
// predecessor so the rollback poller can name the current->target pair to the
// leader. It walks one step back through the durable bundle history:
// Active() gives the current bundle; LookupBundle(active.BundleHash).BaseHash
// gives the predecessor's hash; LookupBundle(baseHash) gives the target bundle.
// When there is no predecessor (first bundle ever applied, empty BaseHash), it
// reports ok=false so the poller skips cleanly.
type conductorRollbackContextProvider struct {
	cache *applycache.Cache
}

func (p conductorRollbackContextProvider) RollbackContext() (current, target policysync.RollbackRef, ok bool, err error) {
	active, err := p.cache.Active()
	if err != nil {
		// No active bundle yet (ErrNoValidBundle) or a read error: nothing to roll
		// back from. Treat as "skip this tick" rather than an error so a follower
		// that has not yet applied a bundle does not log a poll error every cycle.
		if errors.Is(err, applycache.ErrNoValidBundle) {
			return policysync.RollbackRef{}, policysync.RollbackRef{}, false, nil
		}
		return policysync.RollbackRef{}, policysync.RollbackRef{}, false, err
	}
	currentLookup, err := p.cache.LookupBundle(active.BundleHash)
	if err != nil {
		return policysync.RollbackRef{}, policysync.RollbackRef{}, false, err
	}
	if currentLookup.BaseHash == "" {
		// Active bundle is the first one ever applied: no prior to roll back to.
		return policysync.RollbackRef{}, policysync.RollbackRef{}, false, nil
	}
	targetLookup, err := p.cache.LookupBundle(currentLookup.BaseHash)
	if err != nil {
		return policysync.RollbackRef{}, policysync.RollbackRef{}, false, err
	}
	if targetLookup.Bundle.Version >= active.Bundle.Version {
		// A valid rollback authorization can only move to a lower version. This
		// happens naturally after a rollback: re-staging the target records the
		// rolled-away bundle as its BaseHash, but asking the leader for
		// current=1,target=2 can never succeed. Skip locally to avoid noisy 400s.
		return policysync.RollbackRef{}, policysync.RollbackRef{}, false, nil
	}
	current = policysync.RollbackRef{BundleID: active.Bundle.BundleID, Version: active.Bundle.Version}
	target = policysync.RollbackRef{BundleID: targetLookup.Bundle.BundleID, Version: targetLookup.Bundle.Version}
	return current, target, true, nil
}

// conductorRollbackApplier drives a fetched, signed rollback authorization
// through the SAME apply boundary used for forward policy-bundle applies, under
// the SAME conductorApplyMu, so a forward-apply and a rollback-apply can never
// race. It looks up the TARGET bundle from the cache (failing closed if that
// bundle is not on disk) and calls ApplyConductorPolicyBundle with
// AllowRollback set, letting the existing authorizeVersionTransition path
// re-verify the authorization's signatures, audience, and version transition.
type conductorRollbackApplier struct {
	server   *Server
	cache    *applycache.Cache
	resolver conductor.SignatureKeyResolver
	labels   map[string]string
}

func (a conductorRollbackApplier) ApplyRollback(auth conductor.RollbackAuthorization) error {
	target, err := a.targetBundle()
	if err != nil {
		return err
	}
	_, err = a.server.ApplyConductorPolicyBundle(target, ConductorApplyOptions{
		Resolver:      a.resolver,
		Labels:        a.labels,
		Rollback:      &auth,
		AllowRollback: true,
	})
	return err
}

// targetBundle resolves the rollback TARGET: the active bundle's immediate
// on-disk predecessor, reached via the active bundle's BaseHash. A missing
// active bundle, a missing predecessor (empty BaseHash), or an unreadable target
// record all return an error so ApplyRollback fails closed rather than reloading
// nothing. The apply boundary independently re-checks that the authorization's
// TargetBundleID/TargetVersion match this bundle (authorizeVersionTransition),
// so an authorization naming a different target is rejected there, not here.
func (a conductorRollbackApplier) targetBundle() (conductor.PolicyBundle, error) {
	active, err := a.cache.Active()
	if err != nil {
		return conductor.PolicyBundle{}, err
	}
	currentLookup, err := a.cache.LookupBundle(active.BundleHash)
	if err != nil {
		return conductor.PolicyBundle{}, err
	}
	if currentLookup.BaseHash == "" {
		return conductor.PolicyBundle{}, fmt.Errorf("%w: active bundle has no prior to roll back to", applycache.ErrNoValidBundle)
	}
	targetLookup, err := a.cache.LookupBundle(currentLookup.BaseHash)
	if err != nil {
		return conductor.PolicyBundle{}, err
	}
	if targetLookup.Bundle.Version >= active.Bundle.Version {
		return conductor.PolicyBundle{}, fmt.Errorf("%w: target version must be lower than active version", conductor.ErrInvalidRollback)
	}
	return targetLookup.Bundle, nil
}

// buildConductorRollbackPoller wires the follower-side rollback poller. Like the
// bundle poller it ALWAYS builds the real trust resolver: applying a rollback
// mutates the running config, so the authorization must be signature-verified
// regardless of honor_remote_kill_switch. It reuses the shared mTLS client, base
// URL, and poll interval that the bundle and remote-kill pollers use. A
// missing/unloadable roster fails closed here.
func (s *Server) buildConductorRollbackPoller(cfg *config.Config, logWriter io.Writer) (*policysync.RollbackPoller, error) {
	if cfg == nil || !cfg.Conductor.Enabled {
		return nil, nil
	}
	cache, _ := s.conductorApply.(*applycache.Cache)
	if cache == nil {
		// conductor.enabled with no apply cache is a wiring error: the apply cache
		// is built in initConductorApplyAndAudit, which runs first. Fail closed
		// rather than launching a poller that can never read a bundle.
		return nil, applycache.ErrCacheRequired
	}
	client, err := newConductorMTLSClient(cfg.Conductor)
	if err != nil {
		return nil, err
	}
	resolver, err := buildConductorTrustResolver(cfg.Conductor, time.Now)
	if err != nil {
		return nil, fmt.Errorf("building conductor rollback trust resolver: %w", err)
	}
	interval, err := time.ParseDuration(cfg.Conductor.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("parsing conductor rollback poll interval: %w", err)
	}
	if logWriter == nil {
		logWriter = io.Discard
	}
	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "pipelock", "component", "conductor_rollback")
	return policysync.NewRollbackPoller(policysync.RollbackPollerConfig{
		BaseURL:  cfg.Conductor.ConductorURL,
		Client:   client,
		Provider: conductorRollbackContextProvider{cache: cache},
		// Pass the follower's self-declared audience labels so a label-scoped
		// rollback authorization can match this follower. Conductor config is
		// restart-only, so capturing the labels at build time is correct.
		Applier:      conductorRollbackApplier{server: s, cache: cache, resolver: resolver, labels: conductorFollowerLabels(cfg)},
		PollInterval: interval,
		Logger:       logger,
	})
}

// initConductorRollbackPoller stores the rollback poller on the Server so the
// lifecycle can launch its Run loop alongside the other conductor pollers.
// Mirrors initConductorBundlePoller. Must run after initConductorApplyAndAudit
// has opened the apply cache.
func (s *Server) initConductorRollbackPoller(cfg *config.Config, stderr io.Writer) error {
	poller, err := s.buildConductorRollbackPoller(cfg, stderr)
	if err != nil {
		return err
	}
	if poller != nil {
		s.conductorRollback = poller
	}
	return nil
}

// buildConductorStaleEnforcer wires the follower-side stale-bundle enforcer. It
// is the runtime consumer of applycache.DecideStale: a ticker re-evaluates the
// active bundle's age each poll interval and, under a strict_deny_all policy,
// engages the kill switch's conductor_stale source to fail closed when the
// bundle ages past its grace window (or cannot be read). The enforcer shares the
// follower poll interval so staleness is re-checked on the same cadence the
// poller fetches; a missing/corrupt active bundle fails closed.
func (s *Server) buildConductorStaleEnforcer(cfg *config.Config, ks *killswitch.Controller, logWriter io.Writer) (*applycache.StaleEnforcer, error) {
	if cfg == nil || !cfg.Conductor.Enabled {
		return nil, nil
	}
	cache, _ := s.conductorApply.(*applycache.Cache)
	if cache == nil {
		// conductor.enabled with no apply cache is a wiring error: the apply
		// cache is built in initConductorApplyAndAudit, which runs first. Fail
		// closed rather than launching an enforcer that can never read a bundle.
		return nil, applycache.ErrCacheRequired
	}
	interval, err := time.ParseDuration(cfg.Conductor.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("parsing conductor stale check interval: %w", err)
	}
	if logWriter == nil {
		logWriter = io.Discard
	}
	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "pipelock", "component", "conductor_stale_bundle")
	return applycache.NewStaleEnforcer(applycache.StaleEnforcerConfig{
		Cache:         cache,
		KillSwitch:    ks,
		Policy:        cfg.Conductor.StalePolicy,
		CheckInterval: interval,
		Now:           time.Now,
		Logger:        logger,
	})
}

// initConductorStaleEnforcer stores the stale enforcer on the Server so the
// lifecycle can launch its Run loop alongside the other conductor pollers.
// Mirrors initConductorBundlePoller. Must run after s.killswitch is set and
// after initConductorApplyAndAudit has opened the apply cache.
func (s *Server) initConductorStaleEnforcer(cfg *config.Config, ks *killswitch.Controller, stderr io.Writer) error {
	enforcer, err := s.buildConductorStaleEnforcer(cfg, ks, stderr)
	if err != nil {
		return err
	}
	if enforcer != nil {
		s.conductorStale = enforcer
		// Record whether the stale policy is strict_deny_all so teardownConductor
		// can fail closed when the enforcer is cancelled on entitlement loss. Set
		// only alongside a live enforcer (conductor enabled), so a disabled or
		// continue_last_known_good follower never engages stale-deny at teardown.
		if cfg.Conductor.StalePolicy.AfterGrace == config.ConductorStaleStrictDenyAll {
			s.conductorStaleStrictDeny.Store(true)
		}
	}
	return nil
}

func buildConductorTrustResolver(cfg config.Conductor, now func() time.Time) (conductor.SignatureKeyResolver, error) {
	if now == nil {
		now = time.Now
	}
	roster, err := signing.LoadRoster(cfg.TrustRosterPath, cfg.TrustRosterRootFingerprint)
	if err != nil {
		return nil, fmt.Errorf("loading conductor trust roster: %w", err)
	}
	return func(signerKeyID string) (conductor.SignatureKey, error) {
		key, err := roster.ResolveKey(signerKeyID, now().UTC())
		if err != nil {
			return conductor.SignatureKey{}, fmt.Errorf("%w: %w", conductor.ErrSignatureVerification, err)
		}
		pub, err := hex.DecodeString(key.PublicKeyHex)
		if err != nil {
			return conductor.SignatureKey{}, fmt.Errorf("%w: public_key_hex: %w", conductor.ErrSignatureVerification, err)
		}
		notBefore, err := time.Parse(time.RFC3339, key.ValidFrom)
		if err != nil {
			return conductor.SignatureKey{}, fmt.Errorf("%w: valid_from: %w", conductor.ErrSignatureVerification, err)
		}
		var notAfter time.Time
		if key.ValidUntil != nil {
			notAfter, err = time.Parse(time.RFC3339, *key.ValidUntil)
			if err != nil {
				return conductor.SignatureKey{}, fmt.Errorf("%w: valid_until: %w", conductor.ErrSignatureVerification, err)
			}
		}
		return conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.KeyPurpose(key.KeyPurpose),
			NotBefore:  notBefore,
			NotAfter:   notAfter,
		}, nil
	}, nil
}

func newConductorMTLSClient(cfg config.Conductor) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Clean(cfg.ClientCertPath), filepath.Clean(cfg.ClientKeyPath))
	if err != nil {
		return nil, fmt.Errorf("loading conductor mTLS client certificate: %w", err)
	}
	roots, err := loadConductorServerCAs(cfg.ServerCAFile)
	if err != nil {
		return nil, err
	}
	serverName, err := conductorServerName(cfg.ConductorURL)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: conductorHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{cert},
				RootCAs:      roots,
				ServerName:   serverName,
			},
			TLSHandshakeTimeout:    conductorTLSHandshakeTimeout,
			ResponseHeaderTimeout:  conductorResponseHeaderTimeout,
			IdleConnTimeout:        conductorIdleConnTimeout,
			ExpectContinueTimeout:  conductorExpectContinueTimeout,
			MaxResponseHeaderBytes: conductorMaxResponseHeaderBytes,
			ForceAttemptHTTP2:      true,
		},
	}, nil
}

// loadConductorServerCAs reads a PEM bundle and returns it as the only set of
// roots that may validate the Boss server certificate. Mixing the system trust
// store would let any public CA mint a MITM cert for the Boss host; the whole
// point of a pinned roster is to keep that surface closed.
func loadConductorServerCAs(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("loading conductor server CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("conductor server CA bundle did not contain any PEM-encoded certificates")
	}
	return pool, nil
}

func conductorServerName(rawBaseURL string) (string, error) {
	u, err := url.Parse(rawBaseURL)
	if err != nil {
		return "", fmt.Errorf("parsing conductor base URL for ServerName: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("conductor base URL is missing a host for TLS ServerName")
	}
	// Normalize bracketed IPv6 literals: Hostname() already strips brackets and
	// the port. net.SplitHostPort would only matter if a port slipped through
	// without scheme; guard anyway.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host, nil
}

// initConductorApplyAndAudit builds the apply cache and audit queue/transport
// for the follower-side Conductor runtime. Stores opaque handles on the
// Server so the producer setup that runs after the flight recorder is
// constructed can pick them up without re-importing enterprise packages
// into server.go.
func (s *Server) initConductorApplyAndAudit(cfg *config.Config, m *metrics.Metrics) error {
	cache, err := buildConductorApplyCache(cfg)
	if err != nil {
		return err
	}
	if cache != nil {
		s.conductorApply = cache
	}
	queue, transport, err := buildConductorAuditTransport(cfg, m)
	if err != nil {
		return err
	}
	if queue != nil {
		s.conductorAuditQueue = queue
	}
	if transport != nil {
		s.conductorAudit = transport
	}
	return nil
}

// initConductorRemoteKill wires the remote kill poller into the kill switch
// controller. Separated from initConductorApplyAndAudit because the kill
// switch is constructed between the two conductor setup phases.
func (s *Server) initConductorRemoteKill(cfg *config.Config, ks *killswitch.Controller, stderr io.Writer) error {
	poller, err := buildConductorRemoteKillPoller(cfg, ks, stderr)
	if err != nil {
		return err
	}
	if poller != nil {
		s.conductorRemoteKill = poller
	}
	return nil
}

// initConductorProducer connects the durable audit queue to the flight
// recorder via the audit producer. Runs only when initConductorApplyAndAudit
// previously opened a queue (i.e. conductor.enabled is true).
func (s *Server) initConductorProducer(cfg *config.Config, m *metrics.Metrics, recPrivKey ed25519.PrivateKey, stderr io.Writer) error {
	queue, _ := s.conductorAuditQueue.(*auditbatcher.Queue)
	if queue == nil {
		return nil
	}
	if s.recorder == nil {
		return errors.New("conductor audit producer requires flight recorder")
	}
	recPubKey, err := conductorRecorderPublicKey(recPrivKey)
	if err != nil {
		return err
	}
	// The flight-recorder signing key doubles as the audit-batch signer.
	// Reuse is safe because the two signing schemes operate on disjoint
	// byte sets: the recorder signs a bare 64-char hex chain hash, while
	// the audit batch signs canonical JSON (`{...}`). No recorder signature
	// can be replayed as a valid audit-batch signature or vice versa. Key
	// ids stay separate (audit_signing_key_id vs recorder_key_id) so the
	// sink-side roster can distinguish purpose.
	// Gate signed applied-state emission on a capability handshake: only emit
	// when the conductor advertises audit-envelope schema v2. Best-effort and
	// fail-safe — any handshake failure (or an old v1 conductor) leaves it off,
	// so batches still flow without applied-state and stay v1-wire-compatible.
	emitApplied := false
	var appliedProvider func() (conductor.FollowerAppliedState, bool)
	if reporter, ok := s.conductorStatusReporter.(*conductorPolicyStatusReporter); ok && reporter != nil {
		appliedProvider = reporter.appliedStateProvider()
		emitApplied = conductorNegotiateEmitAppliedState(cfg.Conductor, stderr)
	}
	producer, err := auditbatcher.NewProducer(auditbatcher.ProducerConfig{
		Queue:                queue,
		Metrics:              m,
		OrgID:                cfg.Conductor.OrgID,
		FleetID:              cfg.Conductor.FleetID,
		InstanceID:           cfg.Conductor.InstanceID,
		AuditSignerKeyID:     cfg.Conductor.AuditSigningKeyID,
		RecorderKeyID:        cfg.Conductor.RecorderKeyID,
		AuditSigner:          recPrivKey,
		RecorderPublicKey:    recPubKey,
		EmitAppliedState:     emitApplied,
		AppliedStateProvider: appliedProvider,
	})
	if err != nil {
		return fmt.Errorf("creating conductor audit producer: %w", err)
	}
	s.conductorProducer = producer
	s.recorder.SetObserver(producer)
	_, _ = fmt.Fprintf(stderr, "  Conductor: audit producer enabled\n")
	return nil
}

func conductorRecorderPublicKey(priv ed25519.PrivateKey) (ed25519.PublicKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("conductor audit producer requires flight recorder signing key")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("conductor audit producer requires recorder public key")
	}
	return pub, nil
}

// conductorNegotiateEmitAppliedState performs a best-effort capabilities
// handshake and reports whether the conductor accepts audit-envelope schema v2
// (and therefore the signed applied-state field). It fails safe: any error, or
// an older v1-only conductor, returns false so the producer omits applied-state
// and its batches stay byte-identical to v1 past the conductor's strict
// unknown-field decoder.
func conductorNegotiateEmitAppliedState(cfg config.Conductor, stderr io.Writer) bool {
	client, err := newConductorMTLSClient(cfg)
	if err != nil {
		return false
	}
	capClient, err := conductor.NewCapabilitiesClient(cfg.ConductorURL, client, conductor.LocalFollowerCapabilities{})
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), conductorAppliedStateHandshakeTimeout)
	defer cancel()
	negotiated, err := capClient.Handshake(ctx)
	if err != nil {
		if stderr != nil {
			_, _ = fmt.Fprintf(stderr, "  Conductor: applied-state schema negotiation unavailable (%v); omitting signed applied-state\n", err)
		}
		return false
	}
	return negotiated.AuditSchemaVersion >= conductor.AuditEnvelopeSchemaVersion
}
