//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
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
	cache, _ := s.conductorApply.(*applycache.Cache)
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
		Reload:       s.Reload,
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
	applier := &emergency.RemoteKillApplier{
		OrgID:             cfg.Conductor.OrgID,
		FleetID:           cfg.Conductor.FleetID,
		InstanceID:        cfg.Conductor.InstanceID,
		Resolver:          resolver,
		KillSwitch:        ks,
		StatePath:         filepath.Join(cfg.Conductor.BundleCacheDir, emergency.RemoteKillStateFileName),
		DisableRemoteKill: !cfg.Conductor.HonorRemoteKillSwitch,
		Now:               time.Now,
		Logger:            logger,
	}
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
	applier := policysync.ApplierFunc(func(bundle conductor.PolicyBundle) error {
		_, applyErr := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: resolver})
		return applyErr
	})
	return policysync.NewPoller(policysync.PollerConfig{
		BaseURL:      cfg.Conductor.ConductorURL,
		Client:       client,
		Applier:      applier,
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
	producer, err := auditbatcher.NewProducer(auditbatcher.ProducerConfig{
		Queue:             queue,
		Metrics:           m,
		OrgID:             cfg.Conductor.OrgID,
		FleetID:           cfg.Conductor.FleetID,
		InstanceID:        cfg.Conductor.InstanceID,
		AuditSignerKeyID:  cfg.Conductor.AuditSigningKeyID,
		RecorderKeyID:     cfg.Conductor.RecorderKeyID,
		AuditSigner:       recPrivKey,
		RecorderPublicKey: recPubKey,
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
