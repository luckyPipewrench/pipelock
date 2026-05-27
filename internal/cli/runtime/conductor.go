// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
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
	"reflect"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/conductor"
	"github.com/luckyPipewrench/pipelock/internal/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/internal/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/internal/conductor/emergency"
	"github.com/luckyPipewrench/pipelock/internal/config"
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
	if s.conductorApply == nil {
		return applycache.AppliedBundle{}, applycache.ErrCacheRequired
	}
	// Serialize the whole stage -> reload -> activate sequence: the durable
	// last-known-good pointer must never diverge from the running config.
	s.conductorApplyMu.Lock()
	defer s.conductorApplyMu.Unlock()
	cfg := s.currentConfig()
	if cfg == nil && s.proxy != nil {
		cfg = s.proxy.CurrentConfig()
	}
	if cfg == nil {
		return applycache.AppliedBundle{}, errors.New("runtime config unavailable")
	}
	boundary := applycache.Boundary{
		Cache: s.conductorApply,
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

func conductorRuntimeChanged(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}
	return !reflect.DeepEqual(oldCfg.Conductor, newCfg.Conductor)
}
