// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
	"github.com/luckyPipewrench/pipelock/internal/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
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
