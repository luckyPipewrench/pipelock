//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package policysync polls a Conductor leader for the latest signed policy
// bundle scoped to this follower and applies it through the apply boundary.
//
// It mirrors the remote-kill poller (enterprise/conductor/emergency): a single
// goroutine ticks on an interval, issues a GET against the leader over the
// shared mTLS client, and hands the decoded message to an applier. The applier
// here is the follower's policy-bundle apply boundary, which verifies the
// bundle signature, enforces monotonic versioning, and triggers a config
// reload. A rejected bundle leaves the running config untouched (fail closed)
// and is retried on the next interval.
package policysync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

const (
	// LatestPolicyBundlePath mirrors controlplane.LatestPolicyBundlePath. It is
	// duplicated rather than imported to keep the follower-side poller free of a
	// compile-time dependency on the leader-side controlplane package.
	LatestPolicyBundlePath = "/api/v1/conductor/policy/latest"

	defaultPollInterval = 30 * time.Second
	// defaultResponseBytes caps the policy-bundle response body. A bundle wraps
	// a config payload (conductor.MaxConfigYAMLBytes = 256 KiB) plus metadata,
	// signatures, and rule-bundle refs; 1 MiB leaves generous headroom while
	// bounding memory against a hostile or misbehaving leader.
	defaultResponseBytes = 1 << 20

	pollerUserAgent  = "pipelock-conductor-policy-sync/1.0"
	pollerAcceptedCT = "application/json"
)

var (
	ErrPollerRequired = errors.New("conductor policy sync poller required")
	ErrPollResponse   = errors.New("invalid conductor policy bundle poll response")
)

// HTTPDoer is the subset of *http.Client the poller needs. The runtime supplies
// the shared mTLS client; tests supply a stub.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Applier applies a fetched policy bundle and returns an error if the bundle is
// rejected (bad signature, audience mismatch, version regression, reload
// failure). On error the poller leaves the running config untouched and retries
// on the next interval.
type Applier interface {
	ApplyPolicyBundle(conductor.PolicyBundle) error
}

// ApplierFunc adapts a plain function to the Applier interface.
type ApplierFunc func(conductor.PolicyBundle) error

func (f ApplierFunc) ApplyPolicyBundle(b conductor.PolicyBundle) error { return f(b) }

type StatusEvent struct {
	PollAt        time.Time
	AppliedBundle *conductor.PolicyBundle
	ApplyError    error
}

type StatusReporter interface {
	ReportPolicyStatus(context.Context, StatusEvent) error
}

type PollerConfig struct {
	BaseURL          string
	Client           HTTPDoer
	Applier          Applier
	Reporter         StatusReporter
	PollInterval     time.Duration
	MaxResponseBytes int64
	Logger           *slog.Logger
}

type Poller struct {
	client           HTTPDoer
	applier          Applier
	endpoint         string
	pollInterval     time.Duration
	maxResponseBytes int64
	logger           *slog.Logger
	reporter         StatusReporter

	// mu guards lastETag. Run drives PollOnce from a single goroutine, but
	// PollOnce is exported and may be called concurrently by tests, so the
	// validator cache is mutex-guarded to stay race-clean.
	mu       sync.Mutex
	lastETag string
}

func NewPoller(cfg PollerConfig) (*Poller, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("%w: HTTP client", ErrPollerRequired)
	}
	if cfg.Applier == nil {
		return nil, fmt.Errorf("%w: applier", ErrPollerRequired)
	}
	endpoint, err := policyEndpoint(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	interval := cfg.PollInterval
	if interval == 0 {
		interval = defaultPollInterval
	}
	if interval < time.Second {
		return nil, fmt.Errorf("conductor policy bundle poll interval must be >= 1s, got %s", interval)
	}
	maxBytes := cfg.MaxResponseBytes
	if maxBytes == 0 {
		maxBytes = defaultResponseBytes
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("conductor policy bundle max response bytes must be > 0, got %d", maxBytes)
	}
	return &Poller{
		client:           cfg.Client,
		applier:          cfg.Applier,
		endpoint:         endpoint,
		pollInterval:     interval,
		maxResponseBytes: maxBytes,
		logger:           cfg.Logger,
		reporter:         cfg.Reporter,
	}, nil
}

func (p *Poller) Run(ctx context.Context) error {
	if p == nil {
		return ErrPollerRequired
	}
	for {
		if err := p.PollOnce(ctx); err != nil {
			if errors.Is(err, context.Canceled) || (errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil) {
				return err
			}
			p.logPollError(err)
		}
		timer := time.NewTimer(p.pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (p *Poller) PollOnce(ctx context.Context) error {
	if p == nil {
		return ErrPollerRequired
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint, nil)
	if err != nil {
		return fmt.Errorf("create conductor policy bundle poll request: %w", err)
	}
	req.Header.Set("Accept", pollerAcceptedCT)
	req.Header.Set("User-Agent", pollerUserAgent)
	p.mu.Lock()
	etag := p.lastETag
	p.mu.Unlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("poll conductor policy bundle: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified, http.StatusNoContent:
		// 304: follower already holds the latest. 204: no bundle published for
		// this follower's scope. Either way there is nothing to apply.
		p.reportStatus(ctx, StatusEvent{PollAt: time.Now().UTC()})
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("%w: status=%d", ErrPollResponse, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, p.maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read conductor policy bundle response: %w", err)
	}
	if int64(len(body)) > p.maxResponseBytes {
		return fmt.Errorf("%w: body exceeds %d bytes", ErrPollResponse, p.maxResponseBytes)
	}
	var bundle conductor.PolicyBundle
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return fmt.Errorf("%w: decode: %w", ErrPollResponse, err)
	}
	if err := jsonscan.RejectDuplicateKeys(body); err != nil {
		return fmt.Errorf("%w: ambiguous response: %w", ErrPollResponse, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON document", ErrPollResponse)
	}
	if err := p.applier.ApplyPolicyBundle(bundle); err != nil {
		wrapped := fmt.Errorf("apply conductor policy bundle: %w", err)
		p.reportStatus(ctx, StatusEvent{PollAt: time.Now().UTC(), ApplyError: wrapped})
		return wrapped
	}
	p.reportStatus(ctx, StatusEvent{PollAt: time.Now().UTC(), AppliedBundle: &bundle})
	// Advance the cached validator only after a successful apply, so a transient
	// apply failure is retried on the next poll rather than being masked by a
	// 304 (the leader would otherwise short-circuit the follower's recovery).
	p.mu.Lock()
	p.lastETag = resp.Header.Get("ETag")
	p.mu.Unlock()
	return nil
}

func (p *Poller) reportStatus(ctx context.Context, ev StatusEvent) {
	if p.reporter == nil {
		return
	}
	if err := p.reporter.ReportPolicyStatus(ctx, ev); err != nil && p.logger != nil {
		p.logger.Warn("conductor_policy_status_report_error",
			slog.String("event", "conductor_policy_status_report_error"),
			slog.String("error", err.Error()),
		)
	}
}

func (p *Poller) logPollError(err error) {
	if p.logger == nil {
		return
	}
	p.logger.Warn("conductor_policy_bundle_poll_error",
		slog.String("event", "conductor_policy_bundle_poll_error"),
		slog.String("error", err.Error()),
	)
}

func policyEndpoint(rawBaseURL string) (string, error) {
	u, err := url.Parse(rawBaseURL)
	if err != nil {
		return "", fmt.Errorf("parse conductor policy bundle base URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("conductor policy bundle base URL must be https with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("conductor policy bundle base URL must not include userinfo, query, or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("conductor policy bundle base URL must not include a path component")
	}
	u.Path = LatestPolicyBundlePath
	u.RawPath = ""
	return u.String(), nil
}
