//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

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
	"strconv"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

const (
	// RollbackAuthorizationsPath mirrors the leader-side route registered by the
	// control plane. Like LatestPolicyBundlePath it is duplicated rather than
	// imported to keep the follower-side poller free of a compile-time dependency
	// on the controlplane package.
	RollbackAuthorizationsPath = "/api/v1/conductor/rollback-authorizations"

	// defaultRollbackResponseBytes caps the rollback-authorization response body.
	// A RollbackAuthorization is small metadata plus signatures; 64 KiB matches
	// the remote-kill poller's cap and bounds memory against a hostile leader.
	defaultRollbackResponseBytes = 64 * 1024

	rollbackPollerUserAgent  = "pipelock-conductor-rollback-sync/1.0"
	rollbackPollerAcceptedCT = "application/json"

	rollbackQueryCurrentVersion  = "current_version"
	rollbackQueryTargetVersion   = "target_version"
	rollbackQueryCurrentBundleID = "current_bundle_id"
	rollbackQueryTargetBundleID  = "target_bundle_id"
)

var (
	ErrRollbackPollerRequired = errors.New("conductor rollback poller required")
	ErrRollbackPollResponse   = errors.New("invalid conductor rollback poll response")
)

// RollbackRef names one bundle the follower currently holds on disk: its bundle
// id and monotonic version. The poller reports the active bundle (current) and
// its on-disk predecessor (target) so the leader can locate the matching
// authorization.
type RollbackRef struct {
	BundleID string
	Version  uint64
}

// RollbackContextProvider supplies the current/target bundle pair the follower
// would roll back between. ok=false means there is nothing to roll back to (no
// prior bundle on disk); the poller then skips the tick cleanly rather than
// querying the leader. A non-nil err means the cache could not be read and the
// poll is retried on the next interval.
type RollbackContextProvider interface {
	RollbackContext() (current, target RollbackRef, ok bool, err error)
}

// RollbackApplier applies a fetched, signed rollback authorization. It looks up
// the target bundle in the cache and drives it through the apply boundary, which
// re-verifies the authorization's signatures, audience, and version transition.
// A rejected authorization (bad signature, audience mismatch, missing target
// bundle, reload failure) returns an error; the poller leaves the running config
// untouched and retries on the next interval.
type RollbackApplier interface {
	ApplyRollback(conductor.RollbackAuthorization) error
}

type RollbackPollerConfig struct {
	BaseURL          string
	Client           HTTPDoer
	Provider         RollbackContextProvider
	Applier          RollbackApplier
	PollInterval     time.Duration
	MaxResponseBytes int64
	Logger           *slog.Logger
}

type RollbackPoller struct {
	client           HTTPDoer
	provider         RollbackContextProvider
	applier          RollbackApplier
	baseEndpoint     string
	pollInterval     time.Duration
	maxResponseBytes int64
	logger           *slog.Logger
}

func NewRollbackPoller(cfg RollbackPollerConfig) (*RollbackPoller, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("%w: HTTP client", ErrRollbackPollerRequired)
	}
	if cfg.Provider == nil {
		return nil, fmt.Errorf("%w: context provider", ErrRollbackPollerRequired)
	}
	if cfg.Applier == nil {
		return nil, fmt.Errorf("%w: applier", ErrRollbackPollerRequired)
	}
	endpoint, err := rollbackEndpoint(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	interval := cfg.PollInterval
	if interval == 0 {
		interval = defaultPollInterval
	}
	if interval < time.Second {
		return nil, fmt.Errorf("conductor rollback poll interval must be >= 1s, got %s", interval)
	}
	maxBytes := cfg.MaxResponseBytes
	if maxBytes == 0 {
		maxBytes = defaultRollbackResponseBytes
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("conductor rollback max response bytes must be > 0, got %d", maxBytes)
	}
	return &RollbackPoller{
		client:           cfg.Client,
		provider:         cfg.Provider,
		applier:          cfg.Applier,
		baseEndpoint:     endpoint,
		pollInterval:     interval,
		maxResponseBytes: maxBytes,
		logger:           cfg.Logger,
	}, nil
}

func (p *RollbackPoller) Run(ctx context.Context) error {
	if p == nil {
		return ErrRollbackPollerRequired
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

func (p *RollbackPoller) PollOnce(ctx context.Context) error {
	if p == nil {
		return ErrRollbackPollerRequired
	}
	current, target, ok, err := p.provider.RollbackContext()
	if err != nil {
		return fmt.Errorf("resolve conductor rollback context: %w", err)
	}
	if !ok {
		// No prior bundle on disk: there is nothing to roll back to. Skip the tick
		// cleanly rather than querying the leader with an undefined target.
		return nil
	}
	endpoint := p.endpointFor(current, target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("create conductor rollback poll request: %w", err)
	}
	req.Header.Set("Accept", rollbackPollerAcceptedCT)
	req.Header.Set("User-Agent", rollbackPollerUserAgent)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("poll conductor rollback authorization: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNoContent:
		// No matching authorization published for this current->target pair.
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("%w: status=%d", ErrRollbackPollResponse, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, p.maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read conductor rollback response: %w", err)
	}
	if int64(len(body)) > p.maxResponseBytes {
		return fmt.Errorf("%w: body exceeds %d bytes", ErrRollbackPollResponse, p.maxResponseBytes)
	}
	var auth conductor.RollbackAuthorization
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&auth); err != nil {
		return fmt.Errorf("%w: decode: %w", ErrRollbackPollResponse, err)
	}
	if err := jsonscan.RejectDuplicateKeys(body); err != nil {
		return fmt.Errorf("%w: ambiguous response: %w", ErrRollbackPollResponse, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON document", ErrRollbackPollResponse)
	}
	if err := p.applier.ApplyRollback(auth); err != nil {
		return fmt.Errorf("apply conductor rollback authorization: %w", err)
	}
	return nil
}

// endpointFor appends the four required lookup query params to the base
// endpoint. The leader rejects a request missing any of them, and the apply
// boundary independently re-checks the authorization's bundle ids/versions, so
// these params are a routing hint, not a trust boundary.
func (p *RollbackPoller) endpointFor(current, target RollbackRef) string {
	q := url.Values{}
	q.Set(rollbackQueryCurrentVersion, strconv.FormatUint(current.Version, 10))
	q.Set(rollbackQueryTargetVersion, strconv.FormatUint(target.Version, 10))
	q.Set(rollbackQueryCurrentBundleID, current.BundleID)
	q.Set(rollbackQueryTargetBundleID, target.BundleID)
	return p.baseEndpoint + "?" + q.Encode()
}

func (p *RollbackPoller) logPollError(err error) {
	if p.logger == nil {
		return
	}
	p.logger.Warn("conductor_rollback_poll_error",
		slog.String("event", "conductor_rollback_poll_error"),
		slog.String("error", err.Error()),
	)
}

func rollbackEndpoint(rawBaseURL string) (string, error) {
	u, err := url.Parse(rawBaseURL)
	if err != nil {
		return "", fmt.Errorf("parse conductor rollback base URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("conductor rollback base URL must be https with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("conductor rollback base URL must not include userinfo, query, or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("conductor rollback base URL must not include a path component")
	}
	u.Path = RollbackAuthorizationsPath
	u.RawPath = ""
	return u.String(), nil
}
