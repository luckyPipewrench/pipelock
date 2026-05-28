//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package emergency

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
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

const (
	RemoteKillPath                 = "/api/v1/conductor/remote-kill"
	defaultRemoteKillPollInterval  = 30 * time.Second
	defaultRemoteKillResponseBytes = 64 * 1024
	remoteKillPollerUserAgent      = "pipelock-conductor-remote-kill/1.0"
	remoteKillPollerAcceptedCT     = "application/json"
)

var (
	ErrRemoteKillPollerRequired = errors.New("conductor remote kill poller required")
	ErrRemoteKillPollResponse   = errors.New("invalid conductor remote kill poll response")
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type RemoteKillPollerConfig struct {
	BaseURL          string
	Client           HTTPDoer
	Applier          *RemoteKillApplier
	PollInterval     time.Duration
	MaxResponseBytes int64
	Logger           *slog.Logger
}

type RemoteKillPoller struct {
	client           HTTPDoer
	applier          *RemoteKillApplier
	endpoint         string
	pollInterval     time.Duration
	maxResponseBytes int64
	logger           *slog.Logger
}

func NewRemoteKillPoller(cfg RemoteKillPollerConfig) (*RemoteKillPoller, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("%w: HTTP client", ErrRemoteKillPollerRequired)
	}
	if cfg.Applier == nil {
		return nil, fmt.Errorf("%w: applier", ErrRemoteKillPollerRequired)
	}
	endpoint, err := remoteKillEndpoint(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	interval := cfg.PollInterval
	if interval == 0 {
		interval = defaultRemoteKillPollInterval
	}
	if interval < time.Second {
		return nil, fmt.Errorf("conductor remote kill poll interval must be >= 1s, got %s", interval)
	}
	maxBytes := cfg.MaxResponseBytes
	if maxBytes == 0 {
		maxBytes = defaultRemoteKillResponseBytes
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("conductor remote kill max response bytes must be > 0, got %d", maxBytes)
	}
	return &RemoteKillPoller{
		client:           cfg.Client,
		applier:          cfg.Applier,
		endpoint:         endpoint,
		pollInterval:     interval,
		maxResponseBytes: maxBytes,
		logger:           cfg.Logger,
	}, nil
}

func (p *RemoteKillPoller) Run(ctx context.Context) error {
	if p == nil {
		return ErrRemoteKillPollerRequired
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

func (p *RemoteKillPoller) PollOnce(ctx context.Context) error {
	if p == nil {
		return ErrRemoteKillPollerRequired
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint, nil)
	if err != nil {
		return fmt.Errorf("create conductor remote kill poll request: %w", err)
	}
	req.Header.Set("Accept", remoteKillPollerAcceptedCT)
	req.Header.Set("User-Agent", remoteKillPollerUserAgent)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("poll conductor remote kill: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("%w: status=%d", ErrRemoteKillPollResponse, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, p.maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read conductor remote kill response: %w", err)
	}
	if int64(len(body)) > p.maxResponseBytes {
		return fmt.Errorf("%w: body exceeds %d bytes", ErrRemoteKillPollResponse, p.maxResponseBytes)
	}
	var msg conductor.RemoteKillMessage
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&msg); err != nil {
		return fmt.Errorf("%w: decode: %w", ErrRemoteKillPollResponse, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON document", ErrRemoteKillPollResponse)
	}
	return p.applier.Apply(msg)
}

func (p *RemoteKillPoller) logPollError(err error) {
	if p.logger == nil {
		return
	}
	p.logger.Warn("conductor_remote_kill_poll_error",
		slog.String("event", "conductor_remote_kill_poll_error"),
		slog.String("error", err.Error()),
	)
}

func remoteKillEndpoint(rawBaseURL string) (string, error) {
	u, err := url.Parse(rawBaseURL)
	if err != nil {
		return "", fmt.Errorf("parse conductor remote kill base URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("conductor remote kill base URL must be https with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("conductor remote kill base URL must not include userinfo, query, or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("conductor remote kill base URL must not include a path component")
	}
	u.Path = RemoteKillPath
	u.RawPath = ""
	return u.String(), nil
}
