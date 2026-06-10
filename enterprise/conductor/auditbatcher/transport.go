//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

const (
	AuditBatchesPath         = conductor.AuditBatchesPath
	defaultTransportDelay    = time.Second
	maxTransportErrorSnippet = 1024

	// defaultMaxDeliveryAttempts caps how many times a single audit batch may
	// be attempted before it is dead-lettered instead of released for another
	// retry. Without a ceiling a permanently-failing (e.g. 5xx) poison batch
	// sits at the FIFO head forever and starves every batch behind it. The
	// dead-letter is a durable, operator-inspectable quarantine - never a
	// silent discard - so audit loss is surfaced via queue_dead + the
	// max_retries drop reason. Operator knob deferred: this ships as a default
	// constant; TransportConfig.MaxDeliveryAttempts allows runtime override
	// without yet wiring a YAML config field.
	defaultMaxDeliveryAttempts = 10
)

const (
	deliveryOutcomeSuccess = "success"
	deliveryOutcomeRetry   = "retry"
	deliveryOutcomeDrop    = "drop"

	deliveryReasonNetwork     = "network_error"
	deliveryReasonClientError = "http_client_error"
	deliveryReasonRateLimited = "http_rate_limited"
	deliveryReasonServerError = "http_server_error"

	// dropReasonMaxRetries stamps a batch that exhausted the delivery-attempt
	// ceiling. It is the only drop reason produced from the otherwise-retryable
	// path; all other drops come from terminal 4xx/marshal/request errors.
	dropReasonMaxRetries = "max_retries"
)

// HTTPDoer is the narrow boundary between the durable queue and Conductor.
// Runtime wiring must pass a dedicated mTLS-capable client; this package never
// constructs or falls back to a default network client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// MetricsSink records transport observability without coupling this package to
// the Prometheus implementation.
type MetricsSink interface {
	RecordConductorAuditQueue(stats Stats)
	RecordConductorAuditDelivery(outcome, reason string)
}

type TransportConfig struct {
	BaseURL    string
	Client     HTTPDoer
	Queue      *Queue
	Metrics    MetricsSink
	RetryDelay time.Duration
	EmptyDelay time.Duration
	// MaxDeliveryAttempts caps total delivery attempts per batch before
	// dead-lettering. <= 0 uses defaultMaxDeliveryAttempts.
	MaxDeliveryAttempts int
}

type Transport struct {
	endpoint    string
	client      HTTPDoer
	queue       *Queue
	metrics     MetricsSink
	retryDelay  time.Duration
	emptyDelay  time.Duration
	maxAttempts uint64
}

type batchUpload struct {
	Envelope conductor.AuditBatchEnvelope `json:"envelope"`
	Payload  []byte                       `json:"payload"`
}

type deliveryResult struct {
	outcome string
	reason  string
	err     error
}

func NewTransport(cfg TransportConfig) (*Transport, error) {
	if cfg.Queue == nil {
		return nil, errors.New("auditbatcher: transport queue required")
	}
	if cfg.Client == nil {
		return nil, errors.New("auditbatcher: transport http client required")
	}
	endpoint, err := auditEndpoint(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = defaultTransportDelay
	}
	if cfg.EmptyDelay <= 0 {
		cfg.EmptyDelay = defaultTransportDelay
	}
	maxAttempts := uint64(defaultMaxDeliveryAttempts)
	if cfg.MaxDeliveryAttempts > 0 {
		maxAttempts = uint64(cfg.MaxDeliveryAttempts)
	}
	return &Transport{
		endpoint:    endpoint,
		client:      cfg.Client,
		queue:       cfg.Queue,
		metrics:     cfg.Metrics,
		retryDelay:  cfg.RetryDelay,
		emptyDelay:  cfg.EmptyDelay,
		maxAttempts: maxAttempts,
	}, nil
}

// Run drains queued audit batches until ctx is cancelled. Delivery is
// fail-closed with respect to durability: retryable failures are released back
// to pending, terminal failures are dead-lettered, and network errors never
// delete a queue record.
func (t *Transport) Run(ctx context.Context) error {
	if t == nil {
		return errors.New("auditbatcher: nil transport")
	}
	if ctx == nil {
		return errors.New("auditbatcher: nil context")
	}
	for {
		err := t.DeliverOnce(ctx)
		switch {
		case err == nil:
			continue
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return err
		case errors.Is(err, ErrQueueEmpty):
			if !t.sleep(ctx, t.emptyDelay) {
				return ctx.Err()
			}
		default:
			if !t.sleep(ctx, t.retryDelay) {
				return ctx.Err()
			}
		}
	}
}

func (t *Transport) DeliverOnce(ctx context.Context) error {
	if t == nil {
		return errors.New("auditbatcher: nil transport")
	}
	if ctx == nil {
		return errors.New("auditbatcher: nil context")
	}
	lease, err := t.queue.Claim()
	if err != nil {
		if errors.Is(err, ErrQueueEmpty) {
			t.recordQueue()
		}
		return err
	}

	result := t.send(ctx, lease.Batch)
	switch result.outcome {
	case deliveryOutcomeSuccess:
		if err := t.queue.Ack(lease.ID); err != nil {
			return err
		}
	case deliveryOutcomeRetry:
		// The attempt that just failed is attempt number RetryCount+1. Once
		// that number reaches the ceiling the batch is exhausted: escalate to
		// the dead-letter directory instead of releasing it for another retry,
		// so a permanently-failing poison batch cannot starve the FIFO head.
		// Compare without RetryCount+1 to avoid overflow if a corrupt on-disk
		// record carries retry_count=MaxUint64. ctx cancellation is not a
		// delivery failure - never burn an attempt on shutdown, always release
		// so the record survives.
		if ctx.Err() != nil {
			if err := t.queue.Release(lease.ID); err != nil {
				return err
			}
			break
		}
		if t.maxAttempts > 0 && lease.RetryCount >= t.maxAttempts-1 {
			attempts := lease.RetryCount
			if attempts < ^uint64(0) {
				attempts++
			}
			result = deliveryResult{
				outcome: deliveryOutcomeDrop,
				reason:  dropReasonMaxRetries,
				err:     fmt.Errorf("auditbatcher: dropping batch after %d delivery attempts: %w", attempts, result.err),
			}
			if err := t.queue.Drop(lease.ID, result.reason); err != nil {
				return err
			}
			break
		}
		if err := t.queue.ReleaseWithRetry(lease.ID, result.reason); err != nil {
			return err
		}
	case deliveryOutcomeDrop:
		if err := t.queue.Drop(lease.ID, result.reason); err != nil {
			return err
		}
	default:
		return fmt.Errorf("auditbatcher: unknown delivery outcome %q", result.outcome)
	}
	t.recordDelivery(result.outcome, result.reason)
	t.recordQueue()
	return result.err
}

func (t *Transport) send(ctx context.Context, batch Batch) deliveryResult {
	body, err := json.Marshal(batchUpload(batch))
	if err != nil {
		return deliveryResult{outcome: deliveryOutcomeDrop, reason: "marshal_error", err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return deliveryResult{outcome: deliveryOutcomeDrop, reason: "request_error", err: err}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return deliveryResult{outcome: deliveryOutcomeRetry, reason: deliveryReasonNetwork, err: ctx.Err()}
		}
		return deliveryResult{outcome: deliveryOutcomeRetry, reason: deliveryReasonNetwork, err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxTransportErrorSnippet))

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return deliveryResult{outcome: deliveryOutcomeSuccess, reason: deliveryOutcomeSuccess}
	}
	reason := statusReason(resp.StatusCode)
	err = fmt.Errorf("conductor audit batch upload status=%d", resp.StatusCode)
	if isRetryableStatus(resp.StatusCode) {
		return deliveryResult{outcome: deliveryOutcomeRetry, reason: reason, err: err}
	}
	return deliveryResult{outcome: deliveryOutcomeDrop, reason: reason, err: err}
}

func (t *Transport) sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (t *Transport) recordQueue() {
	if t.metrics == nil {
		return
	}
	stats, err := t.queue.Stats()
	if err != nil {
		return
	}
	t.metrics.RecordConductorAuditQueue(stats)
}

func (t *Transport) recordDelivery(outcome, reason string) {
	if t.metrics != nil {
		t.metrics.RecordConductorAuditDelivery(outcome, normalizeAccountingReason(reason))
	}
}

func auditEndpoint(rawBaseURL string) (string, error) {
	if strings.TrimSpace(rawBaseURL) == "" {
		return "", errors.New("auditbatcher: conductor base URL required")
	}
	u, err := url.Parse(rawBaseURL)
	if err != nil {
		return "", fmt.Errorf("auditbatcher: parse conductor base URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", errors.New("auditbatcher: conductor base URL must be https with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("auditbatcher: conductor base URL must not include userinfo, query, or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("auditbatcher: conductor base URL must not include a path component, got %q", u.Path)
	}
	u.Path = AuditBatchesPath
	return u.String(), nil
}

func isRetryableStatus(status int) bool {
	return status == http.StatusRequestTimeout ||
		status == http.StatusTooEarly ||
		status == http.StatusTooManyRequests ||
		status >= http.StatusInternalServerError
}

func statusReason(status int) string {
	switch {
	case status == http.StatusTooManyRequests:
		return deliveryReasonRateLimited
	case status >= http.StatusInternalServerError:
		return deliveryReasonServerError
	case status >= http.StatusBadRequest:
		return deliveryReasonClientError
	default:
		return fmt.Sprintf("http_status_%d", status)
	}
}
