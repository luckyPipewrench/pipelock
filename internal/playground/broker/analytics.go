// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

const (
	RouteAnalytics      = "/api/live/analytics"
	analyticsCookieName = "__Host-playground_funnel"
	maxAnalyticsBody    = 2048
	analyticsDailyCap   = 100_000
	analyticsWorkers    = 4
)

var analyticsSchema = map[string]map[string]string{
	"playground_demo_viewed":          {"mode": "mode"},
	"playground_mode_selected":        {"mode": "mode"},
	"playground_live_unavailable":     {"reason": "reason"},
	"playground_live_session_failed":  {"status": "status", "reason": "reason"},
	"playground_live_session_started": {},
	"playground_message_sent":         {"turn": "turn"},
	"playground_message_failed":       {"status": "status", "reason": "reason"},
	"playground_attack_blocked":       {},
	"playground_verify_clicked":       {"surface": "surface", "mode": "mode"},
	"playground_verify_result":        {"valid": "valid", "checks": "checks"},
	"playground_kit_downloaded":       {"os": "os"},
}

type analyticsInput struct {
	Event      string         `json:"event"`
	Properties map[string]any `json:"properties"`
}

type analyticsCapture struct {
	APIKey     string         `json:"api_key"` // #nosec G117 -- PostHog project ingestion keys are intentionally public.
	Event      string         `json:"event"`
	Properties map[string]any `json:"properties"`
	Timestamp  time.Time      `json:"timestamp"`
}

// AnalyticsRelay accepts only the playground's bounded counts-only schema and
// forwards accepted events asynchronously. Browser-supplied identifiers,
// arbitrary strings, and unknown properties never reach the analytics service.
type AnalyticsRelay struct {
	projectKey  string
	endpoint    string
	client      *http.Client
	queue       chan analyticsCapture
	rate        *livechat.RateLimiter
	globalDay   *livechat.DailyBudget
	trustProxy  bool
	enabled     func() bool
	ctx         context.Context
	alive       atomic.Bool
	done        chan struct{}
	acceptMu    sync.RWMutex
	log         io.Writer
	rejectLog   throttledAnalyticsLog
	upstreamLog throttledAnalyticsLog
	budgetLog   throttledAnalyticsLog
	signingKey  []byte
}

type throttledAnalyticsLog struct {
	mu   sync.Mutex
	last time.Time
}

type AnalyticsConfig struct {
	ProjectKey        string
	Endpoint          string
	Client            *http.Client
	TrustForwardedFor bool
	Enabled           func() bool
	Log               io.Writer
	SigningKey        []byte
}

func NewAnalyticsRelay(ctx context.Context, cfg AnalyticsConfig) (*AnalyticsRelay, error) {
	if ctx == nil {
		return nil, errors.New("analytics context is nil")
	}
	if cfg.ProjectKey == "" {
		return nil, errors.New("analytics project key is empty")
	}
	if cfg.Endpoint == "" {
		return nil, errors.New("analytics endpoint is empty")
	}
	endpointURL, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse analytics endpoint: %w", err)
	}
	if endpointURL.Host == "" || endpointURL.Scheme != "https" {
		return nil, errors.New("analytics endpoint must be an absolute HTTPS URL")
	}
	if len(cfg.SigningKey) < 32 {
		return nil, errors.New("analytics signing key must be at least 32 bytes")
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 3 * time.Second}
	}
	if cfg.Enabled == nil {
		cfg.Enabled = func() bool { return true }
	}
	if cfg.Log == nil {
		cfg.Log = io.Discard
	}
	r := &AnalyticsRelay{
		projectKey: cfg.ProjectKey, endpoint: cfg.Endpoint, client: cfg.Client,
		queue:      make(chan analyticsCapture, 128),
		rate:       livechat.NewRateLimiter(livechat.RateConfig{RefillPerSec: 1, Burst: 20}),
		globalDay:  livechat.NewDailyBudget(analyticsDailyCap),
		trustProxy: cfg.TrustForwardedFor,
		enabled:    cfg.Enabled,
		ctx:        ctx,
		done:       make(chan struct{}),
		log:        cfg.Log,
		signingKey: append([]byte(nil), cfg.SigningKey...),
	}
	r.alive.Store(true)
	go r.run(ctx)
	return r, nil
}

func (r *AnalyticsRelay) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !r.enabled() {
			http.Error(w, "analytics paused", http.StatusServiceUnavailable)
			return
		}
		if !r.alive.Load() {
			http.Error(w, "analytics unavailable", http.StatusServiceUnavailable)
			return
		}
		mediaType, _, mediaErr := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if mediaErr != nil || mediaType != "application/json" || req.Header.Get("Sec-Fetch-Site") != "same-origin" {
			http.Error(w, "same-origin JSON required", http.StatusForbidden)
			return
		}
		ip := livechat.ClientIP(req, r.trustProxy)
		if !r.rate.Allow("ip:" + ip) {
			http.Error(w, "analytics busy", http.StatusTooManyRequests)
			return
		}
		body := http.MaxBytesReader(w, req.Body, maxAnalyticsBody)
		dec := json.NewDecoder(body)
		dec.DisallowUnknownFields()
		var in analyticsInput
		if err := dec.Decode(&in); err != nil {
			http.Error(w, "invalid analytics event", http.StatusBadRequest)
			return
		}
		if err := ensureJSONEOF(dec); err != nil {
			http.Error(w, "invalid analytics event", http.StatusBadRequest)
			return
		}
		props, ok := validateAnalyticsProperties(in.Event, in.Properties)
		if !ok {
			r.logThrottled(&r.rejectLog, "rejected invalid event schema")
			http.Error(w, "invalid analytics event", http.StatusBadRequest)
			return
		}
		distinctID, cookieValue, fresh, err := r.analyticsDistinctID(req)
		if err != nil {
			http.Error(w, "analytics unavailable", http.StatusServiceUnavailable)
			return
		}
		if fresh {
			http.SetCookie(w, &http.Cookie{Name: analyticsCookieName, Value: cookieValue, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		}
		props["distinct_id"] = distinctID
		props["$geoip_disable"] = true
		props["$process_person_profile"] = false
		if !r.globalDay.Charge(1) {
			r.logThrottled(&r.budgetLog, "global daily budget exhausted")
			http.Error(w, "analytics budget exhausted", http.StatusTooManyRequests)
			return
		}
		r.acceptMu.RLock()
		defer r.acceptMu.RUnlock()
		if r.ctx.Err() != nil || !r.alive.Load() {
			r.globalDay.Refund(1)
			http.Error(w, "analytics unavailable", http.StatusServiceUnavailable)
			return
		}
		select {
		case r.queue <- analyticsCapture{APIKey: r.projectKey, Event: in.Event, Properties: props, Timestamp: time.Now().UTC()}:
			w.WriteHeader(http.StatusAccepted)
		default:
			r.globalDay.Refund(1)
			http.Error(w, "analytics busy", http.StatusServiceUnavailable)
		}
	})
}

func (r *AnalyticsRelay) run(ctx context.Context) {
	defer func() {
		r.acceptMu.Lock()
		r.alive.Store(false)
		r.acceptMu.Unlock()
		close(r.done)
	}()
	var workers sync.WaitGroup
	workers.Add(analyticsWorkers)
	for range analyticsWorkers {
		go func() {
			defer workers.Done()
			r.forward(ctx)
		}()
	}
	workers.Wait()
}

func (r *AnalyticsRelay) forward(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-r.queue:
			// #nosec G117 -- the PostHog project ingestion key is intentionally public.
			payload, err := json.Marshal(event)
			if err != nil {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := r.client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					r.logThrottled(&r.upstreamLog, fmt.Sprintf("upstream returned HTTP %d", resp.StatusCode))
				}
			} else {
				r.logThrottled(&r.upstreamLog, "upstream request failed")
			}
		}
	}
}

func (r *AnalyticsRelay) logThrottled(throttle *throttledAnalyticsLog, message string) {
	now := time.Now()
	throttle.mu.Lock()
	defer throttle.mu.Unlock()
	if now.Sub(throttle.last) < time.Minute {
		return
	}
	throttle.last = now
	_, _ = fmt.Fprintf(r.log, "playground analytics: %s\n", message)
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateAnalyticsProperties(event string, input map[string]any) (map[string]any, bool) {
	schema, ok := analyticsSchema[event]
	if !ok {
		return nil, false
	}
	out := make(map[string]any, len(input)+2)
	for key, value := range input {
		kind, exists := schema[key]
		if !exists || !validAnalyticsValue(kind, value) {
			return nil, false
		}
		out[key] = value
	}
	return out, true
}

func validAnalyticsValue(kind string, value any) bool {
	switch kind {
	case "valid":
		_, ok := value.(bool)
		return ok
	case "status", "turn", "checks":
		n, ok := value.(float64)
		return ok && n >= 0 && n <= 999 && n == float64(int(n))
	case "mode":
		return oneOf(value, "replay", "live")
	case "reason":
		return oneOf(value, "at_capacity", "daily_limit", "provider_unavailable", "rate_limited", "payload_too_large", "session_expired", "request_failed", "network", "unknown", "probe_timeout", "killed", "not_ok", "no_health", "probe_error", "invite_rejected", "human_check")
	case "surface":
		return oneOf(value, "browser", "kit")
	case "os":
		return oneOf(value, "linux", "macos", "windows")
	default:
		return false
	}
}

func oneOf(value any, allowed ...string) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	for _, candidate := range allowed {
		if s == candidate {
			return true
		}
	}
	return false
}

func (r *AnalyticsRelay) analyticsDistinctID(req *http.Request) (string, string, bool, error) {
	if cookie, err := req.Cookie(analyticsCookieName); err == nil {
		parts := strings.Split(cookie.Value, ".")
		if len(parts) == 2 {
			raw, decodeErr := hex.DecodeString(parts[0])
			provided, sigErr := hex.DecodeString(parts[1])
			if decodeErr == nil && sigErr == nil && len(raw) == 16 && hmac.Equal(provided, r.signID(parts[0])) {
				return parts[0], cookie.Value, false, nil
			}
		}
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", "", false, err
	}
	id := hex.EncodeToString(raw)
	return id, id + "." + hex.EncodeToString(r.signID(id)), true, nil
}

func (r *AnalyticsRelay) signID(id string) []byte {
	mac := hmac.New(sha256.New, r.signingKey)
	_, _ = io.WriteString(mac, "pipelock-playground-analytics\x00")
	_, _ = io.WriteString(mac, id)
	return mac.Sum(nil)
}
