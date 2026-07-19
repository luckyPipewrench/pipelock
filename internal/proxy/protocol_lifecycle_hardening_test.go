// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/proxy/baseline"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type lifecycleFaultReader struct {
	err error
}

func (r lifecycleFaultReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

type lifecycleRoundTripper func(*http.Request) (*http.Response, error)

func (f lifecycleRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type lifecycleCloser struct {
	calls atomic.Int32
}

func (c *lifecycleCloser) Close() error {
	c.calls.Add(1)
	return errors.New("close failed")
}

func TestProtocolLifecycleMalformedBodyAndLimiterBoundaries(t *testing.T) {
	t.Run("body read failure is rejected", func(t *testing.T) {
		want := errors.New("transport read failed")
		req := &http.Request{Body: io.NopCloser(lifecycleFaultReader{err: want})}
		var dst struct {
			Name string `json:"name"`
		}

		err := decodeJSONBody(req, &dst)
		if err == nil || !errors.Is(err, want) {
			t.Fatalf("decodeJSONBody() error = %v, want wrapped transport failure", err)
		}
	})

	t.Run("unregistered action is denied", func(t *testing.T) {
		h := NewSessionAPIHandler(SessionAPIOptions{})
		if h.checkRateLimit("unregistered") {
			t.Fatal("unregistered admin action bypassed its limiter")
		}
	})

	t.Run("expired limiter window resets independently", func(t *testing.T) {
		h := NewSessionAPIHandler(SessionAPIOptions{})
		st := h.limiters[sessionAPIActionReset]
		st.reqCount = sessionAPIRateLimitMax
		st.windowStart = time.Now().Add(-2 * sessionAPIRateLimitWindow)

		if !h.checkRateLimit(sessionAPIActionReset) {
			t.Fatal("expired limiter window did not admit the first new request")
		}
		if st.reqCount != 1 {
			t.Fatalf("request count = %d, want 1 after window reset", st.reqCount)
		}
	})

	t.Run("agent keys reject control and traversal forms", func(t *testing.T) {
		if !validBaselineAgentKey("aA0._-") {
			t.Fatal("valid baseline key alphabet was rejected")
		}
		for _, key := range []string{"", "..", "agent/name", "agent\x00name"} {
			if validBaselineAgentKey(key) {
				t.Fatalf("unsafe baseline key %q was accepted", key)
			}
		}
	})
}

func TestProtocolLifecycleUnavailableManagerEndpointsFailClosed(t *testing.T) {
	h := newTestSessionAPIHandler(t, nil)
	tests := []struct {
		name   string
		method string
		path   string
		call   func(http.ResponseWriter, *http.Request)
	}{
		{name: "airlock", method: http.MethodPost, path: "/api/v1/sessions/agent%7C10.0.0.1/airlock", call: h.HandleAirlock},
		{name: "explain", method: http.MethodGet, path: "/api/v1/sessions/agent%7C10.0.0.1/explain", call: h.HandleExplain},
		{name: "terminate", method: http.MethodPost, path: "/api/v1/sessions/agent%7C10.0.0.1/terminate", call: h.HandleTerminate},
		{name: "adaptive status", method: http.MethodGet, path: "/api/v1/adaptive/status", call: h.HandleAdaptiveStatus},
		{name: "adaptive flush", method: http.MethodPost, path: "/api/v1/adaptive/flush", call: h.HandleAdaptiveFlush},
		{name: "adaptive whoami", method: http.MethodGet, path: "/api/v1/adaptive/whoami", call: h.HandleAdaptiveWhoami},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), tt.method, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
			w := httptest.NewRecorder()

			tt.call(w, req)

			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusServiceUnavailable, w.Body.String())
			}
		})
	}
}

func TestProtocolLifecycleBodyParsingAndRouteRejection(t *testing.T) {
	t.Run("nonpositive reservation is a no-op", func(t *testing.T) {
		var budget sizeExemptScanBudget
		if !budget.reserveSizeExemptScanBytes(0, 1) {
			t.Fatal("zero-byte reservation was rejected")
		}
		if got := budget.inflightBytes.Load(); got != 0 {
			t.Fatalf("zero-byte reservation changed inflight bytes to %d", got)
		}
	})

	t.Run("empty response host is explicit", func(t *testing.T) {
		if got := responseSizeHost(""); got != "unknown-host" {
			t.Fatalf("responseSizeHost(\"\") = %q", got)
		}
	})

	t.Run("empty route fields do not broaden approval", func(t *testing.T) {
		req := unscannablePassthroughRequest{
			Host:              "downloads.vendor.example",
			ContentType:       "application/octet-stream",
			Header:            http.Header{"Content-Disposition": {`attachment; filename="archive.bin"`}},
			ContentLength:     8,
			SizeExemptDomains: []string{"downloads.vendor.example"},
		}
		entries := []config.UnscannablePassthroughEntry{{
			Host:         "downloads.vendor.example",
			Paths:        []string{"/"},
			ContentTypes: []string{"application/octet-stream"},
			Reason:       "operator approved opaque archive",
			Expires:      time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02"),
		}}

		if match, ok := matchUnscannablePassthrough(req, entries); ok {
			t.Fatalf("empty route unexpectedly approved opaque response: %+v", match)
		}
	})

	t.Run("route predicates reject every mismatched boundary", func(t *testing.T) {
		baseReq := BodyScanRequest{
			Host:        "api.vendor.example",
			Method:      http.MethodPost,
			Path:        "/v1/items/submit",
			ContentType: "application/x-www-form-urlencoded; charset=utf-8",
		}
		baseRoute := redact.UnparseableRouteSpec{
			Host:         "api.vendor.example",
			Methods:      []string{http.MethodPost},
			PathPrefixes: []string{"/v1/"},
			PathSuffixes: []string{"/submit"},
			ContentTypes: []string{"bad content type", "application/x-www-form-urlencoded"},
		}
		if !unparseableRouteMatches(baseReq, baseRoute) {
			t.Fatal("fully matching route was rejected")
		}

		tests := []struct {
			name   string
			mutate func(*BodyScanRequest, *redact.UnparseableRouteSpec)
		}{
			{name: "host", mutate: func(_ *BodyScanRequest, r *redact.UnparseableRouteSpec) { r.Host = "other.vendor.example" }},
			{name: "method", mutate: func(q *BodyScanRequest, _ *redact.UnparseableRouteSpec) { q.Method = http.MethodGet }},
			{name: "prefix", mutate: func(q *BodyScanRequest, _ *redact.UnparseableRouteSpec) { q.Path = "/v2/items/submit" }},
			{name: "suffix", mutate: func(q *BodyScanRequest, _ *redact.UnparseableRouteSpec) { q.Path = "/v1/items/preview" }},
			{name: "request content type", mutate: func(q *BodyScanRequest, _ *redact.UnparseableRouteSpec) { q.ContentType = "not a media type" }},
			{name: "content type", mutate: func(_ *BodyScanRequest, r *redact.UnparseableRouteSpec) {
				r.ContentTypes = []string{"bad content type", "application/xml"}
			}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := baseReq
				route := baseRoute
				tt.mutate(&req, &route)
				if unparseableRouteMatches(req, route) {
					t.Fatal("mismatched route was accepted")
				}
			})
		}
	})

	t.Run("request body reader failure blocks", func(t *testing.T) {
		want := errors.New("body transport failed")
		_, result := scanRequestBody(t.Context(), BodyScanRequest{
			Body:     lifecycleFaultReader{err: want},
			MaxBytes: 64,
		})
		if result.Clean || result.Action != config.ActionBlock || !strings.Contains(result.Reason, want.Error()) {
			t.Fatalf("reader failure result = %+v, want block with transport error", result)
		}
	})

	t.Run("form decoder rejects separators and bad escapes", func(t *testing.T) {
		for _, body := range []string{"a=b;c=d", "%zz=value", "key=%zz"} {
			values, reason := extractFormURLEncoded([]byte(body))
			if values != nil || reason != invalidFormURLEncodedBody {
				t.Fatalf("extractFormURLEncoded(%q) = (%v, %q), want rejection", body, values, reason)
			}
		}
	})

	t.Run("content predicates keep malformed and textual bodies scannable", func(t *testing.T) {
		if !configTextualPassthroughType("image/svg+xml") {
			t.Fatal("SVG was not classified as textual")
		}
		if contentTypeMatchesAny("application/octet-stream", []string{"application/zip"}) {
			t.Fatal("unlisted content type matched")
		}
		if isJSONContentType("not a media type") {
			t.Fatal("malformed media type was classified as JSON")
		}
		if !hostAllowlisted("api.vendor.example:443", []string{"*.vendor.example"}) {
			t.Fatal("wildcard host entry did not match a port-bearing subdomain")
		}
		if !shouldHardBlockBodyPromptInjection(BodyScanResult{InjectionMatches: []scanner.ResponseMatch{{PatternName: "instruction"}}}, "publish.vendor.example", nil) {
			t.Fatal("prompt injection did not block without a configuration snapshot")
		}
		if shouldHardBlockCriticalDLP([]scanner.TextDLPMatch{{Warn: true, Severity: config.SeverityCritical}}, true) {
			t.Fatal("warning-only DLP match was promoted to a hard block")
		}
	})

	t.Run("multipart parser rejects malformed framing", func(t *testing.T) {
		if values, reason := extractMultipart([]byte("--broken\r\n"), "boundary", 64); values != nil || !strings.Contains(reason, "multipart parse error") {
			t.Fatalf("malformed multipart = (%v, %q), want parse rejection", values, reason)
		}
	})

	t.Run("multipart parser caps each part body", func(t *testing.T) {
		var body strings.Builder
		writer := multipart.NewWriter(&body)
		part, err := writer.CreateFormField("field")
		if err != nil {
			t.Fatalf("CreateFormField: %v", err)
		}
		if _, err := io.WriteString(part, "oversized"); err != nil {
			t.Fatalf("write part: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close multipart writer: %v", err)
		}

		values, reason := extractMultipart([]byte(body.String()), writer.Boundary(), 2)
		if values != nil || !strings.Contains(reason, "exceeds max_body_bytes") {
			t.Fatalf("oversized part = (%v, %q), want rejection", values, reason)
		}
	})

	t.Run("multipart parser caps part count", func(t *testing.T) {
		var body strings.Builder
		writer := multipart.NewWriter(&body)
		for i := 0; i < maxMultipartParts; i++ {
			part, err := writer.CreateFormField("field")
			if err != nil {
				t.Fatalf("CreateFormField: %v", err)
			}
			if _, err := io.WriteString(part, "value"); err != nil {
				t.Fatalf("write part: %v", err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close multipart writer: %v", err)
		}

		values, reason := extractMultipart([]byte(body.String()), writer.Boundary(), len(body.String())+1)
		if values != nil || !strings.Contains(reason, "parts limit") {
			t.Fatalf("part limit result = (%v, %q), want rejection", values, reason)
		}
	})
}

func TestProtocolLifecycleSessionResetAndMetrics(t *testing.T) {
	t.Run("empty scope uses global lane", func(t *testing.T) {
		s := &SessionState{}
		if got := s.getOrCreateScopeLocked(" \t "); got != nil {
			t.Fatalf("empty normalized scope created state: %+v", got)
		}
		if got := s.AirlockForScope(""); got != &s.airlock {
			t.Fatal("empty scope did not return global airlock")
		}
		escalated, _, _ := s.RecordScopedSignal("", session.SignalDomainAnomaly, 1)
		if !escalated {
			t.Fatal("empty scoped signal did not use global adaptive lane")
		}
	})

	t.Run("reset cancels scoped and global work", func(t *testing.T) {
		s := &SessionState{
			scopes: map[string]*adaptiveScopeState{
				"destination:api.vendor.example": {airlock: AirlockState{tier: config.AirlockTierHard}},
			},
			airlock: AirlockState{tier: config.AirlockTierHard},
		}
		var scopedCalls atomic.Int32
		var globalCalls atomic.Int32
		s.scopes["destination:api.vendor.example"].airlock.RegisterCancel(func() { scopedCalls.Add(1) })
		s.airlock.RegisterCancel(func() { globalCalls.Add(1) })

		s.Reset()

		if scopedCalls.Load() != 1 || globalCalls.Load() != 1 {
			t.Fatalf("cancel calls scoped=%d global=%d, want one each", scopedCalls.Load(), globalCalls.Load())
		}
		if s.scopes != nil || s.airlock.Tier() != config.AirlockTierNone {
			t.Fatal("reset retained quarantined scope state")
		}
	})

	t.Run("task rotation preserves unrelated overrides", func(t *testing.T) {
		s := &SessionState{
			task: session.TaskContext{CurrentTaskID: "task-old"},
			runtimeOverrides: []session.TrustOverride{
				{TaskID: "task-old"},
				{TaskID: "task-other"},
				{},
			},
		}

		_, _, cleared := s.BeginNewTask("next")
		if cleared != 1 || len(s.runtimeOverrides) != 2 {
			t.Fatalf("cleared=%d remaining=%d, want 1 and 2", cleared, len(s.runtimeOverrides))
		}
	})

	t.Run("provisional tool metrics do not mutate session", func(t *testing.T) {
		s := &SessionState{
			created:      time.Now().Add(-time.Second),
			lastActivity: time.Now(),
			toolCalls:    2,
			uniqueTools:  map[string]struct{}{"zeta": {}},
			requestCount: 3,
			bytesTotal:   4,
		}

		got := s.ProvisionalToolCallMetrics("alpha")
		if got.ToolCalls != 3 || got.UniqueTools != 2 {
			t.Fatalf("provisional metrics = %+v", got)
		}
		if strings.Join(got.ToolIdentities, ",") != "alpha,zeta" {
			t.Fatalf("tool identities = %v, want sorted alpha,zeta", got.ToolIdentities)
		}
		if s.toolCalls != 2 || len(s.uniqueTools) != 1 {
			t.Fatal("provisional metrics mutated committed session state")
		}

		existing := s.ProvisionalToolCallMetrics("zeta")
		if existing.UniqueTools != 1 || len(existing.ToolIdentities) != 1 {
			t.Fatalf("existing tool was counted twice: %+v", existing)
		}
	})

	t.Run("baseline adapters reject wrong identity boundaries", func(t *testing.T) {
		cfg := &config.SessionProfiling{CleanupIntervalSeconds: 300}
		sm := NewSessionManager(cfg, nil, nil)
		defer sm.Close()

		if got := sm.CheckBaselineForRecorder("", nil); got != (session.BaselineDecision{}) {
			t.Fatalf("nil recorder decision = %+v", got)
		}
		s := &SessionState{}
		if got := sm.CheckBaselineForRecorder("agent", s); got != (session.BaselineDecision{}) {
			t.Fatalf("disabled manager recorder decision = %+v", got)
		}
		if got := sm.CheckBaselineForMetrics("", session.BaselineMetrics{}); got != (session.BaselineDecision{}) {
			t.Fatalf("empty identity metrics decision = %+v", got)
		}
		sm.RecordBaselineForRecorder("agent", nil)
		sm.RecordBaselineMetrics("bad/key", session.BaselineMetrics{})
	})

	t.Run("baseline detail remains explicit", func(t *testing.T) {
		if got := baselineDecisionDetail(nil); got != "" {
			t.Fatalf("nil detail = %q", got)
		}
		if got := baselineDecisionDetail(&BaselineResult{Err: errors.New("state read failed")}); got != "state read failed" {
			t.Fatalf("error detail = %q", got)
		}
		if got := baselineDecisionDetail(&BaselineResult{}); got != "baseline deviation" {
			t.Fatalf("empty deviation detail = %q", got)
		}
		got := baselineDecisionDetail(&BaselineResult{Deviations: []baseline.Deviation{{
			Metric:   "requests",
			Observed: 9,
			Baseline: baseline.Range{Mean: 2},
			Severity: config.SeverityHigh,
		}}})
		if !strings.Contains(got, "requests observed=9.00") {
			t.Fatalf("deviation detail = %q", got)
		}
	})

	t.Run("status snapshots normalize zero-value quarantine state", func(t *testing.T) {
		cfg := &config.SessionProfiling{CleanupIntervalSeconds: 300}
		sm := NewSessionManager(cfg, nil, nil)
		defer sm.Close()
		sm.sessions["zeta|10.0.0.2"] = &SessionState{key: "zeta|10.0.0.2"}
		sm.sessions["alpha|10.0.0.1"] = &SessionState{key: "alpha|10.0.0.1"}

		status := sm.AdaptiveStatus()
		if len(status.Sessions) != 2 || status.Sessions[0].Key != "alpha|10.0.0.1" {
			t.Fatalf("status sessions = %+v, want stable key ordering", status.Sessions)
		}
		who := sm.AdaptiveWhoami("10.0.0.1", "alpha")
		if !who.Exists || who.AirlockTier != config.AirlockTierNone {
			t.Fatalf("whoami = %+v, want normalized none tier", who)
		}

		scopes := scopedSnapshotsLocked(map[string]*adaptiveScopeState{
			"destination:z.vendor.example": {},
			"destination:a.vendor.example": {},
		}, defaultMaxLevelDuration)
		if len(scopes) != 2 || scopes[0].Scope != "destination:a.vendor.example" || scopes[0].AirlockTier != config.AirlockTierNone {
			t.Fatalf("scoped snapshots = %+v", scopes)
		}
	})

	t.Run("quarantined session is not selected for eviction", func(t *testing.T) {
		cfg := &config.SessionProfiling{CleanupIntervalSeconds: 300}
		sm := NewSessionManager(cfg, nil, nil)
		defer sm.Close()
		quarantined := &SessionState{lastActivity: time.Now().Add(-time.Hour)}
		quarantined.airlock.tier = config.AirlockTierHard
		sm.sessions["quarantined|10.0.0.1"] = quarantined

		sm.mu.Lock()
		evicted := sm.evictOldest()
		sm.mu.Unlock()
		if evicted != nil || len(sm.sessions) != 1 {
			t.Fatal("quarantined session was selected for eviction")
		}
	})
}

func TestProtocolLifecycleReverseContextAndCleanup(t *testing.T) {
	t.Run("target URL handles nil and query combinations", func(t *testing.T) {
		req := &http.Request{URL: &url.URL{Path: "/items", RawQuery: "page=2"}}
		if got := reverseTargetURL(nil, req); got != "" {
			t.Fatalf("nil upstream target = %q", got)
		}
		if got := reverseTargetURL(&url.URL{Scheme: "https", Host: "api.vendor.example", Path: "/v1", RawQuery: "key=value"}, req); got != "https://api.vendor.example/v1/items?key=value&page=2" {
			t.Fatalf("combined target = %q", got)
		}
		req.URL.RawQuery = ""
		if got := reverseTargetURL(&url.URL{Scheme: "https", Host: "api.vendor.example", RawQuery: "key=value"}, req); got != "https://api.vendor.example/items?key=value" {
			t.Fatalf("upstream-only query target = %q", got)
		}
	})

	t.Run("path joining preserves canonical trailing slash", func(t *testing.T) {
		tests := map[string]string{
			joinReversePaths("/v1/", "/items"): "/v1/items",
			joinReversePaths("/v1", "items"):   "/v1/items",
			cleanReversePath("/v1/../items/"):  "/items/",
		}
		for got, want := range tests {
			if got != want {
				t.Fatalf("path = %q, want %q", got, want)
			}
		}
	})

	t.Run("missing envelope context blocks before transport", func(t *testing.T) {
		var baseCalls atomic.Int32
		rt := &reverseSigningRoundTripper{
			base: lifecycleRoundTripper(func(*http.Request) (*http.Response, error) {
				baseCalls.Add(1)
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
			}),
		}
		em := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: strings.Repeat("a", 64)})
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.vendor.example/items", strings.NewReader("body"))
		req = req.WithContext(context.WithValue(req.Context(), ctxKeyReverseEnvelopeEmitter, em))

		resp, err := rt.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if resp != nil || err == nil {
			t.Fatalf("RoundTrip() = (%v, %v), want blocked request error", resp, err)
		}
		if baseCalls.Load() != 0 {
			t.Fatal("request reached transport without required envelope context")
		}
		if _, ok := blockedRequestErrorFrom(err); !ok {
			t.Fatalf("error type = %T, want blocked request", err)
		}
	})

	t.Run("unsigned transport failure propagates", func(t *testing.T) {
		want := errors.New("dial canceled")
		rt := &reverseSigningRoundTripper{base: lifecycleRoundTripper(func(*http.Request) (*http.Response, error) {
			return nil, want
		})}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example/items", nil)
		resp, err := rt.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, want) {
			t.Fatalf("RoundTrip() error = %v, want transport failure", err)
		}
	})

	t.Run("outcome finalizer is idempotent", func(t *testing.T) {
		tracker := newReverseOutcomeTracker(nil, receiptOptsForLifecycleTest())
		tracker.Record(http.StatusCreated, 7, "complete")
		tracker.EmitOnce(&ReverseProxyHandler{})
		tracker.Record(http.StatusInternalServerError, 0, "late")
		tracker.EmitOnce(&ReverseProxyHandler{})
		if tracker.status != "201" || tracker.bytesTransferred != 7 || tracker.reason != "complete" {
			t.Fatalf("late outcome mutated finalized tracker: %+v", tracker)
		}
	})

	t.Run("nil close and raw remote address are tolerated", func(t *testing.T) {
		safeClose(nil, "nil", nil)
		if got := reverseClientIP(&http.Request{RemoteAddr: "unix-peer"}); got != "unix-peer" {
			t.Fatalf("reverseClientIP fallback = %q", got)
		}
		closer := &lifecycleCloser{}
		safeClose(closer, "body", nil)
		if closer.calls.Load() != 1 {
			t.Fatalf("close calls = %d, want 1", closer.calls.Load())
		}
	})
}

func receiptOptsForLifecycleTest() receipt.EmitOpts {
	return receipt.EmitOpts{Transport: TransportReverse}
}
