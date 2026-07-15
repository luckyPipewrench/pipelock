// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package main is a stdlib-only load-test harness for the playground broker's
// public /api/live/* flow.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	routeSession = "/api/live/session"
	routeMessage = "/api/live/message"
	routeBundle  = "/api/live/bundle"

	stepSession = "session"
	stepMessage = "message"
	stepBundle  = "bundle"

	categoryRateLimited = "rate_limited"
	categoryAuth        = "auth"
	categoryServer      = "server"
	categoryTimeout     = "timeout"
	categoryOther       = "other"

	defaultConcurrency = 50
	defaultTimeout     = 90 * time.Second
	maxConcurrency     = 1000
	maxResponseBytes   = 1 << 20
)

type config struct {
	brokerURL      string
	code           string
	turnstileToken string
	concurrency    int
	ramp           time.Duration
	prompt         string
	timeout        time.Duration
	jsonOutput     bool
}

type sessionRequest struct {
	Code           string `json:"code"`
	TurnstileToken string `json:"turnstile_token,omitempty"`
}

type sessionResponse struct {
	Token string `json:"token"`
}

type messageRequest struct {
	Token   string `json:"token"`
	Message string `json:"message"`
}

type userResult struct {
	ID    int          `json:"id"`
	Steps []stepResult `json:"steps"`
}

type stepResult struct {
	Name       string        `json:"name"`
	Status     int           `json:"status"`
	Latency    time.Duration `json:"latency_ns"`
	Failed     bool          `json:"failed"`
	Category   string        `json:"category,omitempty"`
	ErrMessage string        `json:"error,omitempty"`
}

type aggregate struct {
	Total              int                       `json:"total"`
	Successes          int                       `json:"successes"`
	Failures           int                       `json:"failures"`
	FailureCategories  map[string]int            `json:"failure_categories"`
	StepLatency        map[string]latencySummary `json:"step_latency"`
	StepStatuses       map[string]map[string]int `json:"step_statuses"`
	SessionCreateDist  sessionCreateDistribution `json:"session_create_distribution"`
	MaxUsersInFlight   int                       `json:"max_users_in_flight"`
	PerUserStepResults []userResult              `json:"per_user_step_results,omitempty"`
}

type latencySummary struct {
	Count int           `json:"count"`
	P50   time.Duration `json:"p50_ns"`
	P95   time.Duration `json:"p95_ns"`
	P99   time.Duration `json:"p99_ns"`
}

type sessionCreateDistribution struct {
	Count   int            `json:"count"`
	Min     time.Duration  `json:"min_ns"`
	P50     time.Duration  `json:"p50_ns"`
	P95     time.Duration  `json:"p95_ns"`
	P99     time.Duration  `json:"p99_ns"`
	Max     time.Duration  `json:"max_ns"`
	Buckets map[string]int `json:"buckets"`
}

type inFlightTracker struct {
	mu      sync.Mutex
	current int
	peak    int
}

func (t *inFlightTracker) start() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current++
	if t.current > t.peak {
		t.peak = t.current
	}
}

func (t *inFlightTracker) done() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current > 0 {
		t.current--
	}
}

func (t *inFlightTracker) peakValue() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.peak
}

func main() {
	cfg := parseFlags()
	if err := validateConfig(cfg); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "pipelock-playground-loadtest: %v\n", err)
		os.Exit(2)
	}

	results, peak := runLoadTest(context.Background(), http.DefaultClient, cfg)
	agg := aggregateResults(results, peak)
	if cfg.jsonOutput {
		if err := writeJSON(os.Stdout, agg); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "pipelock-playground-loadtest: write json: %v\n", err)
			os.Exit(1)
		}
		return
	}
	printReport(os.Stdout, agg)
	if agg.Failures > 0 {
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.brokerURL, "broker-url", "", "broker base URL, for example https://playground.example")
	flag.StringVar(&cfg.code, "code", "", "invite code")
	flag.StringVar(&cfg.turnstileToken, "turnstile-token", "", "Cloudflare Turnstile test-mode token")
	flag.IntVar(&cfg.concurrency, "concurrency", defaultConcurrency, "number of concurrent virtual users to run")
	flag.DurationVar(&cfg.ramp, "ramp", 0, "duration to spread user launches over; 0 launches all users at once")
	flag.StringVar(&cfg.prompt, "prompt", "Prove this session is contained and fetch the demo target.", "agent message to send")
	flag.DurationVar(&cfg.timeout, "timeout", defaultTimeout, "per-request timeout")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit machine-readable JSON results")
	flag.Parse()
	return cfg
}

func validateConfig(cfg config) error {
	if strings.TrimSpace(cfg.brokerURL) == "" {
		return errors.New("--broker-url is required")
	}
	u, err := url.Parse(cfg.brokerURL)
	if err != nil {
		return fmt.Errorf("--broker-url: parse: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("--broker-url must use http or https")
	}
	if u.Host == "" {
		return errors.New("--broker-url host is required")
	}
	if strings.TrimSpace(cfg.code) == "" {
		return errors.New("--code is required")
	}
	if strings.TrimSpace(cfg.turnstileToken) == "" {
		return errors.New("--turnstile-token is required")
	}
	if cfg.concurrency <= 0 {
		return errors.New("--concurrency must be > 0")
	}
	if cfg.concurrency > maxConcurrency {
		return fmt.Errorf("--concurrency must be <= %d", maxConcurrency)
	}
	if cfg.ramp < 0 {
		return errors.New("--ramp must be >= 0")
	}
	if strings.TrimSpace(cfg.prompt) == "" {
		return errors.New("--prompt is required")
	}
	if cfg.timeout <= 0 {
		return errors.New("--timeout must be > 0")
	}
	return nil
}

func runLoadTest(ctx context.Context, client *http.Client, cfg config) ([]userResult, int) {
	client = sameOriginClient(client, cfg.brokerURL)
	results := make([]userResult, cfg.concurrency)
	tracker := &inFlightTracker{}
	var wg sync.WaitGroup
	interval := rampInterval(cfg.concurrency, cfg.ramp)

	for i := range cfg.concurrency {
		select {
		case <-ctx.Done():
			wg.Wait()
			return results, tracker.peakValue()
		default:
		}
		if i > 0 && interval > 0 {
			select {
			case <-ctx.Done():
				wg.Wait()
				return results, tracker.peakValue()
			case <-time.After(interval):
			}
		}
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			tracker.start()
			defer tracker.done()
			results[id] = runVirtualUser(ctx, client, cfg, id)
		}(i)
	}
	wg.Wait()
	return results, tracker.peakValue()
}

func rampInterval(concurrency int, ramp time.Duration) time.Duration {
	if concurrency <= 1 || ramp <= 0 {
		return 0
	}
	return ramp / time.Duration(concurrency-1)
}

func runVirtualUser(parent context.Context, client *http.Client, cfg config, id int) userResult {
	result := userResult{ID: id}
	token, step := createSession(parent, client, cfg)
	result.Steps = append(result.Steps, step)
	if step.Failed {
		return result
	}
	step = postMessage(parent, client, cfg, token)
	result.Steps = append(result.Steps, step)
	if step.Failed {
		return result
	}
	step = getBundle(parent, client, cfg, token)
	result.Steps = append(result.Steps, step)
	return result
}

func createSession(parent context.Context, client *http.Client, cfg config) (string, stepResult) {
	body := sessionRequest{Code: cfg.code, TurnstileToken: cfg.turnstileToken}
	resp, step := doJSON(parent, client, cfg, http.MethodPost, routeSession, "", body, stepSession)
	if step.Failed {
		return "", step
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		step.Failed = true
		step.Category = categorizeStatus(resp.StatusCode)
		discardBody(resp.Body)
		return "", step
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		step.Failed = true
		step.Category = categoryOther
		step.ErrMessage = "read session response: oversized or unreadable body"
		return "", step
	}
	var out sessionResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		step.Failed = true
		step.Category = categoryOther
		step.ErrMessage = "decode session response: " + err.Error()
		return "", step
	}
	if out.Token == "" {
		step.Failed = true
		step.Category = categoryOther
		step.ErrMessage = "session response missing token"
		return "", step
	}
	return out.Token, step
}

func postMessage(parent context.Context, client *http.Client, cfg config, token string) stepResult {
	body := messageRequest{Token: token, Message: cfg.prompt}
	resp, step := doJSON(parent, client, cfg, http.MethodPost, routeMessage, "", body, stepMessage)
	if step.Failed {
		return step
	}
	defer func() { _ = resp.Body.Close() }()
	discardBody(resp.Body)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		step.Failed = true
		step.Category = categorizeStatus(resp.StatusCode)
	}
	return step
}

func getBundle(parent context.Context, client *http.Client, cfg config, token string) stepResult {
	query := url.Values{"token": []string{token}}
	resp, step := doRequest(parent, client, cfg, http.MethodGet, routeBundle, query.Encode(), nil, stepBundle)
	if step.Failed {
		return step
	}
	defer func() { _ = resp.Body.Close() }()
	discardBody(resp.Body)
	if resp.StatusCode != http.StatusOK {
		step.Failed = true
		step.Category = categorizeStatus(resp.StatusCode)
	}
	return step
}

func doJSON(parent context.Context, client *http.Client, cfg config, method, path, rawQuery string, body any, stepName string) (*http.Response, stepResult) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, stepResult{Name: stepName, Failed: true, Category: categoryOther, ErrMessage: err.Error()}
	}
	return doRequest(parent, client, cfg, method, path, rawQuery, strings.NewReader(string(b)), stepName)
}

func doRequest(parent context.Context, client *http.Client, cfg config, method, path, rawQuery string, body io.Reader, stepName string) (*http.Response, stepResult) {
	target, err := joinURL(cfg.brokerURL, path, rawQuery)
	if err != nil {
		return nil, stepResult{Name: stepName, Failed: true, Category: categoryOther, ErrMessage: err.Error()}
	}
	reqCtx, cancel := context.WithTimeout(parent, cfg.timeout)
	req, err := http.NewRequestWithContext(reqCtx, method, target, body)
	if err != nil {
		cancel()
		return nil, stepResult{Name: stepName, Failed: true, Category: categoryOther, ErrMessage: err.Error()}
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	step := stepResult{Name: stepName, Latency: latency}
	if err != nil {
		cancel()
		step.Failed = true
		step.Category = categorizeError(err)
		step.ErrMessage = err.Error()
		return nil, step
	}
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	step.Status = resp.StatusCode
	return resp, step
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

func sameOriginClient(client *http.Client, brokerURL string) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	base, err := url.Parse(brokerURL)
	if err != nil {
		return client
	}
	cp := *client
	cp.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Scheme != base.Scheme || req.URL.Host != base.Host {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return &cp
}

func joinURL(baseURL, path, rawQuery string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = rawQuery
	return u.String(), nil
}

func discardBody(r io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r, maxResponseBytes))
}

func categorizeError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return categoryTimeout
	}
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) && netErr.Timeout() {
		return categoryTimeout
	}
	return categoryOther
}

func categorizeStatus(status int) string {
	switch {
	case status == http.StatusTooManyRequests:
		return categoryRateLimited
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return categoryAuth
	case status >= http.StatusInternalServerError && status <= 599:
		return categoryServer
	default:
		return categoryOther
	}
}

func aggregateResults(results []userResult, peak int) aggregate {
	agg := aggregate{
		Total:             len(results),
		FailureCategories: newFailureCategories(),
		StepLatency:       make(map[string]latencySummary),
		StepStatuses:      make(map[string]map[string]int),
		MaxUsersInFlight:  peak,
	}
	latencies := map[string][]time.Duration{
		stepSession: nil,
		stepMessage: nil,
		stepBundle:  nil,
	}

	for _, result := range results {
		failed := false
		failureCategory := ""
		for _, step := range result.Steps {
			latencies[step.Name] = append(latencies[step.Name], step.Latency)
			recordStepStatus(agg.StepStatuses, step)
			if step.Failed && !failed {
				failed = true
				failureCategory = step.Category
				if failureCategory == "" {
					failureCategory = categoryOther
				}
			}
		}
		if failed {
			agg.Failures++
			agg.FailureCategories[failureCategory]++
			continue
		}
		if len(result.Steps) == 3 {
			agg.Successes++
		} else {
			agg.Failures++
			agg.FailureCategories[categoryOther]++
		}
	}

	for step, vals := range latencies {
		agg.StepLatency[step] = summarizeLatencies(vals)
	}
	agg.SessionCreateDist = summarizeSessionCreate(latencies[stepSession])
	return agg
}

func newFailureCategories() map[string]int {
	return map[string]int{
		categoryRateLimited: 0,
		categoryAuth:        0,
		categoryServer:      0,
		categoryTimeout:     0,
		categoryOther:       0,
	}
}

func recordStepStatus(statuses map[string]map[string]int, step stepResult) {
	if statuses[step.Name] == nil {
		statuses[step.Name] = make(map[string]int)
	}
	key := fmt.Sprintf("%d", step.Status)
	if step.Status == 0 {
		key = "error"
	}
	statuses[step.Name][key]++
}

func summarizeLatencies(vals []time.Duration) latencySummary {
	return latencySummary{
		Count: len(vals),
		P50:   percentile(vals, 50),
		P95:   percentile(vals, 95),
		P99:   percentile(vals, 99),
	}
}

func summarizeSessionCreate(vals []time.Duration) sessionCreateDistribution {
	cp := sortedDurations(vals)
	dist := sessionCreateDistribution{
		Count:   len(cp),
		P50:     percentileSorted(cp, 50),
		P95:     percentileSorted(cp, 95),
		P99:     percentileSorted(cp, 99),
		Buckets: map[string]int{"<=1s": 0, "<=5s": 0, "<=15s": 0, "<=30s": 0, ">30s": 0},
	}
	if len(cp) > 0 {
		dist.Min = cp[0]
		dist.Max = cp[len(cp)-1]
	}
	for _, v := range cp {
		switch {
		case v <= time.Second:
			dist.Buckets["<=1s"]++
		case v <= 5*time.Second:
			dist.Buckets["<=5s"]++
		case v <= 15*time.Second:
			dist.Buckets["<=15s"]++
		case v <= 30*time.Second:
			dist.Buckets["<=30s"]++
		default:
			dist.Buckets[">30s"]++
		}
	}
	return dist
}

func percentile(vals []time.Duration, pct int) time.Duration {
	return percentileSorted(sortedDurations(vals), pct)
}

func percentileSorted(vals []time.Duration, pct int) time.Duration {
	if len(vals) == 0 {
		return 0
	}
	if pct <= 0 {
		return vals[0]
	}
	if pct >= 100 {
		return vals[len(vals)-1]
	}
	idx := (pct*len(vals) + 99) / 100
	if idx < 1 {
		idx = 1
	}
	return vals[idx-1]
}

func sortedDurations(vals []time.Duration) []time.Duration {
	cp := append([]time.Duration(nil), vals...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return cp
}

func printReport(w io.Writer, agg aggregate) {
	_, _ = fmt.Fprintf(w, "Pipelock playground broker load test\n")
	_, _ = fmt.Fprintf(w, "total=%d successes=%d failures=%d max_in_flight=%d\n", agg.Total, agg.Successes, agg.Failures, agg.MaxUsersInFlight)
	_, _ = fmt.Fprintf(w, "\nFailures:\n")
	for _, category := range []string{categoryRateLimited, categoryAuth, categoryServer, categoryTimeout, categoryOther} {
		_, _ = fmt.Fprintf(w, "  %s: %d\n", category, agg.FailureCategories[category])
	}
	_, _ = fmt.Fprintf(w, "\nLatency by step:\n")
	for _, step := range []string{stepSession, stepMessage, stepBundle} {
		s := agg.StepLatency[step]
		_, _ = fmt.Fprintf(w, "  %s: count=%d p50=%s p95=%s p99=%s\n", step, s.Count, s.P50, s.P95, s.P99)
	}
	_, _ = fmt.Fprintf(w, "\nStatuses by step:\n")
	for _, step := range []string{stepSession, stepMessage, stepBundle} {
		_, _ = fmt.Fprintf(w, "  %s:", step)
		for _, status := range sortedStatusKeys(agg.StepStatuses[step]) {
			_, _ = fmt.Fprintf(w, " %s=%d", status, agg.StepStatuses[step][status])
		}
		_, _ = fmt.Fprintln(w)
	}
	dist := agg.SessionCreateDist
	_, _ = fmt.Fprintf(w, "\nSession-create distribution:\n")
	_, _ = fmt.Fprintf(w, "  count=%d min=%s p50=%s p95=%s p99=%s max=%s\n", dist.Count, dist.Min, dist.P50, dist.P95, dist.P99, dist.Max)
	_, _ = fmt.Fprintf(w, "  buckets: <=1s=%d <=5s=%d <=15s=%d <=30s=%d >30s=%d\n",
		dist.Buckets["<=1s"], dist.Buckets["<=5s"], dist.Buckets["<=15s"], dist.Buckets["<=30s"], dist.Buckets[">30s"])
}

func sortedStatusKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func writeJSON(w io.Writer, agg aggregate) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(agg)
}
