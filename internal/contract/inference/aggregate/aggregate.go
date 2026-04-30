// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package aggregate turns capture entries into deterministic inference inputs.
package aggregate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference/ingest"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference/normalize"
)

const (
	defaultWindowDuration = time.Hour

	// ActionClassUnclassified is the histogram bucket for capture summaries
	// that did not carry a classifier result.
	ActionClassUnclassified = "unclassified"
)

// ErrInvalidConfig is returned when AggregateConfig contains invalid knobs.
var ErrInvalidConfig = errors.New("aggregate: invalid config")

// AggregateConfig carries aggregation knobs.
type AggregateConfig struct {
	// WindowDuration controls exposure windows used for rule floor counts and
	// rate samples. Zero defaults to one hour. Negative values are invalid.
	WindowDuration time.Duration
}

// Resolved returns cfg with default values filled in.
func (cfg AggregateConfig) Resolved() AggregateConfig {
	out := cfg
	if out.WindowDuration == 0 {
		out.WindowDuration = defaultWindowDuration
	}
	return out
}

// Validate reports invalid aggregation knobs.
func (cfg AggregateConfig) Validate() error {
	if cfg.WindowDuration < 0 {
		return fmt.Errorf("%w (field=window_duration, value=%s)", ErrInvalidConfig, cfg.WindowDuration)
	}
	return nil
}

// Aggregates is the deterministic aggregation output for downstream inference
// and emit steps. Map fields are paired with sorted accessors so callers do not
// have to iterate Go maps directly.
type Aggregates struct {
	WindowStart time.Time
	WindowEnd   time.Time

	TotalEvents     int
	SessionCount    int
	DroppedEvents   int
	MalformedEvents int

	Rules                map[string]RuleCounts
	Budgets              map[string]BudgetSamples
	HostPathFamilies     map[string]map[string]int
	ActionClassHistogram map[string]int
}

// RuleCounts contains the numerator, denominator, and exposure-floor counts
// for a selector-like rule key.
type RuleCounts struct {
	Observed      int
	Opportunities int
	Sessions      int
	Windows       int
}

// BudgetSamples contains numeric sample windows for a host/path/method bucket.
type BudgetSamples struct {
	PayloadBytes    []float64
	ScannerBytes    []float64
	PerMinuteCounts []CountSample
	PerWindowCounts []CountSample
}

// CountSample records the count observed in one deterministic time bucket.
type CountSample struct {
	Start time.Time
	Count int
}

// PayloadBudget returns deterministic percentile stats for payload bytes.
func (s BudgetSamples) PayloadBudget() inference.Budget {
	return inference.BudgetStats(s.PayloadBytes)
}

// ScannerBudget returns deterministic percentile stats for scanner bytes.
func (s BudgetSamples) ScannerBudget() inference.Budget {
	return inference.BudgetStats(s.ScannerBytes)
}

// RuleKeys returns rule keys in ascending byte order.
func (a Aggregates) RuleKeys() []string {
	return sortedMapKeys(a.Rules)
}

// BudgetKeys returns budget bucket keys in ascending byte order.
func (a Aggregates) BudgetKeys() []string {
	return sortedMapKeys(a.Budgets)
}

// HostKeys returns host keys in ascending byte order.
func (a Aggregates) HostKeys() []string {
	return sortedMapKeys(a.HostPathFamilies)
}

// ActionClasses returns action-class labels in ascending byte order.
func (a Aggregates) ActionClasses() []string {
	return sortedMapKeys(a.ActionClassHistogram)
}

// PathFamilies returns deterministic path-family observations for host.
func (a Aggregates) PathFamilies(host string) []normalize.PathFamily {
	families := a.HostPathFamilies[host]
	out := make([]normalize.PathFamily, 0, len(families))
	for pattern, count := range families {
		out = append(out, normalize.PathFamily{
			Host:       host,
			Pattern:    pattern,
			EventCount: count,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Pattern < out[j].Pattern
	})
	return out
}

// Aggregate consumes ingest events and returns deterministic inference
// aggregates.
func Aggregate(events <-chan ingest.Entry, cfg AggregateConfig) (Aggregates, error) {
	if err := cfg.Validate(); err != nil {
		return Aggregates{}, err
	}
	resolved := cfg.Resolved()

	state := newAggregateState(resolved.WindowDuration)
	for event := range events {
		state.add(event)
	}
	return state.finish(), nil
}

type aggregateState struct {
	windowDuration time.Duration

	totalEvents     int
	droppedEvents   int
	malformedEvents int
	windowStart     time.Time
	windowEnd       time.Time
	sessions        map[string]struct{}

	ruleObserved map[string]int
	ruleScope    map[string]string
	ruleSessions map[string]map[string]struct{}
	ruleWindows  map[string]map[time.Time]struct{}

	totalHTTPEvents int
	hostEvents      map[string]int
	pathEvents      map[string]int
	methodEvents    map[string]int

	payloadSamples map[string][]float64
	scannerSamples map[string][]float64
	minuteCounts   map[string]map[time.Time]int
	windowCounts   map[string]map[time.Time]int

	hostPathFamilies map[string]map[string]int
	actionClasses    map[string]int
}

type normalizedEvent struct {
	timestamp       time.Time
	sessionID       string
	host            string
	path            string
	method          string
	effectiveAction string
	actionClass     string
	payloadBytes    int
	scannerBytes    int
}

func newAggregateState(windowDuration time.Duration) *aggregateState {
	return &aggregateState{
		windowDuration:   windowDuration,
		sessions:         make(map[string]struct{}),
		ruleObserved:     make(map[string]int),
		ruleScope:        make(map[string]string),
		ruleSessions:     make(map[string]map[string]struct{}),
		ruleWindows:      make(map[string]map[time.Time]struct{}),
		hostEvents:       make(map[string]int),
		pathEvents:       make(map[string]int),
		methodEvents:     make(map[string]int),
		payloadSamples:   make(map[string][]float64),
		scannerSamples:   make(map[string][]float64),
		minuteCounts:     make(map[string]map[time.Time]int),
		windowCounts:     make(map[string]map[time.Time]int),
		hostPathFamilies: make(map[string]map[string]int),
		actionClasses:    make(map[string]int),
	}
}

func (s *aggregateState) add(event ingest.Entry) {
	if event.Recorder.Type == capture.EntryTypeCaptureDrop {
		dropped, ok := captureDropCount(event.Recorder.Detail)
		if !ok {
			s.malformedEvents++
			return
		}
		s.droppedEvents += dropped
		return
	}
	if event.Recorder.Type == capture.EntryTypeCapture && event.Capture == nil {
		s.malformedEvents++
		return
	}
	if event.Capture == nil {
		return
	}

	normalized, ok := normalizeEvent(event)
	if !ok {
		s.malformedEvents++
		return
	}

	s.totalEvents++
	s.totalHTTPEvents++
	s.sessions[sessionKey(normalized.sessionID)] = struct{}{}
	s.updateWindowRange(normalized.timestamp)
	s.actionClasses[normalized.actionClass]++

	hostKey := hostRuleKey(normalized.host)
	pathKey := pathRuleKey(normalized.host, normalized.path)
	methodKey := methodRuleKey(normalized.host, normalized.path, normalized.method)
	bucketKey := methodKey

	s.hostEvents[normalized.host]++
	s.pathEvents[pathKey]++
	s.methodEvents[methodKey]++

	s.observeRule(hostKey, "total", normalized)
	s.observeRule(pathKey, "host:"+normalized.host, normalized)
	s.observeRule(methodKey, "path:"+pathKey, normalized)

	if normalized.effectiveAction != "" {
		actionKey := actionRuleKey(normalized.host, normalized.path, normalized.method, normalized.effectiveAction)
		s.observeRule(actionKey, "method:"+methodKey, normalized)
	}

	s.payloadSamples[bucketKey] = append(s.payloadSamples[bucketKey], float64(normalized.payloadBytes))
	s.scannerSamples[bucketKey] = append(s.scannerSamples[bucketKey], float64(normalized.scannerBytes))
	incrementTimeBucket(s.minuteCounts, bucketKey, normalized.timestamp.Truncate(time.Minute))
	incrementTimeBucket(s.windowCounts, bucketKey, normalized.timestamp.Truncate(s.windowDuration))

	families := s.hostPathFamilies[normalized.host]
	if families == nil {
		families = make(map[string]int)
		s.hostPathFamilies[normalized.host] = families
	}
	families[normalized.path]++
}

func (s *aggregateState) finish() Aggregates {
	rules := make(map[string]RuleCounts, len(s.ruleObserved))
	for key, observed := range s.ruleObserved {
		rules[key] = RuleCounts{
			Observed:      observed,
			Opportunities: s.opportunitiesFor(key),
			Sessions:      len(s.ruleSessions[key]),
			Windows:       len(s.ruleWindows[key]),
		}
	}

	budgets := make(map[string]BudgetSamples, len(s.payloadSamples))
	for key, payload := range s.payloadSamples {
		budgets[key] = BudgetSamples{
			PayloadBytes:    cloneFloat64s(payload),
			ScannerBytes:    cloneFloat64s(s.scannerSamples[key]),
			PerMinuteCounts: sortedCountSamples(s.minuteCounts[key]),
			PerWindowCounts: sortedCountSamples(s.windowCounts[key]),
		}
	}

	return Aggregates{
		WindowStart:          s.windowStart,
		WindowEnd:            s.windowEnd,
		TotalEvents:          s.totalEvents,
		SessionCount:         len(s.sessions),
		DroppedEvents:        s.droppedEvents,
		MalformedEvents:      s.malformedEvents,
		Rules:                rules,
		Budgets:              budgets,
		HostPathFamilies:     cloneNestedIntMap(s.hostPathFamilies),
		ActionClassHistogram: cloneIntMap(s.actionClasses),
	}
}

func (s *aggregateState) observeRule(key, scope string, event normalizedEvent) {
	s.ruleObserved[key]++
	s.ruleScope[key] = scope

	sessions := s.ruleSessions[key]
	if sessions == nil {
		sessions = make(map[string]struct{})
		s.ruleSessions[key] = sessions
	}
	sessions[sessionKey(event.sessionID)] = struct{}{}

	window := event.timestamp.Truncate(s.windowDuration)
	windows := s.ruleWindows[key]
	if windows == nil {
		windows = make(map[time.Time]struct{})
		s.ruleWindows[key] = windows
	}
	windows[window] = struct{}{}
}

func sessionKey(sessionID string) string {
	if sessionID == "" {
		return "(empty)"
	}
	return sessionID
}

func (s *aggregateState) opportunitiesFor(key string) int {
	switch scope := s.ruleScope[key]; {
	case scope == "total":
		return s.totalHTTPEvents
	case strings.HasPrefix(scope, "host:"):
		return s.hostEvents[strings.TrimPrefix(scope, "host:")]
	case strings.HasPrefix(scope, "path:"):
		return s.pathEvents[strings.TrimPrefix(scope, "path:")]
	case strings.HasPrefix(scope, "method:"):
		return s.methodEvents[strings.TrimPrefix(scope, "method:")]
	default:
		return 0
	}
}

func (s *aggregateState) updateWindowRange(timestamp time.Time) {
	start := timestamp.Truncate(s.windowDuration)
	end := start.Add(s.windowDuration)
	if s.windowStart.IsZero() || start.Before(s.windowStart) {
		s.windowStart = start
	}
	if end.After(s.windowEnd) {
		s.windowEnd = end
	}
}

func normalizeEvent(event ingest.Entry) (normalizedEvent, bool) {
	summary := event.Capture
	parsed, err := url.Parse(summary.Request.URL)
	if err != nil || parsed == nil {
		return normalizedEvent{}, false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return normalizedEvent{}, false
	}
	if parsed.User != nil {
		return normalizedEvent{}, false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return normalizedEvent{}, false
	}

	rawPath := parsed.EscapedPath()
	if rawPath == "" {
		rawPath = "/"
	}
	canonicalPath, _, err := normalize.Canonicalize(rawPath)
	if err != nil {
		return normalizedEvent{}, false
	}

	method := strings.ToUpper(strings.TrimSpace(summary.Request.Method))
	if method == "" {
		method = "UNKNOWN"
	}

	actionClass := strings.ToLower(strings.TrimSpace(summary.ActionClass))
	if actionClass == "" {
		actionClass = ActionClassUnclassified
	}

	return normalizedEvent{
		timestamp:       event.Recorder.Timestamp,
		sessionID:       event.Recorder.SessionID,
		host:            host,
		path:            canonicalPath,
		method:          method,
		effectiveAction: strings.ToLower(strings.TrimSpace(summary.EffectiveAction)),
		actionClass:     actionClass,
		payloadBytes:    nonNegative(summary.PayloadBytes),
		scannerBytes:    nonNegative(summary.ScannerBytes),
	}, true
}

func captureDropCount(detail any) (int, bool) {
	switch typed := detail.(type) {
	case capture.CaptureDropDetail:
		return nonNegative(typed.Count), true
	case json.RawMessage:
		return captureDropCountJSON(typed)
	case []byte:
		return captureDropCountJSON(typed)
	case string:
		return captureDropCountJSON([]byte(typed))
	case map[string]any:
		count, ok := typed["count"]
		if !ok {
			count = typed["Count"]
		}
		return captureDropCountValue(count)
	default:
		detailJSON, err := json.Marshal(detail)
		if err != nil {
			return 0, false
		}
		return captureDropCountJSON(detailJSON)
	}
}

func captureDropCountJSON(detailJSON []byte) (int, bool) {
	var drop capture.CaptureDropDetail
	if err := json.Unmarshal(detailJSON, &drop); err != nil {
		return 0, false
	}
	return nonNegative(drop.Count), true
}

func captureDropCountValue(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return nonNegative(typed), true
	case int64:
		return nonNegative(int(typed)), true
	case float64:
		return nonNegative(int(typed)), true
	case json.Number:
		out, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return nonNegative(int(out)), true
	default:
		return 0, false
	}
}

func nonNegative(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

func incrementTimeBucket(buckets map[string]map[time.Time]int, key string, start time.Time) {
	counts := buckets[key]
	if counts == nil {
		counts = make(map[time.Time]int)
		buckets[key] = counts
	}
	counts[start]++
}

func sortedCountSamples(counts map[time.Time]int) []CountSample {
	out := make([]CountSample, 0, len(counts))
	for start, count := range counts {
		out = append(out, CountSample{Start: start, Count: count})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Start.Before(out[j].Start)
	})
	return out
}

func hostRuleKey(host string) string {
	return "host=" + escapeRuleKeyComponent(host)
}

func pathRuleKey(host, path string) string {
	return hostRuleKey(host) + ";path=" + escapeRuleKeyComponent(path)
}

func methodRuleKey(host, path, method string) string {
	return pathRuleKey(host, path) + ";method=" + escapeRuleKeyComponent(method)
}

func actionRuleKey(host, path, method, action string) string {
	return methodRuleKey(host, path, method) + ";action=" + escapeRuleKeyComponent(action)
}

func escapeRuleKeyComponent(value string) string {
	return strings.NewReplacer(
		"%", "%25",
		";", "%3B",
		"=", "%3D",
	).Replace(value)
}

func cloneFloat64s(in []float64) []float64 {
	out := make([]float64, len(in))
	copy(out, in)
	return out
}

func cloneIntMap(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneNestedIntMap(in map[string]map[string]int) map[string]map[string]int {
	out := make(map[string]map[string]int, len(in))
	for k, values := range in {
		out[k] = cloneIntMap(values)
	}
	return out
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
