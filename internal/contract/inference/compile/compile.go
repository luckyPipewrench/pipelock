// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package compile orchestrates recorder ingest, aggregation, inference, and
// signed artifact emission for candidate contracts.
package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference/aggregate"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference/emit"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference/ingest"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference/normalize"
)

const (
	deterministicUnix = 1_777_500_000
	reviewWarningPct  = 5.0
)

var observationWindowMarshal = json.Marshal

var (
	// ErrInvalidInput rejects missing streams or signers.
	ErrInvalidInput = errors.New("compile: invalid input")

	// ErrIngestFailed wraps fatal ingest errors.
	ErrIngestFailed = errors.New("compile: ingest failed")
)

// CompileInput is the pure input bundle for Compile.
type CompileInput struct {
	Stream           io.Reader
	Config           CompileConfig
	EscrowPrivateKey []byte
}

// CompileConfig carries compile-time settings that affect emitted artifacts.
type CompileConfig struct {
	Agent               string
	Floors              inference.Floors
	Normalization       normalize.DecideConfig
	Cardinality         normalize.CapConfig
	WindowDuration      time.Duration
	CompileConfigHash   string
	Settings            map[string]any
	InputRefs           []contract.InputRef
	AcceptTail          bool
	PipelockVersion     string
	PipelockBuildSHA    string
	GoVersion           string
	ModuleDigestRoot    string
	PriorContractHash   string
	ObservationWindowID string
}

// CompileOptions controls deterministic fixtures and signing.
type CompileOptions struct {
	Deterministic bool
	Clock         func() time.Time
	Signer        emit.Signer
}

// CompileResult contains typed and serialized outputs.
type CompileResult struct {
	Contract         contract.Contract
	Manifest         contract.CompileManifest
	Review           string
	Stats            CompileStats
	YAML             []byte
	ManifestJSON     []byte
	ContractPreimage []byte
	ManifestPreimage []byte
}

// CompileStats reports pipeline counters for CLI audit logs and tests.
type CompileStats struct {
	EventsIngested  int
	EventsDropped   int
	EventsMalformed int
	RulesEmitted    int
	NoOp            bool
	IngestErrors    int
}

// Compile runs Ingest, Aggregate, Infer, and Emit in order.
func Compile(in CompileInput, opts CompileOptions) (CompileResult, error) {
	if in.Stream == nil {
		return CompileResult{}, fmt.Errorf("%w: stream is nil", ErrInvalidInput)
	}
	if opts.Signer == nil {
		return CompileResult{}, fmt.Errorf("%w: signer is nil", ErrInvalidInput)
	}
	aggCfg := aggregate.AggregateConfig{WindowDuration: in.Config.WindowDuration}
	if err := aggCfg.Validate(); err != nil {
		return CompileResult{}, fmt.Errorf("aggregate config: %w", err)
	}
	clock := opts.Clock
	if clock == nil {
		if opts.Deterministic {
			clock = deterministicClock
		} else {
			clock = time.Now
		}
	}

	started := clock().UTC()
	entries, errCh := ingest.Stream(in.Stream, ingest.StreamOptions{EscrowPrivateKey: in.EscrowPrivateKey})

	var (
		mu        sync.Mutex
		ingErrors []error
	)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for err := range errCh {
			mu.Lock()
			ingErrors = append(ingErrors, err)
			mu.Unlock()
		}
	}()

	aggs, err := aggregate.Aggregate(entries, aggCfg)
	wg.Wait()
	if err != nil {
		return CompileResult{}, fmt.Errorf("aggregate events: %w", err)
	}
	fatal := firstFatalIngestError(ingErrors)
	if fatal != nil {
		return CompileResult{}, fmt.Errorf("%w: %w", ErrIngestFailed, fatal)
	}

	c, stats, err := inferContract(aggs, in.Config)
	if err != nil {
		return CompileResult{}, fmt.Errorf("infer contract: %w", err)
	}
	stats.IngestErrors = len(ingErrors)
	finished := clock().UTC()
	emitted, err := emit.EmitContract(c, opts.Signer, emit.EmitOptions{
		StartedAt:         started,
		FinishedAt:        finished,
		CompileConfigHash: in.Config.CompileConfigHash,
		Inputs:            in.Config.InputRefs,
		Settings:          in.Config.Settings,
	})
	if err != nil {
		return CompileResult{}, fmt.Errorf("emit contract: %w", err)
	}

	review := ReviewMarkdown(emitted.Contract, aggs, in.Config)
	return CompileResult{
		Contract:         emitted.Contract,
		Manifest:         emitted.Manifest,
		Review:           review,
		Stats:            stats,
		YAML:             emitted.YAML,
		ManifestJSON:     emitted.ManifestJSON,
		ContractPreimage: emitted.ContractPreimage,
		ManifestPreimage: emitted.ManifestPreimage,
	}, nil
}

func deterministicClock() time.Time {
	return time.Unix(deterministicUnix, 0).UTC()
}

func firstFatalIngestError(errs []error) error {
	for _, err := range errs {
		if !errors.Is(err, ingest.ErrMalformedEntry) {
			return err
		}
	}
	return nil
}

func inferContract(aggs aggregate.Aggregates, cfg CompileConfig) (contract.Contract, CompileStats, error) {
	floors := cfg.Floors.Resolved()
	rules := make([]contract.Rule, 0, len(aggs.Rules))
	for _, key := range aggs.RuleKeys() {
		counts := aggs.Rules[key]
		confidence := inference.Classify(counts.Observed, counts.Opportunities, counts.Sessions, counts.Windows, floors)
		wilson := inference.WilsonLowerBound(counts.Observed, counts.Opportunities, inference.DefaultWilsonAlpha)
		rules = append(rules, buildRule(key, counts, confidence, wilson, floors, aggs.Budgets[key]))
	}

	windowRoot, err := observationWindowRoot(aggs, cfg.ObservationWindowID)
	if err != nil {
		return contract.Contract{}, CompileStats{}, err
	}
	c := contract.Contract{
		SchemaVersion:     contract.SchemaVersionContract,
		ContractKind:      contract.ContractKind,
		PriorContractHash: cfg.PriorContractHash,
		DataClassRoot:     string(contract.DataClassInternal),
		FieldDataClasses:  map[string]string{},
		Selector: contract.Selector{
			Agent:      cfg.Agent,
			SelectorID: selectorID(cfg.Agent),
		},
		ObservationWindow: contract.ObservationWindow{
			Start:                 aggs.WindowStart,
			End:                   aggs.WindowEnd,
			EventCount:            IntToUint64(aggs.TotalEvents),
			SessionCount:          IntToUint64(aggs.SessionCount),
			ObservationWindowRoot: windowRoot,
		},
		Compile: contract.ContractCompile{
			PipelockVersion:        cfg.PipelockVersion,
			PipelockBuildSHA:       cfg.PipelockBuildSHA,
			GoVersion:              cfg.GoVersion,
			ModuleDigestRoot:       cfg.ModuleDigestRoot,
			CompileConfigHash:      cfg.CompileConfigHash,
			InferenceAlgorithm:     "wilson_lb_v1",
			NormalizationAlgorithm: normalize.AlgorithmFrequencyWeightedEntropyV1,
		},
		Defaults: contract.ContractDefaults{
			Fidelity: "medium",
			Confidence: map[string]any{
				"min_sessions": floors.MinSessions,
				"min_events":   floors.MinEvents,
				"min_windows":  floors.MinWindows,
			},
			Privacy: contract.ContractDefaultsPrivacy{
				DefaultDataClass: contract.DataClassInternal,
				ForbidClasses:    []contract.DataClass{contract.DataClassRegulated},
			},
		},
		Rules: rules,
	}
	return c, CompileStats{
		EventsIngested:  aggs.TotalEvents,
		EventsDropped:   aggs.DroppedEvents,
		EventsMalformed: aggs.MalformedEvents,
		RulesEmitted:    len(rules),
		NoOp:            len(rules) == 0,
	}, nil
}

func buildRule(key string, counts aggregate.RuleCounts, confidence inference.Confidence, wilson float64, floors inference.Floors, budget aggregate.BudgetSamples) contract.Rule {
	parts := parseRuleKey(key)
	ruleKind := "http_destination"
	if parts["action"] != "" {
		ruleKind = "http_action"
	}
	selector := map[string]any{}
	if parts["host"] != "" {
		selector["host"] = map[string]any{"value": parts["host"], "data_class": string(contract.DataClassPublic)}
	}
	if parts["path"] != "" {
		selector["paths"] = []any{map[string]any{"value": parts["path"], "data_class": string(contract.DataClassPublic)}}
	}
	if parts["method"] != "" {
		selector["methods"] = []any{parts["method"]}
	}
	if parts["action"] != "" {
		selector["effective_action"] = parts["action"]
	}

	budgets := map[string]any{}
	if budget.PayloadBudget().SampleCount > 0 {
		payload := budget.PayloadBudget()
		budgets["payload_size_bytes"] = budgetMap(payload, inference.DefaultHeadroomSize)
	}
	if budget.ScannerBudget().SampleCount > 0 {
		scanner := budget.ScannerBudget()
		budgets["scanner_size_bytes"] = budgetMap(scanner, inference.DefaultHeadroomSize)
	}

	return contract.Rule{
		RuleID:         ruleID(key),
		DisplayName:    displayName(parts),
		RuleKind:       ruleKind,
		LifecycleState: "capture_only",
		Confidence:     confidence.String(),
		WilsonLower:    fmt.Sprintf("%.6f", wilson),
		Observation: map[string]any{
			"sessions_with_opportunity": counts.Opportunities,
			"sessions_observed":         counts.Sessions,
			"events_observed":           counts.Observed,
			// Aggregation currently records only windows where this rule had
			// observations, so opportunity and observed windows are identical.
			"windows_with_opportunity": counts.Windows,
			"windows_observed":         counts.Windows,
		},
		Selector: selector,
		Budgets:  budgets,
		Rationale: map[string]any{
			"summary":    rationaleSummary(counts, confidence, wilson),
			"data_class": string(contract.DataClassInternal),
		},
		RecurringSupport: map[string]any{
			"windows_seen_in_last_n": counts.Windows,
			"windows_floor":          floors.MinWindows,
		},
		OpportunityHealth: map[string]any{
			"missing_alert_threshold": "0.50",
		},
	}
}

func budgetMap(b inference.Budget, headroom float64) map[string]any {
	return map[string]any{
		"p99":          fmt.Sprintf("%.0f", b.P99),
		"p95":          fmt.Sprintf("%.0f", b.P95),
		"median":       fmt.Sprintf("%.0f", b.Median),
		"max":          b.Max,
		"sample_count": b.SampleCount,
		"enforced":     fmt.Sprintf("%.0f", b.EnforcedValue(headroom)),
		"data_class":   string(contract.DataClassPublic),
	}
}

func parseRuleKey(key string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(key, ";") {
		name, value, ok := strings.Cut(part, "=")
		if ok {
			decoded, err := url.PathUnescape(value)
			if err == nil {
				value = decoded
			}
			out[name] = value
		}
	}
	return out
}

func ruleID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "r-" + hex.EncodeToString(sum[:10])
}

func selectorID(agent string) string {
	sum := sha256.Sum256([]byte("agent=" + agent))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func observationWindowRoot(aggs aggregate.Aggregates, override string) (string, error) {
	if override != "" {
		return override, nil
	}
	payload := map[string]any{
		"start":     aggs.WindowStart.UTC().Format(time.RFC3339Nano),
		"end":       aggs.WindowEnd.UTC().Format(time.RFC3339Nano),
		"events":    aggs.TotalEvents,
		"dropped":   aggs.DroppedEvents,
		"malformed": aggs.MalformedEvents,
		"rules":     aggs.RuleKeys(),
	}
	raw, err := observationWindowMarshal(payload)
	if err != nil {
		return "", fmt.Errorf("observation window root: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func displayName(parts map[string]string) string {
	values := []string{parts["host"], parts["path"], parts["method"], parts["action"]}
	var kept []string
	for _, value := range values {
		if value == "" {
			continue
		}
		kept = append(kept, sanitizeNamePart(value))
	}
	if len(kept) == 0 {
		return "observed_rule"
	}
	return strings.Join(kept, "_")
}

func sanitizeNamePart(value string) string {
	value = strings.Trim(value, "/")
	value = strings.NewReplacer(".", "_", "/", "_", "-", "_", "=", "_").Replace(value)
	value = strings.Trim(value, "_")
	if value == "" {
		return "root"
	}
	return value
}

func rationaleSummary(counts aggregate.RuleCounts, confidence inference.Confidence, wilson float64) string {
	return "Observed " + strconv.Itoa(counts.Observed) + " events across " +
		strconv.Itoa(counts.Sessions) + " sessions; Wilson lower bound " +
		fmt.Sprintf("%.6f", wilson) + " classified as " + confidence.String() + "."
}

// ReviewMarkdown renders deterministic operator review markdown.
func ReviewMarkdown(c contract.Contract, aggs aggregate.Aggregates, cfg CompileConfig) string {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "# Candidate Contract Review\n\n")
	_, _ = fmt.Fprintf(&b, "## Summary\n\n")
	_, _ = fmt.Fprintf(&b, "- Agent: %s\n", c.Selector.Agent)
	_, _ = fmt.Fprintf(&b, "- Observation window: %s to %s\n", c.ObservationWindow.Start.UTC().Format(time.RFC3339), c.ObservationWindow.End.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(&b, "- Total events: %d\n", c.ObservationWindow.EventCount)
	_, _ = fmt.Fprintf(&b, "- Total rules: %d\n\n", len(c.Rules))

	lifecycle := map[string]int{}
	confidence := map[string]int{}
	for _, rule := range c.Rules {
		lifecycle[rule.LifecycleState]++
		confidence[rule.Confidence]++
	}
	writeCounts(&b, "Lifecycle", lifecycle)
	writeCounts(&b, "Confidence", confidence)
	writeClassificationDebt(&b, aggs)
	writeThinSamples(&b, c, cfg.Floors.Resolved())
	writeOpportunityHealth(&b, c)
	writeTailCoverage(&b, aggs, cfg)
	return b.String()
}

func writeCounts(b *strings.Builder, title string, counts map[string]int) {
	_, _ = fmt.Fprintf(b, "## %s\n\n", title)
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		_, _ = fmt.Fprintf(b, "- %s: %d\n", key, counts[key])
	}
	_, _ = fmt.Fprintln(b)
}

func writeClassificationDebt(b *strings.Builder, aggs aggregate.Aggregates) {
	_, _ = fmt.Fprintln(b, "## Classification Debt")
	_, _ = fmt.Fprintln(b)
	total := 0
	for _, count := range aggs.ActionClassHistogram {
		total += count
	}
	unclassified := aggs.ActionClassHistogram[aggregate.ActionClassUnclassified]
	pct := 0.0
	if total > 0 {
		pct = 100 * float64(unclassified) / float64(total)
	}
	if pct > reviewWarningPct {
		_, _ = fmt.Fprintf(b, "- Warning: unclassified action_class events %.2f%% (%d/%d)\n", pct, unclassified, total)
	} else {
		_, _ = fmt.Fprintf(b, "- Unclassified action_class events %.2f%% (%d/%d)\n", pct, unclassified, total)
	}
	for _, key := range aggs.ActionClasses() {
		_, _ = fmt.Fprintf(b, "- %s: %d\n", key, aggs.ActionClassHistogram[key])
	}
	_, _ = fmt.Fprintln(b)
}

func writeThinSamples(b *strings.Builder, c contract.Contract, floors inference.Floors) {
	_, _ = fmt.Fprintln(b, "## Thin-Sample Badges")
	_, _ = fmt.Fprintln(b)
	emitted := false
	for _, rule := range c.Rules {
		for _, value := range rule.Budgets {
			budget, ok := value.(map[string]any)
			if !ok {
				continue
			}
			sampleCount, ok := budget["sample_count"].(int)
			if ok && sampleCount < floors.MinEvents {
				_, _ = fmt.Fprintf(b, "- %s: thin sample (%d < %d)\n", rule.RuleID, sampleCount, floors.MinEvents)
				emitted = true
			}
		}
	}
	if !emitted {
		_, _ = fmt.Fprintln(b, "- none")
	}
	_, _ = fmt.Fprintln(b)
}

func writeOpportunityHealth(b *strings.Builder, c contract.Contract) {
	_, _ = fmt.Fprintln(b, "## Opportunity Health")
	_, _ = fmt.Fprintln(b)
	emitted := false
	for _, rule := range c.Rules {
		observed, _ := rule.Observation["events_observed"].(int)
		opportunities, _ := rule.Observation["sessions_with_opportunity"].(int)
		if opportunities > 0 && observed*2 < opportunities {
			_, _ = fmt.Fprintf(b, "- %s: opportunity dropped (%d/%d)\n", rule.RuleID, observed, opportunities)
			emitted = true
		}
	}
	if !emitted {
		_, _ = fmt.Fprintln(b, "- healthy")
	}
	_, _ = fmt.Fprintln(b)
}

func writeTailCoverage(b *strings.Builder, aggs aggregate.Aggregates, cfg CompileConfig) {
	_, _ = fmt.Fprintln(b, "## Tail Coverage")
	_, _ = fmt.Fprintln(b)
	emitted := false
	for _, host := range aggs.HostKeys() {
		result, err := normalize.CapPerHost(host, aggs.PathFamilies(host), cfg.Cardinality, cfg.AcceptTail)
		if err != nil || !result.Overflowed {
			continue
		}
		pct := 0.0
		if result.HostTotalEvents > 0 {
			pct = 100 * float64(result.Tail.EventCount) / float64(result.HostTotalEvents)
		}
		if result.PromotionBlock {
			_, _ = fmt.Fprintf(b, "- %s: promotion blocked; tail %.2f%% (%d/%d). Re-run with accept_tail or split high-traffic patterns.\n", host, pct, result.Tail.EventCount, result.HostTotalEvents)
		} else {
			_, _ = fmt.Fprintf(b, "- %s: tail %.2f%% (%d/%d)\n", host, pct, result.Tail.EventCount, result.HostTotalEvents)
		}
		emitted = true
	}
	if !emitted {
		_, _ = fmt.Fprintln(b, "- none")
	}
}
