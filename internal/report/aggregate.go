package report

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// categoryMap maps scanner names and event types to human-readable categories.
var categoryMap = map[string]string{
	"dlp":               "DLP / Exfiltration",
	"entropy":           "DLP / Exfiltration",
	"subdomain_entropy": "DLP / Exfiltration",
	"path_entropy":      "DLP / Exfiltration",
	"env_leak":          "DLP / Exfiltration",
	"length":            "DLP / Exfiltration",
	"databudget":        "DLP / Exfiltration",
	"ratelimit":         "DLP / Exfiltration",
	"body_dlp":          "DLP / Exfiltration",
	"header_dlp":        "DLP / Exfiltration",
	"response_scan":     "Prompt Injection",
	"ws_scan":           "Prompt Injection",
	"ssrf":              "SSRF",
	"chain_detection":   "MCP / Tool Abuse",
	"policy":            "MCP / Tool Abuse",
	"mcp_unknown_tool":  "MCP / Tool Abuse",
	"sni_mismatch":      "Domain Fronting",
	"blocklist":         "Domain Policy",
	"allowlist":         "Domain Policy",
	"scheme":            "Domain Policy",
	"redirect":          "Domain Policy",
	"kill_switch_deny":  "Kill Switch",
}

// Event types classified as blocks.
var blockEventTypes = map[string]bool{
	"blocked":          true,
	"ws_blocked":       true,
	"kill_switch_deny": true,
}

// Event types classified as allowed/informational traffic.
var allowedEventTypes = map[string]bool{
	"allowed":      true,
	"tunnel_open":  true,
	"tunnel_close": true,
	"forward_http": true,
	"ws_open":      true,
	"ws_close":     true,
}

// Event types classified as warnings.
var warnEventTypes = map[string]bool{
	"anomaly":         true,
	"session_anomaly": true,
	"sni_mismatch":    true,
}

// Aliases for config constants used in event classification.
// Using the config package's canonical values avoids duplicating strings.
const (
	actionBlock = config.ActionBlock
	actionWarn  = config.ActionWarn

	severityCritical = config.SeverityCritical
	severityHigh     = config.SeverityHigh
	severityMedium   = config.SeverityMedium
)

// Event type constants for repeated string references.
const (
	eventBodyDLP        = "body_dlp"
	eventHeaderDLP      = "header_dlp"
	eventChainDetection = "chain_detection"
	eventStartup        = "startup"
	eventConfigReload   = "config_reload"
	eventKillSwitchDeny = "kill_switch_deny"
	eventResponseScan   = "response_scan"
	eventWSScan         = "ws_scan"
	eventSNIMismatch    = "sni_mismatch"
	eventShutdown       = "shutdown"
)

// maxSampleEvidence is the max samples per category.
const maxSampleEvidence = 3

// hourlyThresholdDays is the day count below which hourly buckets are used.
const hourlyThresholdDays = 3

// ipPattern matches IPv4 and IPv6 addresses for redaction.
// IPv6 pattern requires colon-separated hex groups to avoid matching generic hex strings.
var ipPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|` +
	`(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}`)

// Aggregate processes parsed events into a Report.
func Aggregate(events []Event, opts Options) *Report {
	maxEvidence := opts.MaxEvidence
	if maxEvidence <= 0 {
		maxEvidence = defaultMaxEvidence
	}

	title := opts.Title
	if title == "" {
		title = DefaultTitle
	}

	r := &Report{
		Title:     title,
		Generated: time.Now().UTC(),
		Risk:      RiskGreen,
	}

	if len(events) == 0 {
		r.ConfigHashes = []string{}
		r.Categories = []CategoryStats{}
		r.Timeline = []TimeBucket{}
		r.Evidence = []Event{}
		return r
	}

	// Extract metadata from startup and config_reload events.
	extractMetadata(events, r)

	// Compute time range.
	r.TimeRange = TimeRange{
		Start: events[0].Time,
		End:   events[len(events)-1].Time,
	}

	// Compute summary and collect category data.
	domains := make(map[string]bool)
	catData := make(map[string]*categoryAccumulator)

	for i := range events {
		ev := &events[i]
		r.Summary.TotalEvents++

		// Track unique domains.
		if d := extractDomain(ev); d != "" {
			domains[d] = true
		}

		// Classify into summary buckets.
		classifyEvent(ev, &r.Summary)

		// Map to categories.
		categorizeEvent(ev, catData, opts.Redact)
	}

	r.Summary.UniqueDomains = len(domains)

	// Build category stats.
	r.Categories = buildCategories(catData)

	// Compute risk rating.
	r.Risk = computeRisk(r.Summary)

	// Build timeline.
	r.Timeline = buildTimeline(events, r.TimeRange)

	// Build evidence appendix.
	r.Evidence = buildEvidence(events, maxEvidence, opts.Redact)

	return r
}

// categoryAccumulator collects data for a single category during aggregation.
type categoryAccumulator struct {
	count      int
	severity   string
	techniques map[string]bool
	samples    []string
}

// extractMetadata scans events for startup and config_reload to populate report metadata.
func extractMetadata(events []Event, r *Report) {
	seen := make(map[string]bool)
	var hashes []string

	for i := range events {
		ev := &events[i]
		switch ev.Event {
		case eventStartup:
			if ev.Version != "" {
				r.Version = ev.Version
			}
			if ev.Mode != "" {
				r.Mode = ev.Mode
			}
			if ev.ConfigHash != "" && !seen[ev.ConfigHash] {
				seen[ev.ConfigHash] = true
				hashes = append(hashes, ev.ConfigHash)
			}
		case eventConfigReload:
			if ev.ConfigHash != "" && !seen[ev.ConfigHash] {
				seen[ev.ConfigHash] = true
				hashes = append(hashes, ev.ConfigHash)
			}
		}
	}

	if len(hashes) == 0 {
		r.ConfigHashes = []string{}
	} else {
		r.ConfigHashes = hashes
	}
}

// extractDomain returns the domain from an event's URL or Target field.
func extractDomain(ev *Event) string {
	raw := ev.URL
	if raw == "" {
		raw = ev.Target
	}
	if raw == "" {
		return ""
	}

	// Try parsing as URL first.
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		host := u.Hostname()
		if host != "" {
			return strings.ToLower(host)
		}
	}

	// Target might be host:port format.
	host, _, err := net.SplitHostPort(raw)
	if err == nil && host != "" {
		return strings.ToLower(host)
	}

	return strings.ToLower(raw)
}

// classifyEvent updates summary counters based on the event type and action.
func classifyEvent(ev *Event, s *Summary) {
	evType := ev.Event

	if blockEventTypes[evType] {
		s.Blocks++
		if evType == eventKillSwitchDeny {
			s.Criticals++
		}
		return
	}

	if allowedEventTypes[evType] {
		s.Allowed++
		return
	}

	if warnEventTypes[evType] {
		s.Warnings++
		return
	}

	// Action-based classification for scan events.
	switch evType {
	case eventBodyDLP, eventHeaderDLP:
		if ev.Action == actionBlock {
			s.Blocks++
		} else {
			s.Warnings++
		}
	case eventResponseScan, eventWSScan:
		if ev.Action == actionWarn {
			s.Warnings++
		}
	case eventChainDetection:
		switch ev.Action {
		case actionBlock:
			s.Blocks++
			s.Criticals++
		case actionWarn:
			s.Warnings++
		}
	}
}

// categorizeEvent maps an event to a category and accumulates stats.
func categorizeEvent(ev *Event, cats map[string]*categoryAccumulator, redact bool) {
	catName := lookupCategory(ev)
	if catName == "" {
		return
	}

	acc, ok := cats[catName]
	if !ok {
		acc = &categoryAccumulator{
			techniques: make(map[string]bool),
		}
		cats[catName] = acc
	}

	acc.count++

	// Track severity (highest wins).
	sev := eventSeverity(ev)
	acc.severity = higherSeverity(acc.severity, sev)

	// Track MITRE techniques.
	if ev.MITRETechnique != "" {
		acc.techniques[ev.MITRETechnique] = true
	}

	// Collect sample evidence.
	if len(acc.samples) < maxSampleEvidence {
		sample := eventSample(ev, redact)
		if sample != "" {
			acc.samples = append(acc.samples, sample)
		}
	}
}

// lookupCategory returns the category name for an event, checking scanner first, then event type.
func lookupCategory(ev *Event) string {
	if ev.Scanner != "" {
		if cat, ok := categoryMap[ev.Scanner]; ok {
			return cat
		}
	}
	if cat, ok := categoryMap[ev.Event]; ok {
		return cat
	}
	return ""
}

// eventSeverity determines the severity label for an event.
func eventSeverity(ev *Event) string {
	if ev.Event == eventKillSwitchDeny {
		return severityCritical
	}
	if ev.Event == eventChainDetection && ev.Action == actionBlock {
		return severityCritical
	}
	if ev.Severity != "" {
		return ev.Severity
	}
	if ev.Action == actionBlock {
		return severityHigh
	}
	return severityMedium
}

// higherSeverity returns the more severe of two severity labels.
func higherSeverity(a, b string) string {
	order := map[string]int{
		severityCritical: 4,
		severityHigh:     3,
		severityMedium:   2,
		"low":            1,
		"":               0,
	}
	if order[b] > order[a] {
		return b
	}
	return a
}

// eventSample returns a short summary string for an event.
func eventSample(ev *Event, redact bool) string {
	target := ev.URL
	if target == "" {
		target = ev.Target
	}
	if target == "" {
		return ev.Message
	}

	if redact {
		target = redactURL(target)
	}

	if ev.Reason != "" {
		return target + " (" + ev.Reason + ")"
	}
	return target
}

// redactURL strips path and query from a URL, keeping only the domain.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[redacted-url]"
	}
	if u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// redactIP replaces IP addresses in a string with [redacted].
func redactIP(s string) string {
	return ipPattern.ReplaceAllString(s, "[redacted]")
}

// buildCategories converts the accumulator map to a sorted slice.
func buildCategories(cats map[string]*categoryAccumulator) []CategoryStats {
	result := make([]CategoryStats, 0, len(cats))
	for name, acc := range cats {
		techniques := make([]string, 0, len(acc.techniques))
		for t := range acc.techniques {
			techniques = append(techniques, t)
		}
		sort.Strings(techniques)

		cs := CategoryStats{
			Name:            name,
			Count:           acc.count,
			Severity:        acc.severity,
			MITRETechniques: techniques,
		}
		if len(acc.samples) > 0 {
			cs.SampleEvidence = acc.samples
		}
		result = append(result, cs)
	}

	// Sort by count descending, then by name for stability.
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].Name < result[j].Name
	})

	return result
}

// computeRisk determines the traffic-light risk rating.
func computeRisk(s Summary) RiskRating {
	if s.Criticals > 0 {
		return RiskRed
	}
	if s.Blocks > 0 || s.Warnings > 0 {
		return RiskYellow
	}
	return RiskGreen
}

// buildTimeline creates time-bucketed histogram data.
func buildTimeline(events []Event, tr TimeRange) []TimeBucket {
	if len(events) == 0 {
		return []TimeBucket{}
	}

	duration := tr.End.Sub(tr.Start)
	var step time.Duration
	if duration < time.Duration(hourlyThresholdDays)*24*time.Hour {
		step = time.Hour
	} else {
		step = 24 * time.Hour
	}

	// Build buckets.
	start := tr.Start.Truncate(step)
	end := tr.End.Add(step) // ensure last event's bucket is included
	var buckets []TimeBucket
	for t := start; t.Before(end); t = t.Add(step) {
		buckets = append(buckets, TimeBucket{Start: t})
	}

	if len(buckets) == 0 {
		return []TimeBucket{}
	}

	// Fill buckets.
	for i := range events {
		ev := &events[i]
		idx := int(ev.Time.Sub(start) / step)
		if idx < 0 {
			idx = 0
		}
		if idx >= len(buckets) {
			idx = len(buckets) - 1
		}

		switch {
		case isBlockEvent(ev):
			buckets[idx].Blocks++
		case isWarnEvent(ev):
			buckets[idx].Warns++
		default:
			buckets[idx].Allowed++
		}
	}

	return buckets
}

// isBlockEvent checks if an event counts as a block for timeline purposes.
func isBlockEvent(ev *Event) bool {
	if blockEventTypes[ev.Event] {
		return true
	}
	switch ev.Event {
	case eventBodyDLP, eventHeaderDLP, eventChainDetection:
		return ev.Action == actionBlock
	}
	return false
}

// isWarnEvent checks if an event counts as a warning for timeline purposes.
func isWarnEvent(ev *Event) bool {
	if warnEventTypes[ev.Event] {
		return true
	}
	switch ev.Event {
	case eventResponseScan, eventWSScan:
		return ev.Action == actionWarn
	case eventChainDetection:
		return ev.Action == actionWarn
	case eventBodyDLP, eventHeaderDLP:
		return ev.Action != actionBlock
	case eventSNIMismatch:
		return true
	}
	return false
}

// buildEvidence collects events for the evidence appendix.
func buildEvidence(events []Event, maxCount int, redact bool) []Event {
	var evidence []Event

	for i := range events {
		ev := &events[i]
		// Include only security-relevant events (not pure allowed/info traffic).
		if allowedEventTypes[ev.Event] || ev.Event == eventStartup ||
			ev.Event == eventShutdown || ev.Event == eventConfigReload {
			continue
		}

		evCopy := *ev
		if redact {
			evCopy.ClientIP = redactIP(evCopy.ClientIP)
			if evCopy.URL != "" {
				evCopy.URL = redactURL(evCopy.URL)
			}
			if evCopy.Target != "" {
				evCopy.Target = redactURL(evCopy.Target)
			}
		}
		evidence = append(evidence, evCopy)
	}

	// Sort by severity (critical first), then by time.
	sort.SliceStable(evidence, func(i, j int) bool {
		si := severityOrder(eventSeverity(&evidence[i]))
		sj := severityOrder(eventSeverity(&evidence[j]))
		if si != sj {
			return si > sj
		}
		return evidence[i].Time.Before(evidence[j].Time)
	})

	if len(evidence) > maxCount {
		evidence = evidence[:maxCount]
	}

	return evidence
}

// severityOrder returns a numeric ordering for severity labels.
func severityOrder(sev string) int {
	switch sev {
	case severityCritical:
		return 4
	case severityHigh:
		return 3
	case severityMedium:
		return 2
	default:
		return 1
	}
}
