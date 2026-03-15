// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

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
	"dlp":                  "DLP / Exfiltration",
	"entropy":              "DLP / Exfiltration",
	"subdomain_entropy":    "DLP / Exfiltration",
	"path_entropy":         "DLP / Exfiltration",
	"env_leak":             "DLP / Exfiltration",
	"length":               "DLP / Exfiltration",
	"databudget":           "DLP / Exfiltration",
	"ratelimit":            "DLP / Exfiltration",
	"body_dlp":             "DLP / Exfiltration",
	"header_dlp":           "DLP / Exfiltration",
	eventAddressProtection: "DLP / Exfiltration",
	"response_scan":        "Prompt Injection",
	"ws_scan":              "Prompt Injection",
	"ssrf":                 "SSRF",
	"chain_detection":      "MCP / Tool Abuse",
	"policy":               "MCP / Tool Abuse",
	"mcp_unknown_tool":     "MCP / Tool Abuse",
	"sni_mismatch":         "Domain Fronting",
	"blocklist":            "Domain Policy",
	"allowlist":            "Domain Policy",
	"scheme":               "Domain Policy",
	"redirect":             "Domain Policy",
	"kill_switch_deny":     "Kill Switch",
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
	eventBodyDLP           = "body_dlp"
	eventHeaderDLP         = "header_dlp"
	eventChainDetection    = "chain_detection"
	eventMCPUnknownTool    = "mcp_unknown_tool"
	eventStartup           = "startup"
	eventConfigReload      = "config_reload"
	eventKillSwitchDeny    = "kill_switch_deny"
	eventResponseScan      = "response_scan"
	eventWSScan            = "ws_scan"
	eventSNIMismatch       = "sni_mismatch"
	eventShutdown          = "shutdown"
	eventAddressProtection = "address_protection"
)

// maxSampleEvidence is the max samples per category.
const maxSampleEvidence = 3

// hourlyThresholdDays is the day count below which hourly buckets are used.
const hourlyThresholdDays = 3

// minBucketTarget is the minimum number of buckets to aim for in the timeline.
// Prevents single-bar timelines for short observation windows.
const minBucketTarget = 6

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
		r.Domains = []DomainStats{}
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

	// Compute summary and collect category + domain data.
	domainSet := make(map[string]bool)
	domainStats := make(map[string]*DomainStats)
	catData := make(map[string]*categoryAccumulator)

	for i := range events {
		ev := &events[i]
		r.Summary.TotalEvents++

		// Track unique domains and per-domain stats.
		if d := extractDomain(ev); d != "" {
			domainSet[d] = true
			ds, ok := domainStats[d]
			if !ok {
				ds = &DomainStats{Domain: d}
				domainStats[d] = ds
			}
			ds.Total++
			switch {
			case isBlockEvent(ev):
				ds.Blocks++
			case isWarnEvent(ev):
				ds.Warns++
			default:
				ds.Allowed++
			}
		}

		// Classify into summary buckets.
		classifyEvent(ev, &r.Summary)

		// Map to categories.
		categorizeEvent(ev, catData, opts.Redact)
	}

	r.Summary.UniqueDomains = len(domainSet)

	// Build category stats.
	r.Categories = buildCategories(catData)

	// Build domain stats (top 20 by total events).
	r.Domains = buildDomainStats(domainStats)

	// Compute risk rating.
	r.Risk = computeRisk(r.Summary)

	// Build timeline.
	r.Timeline = buildTimeline(events, r.TimeRange)

	// Build evidence appendix.
	r.Evidence = buildEvidence(events, maxEvidence, opts.Redact)

	// v1.3.0+ breakdowns.
	r.DLPBreakdown = buildDLPBreakdown(events)
	r.TransportBreakdown = buildTransportBreakdown(events)
	r.AgentBreakdown = buildAgentBreakdown(events)
	r.MITRETechniques = buildMITRETechniques(events)

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
			// Extract mode from detail field (e.g. "mode=strict") when
			// the log window doesn't contain a startup event.
			if r.Mode == "" && ev.Detail != "" {
				if m := extractModeFromDetail(ev.Detail); m != "" {
					r.Mode = m
				}
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
		raw = ev.ConnectHost
	}
	if raw == "" {
		raw = ev.SNIHost
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

// modePrefix is the key prefix in config_reload detail fields.
const modePrefix = "mode="

// extractModeFromDetail parses "mode=strict" from a config_reload detail string.
func extractModeFromDetail(detail string) string {
	for _, part := range strings.Split(detail, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, modePrefix) {
			return strings.TrimPrefix(part, modePrefix)
		}
	}
	return ""
}

// classifyEvent updates summary counters based on the event type and action.
func classifyEvent(ev *Event, s *Summary) {
	evType := ev.Event

	if blockEventTypes[evType] {
		s.Blocks++
		if evType == eventKillSwitchDeny {
			s.Criticals++
			return
		}
		if eventSeverity(ev) == severityCritical {
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
	countedCritical := false

	switch evType {
	case eventBodyDLP, eventHeaderDLP, eventAddressProtection:
		if ev.Action == actionBlock {
			s.Blocks++
		} else {
			s.Warnings++
		}
	case eventResponseScan, eventWSScan:
		switch ev.Action {
		case actionBlock:
			s.Blocks++
		case actionWarn:
			s.Warnings++
		}
	case eventChainDetection:
		switch ev.Action {
		case actionBlock:
			s.Blocks++
			s.Criticals++
			countedCritical = true
		case actionWarn:
			s.Warnings++
		}
	case eventMCPUnknownTool:
		if ev.Action == actionBlock {
			s.Blocks++
		} else {
			s.Warnings++
		}
	}

	// Count criticals from resolved severity for events not already counted above.
	if !countedCritical && eventSeverity(ev) == severityCritical {
		s.Criticals++
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
	// Events whose type itself means "blocked" (e.g. "blocked", "ws_blocked")
	// don't carry an action field, but are high severity.
	if blockEventTypes[ev.Event] || ev.Action == actionBlock {
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
// IP-based hosts are fully redacted to prevent leaking internal addresses.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[redacted-url]"
	}
	if u.Host == "" {
		// Bare target (no scheme): could be "ip:port" or bare IP.
		return redactIP(raw)
	}
	// Redact IP-based hosts entirely.
	if host := u.Hostname(); net.ParseIP(host) != nil {
		return "[redacted-url]"
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

// maxDomains is the max domains shown in the domain breakdown.
const maxDomains = 20

// buildDomainStats converts the domain map to a sorted, capped slice.
func buildDomainStats(stats map[string]*DomainStats) []DomainStats {
	result := make([]DomainStats, 0, len(stats))
	for _, ds := range stats {
		result = append(result, *ds)
	}

	// Sort: domains with blocks first, then by total descending.
	sort.Slice(result, func(i, j int) bool {
		if result[i].Blocks != result[j].Blocks {
			return result[i].Blocks > result[j].Blocks
		}
		if result[i].Total != result[j].Total {
			return result[i].Total > result[j].Total
		}
		return result[i].Domain < result[j].Domain
	})

	if len(result) > maxDomains {
		result = result[:maxDomains]
	}

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
	step := timelineStep(duration)

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

	// Fill buckets. Skip administrative events (startup, shutdown, config_reload)
	// that are not actual network traffic.
	for i := range events {
		ev := &events[i]
		if ev.Event == eventStartup || ev.Event == eventShutdown || ev.Event == eventConfigReload {
			continue
		}

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

	// Trim trailing empty buckets so the chart doesn't waste space.
	for len(buckets) > 1 {
		last := buckets[len(buckets)-1]
		if last.Blocks+last.Warns+last.Allowed > 0 {
			break
		}
		buckets = buckets[:len(buckets)-1]
	}

	return buckets
}

// timelineStep picks a bucket duration that produces at least minBucketTarget
// bars for the observation window, clamped to human-readable intervals.
func timelineStep(duration time.Duration) time.Duration {
	switch {
	case duration >= time.Duration(hourlyThresholdDays)*24*time.Hour:
		return 24 * time.Hour
	case duration >= 12*time.Hour:
		return time.Hour
	case duration >= 2*time.Hour:
		return 15 * time.Minute // 2-12h: quarter-hour bars
	case duration >= 30*time.Minute:
		return 5 * time.Minute // 30m-2h: five-minute bars
	default:
		// Under 30 minutes: pick step so we get ~minBucketTarget bars.
		step := duration / minBucketTarget
		// Floor to whole minutes (minimum 1 minute).
		if step < time.Minute {
			step = time.Minute
		} else {
			step = step.Truncate(time.Minute)
		}
		return step
	}
}

// isBlockEvent checks if an event counts as a block for timeline purposes.
func isBlockEvent(ev *Event) bool {
	if blockEventTypes[ev.Event] {
		return true
	}
	switch ev.Event {
	case eventResponseScan, eventWSScan, eventBodyDLP, eventHeaderDLP, eventAddressProtection, eventChainDetection, eventMCPUnknownTool:
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
	case eventChainDetection, eventMCPUnknownTool:
		return ev.Action == actionWarn
	case eventBodyDLP, eventHeaderDLP, eventAddressProtection:
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
			if evCopy.ConnectHost != "" {
				evCopy.ConnectHost = redactIP(evCopy.ConnectHost)
			}
			if evCopy.SNIHost != "" {
				evCopy.SNIHost = redactIP(evCopy.SNIHost)
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

// buildDLPBreakdown computes DLP hits by detection surface.
func buildDLPBreakdown(events []Event) []DLPBreakdownEntry {
	type acc struct{ blocks, warns int }
	surfaces := map[string]*acc{
		"URL":            {},
		"Request Body":   {},
		"Request Header": {},
		"MCP Arguments":  {},
	}

	for i := range events {
		ev := &events[i]
		var surface string
		switch ev.Event {
		case "blocked":
			if ev.Scanner == "dlp" || ev.Scanner == "env_leak" {
				surface = "URL"
			}
		case eventBodyDLP:
			surface = "Request Body"
		case eventHeaderDLP:
			surface = "Request Header"
		case "mcp_input":
			if ev.Scanner == "mcp_input" || ev.Scanner == "" {
				surface = "MCP Arguments"
			}
		case eventAddressProtection:
			surface = "Request Body"
		default:
			continue
		}
		if surface == "" {
			continue
		}
		a := surfaces[surface]
		if ev.Action == actionBlock {
			a.blocks++
		} else {
			a.warns++
		}
	}

	var result []DLPBreakdownEntry
	for _, name := range []string{"URL", "Request Body", "Request Header", "MCP Arguments"} {
		a := surfaces[name]
		total := a.blocks + a.warns
		if total > 0 {
			result = append(result, DLPBreakdownEntry{
				Surface: name,
				Blocks:  a.blocks,
				Warns:   a.warns,
				Total:   total,
			})
		}
	}
	return result
}

// buildTransportBreakdown computes events by transport surface.
func buildTransportBreakdown(events []Event) []TransportBreakdownEntry {
	type acc struct{ blocks, warns, allowed int }
	transports := make(map[string]*acc)

	for i := range events {
		ev := &events[i]

		// Determine transport from event type or transport field.
		transport := "HTTP Fetch" // default
		switch {
		case ev.Transport == "mcp":
			transport = "MCP"
		case ev.Transport == "ws" || ev.Transport == "websocket":
			transport = "WebSocket"
		case ev.Event == "tunnel_open" || ev.Event == "tunnel_close" || ev.Transport == "connect":
			transport = "CONNECT Tunnel"
		case strings.HasPrefix(ev.Event, "ws_"):
			transport = "WebSocket"
		case strings.HasPrefix(ev.Event, "mcp_") || ev.Event == eventChainDetection:
			transport = "MCP"
		case ev.Event == eventStartup || ev.Event == eventShutdown || ev.Event == eventConfigReload:
			continue // skip admin events
		}

		a, ok := transports[transport]
		if !ok {
			a = &acc{}
			transports[transport] = a
		}

		switch {
		case isBlockEvent(ev):
			a.blocks++
		case isWarnEvent(ev):
			a.warns++
		default:
			a.allowed++
		}
	}

	// Sort by total descending.
	var result []TransportBreakdownEntry
	for name, a := range transports {
		total := a.blocks + a.warns + a.allowed
		if total > 0 {
			result = append(result, TransportBreakdownEntry{
				Transport: name,
				Blocks:    a.blocks,
				Warns:     a.warns,
				Allowed:   a.allowed,
				Total:     total,
			})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Total > result[j].Total
	})
	return result
}

// buildAgentBreakdown computes events per client/agent.
func buildAgentBreakdown(events []Event) []AgentBreakdownEntry {
	type acc struct{ blocks, warns, allowed int }
	agents := make(map[string]*acc)

	for i := range events {
		ev := &events[i]
		agent := ev.ClientIP
		if agent == "" {
			continue
		}
		if ev.Event == eventStartup || ev.Event == eventShutdown || ev.Event == eventConfigReload {
			continue
		}

		a, ok := agents[agent]
		if !ok {
			a = &acc{}
			agents[agent] = a
		}

		switch {
		case isBlockEvent(ev):
			a.blocks++
		case isWarnEvent(ev):
			a.warns++
		default:
			a.allowed++
		}
	}

	var result []AgentBreakdownEntry
	for agent, a := range agents {
		total := a.blocks + a.warns + a.allowed
		result = append(result, AgentBreakdownEntry{
			Agent:   agent,
			Blocks:  a.blocks,
			Warns:   a.warns,
			Allowed: a.allowed,
			Total:   total,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Blocks != result[j].Blocks {
			return result[i].Blocks > result[j].Blocks
		}
		return result[i].Total > result[j].Total
	})

	// Cap at 10 agents.
	if len(result) > 10 {
		result = result[:10]
	}
	return result
}

// buildMITRETechniques aggregates MITRE ATT&CK technique counts.
func buildMITRETechniques(events []Event) []MITRETechniqueEntry {
	counts := make(map[string]int)
	for i := range events {
		if events[i].MITRETechnique != "" {
			counts[events[i].MITRETechnique]++
		}
	}

	var result []MITRETechniqueEntry
	for tech, count := range counts {
		result = append(result, MITRETechniqueEntry{
			Technique: tech,
			Count:     count,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	return result
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
