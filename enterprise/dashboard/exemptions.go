//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cli/diag"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	ExemptionStateActive      = "active"
	ExemptionStateInert       = diag.ConfigSemanticKindInert
	ExemptionStateMisdirected = diag.ConfigSemanticKindMisdirected

	notTracked = "not tracked"
)

// ExemptionInventory is the read-only dashboard view over configured
// exemptions in the loaded Pipelock config.
type ExemptionInventory struct {
	ConfigLoaded     bool
	Entries          []ExemptionEntry
	Attention        []ExemptionEntry
	ConfiguredCount  int
	InertCount       int
	MisdirectedCount int
	TrackingNote     string
	// RawRedacted is true when this view was rendered without raw access, so
	// the sensitive configured values (destinations, IPs, addresses, paths,
	// rules, reasons) have been stripped and the template shows a "raw access
	// required" note. Knob names, states, and counts are preserved.
	RawRedacted bool
}

// redactExemptions strips the raw-sensitive surface from an inventory view: the
// configured Scope value, every Attribute value, and the remediation Detail/Next
// text (which can embed a configured value). It keeps the non-sensitive
// structure — knob names, State, and the counts — so a metadata-only operator
// still sees which knobs have inert/misdirected exemptions and how many, without
// a map of internal destinations and enforcement exceptions. Mirrors the
// evidence view's redactRaw boundary. Operates on the freshly built value so raw
// bytes never reach a metadata response.
func redactExemptions(inv ExemptionInventory) ExemptionInventory {
	inv.RawRedacted = true
	inv.Entries = redactExemptionEntries(inv.Entries)
	inv.Attention = redactExemptionEntries(inv.Attention)
	return inv
}

func redactExemptionEntries(entries []ExemptionEntry) []ExemptionEntry {
	if len(entries) == 0 {
		return entries
	}
	out := make([]ExemptionEntry, len(entries))
	for i, e := range entries {
		e.Scope = redactedDestination
		e.semanticSubject = ""
		if e.Detail != "" {
			e.Detail = redactedDestination
		}
		if e.Next != "" {
			e.Next = redactedDestination
		}
		// Owner and Reason can name internal systems; redact them under the
		// metadata (non-raw) view. Keep the lifecycle status (bounded string)
		// and expiry date visible since they carry no sensitive content.
		if e.Owner != notTracked {
			e.Owner = redactedDestination
		}
		if e.Reason != notTracked {
			e.Reason = redactedDestination
		}
		if len(e.Attributes) > 0 {
			redactedAttrs := make([]ExemptionAttribute, len(e.Attributes))
			for j, a := range e.Attributes {
				redactedAttrs[j] = ExemptionAttribute{Name: a.Name, Value: redactedDestination}
			}
			e.Attributes = redactedAttrs
		}
		out[i] = e
	}
	return out
}

// ExemptionEntry is one configured exemption-like knob value.
type ExemptionEntry struct {
	Scanner    string
	Knob       string
	Scope      string
	Attributes []ExemptionAttribute
	State      string
	Detail     string
	Next       string
	// Lifecycle fields populated by the exemption store overlay.
	Owner     string
	Reason    string
	Expiry    string
	Lifecycle string // bounded: "active" | "EXPIRED ..." | "stale ..." | "not observed" | "not tracked"
	// LifecycleExpired / LifecycleStale drive the loud template styling without
	// the template comparing raw status strings (which would drift if the store
	// constants change).
	LifecycleExpired bool
	LifecycleStale   bool
	// LastMatched display string (from the store or "not tracked").
	LastMatched string
	Suppressed  string

	semanticSubject string
}

// ExemptionAttribute is a real config attribute attached to an exemption.
type ExemptionAttribute struct {
	Name  string
	Value string
}

// Exemptions builds a unified read-only inventory of configured exemptions.
func (m *ReadModel) Exemptions() ExemptionInventory {
	if m == nil || m.cfg == nil {
		return ExemptionInventory{
			ConfigLoaded: false,
			TrackingNote: "owner/expiry/last-matched/suppressed-count telemetry is not tracked",
		}
	}
	entries := enumerateExemptionEntries(m.cfg)
	joinSemanticFindings(entries, diag.AnalyzeConfigSemantics(m.cfg))
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Knob != entries[j].Knob {
			return entries[i].Knob < entries[j].Knob
		}
		if entries[i].Scanner != entries[j].Scanner {
			return entries[i].Scanner < entries[j].Scanner
		}
		return entries[i].Scope < entries[j].Scope
	})

	// Overlay the exemption lifecycle store onto the inventory entries.
	if m.exemptionStore != nil {
		now := m.now()
		overlayExemptionLifecycle(entries, m.exemptionStore, now)
	}

	trackingNote := "owner/expiry/last-matched/suppressed-count telemetry is not tracked"
	if m.exemptionStore != nil {
		trackingNote = "lifecycle tracked via exemption store"
	}

	inventory := ExemptionInventory{
		ConfigLoaded:    true,
		Entries:         entries,
		ConfiguredCount: len(entries),
		TrackingNote:    trackingNote,
	}
	for _, entry := range entries {
		switch entry.State {
		case ExemptionStateInert:
			inventory.InertCount++
			inventory.Attention = append(inventory.Attention, entry)
		case ExemptionStateMisdirected:
			inventory.MisdirectedCount++
			inventory.Attention = append(inventory.Attention, entry)
		}
	}
	return inventory
}

func enumerateExemptionEntries(cfg *config.Config) []ExemptionEntry {
	var entries []ExemptionEntry
	addDomainList := func(scanner, knob string, domains []string) {
		for _, domain := range domains {
			entries = append(entries, newExemptionEntry(scanner, knob, domain, domain))
		}
	}

	for _, entry := range cfg.Suppress {
		entries = append(entries, newExemptionEntry("Proxy scanners", diag.ConfigScopeSuppress, entry.Path, strings.ToLower(entry.Rule),
			attr("rule", entry.Rule),
			attrIfSet("reason", entry.Reason),
		))
	}
	addDomainList("Strict-mode reachability", "api_allowlist", cfg.APIAllowlist)
	for _, pattern := range cfg.FileSentry.IgnorePatterns {
		entries = append(entries, newExemptionEntry("File sentry", "file_sentry.ignore_patterns", pattern, pattern))
	}
	for _, pattern := range cfg.DLP.Patterns {
		for _, domain := range pattern.ExemptDomains {
			entries = append(entries, newExemptionEntry("DLP", "dlp.patterns[].exempt_domains", domain, domain,
				attr("pattern", pattern.Name),
			))
		}
	}
	addDomainList("Response scanning", diag.ConfigScopeResponseExemptDomains, cfg.ResponseScanning.ExemptDomains)
	addDomainList("Response scanning size limit", "response_scanning.size_exempt_domains", cfg.ResponseScanning.SizeExemptDomains)
	for _, entry := range cfg.ResponseScanning.UnscannablePassthrough {
		entries = append(entries, newExemptionEntry("Response scanning passthrough", "response_scanning.unscannable_passthrough", entry.Host, entry.Host,
			attrIfSet("paths", strings.Join(entry.Paths, ", ")),
			attrIfSet("content_types", strings.Join(entry.ContentTypes, ", ")),
			attrIfSet("reason", entry.Reason),
		))
	}
	for _, entry := range cfg.ResponseScanning.MCPServers {
		entries = append(entries, newExemptionEntry("MCP response trust", diag.ConfigScopeResponseMCPServers, entry.Server, entry.Server,
			attr("trust", entry.Trust),
		))
	}

	addDomainList("Query entropy", "fetch_proxy.monitoring.query_entropy_exclusions", cfg.FetchProxy.Monitoring.QueryEntropyExclusions)
	addDomainList("Subdomain entropy", "fetch_proxy.monitoring.subdomain_entropy_exclusions", cfg.FetchProxy.Monitoring.SubdomainEntropyExclusions)
	for _, entry := range cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions {
		tuple := queryEntropyParamScope(entry)
		entries = append(entries, newExemptionEntry("Query entropy parameter", "fetch_proxy.monitoring.query_entropy_param_exclusions", tuple, tuple,
			attr("host", entry.Host),
			attr("path", entry.Path),
			attr("param", entry.Param),
			attrIfSet("scheme", entry.Scheme),
			attrIfSet("reason", entry.Reason),
		))
	}

	addDomainList("TLS interception", diag.ConfigScopeTLSPassthroughDomains, cfg.TLSInterception.PassthroughDomains)
	addDomainList("SSRF", "trusted_domains", cfg.TrustedDomains)
	addDomainList("SSRF", "ssrf.ip_allowlist", cfg.SSRF.IPAllowlist)
	for _, cidr := range cfg.KillSwitch.AllowlistIPs {
		entries = append(entries, newExemptionEntry("Kill switch", "kill_switch.allowlist_ips", cidr, cidr))
	}
	addBooleanExemption := func(knob, scope string, enabled *bool) {
		if enabled == nil || !*enabled {
			return
		}
		entries = append(entries, newExemptionEntry("Kill switch", knob, scope, scope, attr("value", "true")))
	}
	addBooleanExemption("kill_switch.health_exempt", "health endpoints", cfg.KillSwitch.HealthExempt)
	addBooleanExemption("kill_switch.metrics_exempt", "metrics endpoints", cfg.KillSwitch.MetricsExempt)
	addBooleanExemption("kill_switch.api_exempt", "kill-switch API endpoints", cfg.KillSwitch.APIExempt)
	addDomainList("Adaptive enforcement", diag.ConfigScopeAdaptiveExemptDomains, cfg.AdaptiveEnforcement.ExemptDomains)
	addDomainList("Cross-request entropy", diag.ConfigScopeCrossRequestEntropyExempt, cfg.CrossRequestDetection.EntropyBudget.ExemptDomains)
	addDomainList("Browser shield", diag.ConfigScopeBrowserShieldExemptDomains, cfg.BrowserShield.ExemptDomains)
	for _, header := range cfg.RequestBodyScanning.IgnoreHeaders {
		entries = append(entries, newExemptionEntry("Request header DLP", diag.ConfigScopeRequestBodyIgnoreHeaders, header, strings.ToLower(header)))
	}
	addDomainList("Taint trust", "taint.allowlisted_domains", cfg.Taint.AllowlistedDomains)
	addDomainList("Taint trust", "taint.trusted_mcp_servers", cfg.Taint.TrustedMCPServers)
	for _, override := range cfg.Taint.TrustOverrides {
		scope := override.Scope
		if scope == "" {
			scope = override.SourceMatch
		}
		entries = append(entries, newExemptionEntry("Taint trust", "taint.trust_overrides", scope, scope,
			attrIfSet("source_match", override.SourceMatch),
			attrIfSet("action_match", override.ActionMatch),
			attrIfSet("reason", override.Reason),
		))
	}

	addDomainList("Address protection", "address_protection.allowed_addresses", cfg.AddressProtection.AllowedAddresses)
	if cfg.ReverseProxy.TrustedUpstream.Host != "" || cfg.ReverseProxy.TrustedUpstream.Port != 0 {
		upstream := cfg.ReverseProxy.TrustedUpstream
		scope := upstream.Host
		if upstream.Port != 0 {
			scope = fmt.Sprintf("%s:%d", upstream.Host, upstream.Port)
		}
		entries = append(entries, newExemptionEntry("Reverse proxy", "reverse_proxy.trusted_upstream", scope, scope,
			attrIfSet("reason", upstream.Reason),
			attrIfSet("added", upstream.Added),
		))
	}

	agentNames := make([]string, 0, len(cfg.Agents))
	for name := range cfg.Agents {
		agentNames = append(agentNames, name)
	}
	sort.Strings(agentNames)
	for _, name := range agentNames {
		profile := cfg.Agents[name]
		for _, domain := range profile.TrustedDomains {
			entries = append(entries, newExemptionEntry("Agent SSRF", "agents[].trusted_domains", domain, domain, attr("agent", name)))
		}
		for _, domain := range profile.APIAllowlist {
			entries = append(entries, newExemptionEntry("Agent strict-mode reachability", "agents[].api_allowlist", domain, domain, attr("agent", name)))
		}
		for _, address := range profile.AllowedAddresses {
			entries = append(entries, newExemptionEntry("Agent address protection", "agents[].allowed_addresses", address, address, attr("agent", name)))
		}
	}

	return entries
}

func newExemptionEntry(scanner, knob, scope, matchValue string, attributes ...ExemptionAttribute) ExemptionEntry {
	return ExemptionEntry{
		Scanner:         scanner,
		Knob:            knob,
		Scope:           scope,
		Attributes:      compactAttributes(attributes),
		State:           ExemptionStateActive,
		Owner:           notTracked,
		Reason:          notTracked,
		Expiry:          notTracked,
		Lifecycle:       notTracked,
		LastMatched:     notTracked,
		Suppressed:      notTracked,
		semanticSubject: normalizeExemptionSemanticSubject(knob, matchValue),
	}
}

func normalizeExemptionSemanticSubject(knob, subject string) string {
	subject = strings.TrimSpace(subject)
	switch knob {
	case diag.ConfigScopeSuppress, diag.ConfigScopeRequestBodyIgnoreHeaders:
		return strings.ToLower(subject)
	default:
		return subject
	}
}

func compactAttributes(attributes []ExemptionAttribute) []ExemptionAttribute {
	out := attributes[:0]
	for _, attribute := range attributes {
		if strings.TrimSpace(attribute.Value) == "" {
			continue
		}
		out = append(out, attribute)
	}
	return out
}

func attr(name, value string) ExemptionAttribute {
	return ExemptionAttribute{Name: name, Value: value}
}

func attrIfSet(name, value string) ExemptionAttribute {
	return ExemptionAttribute{Name: name, Value: strings.TrimSpace(value)}
}

func queryEntropyParamScope(entry config.QueryEntropyParamExclusion) string {
	scheme := entry.Scheme
	if scheme == "" {
		scheme = config.QueryEntropyParamDefaultScheme
	}
	return fmt.Sprintf("%s://%s%s?%s", scheme, entry.Host, entry.Path, entry.Param)
}

func joinSemanticFindings(entries []ExemptionEntry, findings []diag.ConfigSemanticFinding) {
	for _, finding := range findings {
		if finding.Kind != diag.ConfigSemanticKindInert && finding.Kind != diag.ConfigSemanticKindMisdirected {
			continue
		}
		for i := range entries {
			if !semanticFindingMatchesEntry(finding, entries[i]) {
				continue
			}
			entries[i].State = finding.Kind
			entries[i].Detail = finding.Detail
			entries[i].Next = finding.Next
		}
	}
}

// overlayExemptionLifecycle joins lifecycle records from the store onto the
// inventory entries. For each entry, if a record with matching Scope exists
// in the store, its Owner, Reason, Expiry, Lifecycle status, and
// LastMatched are populated. Entries without a matching record keep their
// "not tracked" defaults.
func overlayExemptionLifecycle(entries []ExemptionEntry, store *ExemptionStore, now time.Time) {
	for i := range entries {
		rec, ok := store.Find(entries[i].Scope, now)
		if !ok {
			continue
		}
		entries[i].Owner = rec.Owner
		entries[i].Reason = rec.Reason
		entries[i].Expiry = rec.Expiry.Format(time.RFC3339)
		entries[i].Lifecycle = rec.Status(now)
		entries[i].LifecycleExpired = entries[i].Lifecycle == lifecycleExpired
		entries[i].LifecycleStale = entries[i].Lifecycle == lifecycleStale
		if rec.LastMatched != nil {
			entries[i].LastMatched = rec.LastMatched.Format(time.RFC3339)
		} else {
			entries[i].LastMatched = lifecycleUnobserved
		}
	}
}

func semanticFindingMatchesEntry(finding diag.ConfigSemanticFinding, entry ExemptionEntry) bool {
	if finding.Scope != entry.Knob {
		return false
	}
	if finding.Subject == "" {
		return true
	}
	return finding.Subject != "" && finding.Subject == entry.semanticSubject
}
