package report

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	testClientIP    = "10.0.0.1"
	testRequestID   = "req-001"
	testVersion     = "0.3.5"
	testHash        = "abc123"
	testHash2       = "def456"
	testMode        = "balanced"
	testDLPEvent    = "blocked"
	testScanner     = "dlp"
	testEvStartup   = "startup"
	testEvRespScan  = "response_scan"
	testEvCfgReload = "config_reload"
)

const fixtureJSONL = `{"level":"info","time":"2026-03-05T10:00:00Z","component":"pipelock","event":"startup","listen":":8888","mode":"balanced","version":"0.3.5","config_hash":"abc123","message":"pipelock started"}
{"level":"info","time":"2026-03-05T10:00:01Z","component":"pipelock","event":"allowed","method":"GET","url":"https://api.example.com/data","client_ip":"10.0.0.1","request_id":"req-001","status_code":200,"size_bytes":1234,"message":"request allowed"}
{"level":"warn","time":"2026-03-05T10:00:02Z","component":"pipelock","event":"blocked","method":"GET","url":"https://evil.com/exfil?key=secret","client_ip":"10.0.0.1","request_id":"req-002","scanner":"dlp","reason":"AWS key pattern matched","mitre_technique":"T1048","message":"request blocked"}
{"level":"warn","time":"2026-03-05T10:00:03Z","component":"pipelock","event":"response_scan","url":"https://docs.example.com","client_ip":"10.0.0.1","request_id":"req-003","action":"warn","match_count":2,"patterns":["ignore_instructions","system_prompt"],"mitre_technique":"T1059","message":"response scan detected prompt injection"}
{"level":"info","time":"2026-03-05T10:00:04Z","component":"pipelock","event":"config_reload","status":"success","detail":"mode=strict","config_hash":"def456","message":"configuration reloaded"}
{"level":"warn","time":"2026-03-05T10:00:05Z","component":"pipelock","event":"chain_detection","pattern":"read-then-exec","severity":"high","action":"warn","tool":"execute_command","session":"sess-1","mitre_technique":"T1059","message":"chain pattern detected"}
{"level":"info","time":"2026-03-05T10:00:06Z","component":"pipelock","event":"kill_switch_deny","transport":"http","endpoint":"/fetch","source":"api","deny_message":"emergency shutdown","client_ip":"10.0.0.1","message":"kill switch denied request"}
`

// ---- Parsing tests ----

func TestParseEvents_Basic(t *testing.T) {
	result, err := ParseEvents(strings.NewReader(fixtureJSONL), ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 7 {
		t.Fatalf("expected 7 events, got %d", len(result.Events))
	}
	if result.SkippedLines != 0 {
		t.Errorf("expected 0 skipped lines, got %d", result.SkippedLines)
	}

	// Verify sorted by time.
	for i := 1; i < len(result.Events); i++ {
		if result.Events[i].Time.Before(result.Events[i-1].Time) {
			t.Errorf("events not sorted at index %d", i)
		}
	}

	// Verify first event is startup.
	if result.Events[0].Event != testEvStartup {
		t.Errorf("expected first event to be startup, got %q", result.Events[0].Event)
	}
	if result.Events[0].Version != testVersion {
		t.Errorf("expected version %q, got %q", testVersion, result.Events[0].Version)
	}
}

func TestParseEvents_TimeFilter(t *testing.T) {
	since := time.Date(2026, 3, 5, 10, 0, 3, 0, time.UTC)
	until := time.Date(2026, 3, 5, 10, 0, 5, 0, time.UTC)

	result, err := ParseEvents(strings.NewReader(fixtureJSONL), ParseOptions{
		Since: since,
		Until: until,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should include events at 10:00:03 and 10:00:04, but not 10:00:05 (at or after Until).
	if len(result.Events) != 2 {
		t.Fatalf("expected 2 events with time filter, got %d", len(result.Events))
	}
	if result.Events[0].Event != testEvRespScan {
		t.Errorf("expected response_scan, got %q", result.Events[0].Event)
	}
	if result.Events[1].Event != testEvCfgReload {
		t.Errorf("expected config_reload, got %q", result.Events[1].Event)
	}
}

func TestParseEvents_MalformedLines(t *testing.T) {
	input := `{"level":"info","time":"2026-03-05T10:00:00Z","event":"startup","message":"ok"}
this is not json
{"level":"info","time":"2026-03-05T10:00:01Z","event":"allowed","message":"ok2"}
{broken json
`

	result, err := ParseEvents(strings.NewReader(input), ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected 2 events (malformed skipped), got %d", len(result.Events))
	}
	if result.SkippedLines != 2 {
		t.Errorf("expected 2 skipped lines, got %d", result.SkippedLines)
	}
}

func TestParseEvents_Empty(t *testing.T) {
	result, err := ParseEvents(strings.NewReader(""), ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(result.Events))
	}
}

func TestParseEvents_EmptyLines(t *testing.T) {
	input := `
{"level":"info","time":"2026-03-05T10:00:00Z","event":"startup","message":"ok"}

`
	result, err := ParseEvents(strings.NewReader(input), ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result.Events))
	}
	if result.SkippedLines != 0 {
		t.Errorf("empty lines should not count as skipped, got %d", result.SkippedLines)
	}
}

func TestGenerate_SkippedLinesInReport(t *testing.T) {
	input := `{"level":"info","time":"2026-03-05T10:00:00Z","event":"startup","message":"ok"}
this is not json
{"level":"info","time":"2026-03-05T10:00:01Z","event":"allowed","message":"ok2"}
{broken json
`

	r, err := Generate(strings.NewReader(input), ParseOptions{}, Options{})
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if r.Summary.SkippedLines != 2 {
		t.Errorf("expected 2 skipped lines in report summary, got %d", r.Summary.SkippedLines)
	}
}

// ---- Aggregation tests ----

func TestAggregate_GreenReport(t *testing.T) {
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvStartup, Version: testVersion, Mode: testMode, ConfigHash: testHash},
		{Time: time.Date(2026, 3, 5, 10, 0, 1, 0, time.UTC), Event: "allowed", URL: "https://api.example.com/data", ClientIP: testClientIP},
		{Time: time.Date(2026, 3, 5, 10, 0, 2, 0, time.UTC), Event: "allowed", URL: "https://cdn.example.com/js", ClientIP: testClientIP},
	}

	r := Aggregate(events, Options{})

	if r.Risk != RiskGreen {
		t.Errorf("expected green risk, got %q", r.Risk)
	}
	if r.Summary.TotalEvents != 3 {
		t.Errorf("expected 3 total events, got %d", r.Summary.TotalEvents)
	}
	if r.Summary.Allowed != 2 {
		t.Errorf("expected 2 allowed, got %d", r.Summary.Allowed)
	}
	if r.Summary.Blocks != 0 {
		t.Errorf("expected 0 blocks, got %d", r.Summary.Blocks)
	}
	if r.Summary.UniqueDomains != 2 {
		t.Errorf("expected 2 unique domains, got %d", r.Summary.UniqueDomains)
	}
}

func TestAggregate_YellowReport(t *testing.T) {
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvStartup, Version: testVersion, Mode: testMode, ConfigHash: testHash},
		{Time: time.Date(2026, 3, 5, 10, 0, 1, 0, time.UTC), Event: "allowed", URL: "https://api.example.com/data"},
		{Time: time.Date(2026, 3, 5, 10, 0, 2, 0, time.UTC), Event: testDLPEvent, URL: "https://evil.com/exfil", Scanner: testScanner, Reason: "AWS key matched", MITRETechnique: "T1048"},
	}

	r := Aggregate(events, Options{})

	if r.Risk != RiskYellow {
		t.Errorf("expected yellow risk, got %q", r.Risk)
	}
	if r.Summary.Blocks != 1 {
		t.Errorf("expected 1 block, got %d", r.Summary.Blocks)
	}
}

func TestAggregate_RedReport(t *testing.T) {
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvStartup, Version: testVersion, Mode: testMode, ConfigHash: testHash},
		{Time: time.Date(2026, 3, 5, 10, 0, 1, 0, time.UTC), Event: "kill_switch_deny", Transport: "http", ClientIP: testClientIP},
	}

	r := Aggregate(events, Options{})

	if r.Risk != RiskRed {
		t.Errorf("expected red risk, got %q", r.Risk)
	}
	if r.Summary.Criticals != 1 {
		t.Errorf("expected 1 critical, got %d", r.Summary.Criticals)
	}
	if r.Summary.Blocks != 1 {
		t.Errorf("expected 1 block, got %d", r.Summary.Blocks)
	}
}

func TestAggregate_RedReport_ChainBlock(t *testing.T) {
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvStartup, Version: testVersion, Mode: testMode, ConfigHash: testHash},
		{Time: time.Date(2026, 3, 5, 10, 0, 1, 0, time.UTC), Event: "chain_detection", Action: actionBlock, Pattern: "read-then-exec", MITRETechnique: "T1059"},
	}

	r := Aggregate(events, Options{})

	if r.Risk != RiskRed {
		t.Errorf("expected red risk for chain_detection block, got %q", r.Risk)
	}
	if r.Summary.Criticals != 1 {
		t.Errorf("expected 1 critical, got %d", r.Summary.Criticals)
	}
}

func TestAggregate_MultipleConfigHashes(t *testing.T) {
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvStartup, Version: testVersion, Mode: testMode, ConfigHash: testHash},
		{Time: time.Date(2026, 3, 5, 10, 0, 4, 0, time.UTC), Event: testEvCfgReload, ConfigHash: testHash2},
	}

	r := Aggregate(events, Options{})

	if len(r.ConfigHashes) != 2 {
		t.Fatalf("expected 2 config hashes, got %d", len(r.ConfigHashes))
	}
	if r.ConfigHashes[0] != testHash {
		t.Errorf("expected first hash %q, got %q", testHash, r.ConfigHashes[0])
	}
	if r.ConfigHashes[1] != testHash2 {
		t.Errorf("expected second hash %q, got %q", testHash2, r.ConfigHashes[1])
	}
}

func TestAggregate_DuplicateConfigHash(t *testing.T) {
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvStartup, ConfigHash: testHash},
		{Time: time.Date(2026, 3, 5, 10, 0, 4, 0, time.UTC), Event: testEvCfgReload, ConfigHash: testHash},
	}

	r := Aggregate(events, Options{})

	if len(r.ConfigHashes) != 1 {
		t.Fatalf("expected 1 unique config hash, got %d", len(r.ConfigHashes))
	}
}

func TestAggregate_EvidenceCap(t *testing.T) {
	var events []Event
	events = append(events, Event{
		Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvStartup,
		Version: testVersion, Mode: testMode, ConfigHash: testHash,
	})

	// Generate more warn events than the cap.
	for i := range 150 {
		events = append(events, Event{
			Time:    time.Date(2026, 3, 5, 10, 0, 1+i, 0, time.UTC),
			Event:   "anomaly",
			Scanner: "ssrf",
			URL:     "https://evil.com/test",
		})
	}

	r := Aggregate(events, Options{MaxEvidence: 50})

	if len(r.Evidence) != 50 {
		t.Errorf("expected evidence capped at 50, got %d", len(r.Evidence))
	}
}

func TestAggregate_Redaction(t *testing.T) {
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvStartup, Version: testVersion, Mode: testMode, ConfigHash: testHash},
		{
			Time: time.Date(2026, 3, 5, 10, 0, 1, 0, time.UTC), Event: testDLPEvent,
			URL: "https://evil.com/exfil?key=secret", Scanner: testScanner,
			Reason: "AWS key matched", ClientIP: testClientIP,
			MITRETechnique: "T1048",
		},
	}

	r := Aggregate(events, Options{Redact: true})

	// Evidence should have redacted IP.
	for _, ev := range r.Evidence {
		if strings.Contains(ev.ClientIP, "10.0.0.1") {
			t.Error("expected IP to be redacted in evidence")
		}
		if ev.URL != "" && strings.Contains(ev.URL, "/exfil") {
			t.Error("expected URL path to be stripped in evidence")
		}
	}

	// Category samples should have redacted URL.
	for _, cat := range r.Categories {
		for _, sample := range cat.SampleEvidence {
			if strings.Contains(sample, "?key=secret") {
				t.Error("expected URL query to be stripped in sample evidence")
			}
		}
	}
}

func TestAggregate_RedactionSNIFields(t *testing.T) {
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvStartup, Version: testVersion, Mode: testMode, ConfigHash: testHash},
		{
			Time: time.Date(2026, 3, 5, 10, 0, 1, 0, time.UTC), Event: "sni_mismatch",
			ConnectHost: "169.254.169.254", SNIHost: "192.168.1.100",
			ClientIP: testClientIP, MITRETechnique: "T1090",
		},
	}

	r := Aggregate(events, Options{Redact: true})

	for _, ev := range r.Evidence {
		if ev.Event != "sni_mismatch" {
			continue
		}
		if strings.Contains(ev.ConnectHost, "169.254") {
			t.Error("expected connect_host IP to be redacted")
		}
		if strings.Contains(ev.SNIHost, "192.168") {
			t.Error("expected sni_host IP to be redacted")
		}
		if strings.Contains(ev.ClientIP, "10.0.0") {
			t.Error("expected client_ip to be redacted")
		}
	}
}

func TestEventSeverity_PlainBlockedIsHigh(t *testing.T) {
	// Plain "blocked" events (URL/DLP/SSRF blocks) have no action field,
	// but should be high severity because the event type itself means blocked.
	ev := &Event{Event: "blocked", Scanner: "dlp", URL: "https://evil.com"}
	sev := eventSeverity(ev)
	if sev != severityHigh {
		t.Errorf("expected blocked event to be high severity, got %q", sev)
	}

	// ws_blocked should also be high.
	wsEv := &Event{Event: "ws_blocked", Scanner: "dlp"}
	wsSev := eventSeverity(wsEv)
	if wsSev != severityHigh {
		t.Errorf("expected ws_blocked event to be high severity, got %q", wsSev)
	}
}

func TestAggregate_Categories(t *testing.T) {
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvStartup, Version: testVersion, Mode: testMode, ConfigHash: testHash},
		{Time: time.Date(2026, 3, 5, 10, 0, 1, 0, time.UTC), Event: testDLPEvent, Scanner: testScanner, MITRETechnique: "T1048", URL: "https://evil.com/a"},
		{Time: time.Date(2026, 3, 5, 10, 0, 2, 0, time.UTC), Event: testDLPEvent, Scanner: testScanner, MITRETechnique: "T1048", URL: "https://evil.com/b"},
		{Time: time.Date(2026, 3, 5, 10, 0, 3, 0, time.UTC), Event: testEvRespScan, Action: actionWarn, MITRETechnique: "T1059", URL: "https://docs.example.com"},
		{Time: time.Date(2026, 3, 5, 10, 0, 4, 0, time.UTC), Event: "kill_switch_deny", Transport: "http"},
	}

	r := Aggregate(events, Options{})

	if len(r.Categories) < 3 {
		t.Fatalf("expected at least 3 categories, got %d", len(r.Categories))
	}

	// DLP should have count 2 and be first (highest count).
	found := false
	for _, cat := range r.Categories {
		if cat.Name == "DLP / Exfiltration" {
			found = true
			if cat.Count != 2 {
				t.Errorf("expected DLP count 2, got %d", cat.Count)
			}
		}
	}
	if !found {
		t.Error("DLP / Exfiltration category not found")
	}
}

func TestAggregate_EmptyEvents(t *testing.T) {
	r := Aggregate(nil, Options{})

	if r.Risk != RiskGreen {
		t.Errorf("expected green risk for empty, got %q", r.Risk)
	}
	if r.Summary.TotalEvents != 0 {
		t.Errorf("expected 0 events, got %d", r.Summary.TotalEvents)
	}
	if r.ConfigHashes == nil {
		t.Error("expected non-nil ConfigHashes slice")
	}
	if r.Categories == nil {
		t.Error("expected non-nil Categories slice")
	}
	if r.Timeline == nil {
		t.Error("expected non-nil Timeline slice")
	}
	if r.Evidence == nil {
		t.Error("expected non-nil Evidence slice")
	}
}

func TestAggregate_BodyDLPBlock(t *testing.T) {
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvStartup, Version: testVersion, Mode: testMode, ConfigHash: testHash},
		{Time: time.Date(2026, 3, 5, 10, 0, 1, 0, time.UTC), Event: "body_dlp", Action: actionBlock, URL: "https://api.com/data", MITRETechnique: "T1048"},
	}

	r := Aggregate(events, Options{})

	if r.Summary.Blocks != 1 {
		t.Errorf("expected 1 block for body_dlp block action, got %d", r.Summary.Blocks)
	}
}

func TestAggregate_BodyDLPWarn(t *testing.T) {
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvStartup, Version: testVersion, Mode: testMode, ConfigHash: testHash},
		{Time: time.Date(2026, 3, 5, 10, 0, 1, 0, time.UTC), Event: "body_dlp", Action: actionWarn, URL: "https://api.com/data"},
	}

	r := Aggregate(events, Options{})

	if r.Summary.Warnings != 1 {
		t.Errorf("expected 1 warning for body_dlp warn action, got %d", r.Summary.Warnings)
	}
}

func TestAggregate_DomainExtraction(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		target   string
		expected string
	}{
		{name: "full_url", url: "https://api.example.com/path?q=1", expected: "api.example.com"},
		{name: "host_port", target: "evil.com:443", expected: "evil.com"},
		{name: "bare_host", target: "example.org", expected: "example.org"},
		{name: "empty", url: "", target: "", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &Event{URL: tt.url, Target: tt.target}
			got := extractDomain(ev)
			if got != tt.expected {
				t.Errorf("extractDomain(%q, %q) = %q, want %q", tt.url, tt.target, got, tt.expected)
			}
		})
	}
}

// ---- Rendering tests ----

func TestRenderHTML_Basic(t *testing.T) {
	r := &Report{
		Title:        "Test Report",
		Generated:    time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC),
		Version:      testVersion,
		ConfigHashes: []string{testHash},
		Mode:         testMode,
		Risk:         RiskYellow,
		TimeRange: TimeRange{
			Start: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC),
			End:   time.Date(2026, 3, 5, 11, 0, 0, 0, time.UTC),
		},
		Summary: Summary{
			TotalEvents:   100,
			Blocks:        5,
			Warnings:      10,
			Criticals:     0,
			Allowed:       85,
			UniqueDomains: 20,
		},
		Categories: []CategoryStats{
			{Name: "DLP / Exfiltration", Count: 5, Severity: severityHigh, MITRETechniques: []string{"T1048"}},
		},
		Timeline: []TimeBucket{},
		Evidence: []Event{},
	}

	var buf bytes.Buffer
	if err := RenderHTML(&buf, r); err != nil {
		t.Fatalf("RenderHTML error: %v", err)
	}

	html := buf.String()
	checks := []string{
		"Test Report",
		"MODERATE",
		"#eab308",
		testVersion,
		testMode,
		"DLP / Exfiltration",
		"T1048",
		testHash,
	}
	for _, check := range checks {
		if !strings.Contains(html, check) {
			t.Errorf("HTML missing expected string %q", check)
		}
	}
}

func TestRenderHTML_EmptyEvidence(t *testing.T) {
	r := &Report{
		Title:        DefaultTitle,
		Generated:    time.Now().UTC(),
		ConfigHashes: []string{},
		Risk:         RiskGreen,
		TimeRange:    TimeRange{Start: time.Now().UTC(), End: time.Now().UTC()},
		Summary:      Summary{},
		Categories:   []CategoryStats{},
		Timeline:     []TimeBucket{},
		Evidence:     []Event{},
	}

	var buf bytes.Buffer
	if err := RenderHTML(&buf, r); err != nil {
		t.Fatalf("RenderHTML error: %v", err)
	}

	html := buf.String()
	if strings.Contains(html, "Evidence Appendix") {
		t.Error("expected no evidence section when evidence is empty")
	}
}

func TestRenderHTML_AllRiskLevels(t *testing.T) {
	tests := []struct {
		risk     RiskRating
		label    string
		colorHex string
	}{
		{RiskRed, "HIGH RISK", "#f44336"},
		{RiskYellow, "MODERATE", "#eab308"},
		{RiskGreen, "LOW RISK", "#00CC66"},
	}

	for _, tt := range tests {
		t.Run(string(tt.risk), func(t *testing.T) {
			r := &Report{
				Title:        DefaultTitle,
				Generated:    time.Now().UTC(),
				ConfigHashes: []string{},
				Risk:         tt.risk,
				TimeRange:    TimeRange{Start: time.Now().UTC(), End: time.Now().UTC()},
				Summary:      Summary{},
				Categories:   []CategoryStats{},
				Timeline:     []TimeBucket{},
				Evidence:     []Event{},
			}

			var buf bytes.Buffer
			if err := RenderHTML(&buf, r); err != nil {
				t.Fatalf("RenderHTML error: %v", err)
			}

			html := buf.String()
			if !strings.Contains(html, tt.label) {
				t.Errorf("expected label %q for risk %q", tt.label, tt.risk)
			}
			if !strings.Contains(html, tt.colorHex) {
				t.Errorf("expected color %q for risk %q", tt.colorHex, tt.risk)
			}
		})
	}
}

func TestRenderJSON_Roundtrip(t *testing.T) {
	original := &Report{
		Title:        "JSON Test",
		Generated:    time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC),
		Version:      testVersion,
		ConfigHashes: []string{testHash, testHash2},
		Mode:         testMode,
		Risk:         RiskYellow,
		TimeRange: TimeRange{
			Start: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC),
			End:   time.Date(2026, 3, 5, 11, 0, 0, 0, time.UTC),
		},
		Summary: Summary{
			TotalEvents: 10,
			Blocks:      2,
			Warnings:    3,
		},
		Categories: []CategoryStats{
			{Name: "DLP / Exfiltration", Count: 2, Severity: severityHigh, MITRETechniques: []string{"T1048"}},
		},
		Timeline: []TimeBucket{},
		Evidence: []Event{},
	}

	var buf bytes.Buffer
	if err := RenderJSON(&buf, original); err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	if decoded.Title != original.Title {
		t.Errorf("title mismatch: %q vs %q", decoded.Title, original.Title)
	}
	if decoded.Risk != original.Risk {
		t.Errorf("risk mismatch: %q vs %q", decoded.Risk, original.Risk)
	}
	if decoded.Summary.Blocks != original.Summary.Blocks {
		t.Errorf("blocks mismatch: %d vs %d", decoded.Summary.Blocks, original.Summary.Blocks)
	}
	if len(decoded.ConfigHashes) != 2 {
		t.Errorf("expected 2 config hashes, got %d", len(decoded.ConfigHashes))
	}
	if len(decoded.Categories) != 1 {
		t.Errorf("expected 1 category, got %d", len(decoded.Categories))
	}
}

// ---- Bundle tests ----

func TestWriteBundle_NoSign(t *testing.T) {
	dir := t.TempDir()
	r := makeTestReport()

	if err := WriteBundle(dir, r, nil); err != nil {
		t.Fatalf("WriteBundle error: %v", err)
	}

	// Check 3 files exist.
	for _, name := range []string{fileReportHTML, fileReportJSON, fileManifest} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("file %s missing: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", name)
		}
	}

	// No .sig file.
	sigPath := filepath.Join(dir, fileManifest+signing.SigExtension)
	if _, err := os.Stat(sigPath); err == nil {
		t.Error("expected no .sig file when key is nil")
	}
}

func TestWriteBundle_WithSign(t *testing.T) {
	dir := t.TempDir()
	r := makeTestReport()

	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation error: %v", err)
	}

	if err := WriteBundle(dir, r, priv); err != nil {
		t.Fatalf("WriteBundle error: %v", err)
	}

	// Check 4 files exist.
	expectedFiles := []string{fileReportHTML, fileReportJSON, fileManifest, fileManifest + signing.SigExtension}
	for _, name := range expectedFiles {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("file %s missing: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", name)
		}
	}

	// Verify signature.
	manifestPath := filepath.Join(dir, fileManifest)
	if err := signing.VerifyFile(manifestPath, "", pub); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestWriteBundle_ManifestHashes(t *testing.T) {
	dir := t.TempDir()
	r := makeTestReport()

	if err := WriteBundle(dir, r, nil); err != nil {
		t.Fatalf("WriteBundle error: %v", err)
	}

	// Read manifest.
	manifestData, err := os.ReadFile(filepath.Clean(filepath.Join(dir, fileManifest)))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("unmarshaling manifest: %v", err)
	}

	// Verify HTML hash.
	htmlData, err := os.ReadFile(filepath.Clean(filepath.Join(dir, fileReportHTML)))
	if err != nil {
		t.Fatalf("reading HTML: %v", err)
	}
	htmlHash := sha256.Sum256(htmlData)
	expectedHTMLHash := hex.EncodeToString(htmlHash[:])
	if manifest.Files[fileReportHTML] != expectedHTMLHash {
		t.Errorf("HTML hash mismatch:\n  manifest: %s\n  actual:   %s", manifest.Files[fileReportHTML], expectedHTMLHash)
	}

	// Verify JSON hash.
	jsonData, err := os.ReadFile(filepath.Clean(filepath.Join(dir, fileReportJSON)))
	if err != nil {
		t.Fatalf("reading JSON: %v", err)
	}
	jsonHash := sha256.Sum256(jsonData)
	expectedJSONHash := hex.EncodeToString(jsonHash[:])
	if manifest.Files[fileReportJSON] != expectedJSONHash {
		t.Errorf("JSON hash mismatch:\n  manifest: %s\n  actual:   %s", manifest.Files[fileReportJSON], expectedJSONHash)
	}
}

func TestWriteBundle_CreatesDirectory(t *testing.T) {
	base := t.TempDir()
	nested := filepath.Join(base, "nested", "output")

	r := makeTestReport()
	if err := WriteBundle(nested, r, nil); err != nil {
		t.Fatalf("WriteBundle error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(nested, fileReportHTML)); err != nil {
		t.Error("expected HTML file in nested directory")
	}
}

// ---- Generate end-to-end test ----

func TestGenerate_EndToEnd(t *testing.T) {
	r, err := Generate(strings.NewReader(fixtureJSONL), ParseOptions{}, Options{
		Title: "End-to-End Test",
	})
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	if r.Title != "End-to-End Test" {
		t.Errorf("expected title %q, got %q", "End-to-End Test", r.Title)
	}
	if r.Version != testVersion {
		t.Errorf("expected version %q, got %q", testVersion, r.Version)
	}
	if r.Mode != testMode {
		t.Errorf("expected mode %q, got %q", testMode, r.Mode)
	}
	if r.Risk != RiskRed {
		t.Errorf("expected red risk (kill_switch_deny), got %q", r.Risk)
	}
	if r.Summary.TotalEvents != 7 {
		t.Errorf("expected 7 total events, got %d", r.Summary.TotalEvents)
	}
	if r.Summary.Blocks < 2 {
		t.Errorf("expected at least 2 blocks, got %d", r.Summary.Blocks)
	}
	if len(r.ConfigHashes) != 2 {
		t.Errorf("expected 2 config hashes, got %d", len(r.ConfigHashes))
	}
	if len(r.Categories) == 0 {
		t.Error("expected at least one category")
	}
	if len(r.Timeline) == 0 {
		t.Error("expected at least one timeline bucket")
	}
}

func TestGenerate_DefaultTitle(t *testing.T) {
	input := `{"level":"info","time":"2026-03-05T10:00:00Z","event":"startup","message":"ok"}
`
	r, err := Generate(strings.NewReader(input), ParseOptions{}, Options{})
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if r.Title != DefaultTitle {
		t.Errorf("expected default title %q, got %q", DefaultTitle, r.Title)
	}
}

func TestAggregate_TimelineSkipsAdminEvents(t *testing.T) {
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvStartup, Version: testVersion, Mode: testMode, ConfigHash: testHash},
		{Time: time.Date(2026, 3, 5, 10, 0, 1, 0, time.UTC), Event: "allowed", URL: "https://api.com"},
		{Time: time.Date(2026, 3, 5, 10, 0, 2, 0, time.UTC), Event: testEvCfgReload, ConfigHash: testHash2},
		{Time: time.Date(2026, 3, 5, 10, 0, 3, 0, time.UTC), Event: "shutdown"},
	}

	r := Aggregate(events, Options{})

	totalAllowed := 0
	for _, b := range r.Timeline {
		totalAllowed += b.Allowed
	}
	// Only the "allowed" event should count; startup, config_reload, and shutdown are admin.
	if totalAllowed != 1 {
		t.Errorf("expected 1 allowed in timeline (admin events excluded), got %d", totalAllowed)
	}
}

func TestExtractModeFromDetail(t *testing.T) {
	tests := []struct {
		detail   string
		expected string
	}{
		{"mode=strict", "strict"},
		{"mode=balanced", "balanced"},
		{"mode=audit, enforce=true", "audit"},
		{"enforce=true", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := extractModeFromDetail(tt.detail)
		if got != tt.expected {
			t.Errorf("extractModeFromDetail(%q) = %q, want %q", tt.detail, got, tt.expected)
		}
	}
}

func TestAggregate_ModeFromReload(t *testing.T) {
	// When the log window has only a config_reload (no startup), mode should
	// be extracted from the detail field.
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: testEvCfgReload, Detail: "mode=strict", ConfigHash: testHash},
		{Time: time.Date(2026, 3, 5, 10, 0, 1, 0, time.UTC), Event: "allowed", URL: "https://api.com"},
	}

	r := Aggregate(events, Options{})

	if r.Mode != "strict" {
		t.Errorf("expected mode %q from reload detail, got %q", "strict", r.Mode)
	}
}

func TestRenderHTML_SkippedLinesWarning(t *testing.T) {
	r := makeTestReport()
	r.Summary.SkippedLines = 5

	var buf bytes.Buffer
	if err := RenderHTML(&buf, r); err != nil {
		t.Fatalf("RenderHTML error: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "malformed") {
		t.Error("expected HTML to show malformed lines warning")
	}
	if !strings.Contains(html, "5") {
		t.Error("expected HTML to show count of 5 skipped lines")
	}
}

func TestRenderHTML_NoWarningWhenClean(t *testing.T) {
	r := makeTestReport()

	var buf bytes.Buffer
	if err := RenderHTML(&buf, r); err != nil {
		t.Fatalf("RenderHTML error: %v", err)
	}

	if strings.Contains(buf.String(), "malformed") {
		t.Error("expected no malformed warning when SkippedLines is 0")
	}
}

// ---- Timeline tests ----

func TestAggregate_TimelineHourly(t *testing.T) {
	// Events within 1 hour: should produce hourly buckets.
	events := []Event{
		{Time: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC), Event: "allowed", URL: "https://a.com"},
		{Time: time.Date(2026, 3, 5, 10, 30, 0, 0, time.UTC), Event: testDLPEvent, Scanner: testScanner, URL: "https://b.com"},
		{Time: time.Date(2026, 3, 5, 10, 59, 0, 0, time.UTC), Event: "allowed", URL: "https://c.com"},
	}

	r := Aggregate(events, Options{})
	if len(r.Timeline) == 0 {
		t.Fatal("expected timeline buckets")
	}

	// Verify some bucket has data.
	totalBlocks := 0
	totalAllowed := 0
	for _, b := range r.Timeline {
		totalBlocks += b.Blocks
		totalAllowed += b.Allowed
	}
	if totalBlocks != 1 {
		t.Errorf("expected 1 total block in timeline, got %d", totalBlocks)
	}
	if totalAllowed != 2 {
		t.Errorf("expected 2 total allowed in timeline, got %d", totalAllowed)
	}
}

// ---- Redaction helper tests ----

func TestRedactURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://evil.com/exfil?key=secret", "https://evil.com"},
		{"https://api.example.com:8443/path", "https://api.example.com:8443"},
		{"not-a-url", "not-a-url"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := redactURL(tt.input)
			if got != tt.expected {
				t.Errorf("redactURL(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestRedactIP(t *testing.T) {
	input := "Connection from 10.0.0.1 to 192.168.1.1"
	got := redactIP(input)
	if strings.Contains(got, "10.0.0.1") || strings.Contains(got, "192.168.1.1") {
		t.Errorf("IPs not redacted: %q", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Errorf("expected [redacted] in output: %q", got)
	}
}

// ---- Severity ordering tests ----

func TestHigherSeverity(t *testing.T) {
	tests := []struct {
		a, b     string
		expected string
	}{
		{severityMedium, severityHigh, severityHigh},
		{severityCritical, severityMedium, severityCritical},
		{"", severityMedium, severityMedium},
		{severityHigh, severityHigh, severityHigh},
	}

	for _, tt := range tests {
		got := higherSeverity(tt.a, tt.b)
		if got != tt.expected {
			t.Errorf("higherSeverity(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.expected)
		}
	}
}

// ---- Unused key check: verify signing key types work ----

func TestWriteBundle_VerifyKeyTypes(t *testing.T) {
	// Ensure we can use a raw ed25519 key (not just signing package).
	dir := t.TempDir()
	r := makeTestReport()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("key generation: %v", err)
	}

	if err := WriteBundle(dir, r, priv); err != nil {
		t.Fatalf("WriteBundle with ed25519 key: %v", err)
	}
}

// makeTestReport creates a minimal Report for bundle tests.
func makeTestReport() *Report {
	return &Report{
		Title:        "Test Bundle Report",
		Generated:    time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC),
		Version:      testVersion,
		ConfigHashes: []string{testHash},
		Mode:         testMode,
		Risk:         RiskGreen,
		TimeRange: TimeRange{
			Start: time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC),
			End:   time.Date(2026, 3, 5, 11, 0, 0, 0, time.UTC),
		},
		Summary:    Summary{TotalEvents: 1, Allowed: 1},
		Categories: []CategoryStats{},
		Timeline:   []TimeBucket{},
		Evidence:   []Event{},
	}
}
