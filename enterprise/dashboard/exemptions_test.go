//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/diag"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestExemptions_NoConfigLoaded(t *testing.T) {
	t.Parallel()

	model := NewReadModel(Options{})
	inventory := model.Exemptions()
	if inventory.ConfigLoaded {
		t.Fatal("ConfigLoaded = true, want false")
	}
	if inventory.ConfiguredCount != 0 || len(inventory.Entries) != 0 {
		t.Fatalf("empty inventory = %+v", inventory)
	}
	if !strings.Contains(inventory.TrackingNote, "not tracked") {
		t.Fatalf("TrackingNote = %q, want not tracked", inventory.TrackingNote)
	}

	var nilModel *ReadModel
	nilInventory := nilModel.Exemptions()
	if nilInventory.ConfigLoaded || nilInventory.ConfiguredCount != 0 {
		t.Fatalf("nil model inventory = %+v, want unloaded empty inventory", nilInventory)
	}
}

func TestExemptions_ConfigLoadedNoEntries(t *testing.T) {
	t.Parallel()

	inventory := NewReadModel(Options{Config: &config.Config{}}).Exemptions()
	if !inventory.ConfigLoaded {
		t.Fatal("ConfigLoaded = false, want true")
	}
	if inventory.ConfiguredCount != 0 || len(inventory.Entries) != 0 || len(inventory.Attention) != 0 {
		t.Fatalf("loaded empty inventory = %+v, want no entries or attention", inventory)
	}
}

func TestExemptionsEmptyStatesExplainSources(t *testing.T) {
	t.Parallel()

	t.Run("no config loaded", func(t *testing.T) {
		t.Parallel()
		handler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       t.TempDir(),
			HasFeature:       allowAgentsFeature,
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/exemptions", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, want := range []string{
			"The exemptions inventory proves which exemption-like knobs",
			"No config source is connected",
			"--config",
			"--exemption-store",
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("exemptions no-config body missing %q: %s", want, body)
			}
		}
	})

	t.Run("config loaded with no entries", func(t *testing.T) {
		t.Parallel()
		handler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       t.TempDir(),
			Config:           &config.Config{},
			HasFeature:       allowAgentsFeature,
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/exemptions", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, want := range []string{
			"The exemptions inventory proves which exemption-like knobs",
			"A config source is loaded",
			"contains no exemption entries",
			"--config",
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("exemptions loaded-empty body missing %q: %s", want, body)
			}
		}
	})
}

func TestExemptions_PristineDefaultsHaveNoAttentionFindings(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.ApplyDefaults()
	inventory := NewReadModel(Options{Config: cfg}).Exemptions()
	if !inventory.ConfigLoaded {
		t.Fatal("ConfigLoaded = false, want true")
	}
	t.Logf("dashboard default inert count = %d, misdirected count = %d", inventory.InertCount, inventory.MisdirectedCount)
	if inventory.InertCount != 0 || inventory.MisdirectedCount != 0 {
		t.Fatalf("pristine default attention counts: inert=%d misdirected=%d, want 0/0; attention=%+v",
			inventory.InertCount, inventory.MisdirectedCount, inventory.Attention)
	}
}

func TestExemptions_EnumeratesConfiguredKnobFamiliesAndJoinsFindings(t *testing.T) {
	t.Parallel()

	enabled := true
	cfg := &config.Config{
		APIAllowlist: []string{"public.vendor.example"},
		Suppress: []config.SuppressEntry{{
			Rule:   "Vendor Token",
			Path:   "*api.vendor.example*",
			Reason: "provider-bound credential",
		}},
		FileSentry: config.FileSentry{
			IgnorePatterns: []string{"vendor-cache/**"},
		},
		DLP: config.DLP{
			Patterns: []config.DLPPattern{{
				Name:          "Vendor Token",
				Regex:         "vendortok_[a-z0-9]{20}",
				Severity:      config.SeverityHigh,
				ExemptDomains: []string{"api.vendor.example"},
			}},
		},
		ResponseScanning: config.ResponseScanning{
			Enabled:       false,
			ExemptDomains: []string{"responses.vendor.example"},
			SizeExemptDomains: []string{
				"downloads.vendor.example",
			},
			UnscannablePassthrough: []config.UnscannablePassthroughEntry{{
				Host:         "media.vendor.example",
				Paths:        []string{"/asset.bin"},
				ContentTypes: []string{"application/octet-stream"},
				Reason:       "opaque binary",
			}},
			MCPServers: []config.MCPResponseServerTrust{{
				Server: "reasoning-cache",
				Trust:  config.ResponseTrustReasoning,
			}},
		},
		RequestBodyScanning: config.RequestBodyScanning{
			Enabled:       true,
			ScanHeaders:   false,
			IgnoreHeaders: []string{"X-Provider-Trace"},
		},
		FetchProxy: config.FetchProxy{Monitoring: config.Monitoring{
			EntropyThreshold:           4.5,
			QueryEntropyExclusions:     []string{"query.vendor.example"},
			SubdomainEntropyExclusions: []string{"*.cdn.vendor.example"},
			QueryEntropyParamExclusions: []config.QueryEntropyParamExclusion{{
				Host:   "api.vendor.example",
				Path:   "/v1/search",
				Param:  "query",
				Reason: "structured query",
			}},
		}},
		TLSInterception: config.TLSInterception{
			PassthroughDomains: []string{"tls.vendor.example"},
		},
		TrustedDomains: []string{"internal.vendor.example"},
		SSRF: config.SSRF{
			IPAllowlist: []string{"10.0.0.0/24"},
		},
		KillSwitch: config.KillSwitch{
			HealthExempt:  &enabled,
			MetricsExempt: &enabled,
			APIExempt:     &enabled,
			AllowlistIPs:  []string{"192.0.2.10/32"},
		},
		AdaptiveEnforcement: config.AdaptiveEnforcement{
			Enabled:       false,
			ExemptDomains: []string{"adaptive.vendor.example"},
		},
		CrossRequestDetection: config.CrossRequestDetection{
			EntropyBudget: config.CrossRequestEntropyBudget{
				ExemptDomains: []string{"entropy.vendor.example"},
			},
		},
		BrowserShield: config.BrowserShield{
			ExemptDomains: []string{"browser.vendor.example"},
		},
		Taint: config.TaintConfig{
			AllowlistedDomains: []string{"docs.vendor.example"},
			TrustedMCPServers:  []string{"trusted-docs"},
			TrustOverrides: []config.TaintTrustOverride{{
				Scope:       "source",
				SourceMatch: "docs.vendor.example",
				ActionMatch: "read",
				Reason:      "operator docs",
			}},
		},
		AddressProtection: config.AddressProtection{
			AllowedAddresses: []string{"0x1111111111111111111111111111111111111111"},
		},
		ReverseProxy: config.ReverseProxy{
			TrustedUpstream: config.ReverseProxyTrustedUpstream{
				Host:   "submit.vendor.example",
				Port:   443,
				Reason: "submit endpoint",
				Added:  "2026-01-01",
			},
		},
		Agents: map[string]config.AgentProfile{
			"agent-a": {
				APIAllowlist:     []string{"agent-api.vendor.example"},
				TrustedDomains:   []string{"agent-internal.vendor.example"},
				AllowedAddresses: []string{"0x2222222222222222222222222222222222222222"},
			},
		},
	}

	inventory := NewReadModel(Options{Config: cfg}).Exemptions()
	if !inventory.ConfigLoaded {
		t.Fatal("ConfigLoaded = false, want true")
	}
	if inventory.ConfiguredCount != 30 {
		t.Fatalf("ConfiguredCount = %d, want 30; entries=%+v", inventory.ConfiguredCount, inventory.Entries)
	}
	if inventory.InertCount != 7 {
		t.Fatalf("InertCount = %d, want 7", inventory.InertCount)
	}
	if inventory.MisdirectedCount != 0 {
		t.Fatalf("MisdirectedCount = %d, want 0", inventory.MisdirectedCount)
	}
	assertEntryState(t, inventory, "response_scanning.exempt_domains", "responses.vendor.example", ExemptionStateInert)
	assertEntryState(t, inventory, "adaptive_enforcement.exempt_domains", "adaptive.vendor.example", ExemptionStateInert)
	assertEntryState(t, inventory, "cross_request_detection.entropy_budget.exempt_domains", "entropy.vendor.example", ExemptionStateInert)
	assertEntryState(t, inventory, "browser_shield.exempt_domains", "browser.vendor.example", ExemptionStateInert)
	assertEntryState(t, inventory, "tls_interception.passthrough_domains", "tls.vendor.example", ExemptionStateInert)
	assertEntryState(t, inventory, "file_sentry.ignore_patterns", "vendor-cache/**", ExemptionStateActive)
	assertEntryState(t, inventory, "kill_switch.allowlist_ips", "192.0.2.10/32", ExemptionStateActive)
	assertEntryState(t, inventory, "kill_switch.health_exempt", "health endpoints", ExemptionStateActive)
	assertEntryState(t, inventory, "kill_switch.metrics_exempt", "metrics endpoints", ExemptionStateActive)
	assertEntryState(t, inventory, "kill_switch.api_exempt", "kill-switch API endpoints", ExemptionStateActive)
	assertEntryState(t, inventory, "request_body_scanning.ignore_headers", "X-Provider-Trace", ExemptionStateInert)
	assertEntryState(t, inventory, "response_scanning.mcp_servers", "reasoning-cache", ExemptionStateInert)
	assertEntryState(t, inventory, "suppress", "*api.vendor.example*", ExemptionStateActive)
	assertEntryState(t, inventory, "api_allowlist", "public.vendor.example", ExemptionStateActive)
	assertEntryState(t, inventory, "agents[].api_allowlist", "agent-api.vendor.example", ExemptionStateActive)
	assertEntryState(t, inventory, "fetch_proxy.monitoring.query_entropy_param_exclusions", "https://api.vendor.example/v1/search?query", ExemptionStateActive)
}

func TestExemptions_JoinDoesNotUseRenderedDetailSubstring(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	body := []byte(`version: 1
mode: balanced
response_scanning:
  enabled: true
  mcp_servers:
    - server: "reasoning\"cache"
      trust: reasoning
`)
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load(config): %v", err)
	}

	inventory := NewReadModel(Options{Config: cfg}).Exemptions()
	assertEntryState(t, inventory, "response_scanning.mcp_servers", `reasoning"cache`, ExemptionStateMisdirected)
}

func TestExemptions_JoinsMixedCaseHeaderFinding(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		RequestBodyScanning: config.RequestBodyScanning{
			Enabled:       true,
			ScanHeaders:   false,
			IgnoreHeaders: []string{"X-Provider-Trace"},
		},
	}

	inventory := NewReadModel(Options{Config: cfg}).Exemptions()
	assertEntryState(t, inventory, "request_body_scanning.ignore_headers", "X-Provider-Trace", ExemptionStateInert)
}

func TestExemptions_HeaderDefaultStaysActiveButOperatorAddedInertWhenDisabled(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	body := []byte(`mode: balanced
request_body_scanning:
  enabled: false
  scan_headers: true
  header_mode: all
  ignore_headers:
    - Accept
    - X-Provider-Trace
`)
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load(config): %v", err)
	}

	inventory := NewReadModel(Options{Config: cfg}).Exemptions()
	// Accept is an auto-filled default header, not an operator-authored
	// exemption, so it is never flagged even when the scanner is disabled.
	assertEntryState(t, inventory, "request_body_scanning.ignore_headers", "Accept", ExemptionStateActive)
	// X-Provider-Trace is operator-added and non-default, so it is inert while
	// the ignore-list is not consumed.
	assertEntryState(t, inventory, "request_body_scanning.ignore_headers", "X-Provider-Trace", ExemptionStateInert)
}

func TestExemptions_DefaultBaselinesDoNotBecomeAttentionWhenFeatureDisabled(t *testing.T) {
	t.Parallel()

	defaults := config.Defaults()
	defaults.ApplyDefaults()
	cfg := &config.Config{
		BrowserShield: config.BrowserShield{
			Enabled:       false,
			ExemptDomains: append([]string(nil), defaults.BrowserShield.ExemptDomains...),
		},
		TLSInterception: config.TLSInterception{
			Enabled:            false,
			PassthroughDomains: append([]string(nil), defaults.TLSInterception.PassthroughDomains...),
		},
		RequestBodyScanning: config.RequestBodyScanning{
			Enabled:       false,
			ScanHeaders:   true,
			HeaderMode:    config.HeaderModeAll,
			IgnoreHeaders: append([]string(nil), defaults.RequestBodyScanning.IgnoreHeaders...),
		},
	}

	inventory := NewReadModel(Options{Config: cfg}).Exemptions()
	for _, domain := range defaults.BrowserShield.ExemptDomains {
		assertEntryState(t, inventory, "browser_shield.exempt_domains", domain, ExemptionStateActive)
	}
	for _, domain := range defaults.TLSInterception.PassthroughDomains {
		assertEntryState(t, inventory, "tls_interception.passthrough_domains", domain, ExemptionStateActive)
	}
	for _, header := range defaults.RequestBodyScanning.IgnoreHeaders {
		assertEntryState(t, inventory, "request_body_scanning.ignore_headers", header, ExemptionStateActive)
	}
	if inventory.InertCount != 0 {
		t.Fatalf("InertCount = %d, want 0; inventory=%+v", inventory.InertCount, inventory)
	}

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		Config:           cfg,
		HasFeature:       allowAgentsFeature,
		Authorize:        func(*http.Request) error { return nil },
		AuthorizeRaw:     allowRawAccess,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/exemptions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, `chip inert">inert</span>`) {
		t.Fatalf("default baselines should not render an inert chip: %s", body)
	}
}

func TestExemptions_ResponseSizeAndUnscannableRemainActiveWhenResponseScanningDisabled(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	body := []byte(`mode: balanced
response_scanning:
  enabled: false
  size_exempt_domains:
    - downloads.vendor.example
  unscannable_passthrough:
    - host: downloads.vendor.example
      paths:
        - /archive.bin
      content_types:
        - application/octet-stream
      reason: trusted binary mirror
      expires: 2099-01-01
`)
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load(config): %v", err)
	}

	inventory := NewReadModel(Options{Config: cfg}).Exemptions()
	assertEntryState(t, inventory, "response_scanning.size_exempt_domains", "downloads.vendor.example", ExemptionStateActive)
	assertEntryState(t, inventory, "response_scanning.unscannable_passthrough", "downloads.vendor.example", ExemptionStateActive)
}

func TestExemptions_CountsMisdirectedAttention(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		ResponseScanning: config.ResponseScanning{
			Enabled: true,
			MCPServers: []config.MCPResponseServerTrust{{
				Server: "reasoning-cache",
				Trust:  config.ResponseTrustReasoning,
			}},
		},
	}

	inventory := NewReadModel(Options{Config: cfg}).Exemptions()
	if inventory.MisdirectedCount != 1 {
		t.Fatalf("MisdirectedCount = %d, want 1; inventory=%+v", inventory.MisdirectedCount, inventory)
	}
	if len(inventory.Attention) != 1 || inventory.Attention[0].State != ExemptionStateMisdirected {
		t.Fatalf("Attention = %+v, want one misdirected entry", inventory.Attention)
	}
	assertEntryState(t, inventory, "response_scanning.mcp_servers", "reasoning-cache", ExemptionStateMisdirected)
}

func TestSemanticFindingMatchesEntryBranches(t *testing.T) {
	t.Parallel()

	entry := newExemptionEntry("Request header DLP", "request_body_scanning.ignore_headers", "X-Provider-Trace", "X-Provider-Trace")
	tests := []struct {
		name    string
		finding diag.ConfigSemanticFinding
		want    bool
	}{
		{
			name: "scope mismatch",
			finding: diag.ConfigSemanticFinding{
				Scope:   "suppress",
				Subject: "x-provider-trace",
			},
			want: false,
		},
		{
			name: "family wide fallback",
			finding: diag.ConfigSemanticFinding{
				Scope: "request_body_scanning.ignore_headers",
			},
			want: true,
		},
		{
			name: "normalized subject match",
			finding: diag.ConfigSemanticFinding{
				Scope:   "request_body_scanning.ignore_headers",
				Subject: "x-provider-trace",
			},
			want: true,
		},
		{
			name: "subject mismatch",
			finding: diag.ConfigSemanticFinding{
				Scope:   "request_body_scanning.ignore_headers",
				Subject: "x-other",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := semanticFindingMatchesEntry(tt.finding, entry); got != tt.want {
				t.Fatalf("semanticFindingMatchesEntry() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandler_ExemptionsHostileConfigEscapes(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		ResponseScanning: config.ResponseScanning{
			Enabled:       true,
			ExemptDomains: []string{hostileScript},
		},
		Suppress: []config.SuppressEntry{{
			Rule:   hostileImage,
			Path:   hostileJSURL,
			Reason: hostileJSON,
		}},
	}
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		Config:           cfg,
		HasFeature:       allowAgentsFeature,
		Authorize:        func(*http.Request) error { return nil },
		// Raw access so the hostile config values are actually rendered (and
		// therefore html/template-escaped); the metadata-only path redacts them
		// instead and is covered by TestHandler_ExemptionsMetadataViewRedactsRawValues.
		AuthorizeRaw: allowRawAccess,
		AuditWriter:  &strings.Builder{},
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/exemptions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, raw := range []string{hostileScript, hostileImage, hostileJSON} {
		if strings.Contains(body, raw) {
			t.Fatalf("response contains unescaped hostile config value %q", raw)
		}
	}
	if strings.Contains(body, `href="javascript:`) {
		t.Fatal("response contains javascript URL in href context")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("response should contain escaped script text")
	}
	if !strings.Contains(body, "not tracked") {
		t.Fatal("response should state lifecycle telemetry is not tracked")
	}
}

func assertEntryState(t *testing.T, inventory ExemptionInventory, knob, scope, state string) {
	t.Helper()
	for _, entry := range inventory.Entries {
		if entry.Knob == knob && entry.Scope == scope {
			if entry.State != state {
				t.Fatalf("%s %s state = %q, want %q; entry=%+v", knob, scope, entry.State, state, entry)
			}
			return
		}
	}
	t.Fatalf("missing entry knob=%q scope=%q; entries=%+v", knob, scope, inventory.Entries)
}

func TestHandler_ExemptionsMetadataViewRedactsRawValues(t *testing.T) {
	t.Parallel()

	const (
		shieldDomain = "secret-shield.internal.example"
		ssrfDomain   = "secret-ssrf.internal.example"
		ssrfIP       = "10.9.8.7/32"
		agentDomain  = "secret-agent.internal.example"
	)
	cfg := &config.Config{
		BrowserShield:  config.BrowserShield{Enabled: false, ExemptDomains: []string{shieldDomain}},
		TrustedDomains: []string{ssrfDomain},
		SSRF:           config.SSRF{IPAllowlist: []string{ssrfIP}},
		Agents:         map[string]config.AgentProfile{"agent-a": {TrustedDomains: []string{agentDomain}}},
	}
	sensitive := []string{shieldDomain, ssrfDomain, ssrfIP, agentDomain}

	// Metadata-only view (no raw authorizer): raw infra values must be redacted.
	metaBody := serveExemptionsBody(t, cfg, false)
	for _, s := range sensitive {
		if strings.Contains(metaBody, s) {
			t.Fatalf("metadata view leaked raw value %q; body=%s", s, metaBody)
		}
	}
	// The view stays useful: knob names, states, counts, and the redaction note.
	for _, want := range []string{diag.ConfigScopeBrowserShieldExemptDomains, "raw access is required", "inert"} {
		if !strings.Contains(metaBody, want) {
			t.Fatalf("metadata view missing %q; body=%s", want, metaBody)
		}
	}

	// Raw-authorized view shows the actual values.
	rawBody := serveExemptionsBody(t, cfg, true)
	for _, s := range sensitive {
		if !strings.Contains(rawBody, s) {
			t.Fatalf("raw view missing value %q", s)
		}
	}
}

func TestHandler_ExemptionsLongOpaqueValuesUseOverflowGuards(t *testing.T) {
	t.Parallel()

	longGlob := "/artifacts/" + strings.Repeat("abcdef0123456789", 16) + "/\"><script>alert(1)</script>/*.tar.gz"
	longInertDomain := "responses-" + strings.Repeat("0123456789abcdef", 16) + ".vendor.example\"><script>alert(1)</script>"
	longRule := "dlp_" + strings.Repeat("0123456789abcdef", 16)
	cfg := &config.Config{
		ResponseScanning: config.ResponseScanning{
			Enabled:       false,
			ExemptDomains: []string{longInertDomain},
		},
		Suppress: []config.SuppressEntry{{
			Rule:   longRule,
			Path:   longGlob,
			Reason: "operator-approved-test-fixture",
		}},
	}

	body := serveExemptionsBody(t, cfg, true)
	escapedGlob := html.EscapeString(longGlob)
	escapedInertDomain := html.EscapeString(longInertDomain)
	for _, want := range []string{
		`<div class="opaque-cell"><span class="opaque-value">` + escapedGlob + `</span></div>`,
		`<div class="dim mono opaque-cell"><span class="opaque-value">` + escapedInertDomain + `</span></div>`,
		`<span class="mono opaque-cell"><span class="opaque-value">` + longRule + `</span></span>`,
		`<td class="mono knob-cell" title="` + diag.ConfigScopeResponseExemptDomains + `"><div class="opaque-cell"><span class="opaque-value">` + diag.ConfigScopeResponseExemptDomains + `</span></div></td>`,
		`.knob-cell .opaque-value { display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; word-break: normal; overflow-wrap: normal; }`,
		`word-break: break-all`,
		`overflow-x: auto`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("exemptions overflow guard missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, longGlob) {
		t.Fatalf("long hostile scope rendered without escaping: %s", body)
	}
	if strings.Contains(body, longInertDomain) {
		t.Fatalf("long hostile attention scope rendered without escaping: %s", body)
	}
	if strings.Contains(body, `<td class="scope mono">`+escapedGlob+`</td>`) {
		t.Fatalf("long scope rendered as raw table-cell text: %s", body)
	}
}

func serveExemptionsBody(t *testing.T, cfg *config.Config, raw bool) string {
	t.Helper()
	opts := Options{
		ReceiptDir: t.TempDir(),
		Config:     cfg,
		HasFeature: allowAgentsFeature,
		Authorize:  func(*http.Request) error { return nil },
	}
	if raw {
		opts.AuthorizeRaw = allowRawAccess
	}
	handler := New(opts)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/exemptions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	return rec.Body.String()
}
