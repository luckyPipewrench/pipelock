//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/evidenceview"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// --- Route-gating enumerator: every new route is 403 without the agents feature
// AND 403 when authorize rejects ---

func TestHandler_NewRouteGating(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	writeReceiptsToDir(t, dir, buildDashboardChain(t, priv, 2))

	gatedPaths := []string{
		"/agents",
		"/agent/" + testActor,
		"/session/" + testSessionID + "/receipt/0",
	}

	t.Run("no_feature", func(t *testing.T) {
		handler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       dir,
			TrustedKeys: map[string]TrustedKey{
				keyHex: {Source: trustedKeySource},
			},
			HasFeature: func(string) bool { return false },
		})
		for _, path := range gatedPaths {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, path, nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("path %s: no-feature status = %d, want %d", path, rec.Code, http.StatusForbidden)
			}
		}
	})

	t.Run("nil_feature", func(t *testing.T) {
		handler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       dir,
			TrustedKeys: map[string]TrustedKey{
				keyHex: {Source: trustedKeySource},
			},
		})
		for _, path := range gatedPaths {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, path, nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("path %s: nil-feature status = %d, want %d", path, rec.Code, http.StatusForbidden)
			}
		}
	})

	t.Run("authorize_rejects", func(t *testing.T) {
		handler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       dir,
			TrustedKeys: map[string]TrustedKey{
				keyHex: {Source: trustedKeySource},
			},
			HasFeature: allowAgentsFeature,
			Authorize:  func(*http.Request) error { return errors.New("denied") },
		})
		for _, path := range gatedPaths {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, path, nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("path %s: authorize-reject status = %d, want %d", path, rec.Code, http.StatusForbidden)
			}
			if strings.Contains(rec.Body.String(), "Scorecard") || strings.Contains(rec.Body.String(), "agent-card") {
				t.Errorf("path %s: forbidden response leaked evidence body", path)
			}
		}
	})

	t.Run("wrong_tier", func(t *testing.T) {
		handler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       dir,
			TrustedKeys: map[string]TrustedKey{
				keyHex: {Source: trustedKeySource},
			},
			HasFeature: func(feature string) bool {
				// Has "fleet" but not "agents".
				return feature == license.FeatureFleet
			},
		})
		for _, path := range gatedPaths {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, path, nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("path %s: wrong-tier status = %d, want %d", path, rec.Code, http.StatusForbidden)
			}
		}
	})
}

// --- Agents route renders agent groups ---

func TestHandler_AgentsRendersGroups(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys:      trusted,
		HasFeature:       allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/agents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Cross-Agent Evidence Explorer") {
		t.Fatal("body should contain the agents page heading")
	}
	if !strings.Contains(body, testActor) {
		t.Fatalf("body should contain agent name %q", testActor)
	}
	// Verify bounded rollup counts are shown, not aggregate labels.
	if !strings.Contains(body, "chains intact") {
		t.Fatal("body should show 'chains intact' rollup label")
	}
	if !strings.Contains(body, "chains broken") {
		t.Fatal("body should show 'chains broken' rollup label")
	}
	// CSP headers set by gate.
	if got := rec.Header().Get("Content-Security-Policy"); got != contentSecurityPolicy {
		t.Fatalf("CSP = %q, want %q", got, contentSecurityPolicy)
	}
}

func TestHandler_AgentsHostileEvidenceEscapedAndNoAggregateGreen(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	r := signDashboardReceipt(t, priv, 0, receipt.GenesisHash, time.Date(2026, 7, 3, 13, 0, 0, 0, time.UTC))
	r.ActionRecord.Actor = hostileScript
	resigned, err := signAlteredReceipt(r, priv)
	if err != nil {
		t.Fatalf("signAlteredReceipt: %v", err)
	}
	writeReceiptsToDir(t, dir, []receipt.Receipt{resigned})

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys:      map[string]TrustedKey{keyHex: {Source: trustedKeySource}},
		HasFeature:       allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/agents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, hostileScript) {
		t.Fatal("agents response contains raw script tag")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("agents response should contain HTML-escaped script text")
	}
	for _, banned := range []string{"healthy", "clean", "all clear", "everything verified", "fully verified"} {
		if strings.Contains(strings.ToLower(body), banned) {
			t.Fatalf("agents response contains aggregate-green wording %q", banned)
		}
	}
}

// --- Agent detail route ---

func TestHandler_AgentDetail(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys:      trusted,
		HasFeature:       allowAgentsFeature,
	})

	t.Run("found", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/agent/"+testActor, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), testActor) {
			t.Fatal("body should contain agent name")
		}
	})

	t.Run("not_found", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/agent/nonexistent", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("nested_path_404", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/agent/"+testActor+"/extra", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("nested agent path status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("empty_agent_id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/agent/", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("empty agent id status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})
}

// --- Investigator route ---

func TestHandler_Investigator(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	writeReceiptsToDir(t, dir, buildDashboardChain(t, priv, 3))
	trusted := map[string]TrustedKey{keyHex: {Source: trustedKeySource}}

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys:      trusted,
		HasFeature:       allowAgentsFeature,
	})

	t.Run("found_seq_0", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/"+testSessionID+"/receipt/0", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Receipt Detail") {
			t.Fatal("body should contain investigator heading")
		}
		if !strings.Contains(body, "allow") {
			t.Fatal("body should show the verdict")
		}
	})

	t.Run("found_seq_2", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/"+testSessionID+"/receipt/2", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("not_found_seq", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/"+testSessionID+"/receipt/999", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("bad_seq_format", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/"+testSessionID+"/receipt/abc", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("malformed_receipt_paths_404", func(t *testing.T) {
		paths := []string{
			"/session/" + testSessionID + "/receipt/-1",
			"/session/" + testSessionID + "/receipt/18446744073709551616",
			"/session/" + testSessionID + "/receipt/0/extra",
			"/session/" + testSessionID + "/receipt/%2f0",
			"/session/" + testSessionID + "/receipt/%2e%2e",
		}
		for _, path := range paths {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, path, nil))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("path %s status = %d, want %d; body=%s", path, rec.Code, http.StatusNotFound, rec.Body.String())
			}
		}
	})

	t.Run("path_traversal_rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/../receipt/0", nil))
		// The security property: a "../" path must never be served as a valid
		// investigator page (never 200 with receipt content). Go's ServeMux
		// cleans the path and redirects it away (301 on Go <=1.25, 307 on Go
		// >=1.26); a 404 is also acceptable. Assert the property, not one exact
		// redirect code, so a future net/http redirect-code change cannot flip
		// this from green to red.
		if rec.Code == http.StatusOK {
			t.Fatalf("path traversal was served (200); must be redirected away or 404. body=%s", rec.Body.String())
		}
		isRedirect := rec.Code >= 300 && rec.Code < 400
		if !isRedirect && rec.Code != http.StatusNotFound {
			t.Fatalf("path traversal status = %d, want a 3xx redirect or 404", rec.Code)
		}
	})

	t.Run("missing_receipt_segment", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/"+testSessionID+"/notreceipt/0", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("bad sub-path status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})
}

// --- Investigator hostile evidence render: attacker-controlled fields are HTML-escaped ---

func TestHandler_InvestigatorHostileEvidenceEscaped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	r := signDashboardReceipt(t, priv, 0, receipt.GenesisHash, time.Date(2026, 7, 3, 13, 0, 0, 0, time.UTC))
	r.ActionRecord.Target = hostileScript
	r.ActionRecord.Pattern = hostileImage
	r.ActionRecord.Verdict = hostileScript
	r.ActionRecord.Intent = hostileJSON
	r.ActionRecord.SessionTaintLevel = "<b>high</b>"
	r.ActionRecord.RecentTaintSources = []session.TaintSourceRef{{URL: "<script>src</script>", Kind: "test"}}
	resigned, err := signAlteredReceipt(r, priv)
	if err != nil {
		t.Fatalf("signAlteredReceipt: %v", err)
	}
	writeReceiptsToDir(t, dir, []receipt.Receipt{resigned})

	t.Run("raw_view_escapes", func(t *testing.T) {
		handler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       dir,
			TrustedKeys:      map[string]TrustedKey{keyHex: {Source: trustedKeySource}},
			HasFeature:       allowAgentsFeature,
			AuthorizeRaw:     allowRawAccess,
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/"+testSessionID+"/receipt/0", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		body := rec.Body.String()
		if strings.Contains(body, hostileScript) {
			t.Fatal("investigator response contains raw script tag")
		}
		if strings.Contains(body, hostileImage) {
			t.Fatal("investigator response contains raw image injection")
		}
		if strings.Contains(body, hostileJSON) {
			t.Fatal("investigator response contains raw script-breaking JSON payload")
		}
		// HTML-escaped versions should be present.
		if !strings.Contains(body, "&lt;script&gt;") {
			t.Fatal("investigator should contain HTML-escaped script text")
		}
	})

	t.Run("metadata_view_redacts_target", func(t *testing.T) {
		handler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       dir,
			TrustedKeys:      map[string]TrustedKey{keyHex: {Source: trustedKeySource}},
			HasFeature:       allowAgentsFeature,
			// No AuthorizeRaw => metadata view.
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/"+testSessionID+"/receipt/0", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		body := rec.Body.String()
		// Target must be redacted in metadata view — it was set to hostileScript.
		// The redaction placeholder must be present instead of the raw target.
		if !strings.Contains(body, redactedDestination) {
			t.Fatal("metadata view should show the redaction placeholder for Target")
		}
		// The raw hostile target must not appear (even HTML-escaped, the Target
		// field value should be replaced by the redacted placeholder).
		if strings.Contains(body, hostileScript) {
			t.Fatal("metadata view must not contain the raw hostile target")
		}
		// The redacted view banner should be present.
		if !strings.Contains(body, "Metadata view") {
			t.Fatal("metadata view should show the redaction banner")
		}
		// Taint sources raw length should be cleared.
		// The taint source count detail should not expose source URLs.
		if strings.Contains(body, "&lt;script&gt;src&lt;/script&gt;") {
			t.Fatal("metadata view must not leak taint source URLs")
		}
	})
}

func TestHandler_InvestigatorMetadataRedactsRawExplanationFields(t *testing.T) {
	t.Parallel()

	const secret = "metadata-only-" + "marker"
	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	r := signDashboardReceipt(t, priv, 0, receipt.GenesisHash, time.Date(2026, 7, 3, 13, 0, 0, 0, time.UTC))
	// The secret lives ONLY in the attacker/agent-controllable fields the
	// metadata view redacts. Scanner/config fields carry benign labels that must
	// stay visible.
	r.ActionRecord.Target = "https://api.vendor.example/" + secret
	r.ActionRecord.Pattern = "pattern-" + secret
	r.ActionRecord.Intent = "intent-" + secret
	r.ActionRecord.Layer = "dlp"
	r.ActionRecord.Severity = "high"
	r.ActionRecord.DataClassesIn = []string{"pii"}
	r.ActionRecord.DataClassesOut = []string{"credential"}
	r.ActionRecord.TaintDecisionReason = "source-" + secret
	r.ActionRecord.RecentTaintSources = []session.TaintSourceRef{{
		URL:  "https://source.vendor.example/" + secret,
		Kind: "url",
	}}
	r.ActionRecord.Redaction = &receipt.RedactionSummary{
		TotalRedactions: 1,
		ByClass:         map[string]int{"aws": 1},
	}
	r.ActionRecord.Shield = &receipt.ShieldSummary{
		Pipeline:      "html",
		TotalRewrites: 1,
	}
	resigned, err := signAlteredReceipt(r, priv)
	if err != nil {
		t.Fatalf("signAlteredReceipt: %v", err)
	}
	writeReceiptsToDir(t, dir, []receipt.Receipt{resigned})

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys:      map[string]TrustedKey{keyHex: {Source: trustedKeySource}},
		HasFeature:       allowAgentsFeature,
		// No AuthorizeRaw => metadata view.
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/session/"+testSessionID+"/receipt/0", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Fatalf("metadata investigator leaked raw explanation secret %q in body: %s", secret, body)
	}
	if !strings.Contains(body, redactedDestination) {
		t.Fatal("metadata investigator should show redaction placeholder")
	}
	// The metadata view must still explain WHY: benign scanner/config semantics
	// stay visible (proves the redaction did not over-strip the investigator).
	for _, want := range []string{"dlp", "high", "pii", "credential"} {
		if !strings.Contains(body, want) {
			t.Fatalf("metadata investigator dropped decision semantics %q; body=%s", want, body)
		}
	}
}

// --- Bounded filter tests ---

func writeReceiptsToDirWithSession(t *testing.T, dir string, sessionID string, receipts []receipt.Receipt) {
	t.Helper()
	rec := newTestRecorder(t, dir, nil)
	for i, r := range receipts {
		if err := rec.Record(recorder.Entry{
			SessionID: sessionID,
			Type:      testReceiptEntryType,
			EventKind: string(r.ActionRecord.ActionType),
			Transport: r.ActionRecord.Transport,
			Summary:   "receipt",
			Detail:    r,
		}); err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}
	_ = rec.Close()
}

func buildChainForAgent(t *testing.T, priv ed25519.PrivateKey, agentName, sessionID string, count int) []receipt.Receipt {
	t.Helper()
	chain := make([]receipt.Receipt, 0, count)
	prevHash := receipt.GenesisHash
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

	for i := range count {
		ar := receipt.ActionRecord{
			Version:         receipt.ActionRecordVersion,
			ActionID:        receipt.NewActionID(),
			ActionType:      receipt.ActionRead,
			Timestamp:       base.Add(time.Duration(i) * time.Second),
			Principal:       testPrincipal,
			Actor:           agentName,
			Target:          testTarget,
			SideEffectClass: receipt.SideEffectExternalRead,
			Reversibility:   receipt.ReversibilityFull,
			PolicyHash:      testPolicyHash,
			Verdict:         "allow",
			SessionID:       sessionID,
			Transport:       testTransport,
			Method:          http.MethodGet,
			Layer:           "allowlist",
			Pattern:         "api.vendor.example",
			ChainPrevHash:   prevHash,
			ChainSeq:        uint64(i),
		}
		r, err := receipt.Sign(ar, priv)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		hash, err := receipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash: %v", err)
		}
		chain = append(chain, r)
		prevHash = hash
	}
	return chain
}

func TestHandler_BoundedFilter(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)

	// Create two sessions with different agents.
	chainA := buildChainForAgent(t, priv, "agent-a", "session-a", 2)
	writeReceiptsToDirWithSession(t, dir, "session-a", chainA)

	chainB := buildChainForAgent(t, priv, "agent-b", "session-b", 2)
	writeReceiptsToDirWithSession(t, dir, "session-b", chainB)

	trusted := map[string]TrustedKey{keyHex: {Source: trustedKeySource}}

	model := NewReadModel(Options{
		ReceiptDir:  dir,
		TrustedKeys: trusted,
	})

	t.Run("no_filter_returns_all", func(t *testing.T) {
		groups, err := model.Agents(FilterSpec{})
		if err != nil {
			t.Fatalf("Agents: %v", err)
		}
		if len(groups) < 2 {
			t.Fatalf("expected at least 2 agent groups, got %d", len(groups))
		}
	})

	t.Run("agent_filter_selects", func(t *testing.T) {
		groups, err := model.Agents(FilterSpec{Agent: "agent-a"})
		if err != nil {
			t.Fatalf("Agents: %v", err)
		}
		if len(groups) != 1 {
			t.Fatalf("expected 1 agent group, got %d", len(groups))
		}
		if groups[0].Agent != "agent-a" {
			t.Fatalf("Agent = %q, want agent-a", groups[0].Agent)
		}
	})

	t.Run("unknown_filter_values_fail_closed", func(t *testing.T) {
		groups, err := model.Agents(FilterSpec{Verdict: "invalid", Chain: "bogus"})
		if err != nil {
			t.Fatalf("Agents: %v", err)
		}
		if len(groups) != 0 {
			t.Fatalf("unknown filter values should match no groups; got %d", len(groups))
		}
	})

	t.Run("chain_intact_filter", func(t *testing.T) {
		groups, err := model.Agents(FilterSpec{Chain: chainIntact})
		if err != nil {
			t.Fatalf("Agents: %v", err)
		}
		// Both agents have intact chains (signed properly).
		if len(groups) < 2 {
			t.Fatalf("chain=intact should match both agents; got %d", len(groups))
		}
	})
}

// --- Preset pre-fill + query-param override ---

func TestHandler_FilterPresets(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	presets := map[string]FilterSpec{
		"blocks-only": {Verdict: verdictBlock, Chain: chainBroken},
	}

	model := NewReadModel(Options{
		ReceiptDir:    dir,
		TrustedKeys:   trusted,
		FilterPresets: presets,
	})

	t.Run("preset_resolves", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/agents?preset=blocks-only", nil)
		f := model.ResolveFilter(req)
		if f.Verdict != verdictBlock {
			t.Fatalf("Verdict = %q, want %q", f.Verdict, verdictBlock)
		}
		if f.Chain != chainBroken {
			t.Fatalf("Chain = %q, want %q", f.Chain, chainBroken)
		}
	})

	t.Run("explicit_overrides_preset", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/agents?preset=blocks-only&verdict=allow", nil)
		f := model.ResolveFilter(req)
		// Explicit verdict should win; but since we check "if all explicit are empty, use preset"
		// the explicit verdict="allow" means we DON'T use the preset at all.
		if f.Verdict != verdictAllow {
			t.Fatalf("Verdict = %q, want %q", f.Verdict, verdictAllow)
		}
	})

	t.Run("unknown_preset_ignored", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/agents?preset=nonexistent", nil)
		f := model.ResolveFilter(req)
		if f.Verdict != "" {
			t.Fatalf("Verdict = %q, want empty for unknown preset", f.Verdict)
		}
	})
}

// --- No-license and wrong-tier negative tests (comprehensive) ---

func TestHandler_NoLicenseAllRoutes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	allPaths := []string{
		"/",
		"/agents",
		"/agent/test",
		"/session/test",
		"/session/test/receipt/0",
		"/exemptions",
	}

	handler := New(Options{
		TrustedOuterAuth: true, ReceiptDir: dir,
	})
	for _, path := range allPaths {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, path, nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("path %s: no-license status = %d, want %d", path, rec.Code, http.StatusForbidden)
		}
	}
}

// --- ReadModel.ReceiptDetail tests ---

func TestReadModel_ReceiptDetail(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	writeReceiptsToDir(t, dir, buildDashboardChain(t, priv, 3))

	model := NewReadModel(Options{
		ReceiptDir:  dir,
		TrustedKeys: map[string]TrustedKey{keyHex: {Source: trustedKeySource}},
	})

	t.Run("found", func(t *testing.T) {
		exp, found, err := model.ReceiptDetail(testSessionID, 1)
		if err != nil {
			t.Fatalf("ReceiptDetail: %v", err)
		}
		if !found {
			t.Fatal("expected receipt to be found")
		}
		if !exp.Verdict.Present {
			t.Fatal("Verdict should be present")
		}
		if exp.Verdict.Detail != "allow" {
			t.Fatalf("Verdict.Detail = %q, want allow", exp.Verdict.Detail)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		_, found, err := model.ReceiptDetail(testSessionID, 999)
		if err != nil {
			t.Fatalf("ReceiptDetail: %v", err)
		}
		if found {
			t.Fatal("expected receipt to not be found")
		}
	})
}

// --- RedactExplanation strips Target in metadata view ---

func TestRedactExplanation_StripsTarget(t *testing.T) {
	t.Parallel()

	exp := evidenceview.DecisionExplanation{
		Target: evidenceview.ExplanationField{
			Present: true,
			Label:   "Target",
			Detail:  "https://api.vendor.example/secret",
		},
		TaintSourcesRawLen: 3,
	}
	redacted := evidenceview.RedactExplanation(exp)
	if redacted.Target.Detail != evidenceview.RedactedDestination {
		t.Fatalf("Target.Detail = %q, want redaction placeholder", redacted.Target.Detail)
	}
	if redacted.TaintSourcesRawLen != 0 {
		t.Fatalf("TaintSourcesRawLen = %d, want 0 after redaction", redacted.TaintSourcesRawLen)
	}
}

// --- Session receipt sub-route preserves existing session path behavior ---

func TestHandler_SessionPathStillWorks(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys:      trusted,
		HasFeature:       allowAgentsFeature,
	})

	t.Run("direct_session", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "Scorecard") {
			t.Fatal("session view should render scorecard")
		}
	})

	t.Run("empty_session", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("empty session status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})
}

func TestApplyFilter_VerdictSelects(t *testing.T) {
	sessions := []SessionSummary{
		{ID: "s1", Agent: "agent-a", Verdicts: []string{"allow", "block"}},
		{ID: "s2", Agent: "agent-b", Verdicts: []string{"allow"}},
		{ID: "s3", Agent: "agent-c", Verdicts: nil},
	}

	cases := []struct {
		name    string
		filter  FilterSpec
		wantIDs []string
	}{
		{"no verdict filter returns all", FilterSpec{}, []string{"s1", "s2", "s3"}},
		{"block selects only blocking session", FilterSpec{Verdict: verdictBlock}, []string{"s1"}},
		{"allow selects both allowing sessions", FilterSpec{Verdict: verdictAllow}, []string{"s1", "s2"}},
		{"warn selects none", FilterSpec{Verdict: verdictWarn}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyFilter(sessions, normalizeFilter(tc.filter))
			gotIDs := make([]string, 0, len(got))
			for _, s := range got {
				gotIDs = append(gotIDs, s.ID)
			}
			if len(gotIDs) != len(tc.wantIDs) {
				t.Fatalf("filter %+v selected %v, want %v", tc.filter, gotIDs, tc.wantIDs)
			}
			for i := range tc.wantIDs {
				if gotIDs[i] != tc.wantIDs[i] {
					t.Fatalf("filter %+v selected %v, want %v", tc.filter, gotIDs, tc.wantIDs)
				}
			}
		})
	}
}

func TestApplyFilter_AgentSubstringCaseInsensitive(t *testing.T) {
	sessions := []SessionSummary{
		{ID: "s1", Agent: "prod-web-agent"},
		{ID: "s2", Agent: "prod-worker"},
		{ID: "s3", Agent: "staging-web"},
	}
	cases := []struct {
		name    string
		agent   string
		wantIDs []string
	}{
		{"substring matches multiple", "prod", []string{"s1", "s2"}},
		{"case-insensitive", "WEB", []string{"s1", "s3"}},
		{"exact still matches", "prod-worker", []string{"s2"}},
		{"no match", "nope", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyFilter(sessions, normalizeFilter(FilterSpec{Agent: tc.agent}))
			gotIDs := make([]string, 0, len(got))
			for _, s := range got {
				gotIDs = append(gotIDs, s.ID)
			}
			if len(gotIDs) != len(tc.wantIDs) {
				t.Fatalf("agent %q selected %v, want %v", tc.agent, gotIDs, tc.wantIDs)
			}
			for i := range tc.wantIDs {
				if gotIDs[i] != tc.wantIDs[i] {
					t.Fatalf("agent %q selected %v, want %v", tc.agent, gotIDs, tc.wantIDs)
				}
			}
		})
	}
}
