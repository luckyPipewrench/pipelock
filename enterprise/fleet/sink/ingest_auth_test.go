//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestHandler_ReaderTokenRequired ensures GET endpoints reject requests
// when --reader-token-file is configured and the caller does not supply
// a matching Authorization header.
func TestHandler_ReaderTokenRequired(t *testing.T) {
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(context.Background(), t.TempDir()+"/sink.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	const token = "s3cret-reader-token"
	handler, err := NewHandler(Options{
		Store:       store,
		Resolver:    staticResolver(pub),
		DLPScanner:  scanner.New(config.Defaults()),
		Now:         func() time.Time { return sinkTestNow },
		ReaderToken: token,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"events":[{"message":"clean"}]}`)
	env := signedEnvelope(t, "batch-auth", 1, 1, payload, priv)
	if resp := postBatch(t, handler, env, payload); resp.Code != http.StatusAccepted {
		t.Fatalf("post status = %d body=%s", resp.Code, resp.Body.String())
	}

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"no_header", "", http.StatusUnauthorized},
		{"wrong_scheme", "Basic " + token, http.StatusUnauthorized},
		{"wrong_token", "Bearer not-the-token", http.StatusUnauthorized},
		{"correct_token", "Bearer " + token, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run("list_"+tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				AuditBatchesPath+"?org_id=org-test&fleet_id=fleet-prod&instance_id=instance-a", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if resp.Code != tc.want {
				t.Fatalf("status = %d body=%s want=%d", resp.Code, resp.Body.String(), tc.want)
			}
		})
		t.Run("get_"+tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				AuditBatchesPath+"/batch-auth?org_id=org-test&fleet_id=fleet-prod&instance_id=instance-a", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if resp.Code != tc.want {
				t.Fatalf("status = %d body=%s want=%d", resp.Code, resp.Body.String(), tc.want)
			}
		})
	}

	// Ingest is signature-authenticated regardless of reader token.
	otherPayload := []byte(`{"events":[{"message":"clean2"}]}`)
	otherEnv := signedEnvelope(t, "batch-auth-2", 2, 2, otherPayload, priv)
	if resp := postBatch(t, handler, otherEnv, otherPayload); resp.Code != http.StatusAccepted {
		t.Fatalf("ingest without Authorization should still succeed: %d %s", resp.Code, resp.Body.String())
	}
}

// TestHandler_RequiresFullNamespaceOnList tightens enumeration scope:
// even when reader auth is satisfied, the list endpoint requires all
// three namespace fields. This prevents a single GET from sweeping
// every tenant's batches in a multi-tenant deployment.
func TestHandler_RequiresFullNamespaceOnList(t *testing.T) {
	handler, _, priv := testHandler(t)
	payload := []byte(`{"events":[{"message":"clean"}]}`)
	env := signedEnvelope(t, "batch-1", 1, 1, payload, priv)
	if resp := postBatch(t, handler, env, payload); resp.Code != http.StatusAccepted {
		t.Fatalf("post = %d body=%s", resp.Code, resp.Body.String())
	}
	cases := []struct {
		name string
		path string
		want int
	}{
		{"no_filters", AuditBatchesPath, http.StatusBadRequest},
		{"only_org", AuditBatchesPath + "?org_id=org-test", http.StatusBadRequest},
		{"org_fleet", AuditBatchesPath + "?org_id=org-test&fleet_id=fleet-prod", http.StatusBadRequest},
		{"full", AuditBatchesPath + "?org_id=org-test&fleet_id=fleet-prod&instance_id=instance-a", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.path, nil)
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if resp.Code != tc.want {
				t.Fatalf("status = %d body=%s want=%d", resp.Code, resp.Body.String(), tc.want)
			}
		})
	}
}

// TestHandler_EnforcesKeyBinding rejects valid signatures whose signing
// key is configured with a tenant binding that does not match the
// envelope's namespace. Binding enforcement runs AFTER signature
// verification — only proven-possession keys can trip it.
func TestHandler_EnforcesKeyBinding(t *testing.T) {
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(context.Background(), t.TempDir()+"/sink.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	bindings := map[string]KeyBinding{
		"audit-signer": {OrgID: "globex", FleetID: "prod", InstanceID: "pl-1"},
	}
	handler, err := NewHandler(Options{
		Store:       store,
		Resolver:    staticResolver(pub),
		DLPScanner:  scanner.New(config.Defaults()),
		Now:         func() time.Time { return sinkTestNow },
		KeyBindings: bindings,
	})
	if err != nil {
		t.Fatal(err)
	}

	// signedEnvelope uses org-test/fleet-prod/instance-a — does NOT match the binding.
	payload := []byte(`{"events":[{"message":"clean"}]}`)
	mismatch := signedEnvelope(t, "batch-binding-fail", 1, 1, payload, priv)
	resp := postBatch(t, handler, mismatch, payload)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s want=403", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "not authorized for batch namespace") {
		t.Fatalf("response missing binding error: %s", resp.Body.String())
	}
}

// TestHandler_AllowsMatchingKeyBinding accepts a batch whose envelope
// namespace satisfies the configured binding for every signing key.
func TestHandler_AllowsMatchingKeyBinding(t *testing.T) {
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(context.Background(), t.TempDir()+"/sink.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	bindings := map[string]KeyBinding{
		// Bind to the namespace used by signedEnvelope().
		"audit-signer": {OrgID: "org-test", FleetID: "fleet-prod", InstanceID: "instance-a"},
	}
	handler, err := NewHandler(Options{
		Store:       store,
		Resolver:    staticResolver(pub),
		DLPScanner:  scanner.New(config.Defaults()),
		Now:         func() time.Time { return sinkTestNow },
		KeyBindings: bindings,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"events":[{"message":"clean"}]}`)
	env := signedEnvelope(t, "batch-binding-ok", 1, 1, payload, priv)
	if resp := postBatch(t, handler, env, payload); resp.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestHandler_RejectsExplicitJSONNull covers the documented bypass
// vector where `json.RawMessage("null")` slips past a `== nil` check.
// Even though downstream validation eventually rejects zero-value
// envelopes, the parser layer itself must reject explicit-null too.
func TestHandler_RejectsExplicitJSONNull(t *testing.T) {
	handler, _, priv := testHandler(t)
	payload := []byte(`{"events":[{"message":"clean"}]}`)
	env := signedEnvelope(t, "batch-null", 1, 1, payload, priv)
	envelopeJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		body string
	}{
		{"envelope_null", `{"envelope":null,"payload":` + string(payloadJSON) + `}`},
		{"payload_null", `{"envelope":` + string(envelopeJSON) + `,"payload":null}`},
		{"both_null", `{"envelope":null,"payload":null}`},
		{"whitespace_null", `{"envelope": ` + "  null  " + `,"payload":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
				AuditBatchesPath, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if resp.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s want=400", resp.Code, resp.Body.String())
			}
			if !strings.Contains(resp.Body.String(), "expected envelope and payload only") {
				t.Fatalf("body did not surface the parser-layer rejection: %s", resp.Body.String())
			}
		})
	}
}

// TestStore_DetectForkUsesSeqRangeOverlap exercises the SQL range
// query path: a non-overlapping seq window must NOT trigger fork
// detection (would be a false positive); an overlapping window with
// different content MUST.
func TestStore_DetectForkUsesSeqRangeOverlap(t *testing.T) {
	handler, _, priv := testHandler(t)

	// Seed two non-overlapping batches in the same namespace.
	first := signedEnvelope(t, "batch-non-overlap-1", 1, 2, []byte(`{"events":[{"m":"a"}]}`), priv)
	if resp := postBatch(t, handler, first, []byte(`{"events":[{"m":"a"}]}`)); resp.Code != http.StatusAccepted {
		t.Fatalf("first = %d body=%s", resp.Code, resp.Body.String())
	}
	third := signedEnvelope(t, "batch-non-overlap-3", 5, 6, []byte(`{"events":[{"m":"c"}]}`), priv)
	if resp := postBatch(t, handler, third, []byte(`{"events":[{"m":"c"}]}`)); resp.Code != http.StatusAccepted {
		t.Fatalf("third = %d body=%s", resp.Code, resp.Body.String())
	}

	// A new batch with seq [3,4] does NOT overlap either — must succeed.
	middle := signedEnvelope(t, "batch-non-overlap-2", 3, 4, []byte(`{"events":[{"m":"b"}]}`), priv)
	if resp := postBatch(t, handler, middle, []byte(`{"events":[{"m":"b"}]}`)); resp.Code != http.StatusAccepted {
		t.Fatalf("middle = %d body=%s; non-overlapping seq window should not trigger fork", resp.Code, resp.Body.String())
	}

	// A batch with seq [2,3] DOES overlap [1,2] — must be flagged.
	overlap := signedEnvelope(t, "batch-overlap", 2, 3, []byte(`{"events":[{"m":"z"}]}`), priv)
	if resp := postBatch(t, handler, overlap, []byte(`{"events":[{"m":"z"}]}`)); resp.Code != http.StatusConflict {
		t.Fatalf("overlap = %d body=%s; overlapping seq with different content must conflict", resp.Code, resp.Body.String())
	}
}

// TestStore_DBFileIsOwnerOnly checks the owner-only store mode:
// audit payloads sit in this file, so it must not be world- or
// group-readable even if umask is permissive.
func TestStore_DBFileIsOwnerOnly(t *testing.T) {
	path := t.TempDir() + "/sink.db"
	store, err := OpenStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("db file mode = %o, want 0600", mode)
	}
}

func TestStore_RejectsSymlinkDBPath(t *testing.T) {
	dir := t.TempDir()
	target := dir + "/target.db"
	link := dir + "/sink.db"
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(context.Background(), link); err == nil {
		t.Fatal("OpenStore accepted symlink DB path")
	}
}

func TestStore_UsesResolvedParentPath(t *testing.T) {
	dir := t.TempDir()
	realParent := filepath.Join(dir, "real")
	if err := os.Mkdir(realParent, 0o750); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(dir, "link")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(context.Background(), filepath.Join(linkParent, "sink.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	if _, err := os.Stat(filepath.Join(realParent, "sink.db")); err != nil {
		t.Fatalf("resolved parent DB missing: %v", err)
	}
}

// TestStore_FormatUintIsLexNumericSortable verifies the padding
// behavior that fixes the lex-vs-numeric sort hazard on TEXT seq
// columns. Without padding "9" > "100" lex-sorts wrong and the
// namespace_sequence index becomes useless.
func TestStore_FormatUintIsLexNumericSortable(t *testing.T) {
	values := []uint64{0, 1, 9, 10, 100, 1000, 18446744073709551615}
	encoded := make([]string, len(values))
	for i, v := range values {
		encoded[i] = formatUint(v)
		if len(encoded[i]) != uintTextWidth {
			t.Fatalf("formatUint(%d) = %q (len=%d), want width %d", v, encoded[i], len(encoded[i]), uintTextWidth)
		}
	}
	// Strings should sort identically to the underlying uints.
	for i := 1; i < len(encoded); i++ {
		if encoded[i-1] >= encoded[i] {
			t.Fatalf("encoded[%d]=%q !< encoded[%d]=%q; lex order != numeric order", i-1, encoded[i-1], i, encoded[i])
		}
	}
}

// TestStore_RecoveryRoundtripParsesPaddedSeq guards against a future
// formatUint change that breaks parseUintField round-trip.
func TestStore_RecoveryRoundtripParsesPaddedSeq(t *testing.T) {
	for _, v := range []uint64{0, 1, 1000, 18446744073709551615} {
		got, err := parseUintField("seq", formatUint(v))
		if err != nil {
			t.Fatalf("parseUintField(formatUint(%d)) error = %v", v, err)
		}
		if got != v {
			t.Fatalf("round-trip mismatch: in=%d out=%d", v, got)
		}
	}
}

// TestNewHandler_CopiesKeyBindings makes sure post-construction
// mutation of the caller's binding map cannot affect the handler.
func TestNewHandler_CopiesKeyBindings(t *testing.T) {
	pub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(context.Background(), t.TempDir()+"/sink.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	bindings := map[string]KeyBinding{"audit-signer": {OrgID: "acme"}}
	handler, err := NewHandler(Options{
		Store:       store,
		Resolver:    staticResolver(pub),
		DLPScanner:  scanner.New(config.Defaults()),
		KeyBindings: bindings,
	})
	if err != nil {
		t.Fatal(err)
	}
	delete(bindings, "audit-signer")
	if _, ok := handler.keyBindings["audit-signer"]; !ok {
		t.Fatal("handler.keyBindings was aliased to caller-supplied map")
	}
}

// TestIsMissingOrNull exercises the documented bypass-pattern fix
// directly so future regressions get caught in unit scope.
func TestIsMissingOrNull(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
		want bool
	}{
		{"nil", nil, true},
		{"empty", json.RawMessage{}, true},
		{"null_literal", json.RawMessage(`null`), true},
		{"null_with_whitespace", json.RawMessage(` null `), true},
		{"valid_object", json.RawMessage(`{}`), false},
		{"valid_string", json.RawMessage(`"hi"`), false},
		{"valid_number", json.RawMessage(`0`), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMissingOrNull(tc.raw); got != tc.want {
				t.Fatalf("isMissingOrNull(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestKeyBinding_IsZero covers the convenience predicate used by the
// CLI to decide whether to populate the bindings map.
func TestKeyBinding_IsZero(t *testing.T) {
	if !(KeyBinding{}).IsZero() {
		t.Fatal("empty binding reports non-zero")
	}
	if (KeyBinding{OrgID: "x"}).IsZero() {
		t.Fatal("binding with org reports zero")
	}
	if (KeyBinding{FleetID: "x"}).IsZero() {
		t.Fatal("binding with fleet reports zero")
	}
	if (KeyBinding{InstanceID: "x"}).IsZero() {
		t.Fatal("binding with instance reports zero")
	}
}

// TestEnforceBindings_SkipsUnboundKeys exercises the branch where a
// signer key id has no binding configured: such keys are unrestricted
// and must not be rejected even when the map has other entries.
func TestEnforceBindings_SkipsUnboundKeys(t *testing.T) {
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(context.Background(), t.TempDir()+"/sink.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	// Bind a DIFFERENT key id; the signer "audit-signer" is unbound.
	handler, err := NewHandler(Options{
		Store:      store,
		Resolver:   staticResolver(pub),
		DLPScanner: scanner.New(config.Defaults()),
		Now:        func() time.Time { return sinkTestNow },
		KeyBindings: map[string]KeyBinding{
			"other-signer": {OrgID: "anything"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"events":[{"message":"clean"}]}`)
	env := signedEnvelope(t, "batch-unbound", 1, 1, payload, priv)
	if resp := postBatch(t, handler, env, payload); resp.Code != http.StatusAccepted {
		t.Fatalf("unbound signer should be accepted; got %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestParseLimit_ExplicitValue covers the success branch of
// parseLimit with a parseable integer, exercising the
// normalizeLimit clamp from inside parseLimit too.
func TestParseLimit_ExplicitValue(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"", defaultQueryLimit},
		{"  ", defaultQueryLimit},
		{"5", 5},
		{"99999", maxQueryLimit},
		{"-1", defaultQueryLimit},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseLimit(tc.in)
			if err != nil {
				t.Fatalf("parseLimit(%q) err = %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("parseLimit(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestOpenStore_RejectsBadPaths covers the early failure branches:
// empty path is handled by an explicit error; using an existing
// directory as the DB path causes sql.Open + migrate to fail.
func TestOpenStore_RejectsBadPaths(t *testing.T) {
	if _, err := OpenStore(context.Background(), ""); err == nil {
		t.Fatal("empty path accepted")
	}
	if _, err := OpenStore(context.Background(), "   "); err == nil {
		t.Fatal("whitespace path accepted")
	}
	dir := t.TempDir()
	// Passing the directory itself to OpenStore should fail when SQLite
	// or our chmod tries to operate on it as a file.
	if _, err := OpenStore(context.Background(), dir); err == nil {
		t.Fatal("directory-as-db-path accepted")
	}
}

// TestStore_ListWithExplicitFilters exercises every WHERE-clause
// branch in List so the conditional query builder is fully covered.
func TestStore_ListWithExplicitFilters(t *testing.T) {
	handler, store, priv := testHandler(t)
	payload := []byte(`{"events":[{"m":"x"}]}`)
	env := signedEnvelope(t, "batch-filters", 1, 1, payload, priv)
	if resp := postBatch(t, handler, env, payload); resp.Code != http.StatusAccepted {
		t.Fatalf("post = %d body=%s", resp.Code, resp.Body.String())
	}

	cases := []struct {
		name string
		q    Query
		want int
	}{
		{"all_filters", Query{OrgID: "org-test", FleetID: "fleet-prod", InstanceID: "instance-a", BatchID: "batch-filters"}, 1},
		{"namespace_only", Query{OrgID: "org-test", FleetID: "fleet-prod", InstanceID: "instance-a"}, 1},
		{"wrong_batch", Query{OrgID: "org-test", FleetID: "fleet-prod", InstanceID: "instance-a", BatchID: "missing"}, 0},
		{"wrong_org", Query{OrgID: "globex", FleetID: "fleet-prod", InstanceID: "instance-a"}, 0},
		{"only_fleet", Query{FleetID: "fleet-prod"}, 1},
		{"only_instance", Query{InstanceID: "instance-a"}, 1},
		{"unfiltered", Query{}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.List(context.Background(), tc.q)
			if err != nil {
				t.Fatalf("List err = %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("len(List) = %d, want %d (%+v)", len(got), tc.want, got)
			}
		})
	}
}

// TestStore_GetMissing covers the not-found branch (sql.ErrNoRows
// mapped to ok=false) and the namespace-mismatch branch (same
// batch id but different org).
func TestStore_GetMissing(t *testing.T) {
	handler, store, priv := testHandler(t)
	payload := []byte(`{"events":[{"m":"x"}]}`)
	env := signedEnvelope(t, "batch-get", 1, 1, payload, priv)
	if resp := postBatch(t, handler, env, payload); resp.Code != http.StatusAccepted {
		t.Fatalf("post = %d body=%s", resp.Code, resp.Body.String())
	}

	_, ok, err := store.Get(context.Background(), "wrong-org", "fleet-prod", "instance-a", "batch-get")
	if err != nil {
		t.Fatalf("Get err = %v", err)
	}
	if ok {
		t.Fatal("Get returned ok for mismatched org")
	}

	_, ok, err = store.Get(context.Background(), "org-test", "fleet-prod", "instance-a", "nope")
	if err != nil {
		t.Fatalf("Get err = %v", err)
	}
	if ok {
		t.Fatal("Get returned ok for unknown batch")
	}
}

// TestStore_OperationsAfterClose covers the error branches of List,
// Get, and Put when the underlying DB has been closed. Mirrors what
// happens during an unclean shutdown race.
func TestStore_OperationsAfterClose(t *testing.T) {
	store, err := OpenStore(context.Background(), t.TempDir()+"/sink.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(context.Background(), Query{OrgID: "any", FleetID: "f", InstanceID: "i"}); err == nil {
		t.Fatal("List on closed store accepted")
	}
	if _, _, err := store.Get(context.Background(), "o", "f", "i", "b"); err == nil {
		t.Fatal("Get on closed store accepted")
	}
}

// TestHandler_StoreErrorsFromGetEndpoints exercises the handleList and
// handleGet 500 branches: closing the store after handler construction
// makes any DB call return an error, which the handlers must convert
// to InternalServerError rather than leaking sql package details.
func TestHandler_StoreErrorsFromGetEndpoints(t *testing.T) {
	handler, store, _ := testHandler(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	listReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		AuditBatchesPath+"?org_id=org-test&fleet_id=fleet-prod&instance_id=instance-a", nil)
	listResp := httptest.NewRecorder()
	handler.ServeHTTP(listResp, listReq)
	if listResp.Code != http.StatusInternalServerError {
		t.Fatalf("list after close: status = %d body=%s", listResp.Code, listResp.Body.String())
	}

	getReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		AuditBatchesPath+"/any-id?org_id=org-test&fleet_id=fleet-prod&instance_id=instance-a", nil)
	getResp := httptest.NewRecorder()
	handler.ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusInternalServerError {
		t.Fatalf("get after close: status = %d body=%s", getResp.Code, getResp.Body.String())
	}
}

// TestHandler_IngestStoreErrorMapped covers the Put error path: closing
// the store after handler construction causes Put to fail, which the
// handler must convert via statusForError. This walks every line of
// handleIngest after VerifySignaturesAt.
func TestHandler_IngestStoreErrorMapped(t *testing.T) {
	handler, store, priv := testHandler(t)
	payload := []byte(`{"events":[{"m":"clean"}]}`)
	env := signedEnvelope(t, "batch-store-err", 1, 1, payload, priv)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	resp := postBatch(t, handler, env, payload)
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s want 500", resp.Code, resp.Body.String())
	}
}

// TestHandler_RejectsMethodOnSubpath covers the path / method routing
// fallthroughs that aren't hit by the simpler routing table test.
func TestHandler_RejectsMethodOnSubpath(t *testing.T) {
	handler, _, _ := testHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete,
		AuditBatchesPath+"/some-id?org_id=o&fleet_id=f&instance_id=i", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("DELETE on subpath status = %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestHandler_RejectsTrailingSlashGet covers the empty-batch-id branch
// when a client sends GET .../audit/batches/ (trailing slash, nothing
// after). Without the explicit check this would fall into handleGet
// with an empty id and may surface a misleading 404 from the store.
func TestHandler_RejectsTrailingSlashGet(t *testing.T) {
	handler, _, _ := testHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		AuditBatchesPath+"/?org_id=o&fleet_id=f&instance_id=i", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("trailing-slash get status = %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestHandler_RejectsNestedBatchID covers the slash-in-id rejection
// inside handleGet (path traversal-shaped input).
func TestHandler_RejectsNestedBatchID(t *testing.T) {
	handler, _, _ := testHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		AuditBatchesPath+"/foo/bar?org_id=o&fleet_id=f&instance_id=i", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("nested-id get status = %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestStatusForError covers the new error mappings (Unauthorized,
// KeyBindingViolated) added in this change. The default case is
// covered elsewhere.
func TestStatusForError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"unauthorized", ErrUnauthorized, http.StatusUnauthorized},
		{"binding", ErrKeyBindingViolated, http.StatusForbidden},
		{"conflict", ErrBatchConflict, http.StatusConflict},
		{"fork", ErrForkDetected, http.StatusConflict},
		{"too_large", ErrRequestTooLarge, http.StatusRequestEntityTooLarge},
		{"bad_request", ErrInvalidRequestBody, http.StatusBadRequest},
		{"wrapped_unauthorized", fmt.Errorf("wrap: %w", ErrUnauthorized), http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := statusForError(tc.err); got != tc.want {
				t.Fatalf("statusForError(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}
