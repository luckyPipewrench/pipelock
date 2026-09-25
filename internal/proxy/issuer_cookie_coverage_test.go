// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// --- recordIssuerCookieAllow: name truncation and invalid target ---

func TestRecordIssuerCookieAllow_NameTruncationAndInvalidTarget(t *testing.T) {
	p := &Proxy{}
	ctx, err := audit.NewHTTPLogContext(http.MethodGet, "https://app.vendor.example/x", "192.0.2.1", "req-1", "agent-one")
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("n", issuerCookieMaxLoggedName+10)
	// A nil logger and no receipt sink; this must not panic and must not
	// grow the name past the bound (exercised through logging is not
	// observable here, but the function must run the truncation branch).
	p.recordIssuerCookieAllow(ctx, "AWS Access ID", long, "https://app.vendor.example/x", "req-1", "agent-one", http.MethodGet)

	for _, target := range []string{
		"not a url\x7f",               // url.Parse error
		"http://app.vendor.example/x", // wrong scheme
		"https:///x",                  // empty hostname
	} {
		p.recordIssuerCookieAllow(ctx, "AWS Access ID", "cookie", target, "req-1", "agent-one", http.MethodGet)
	}
}

// --- recordDeliveredIssuerCookies: nil-argument short-circuit ---

func TestRecordDeliveredIssuerCookies_NilArgsNoop(t *testing.T) {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://app.vendor.example/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{Header: http.Header{}}
	// None of these may panic; each hits the nil short-circuit before any
	// store lookup.
	recordDeliveredIssuerCookies(nil, req, resp, true)
	recordDeliveredIssuerCookies(&InterceptContext{}, nil, resp, true)
	recordDeliveredIssuerCookies(&InterceptContext{}, req, nil, true)
}

// --- issuerCookieStatePath: HOME resolution and non-absolute XDG_STATE_HOME ---

func TestIssuerCookieStatePath_HomeResolution(t *testing.T) {
	t.Run("XDG unset uses UserHomeDir", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", "")
		home := t.TempDir()
		t.Setenv("HOME", home)
		path, err := issuerCookieStatePath()
		if err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(home, ".local", "state", "pipelock", "proxy", "issuer-cookies.json")
		if path != want {
			t.Fatalf("path = %q, want %q", path, want)
		}
	})

	t.Run("XDG unset and HOME unset fails", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", "")
		t.Setenv("HOME", "")
		if _, err := issuerCookieStatePath(); err == nil {
			t.Fatal("expected an error when neither XDG_STATE_HOME nor HOME resolve")
		}
	})

	t.Run("relative XDG_STATE_HOME is rejected", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", "relative/state")
		if _, err := issuerCookieStatePath(); err == nil {
			t.Fatal("expected an error for a non-absolute state home")
		}
	})
}

// --- newPersistentIssuerCookieStore: path resolution and load failures reach the logger ---

func TestNewPersistentIssuerCookieStore_PathFailureLogs(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", "")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)

	store := newPersistentIssuerCookieStore(logger)
	if store == nil || store.path != "" {
		t.Fatalf("store = %+v, want a store with no path", store)
	}
	logger.Close()
	raw, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("issuer cookie state unavailable")) {
		t.Fatalf("audit log missing path-resolution failure: %s", raw)
	}
}

func TestNewPersistentIssuerCookieStore_LoadFailureLogs(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	dir := filepath.Join(stateHome, "pipelock", "proxy")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "issuer-cookies.json")
	if err := os.WriteFile(statePath, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)

	store := newPersistentIssuerCookieStore(logger)
	if store == nil || store.disabled {
		t.Fatalf("a load failure must keep the generated key/empty map, not disable: %+v", store)
	}
	logger.Close()
	raw, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("issuer cookie state ignored")) {
		t.Fatalf("audit log missing load failure: %s", raw)
	}
}

// --- load(): directory-permission, lookup, open, and fstat failure paths ---

func TestLoad_DirectoryPermissionInvalid(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	validMode := os.FileMode(0o750)
	if err := os.MkdirAll(dir, validMode); err != nil {
		t.Fatal(err)
	}
	// A deliberately insecure directory mode exercises the rejection path.
	insecureMode := os.FileMode(0o777)
	if err := os.Chmod(dir, insecureMode); err != nil { // umask must not mask this down
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, validMode) })
	s := newIssuerBoundCookieStore()
	s.path = filepath.Join(dir, "issuer-cookies.json")
	if err := s.load(time.Now()); err == nil {
		t.Fatal("a world-writable state directory must be rejected")
	}
}

func TestLoad_LstatNonNotExistError(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	validMode := os.FileMode(0o750)
	// A deliberately search-denied directory exercises a non-ErrNotExist
	// lookup failure.
	noSearchMode := os.FileMode(0o000)
	if err := os.MkdirAll(dir, noSearchMode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, validMode) })
	s := newIssuerBoundCookieStore()
	s.path = filepath.Join(dir, "issuer-cookies.json")
	err := s.load(time.Now())
	if err == nil {
		t.Fatal("a search-denied state directory must fail to load")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected a permission error, not ErrNotExist: %v", err)
	}
}

func TestLoad_InvalidKeyRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
	}{
		{name: "not hex", key: "not-hex-at-all"},
		{name: "wrong length", key: "00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "issuer-cookies.json")
			disk := issuerCookieDisk{Version: issuerCookieStateVersion, Key: tc.key}
			raw, err := json.Marshal(disk)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			s := newIssuerBoundCookieStore()
			s.path = path
			if err := s.load(time.Now()); err == nil {
				t.Fatal("an invalid state key must be rejected")
			}
		})
	}
}

func TestLoad_DuplicateSessionIDRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issuer-cookies.json")
	entry := issuerCookieDiskEntry{Digest: hex.EncodeToString(make([]byte, 32)), Host: "a.example", Port: "443", Path: "/"}
	disk := issuerCookieDisk{
		Version: issuerCookieStateVersion,
		Key:     hex.EncodeToString(make([]byte, 32)),
		Sessions: []issuerCookieDiskSession{
			{ID: "dup", Entries: []issuerCookieDiskEntry{entry}},
			{ID: "dup", Entries: []issuerCookieDiskEntry{entry}},
		},
	}
	raw, err := json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newIssuerBoundCookieStore()
	s.path = path
	if err := s.load(time.Now()); err == nil {
		t.Fatal("a duplicate session id in the state file must be rejected")
	}
}

// --- issuerBoundCookieStore.flush: short-circuits, expiry pruning, empty-session
// deletion, oversized state, and remove-on-invalidate failure ---

func TestFlush_DisabledStoreNoOp(t *testing.T) {
	s := newIssuerBoundCookieStore()
	s.path = filepath.Join(t.TempDir(), "issuer-cookies.json")
	s.disabled = true
	s.dirty = true
	s.flush(time.Now(), true)
	if _, err := os.Stat(s.path); !os.IsNotExist(err) {
		t.Fatal("a disabled store must never write state")
	}
}

func TestFlush_NotDirtyNotForcedNoOp(t *testing.T) {
	s := newIssuerBoundCookieStore()
	s.path = filepath.Join(t.TempDir(), "issuer-cookies.json")
	s.flush(time.Now(), false)
	if _, err := os.Stat(s.path); !os.IsNotExist(err) {
		t.Fatal("a clean, unforced flush must not write")
	}
}

func TestFlush_PrunesExpiredEntriesAndEmptySessions(t *testing.T) {
	now := time.Now()
	s := newIssuerBoundCookieStore()
	s.path = filepath.Join(t.TempDir(), "state", "issuer-cookies.json")
	s.sessions["keep"] = &issuerCookieSession{
		lastUsed: now,
		entries: []issuerCookieEntry{
			{digest: [32]byte{1}, host: "a.example", port: "443", path: "/", expires: now.Add(time.Hour)},
			{digest: [32]byte{2}, host: "a.example", port: "443", path: "/", expires: now.Add(-time.Hour)},
		},
	}
	s.sessions["all-expired"] = &issuerCookieSession{
		lastUsed: now,
		entries: []issuerCookieEntry{
			{digest: [32]byte{3}, host: "b.example", port: "443", path: "/", expires: now.Add(-time.Minute)},
		},
	}
	s.dirty = true
	s.flush(now, true)
	if len(s.sessions["keep"].entries) != 1 {
		t.Fatalf("expired entry not pruned: %+v", s.sessions["keep"].entries)
	}
	if _, ok := s.sessions["all-expired"]; ok {
		t.Fatal("a session left with no live entries must be deleted")
	}
	raw, err := os.ReadFile(filepath.Clean(s.path))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(raw, []byte(`"id":"keep"`)) != 1 {
		t.Fatalf("persisted state missing the surviving session: %s", raw)
	}
	if bytes.Contains(raw, []byte("all-expired")) {
		t.Fatalf("persisted state kept an emptied session: %s", raw)
	}
}

func TestFlush_MarshalFailureInvalidatesState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "issuer-cookies.json")
	now := time.Now()
	s := newIssuerBoundCookieStore()
	s.path = path
	// A year outside [0,9999] makes time.Time.MarshalJSON fail, which
	// makes the enclosing json.Marshal of the disk snapshot fail too.
	badYear := time.Date(99999, 1, 1, 0, 0, 0, 0, time.UTC)
	s.sessions["s"] = &issuerCookieSession{
		lastUsed: now,
		entries:  []issuerCookieEntry{{digest: [32]byte{9}, host: "a.example", port: "443", path: "/", expires: badYear}},
	}
	s.dirty = true
	// Seed an existing (valid) snapshot so we can prove it gets removed.
	if err := os.WriteFile(path, []byte(`{"version":1,"key":"00","sessions":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s.flush(now, true)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a marshal failure must discard the prior snapshot")
	}
}

func TestFlush_OversizedStateInvalidatesState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "issuer-cookies.json")
	now := time.Now()
	s := newIssuerBoundCookieStore()
	s.path = path
	huge := strings.Repeat("x", 5<<20)
	sess := &issuerCookieSession{lastUsed: now}
	for i := 0; i < 8; i++ {
		var digest [32]byte
		digest[0] = byte(i)
		sess.entries = append(sess.entries, issuerCookieEntry{digest: digest, host: "a.example", port: "443", path: "/" + huge, expires: now.Add(time.Hour)})
	}
	s.sessions["s"] = sess
	s.dirty = true
	if err := os.WriteFile(path, []byte(`{"version":1,"key":"00","sessions":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s.flush(now, true)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("state exceeding the byte cap must discard the prior snapshot")
	}
}

func TestFlush_RemoveOnInvalidateFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "issuer-cookies.json")
	now := time.Now()
	s := newIssuerBoundCookieStore()
	s.path = path
	badYear := time.Date(99999, 1, 1, 0, 0, 0, 0, time.UTC)
	s.sessions["s"] = &issuerCookieSession{
		lastUsed: now,
		entries:  []issuerCookieEntry{{digest: [32]byte{9}, host: "a.example", port: "443", path: "/", expires: badYear}},
	}
	s.dirty = true
	if err := os.WriteFile(path, []byte(`{"version":1,"key":"00","sessions":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	validMode := os.FileMode(0o750)
	// A deliberately write-denied directory exercises the removal-failure
	// path when a bad snapshot must be discarded.
	noWriteMode := os.FileMode(0o500)
	if err := os.Chmod(dir, noWriteMode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, validMode) })
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	s.logError = func(logErr error) { logger.LogError(audit.NewMethodLogContext("ISSUER_COOKIE"), logErr) }
	s.flush(now, true)
	logger.Close()
	raw, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("issuer cookie stale state removal failed")) {
		t.Fatalf("expected a removal-failure log: %s", raw)
	}
}

// --- retire(): nil receiver and stopping a pending debounce timer ---

func TestRetire_NilStore(t *testing.T) {
	var s *issuerBoundCookieStore
	if got := s.retire(); got != "" {
		t.Fatalf("retire on a nil store = %q, want empty", got)
	}
}

func TestRetire_StopsPendingTimer(t *testing.T) {
	s := newIssuerBoundCookieStore()
	s.path = filepath.Join(t.TempDir(), "issuer-cookies.json")
	s.dirty = true
	s.lastWrite = time.Now()
	// Within the debounce interval and not forced: schedules a timer
	// instead of writing immediately.
	s.flush(s.lastWrite.Add(time.Second), false)
	if s.timer == nil {
		t.Fatal("expected a pending debounce timer")
	}
	path := s.retire()
	if path == "" {
		t.Fatal("retire must return the prior path")
	}
	if s.timer != nil {
		t.Fatal("retire must stop and clear the pending timer")
	}
	if !s.disabled || s.path != "" {
		t.Fatal("retire must disable the store and clear its path")
	}
}

// --- sessionLocked: disabled store and empty session id ---

func TestSessionLocked_DisabledOrEmptyID(t *testing.T) {
	now := time.Now()
	disabled := newIssuerBoundCookieStore()
	disabled.disabled = true
	if disabled.sessionLocked("agent", true, now) != nil {
		t.Fatal("a disabled store must never produce a session")
	}
	enabled := newIssuerBoundCookieStore()
	if enabled.sessionLocked("", true, now) != nil {
		t.Fatal("an empty session id must never produce a session")
	}
}

// --- parseIssuerSetCookie: attribute-parsing edge branches ---

func TestParseIssuerSetCookie_AttributeEdges(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name string
		line string
		ok   bool
	}{
		{name: "overlong attribute value skipped", line: "sid=v; Comment=" + strings.Repeat("z", issuerCookieMaxAttrBytes+1) + "; Path=/", ok: true},
		{name: "max-age not parseable as int64", line: "sid=v; Max-Age=99999999999999999999999999", ok: true},
		{name: "max-age beyond duration ceiling", line: "sid=v; Max-Age=99999999999", ok: true},
		{name: "max-age wins, later expires ignored", line: "sid=v; Max-Age=60; Expires=" + now.Add(-time.Hour).UTC().Format(http.TimeFormat), ok: true},
		{name: "expires unparsable", line: "sid=v; Expires=not-a-date", ok: true},
		{name: "path attribute empty resets to default", line: "sid=v; Path=", ok: true},
		{name: "path attribute relative resets to default", line: "sid=v; Path=relative", ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := parseIssuerSetCookie(tc.line, "/default", now)
			if ok != tc.ok {
				t.Fatalf("%q: ok = %t, want %t", tc.line, ok, tc.ok)
			}
			if strings.Contains(tc.name, "path attribute") && c.path != "/default" {
				t.Fatalf("%q: path = %q, want default", tc.line, c.path)
			}
		})
	}

	// max-age beyond the duration ceiling must not expire the cookie.
	c, ok := parseIssuerSetCookie("sid=v; Max-Age=99999999999", "/", now)
	if !ok || c.expired || !c.expires.IsZero() {
		t.Fatalf("beyond-ceiling max-age: ok=%t expired=%t expires=%v", ok, c.expired, c.expires)
	}
	_ = strconv.Itoa // keep strconv imported for the numeric edges above
}

// --- observeResponse: invalid origin, oversized Set-Cookie batch, empty
// session id, and entry replacement ---

func TestObserveResponse_InvalidOriginNoop(t *testing.T) {
	s := newIssuerBoundCookieStore()
	origin, _ := url.Parse("http://app.vendor.example/login") // not https
	s.observeResponse("agent-one", origin, http.Header{"Set-Cookie": {"lb=v; Path=/"}}, true, time.Now())
	if len(s.sessions) != 0 {
		t.Fatal("an invalid origin must record nothing")
	}
}

func TestObserveResponse_TruncatesOversizedSetCookieBatch(t *testing.T) {
	s := newIssuerBoundCookieStore()
	origin, _ := url.Parse("https://app.vendor.example/login")
	headers := http.Header{}
	for i := 0; i < issuerCookieMaxSetCookies+10; i++ {
		headers.Add("Set-Cookie", fmt.Sprintf("c%d=v%d; Path=/", i, i))
	}
	now := time.Now()
	s.observeResponse("agent-one", origin, headers, true, now)
	sess := s.sessions["agent-one"]
	if sess == nil || len(sess.entries) != issuerCookieMaxSetCookies {
		got := 0
		if sess != nil {
			got = len(sess.entries)
		}
		t.Fatalf("entries recorded = %d, want %d (batch must be truncated)", got, issuerCookieMaxSetCookies)
	}
	if s.allows("agent-one", origin, fmt.Sprintf("c%d", issuerCookieMaxSetCookies), fmt.Sprintf("v%d", issuerCookieMaxSetCookies), now) {
		t.Fatal("a Set-Cookie line past the batch cap must not be recorded")
	}
}

func TestObserveResponse_EmptySessionIDNoop(t *testing.T) {
	s := newIssuerBoundCookieStore()
	origin, _ := url.Parse("https://app.vendor.example/login")
	s.observeResponse("", origin, http.Header{"Set-Cookie": {"lb=v; Path=/"}}, true, time.Now())
	if len(s.sessions) != 0 {
		t.Fatal("an empty session id must record nothing")
	}
}

func TestObserveResponse_ReplacesExistingEntry(t *testing.T) {
	s := newIssuerBoundCookieStore()
	origin, _ := url.Parse("https://app.vendor.example/login")
	now := time.Now()
	s.observeResponse("agent-one", origin, http.Header{"Set-Cookie": {"lb=v1; Path=/; Max-Age=60"}}, true, now)
	if len(s.sessions["agent-one"].entries) != 1 {
		t.Fatal("expected one entry after the first issuance")
	}
	// Re-issuing the exact same name/value/scope replaces the entry in place
	// rather than appending a duplicate.
	later := now.Add(time.Second)
	s.observeResponse("agent-one", origin, http.Header{"Set-Cookie": {"lb=v1; Path=/; Max-Age=600"}}, true, later)
	if len(s.sessions["agent-one"].entries) != 1 {
		t.Fatalf("entries = %d, want 1 after replacement", len(s.sessions["agent-one"].entries))
	}
	if !s.allows("agent-one", origin, "lb", "v1", later.Add(100*time.Second)) {
		t.Fatal("the replaced entry must carry the refreshed expiry")
	}
}

// --- issuerCookieDefaultPath: empty and non-slash-prefixed paths ---

func TestIssuerCookieDefaultPath_EmptyAndNonSlash(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{in: "", want: "/"},
		{in: "relative", want: "/"},
	} {
		if got := issuerCookieDefaultPath(tc.in); got != tc.want {
			t.Fatalf("issuerCookieDefaultPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- allows: empty request path defaults to "/" ---

func TestAllows_EmptyRequestPathDefaultsToRoot(t *testing.T) {
	s := newIssuerBoundCookieStore()
	origin, _ := url.Parse("https://app.vendor.example/login")
	now := time.Now()
	s.observeResponse("agent-one", origin, http.Header{"Set-Cookie": {"lb=v; Path=/; Max-Age=60"}}, true, now)
	target, _ := url.Parse("https://app.vendor.example")
	if target.Path != "" {
		t.Fatal("test setup expected an empty request path")
	}
	if !s.allows("agent-one", target, "lb", "v", now) {
		t.Fatal("an empty request path must default to root and match the root-scoped cookie")
	}
}

// --- issuerCookieScanHeaders: nil store/target short-circuit ---

func TestIssuerCookieScanHeaders_NilStoreOrTarget(t *testing.T) {
	headers := http.Header{"Cookie": {"a=b"}}
	target, _ := url.Parse("https://app.vendor.example/")
	scan, allowances := issuerCookieScanHeaders(t.Context(), headers, nil, nil, "agent-one", target, time.Now())
	if allowances != nil || scan.Get("Cookie") != "a=b" {
		t.Fatalf("nil store must be a no-op: scan=%v allowances=%v", scan, allowances)
	}
	store := newIssuerBoundCookieStore()
	scan, allowances = issuerCookieScanHeaders(t.Context(), headers, nil, store, "agent-one", nil, time.Now())
	if allowances != nil || scan.Get("Cookie") != "a=b" {
		t.Fatalf("nil target must be a no-op: scan=%v allowances=%v", scan, allowances)
	}
}

// --- issuerCookieScanHeaders / cookieNamesWithDLPMatch: empty Cookie segments ---

func TestIssuerCookieScanHeaders_SkipsEmptySegments(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	store := newIssuerBoundCookieStore()
	target, _ := url.Parse("https://app.vendor.example/")
	now := time.Now()
	// An issuance is required so the rewritten header (with empty segments
	// dropped) is observable: with no allowances the function returns the
	// original header unchanged.
	store.observeResponse("agent-one", target, http.Header{"Set-Cookie": {"lb=" + issuerAWSShapedValue() + "; Path=/"}}, true, now)
	headers := http.Header{"Cookie": {"a=b; ; lb=" + issuerAWSShapedValue() + "; ;"}}
	scan, allowances := issuerCookieScanHeaders(t.Context(), headers, sc, store, "agent-one", target, now)
	if len(allowances) != 1 || allowances[0].Name != "lb" {
		t.Fatalf("expected a single allowance for lb: %v", allowances)
	}
	if got := scan.Get("Cookie"); got != "a=b" {
		t.Fatalf("scanned Cookie = %q, want empty segments dropped and the issued pair removed", got)
	}
}

func TestCookieNamesWithDLPMatch_SkipsEmptySegments(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	aws := issuerAWSShapedValue()
	headers := http.Header{"Cookie": {"; lb=" + aws + "; ;"}}
	got := cookieNamesWithDLPMatch(t.Context(), headers, sc)
	if len(got) != 1 || got[0] != "lb" {
		t.Fatalf("names = %v, want just [lb]", got)
	}
}

// --- Proxy.New: startup cleanup of stale state when the feature is disabled ---

func TestNew_DisabledFeatureRemovalFailureLogs(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	dir := filepath.Join(stateHome, "pipelock", "proxy")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "issuer-cookies.json")
	if err := os.WriteFile(statePath, []byte(`{"version":1,"key":"00","sessions":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	validMode := os.FileMode(0o750)
	// A deliberately write-denied directory exercises the startup
	// removal-failure path.
	noWriteMode := os.FileMode(0o500)
	if err := os.Chmod(dir, noWriteMode); err != nil { // no write: os.Remove fails
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, validMode) })

	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = false // issuerCookieEnabled(cfg) == false
	cfg.Internal = nil
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	logger.Close()
	raw, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("issuer cookie state reset failed")) {
		t.Fatalf("expected a removal-failure log at startup: %s", raw)
	}
}

// --- Proxy.Reload: previously-disabled prerequisite becomes enabled for the
// first time, so old on-disk evidence (if any) must be treated as
// inadmissible and a fresh persistent store started ---

func TestReload_FirstEnableFromNeverEnabledStartsPersistentStore(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = false // disabled at startup: never had a path
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if startPath := p.issuerCookieRuntime.Load().store.path; startPath != "" {
		t.Fatalf("a store never enabled at startup must have no path, got %q", startPath)
	}

	on := cfg.Clone()
	on.TLSInterception.Enabled = true
	if !p.Reload(on, scanner.MustNew(on)) {
		t.Fatal("enabling reload rejected")
	}
	runtime := p.issuerCookieRuntime.Load()
	if runtime.store == nil || runtime.store.path == "" {
		t.Fatal("first-enabled reload must start a persistent store with a resolved path")
	}
	path, err := issuerCookieStatePath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected the fresh (empty) state file to be flushed: %v", err)
	}
}

// TestReload_FirstEnableFlushFailureLogsThroughProxyLogger exercises the
// same first-enable path as above, but with the state directory unwritable
// so the initial flush fails and the reload-installed logError closure runs
// (proxy.go's issuerCookieRuntime install for a never-before-enabled store).
func TestReload_FirstEnableFlushFailureLogsThroughProxyLogger(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	dir := filepath.Join(stateHome, "pipelock", "proxy")
	validMode := os.FileMode(0o750)
	if err := os.MkdirAll(dir, validMode); err != nil {
		t.Fatal(err)
	}
	// A deliberately write-denied directory exercises the first-enable
	// flush-failure path.
	noWriteMode := os.FileMode(0o500)
	if err := os.Chmod(dir, noWriteMode); err != nil { // no write: atomicfile.Write fails
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, validMode) })

	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = false
	cfg.Internal = nil
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	on := cfg.Clone()
	on.TLSInterception.Enabled = true
	if !p.Reload(on, scanner.MustNew(on)) {
		t.Fatal("enabling reload rejected")
	}
	// Read while the logger is still open: the file sink writes
	// synchronously, and closing here (before the registered t.Cleanup
	// closes of p and then the logger) would race a later flush attempt
	// during p.Close() against an already-closed file handle.
	raw, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("ISSUER_COOKIE")) {
		t.Fatalf("expected the flush failure to reach the proxy logger: %s", raw)
	}
}
