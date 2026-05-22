// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	domenvelope "github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const testTrustDomain = "partner.example"

func TestTrustAddListRemoveRoundTrip(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "trust.json")
	pub, _, pubHex := testTrustKey(t)

	out, stderr, err := runEnvelopeCmdFull("", "trust", "--store", storePath, "add", testTrustDomain, "--key", pubHex)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if !strings.Contains(out, "trusted\tpartner.example") {
		t.Fatalf("add output = %q", out)
	}
	if !strings.Contains(stderr, "runtime proxy verification reads trusted keys from pipelock.yaml") {
		t.Fatalf("add stderr = %q", stderr)
	}
	info, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("stat store: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("store mode = %v, want 0o600", got)
	}

	out, err = runEnvelopeCmd("trust", "--store", storePath, "list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, testTrustDomain) || !strings.Contains(out, pubHex[:12]) {
		t.Fatalf("list output = %q", out)
	}

	out, err = runEnvelopeCmd("trust", "--store", storePath, "list", "--json")
	if err != nil {
		t.Fatalf("list json: %v", err)
	}
	var records []trustRecord
	if err := json.Unmarshal([]byte(out), &records); err != nil {
		t.Fatalf("decode list json: %v\n%s", err, out)
	}
	if len(records) != 1 || records[0].TrustDomain != testTrustDomain || records[0].KeyHex != hex.EncodeToString(pub) {
		t.Fatalf("records = %+v", records)
	}

	out, err = runEnvelopeCmd("trust", "--store", storePath, "remove", testTrustDomain)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !strings.Contains(out, "removed\tpartner.example") {
		t.Fatalf("remove output = %q", out)
	}
	out, err = runEnvelopeCmd("trust", "--store", storePath, "list", "--json")
	if err != nil {
		t.Fatalf("list json after remove: %v", err)
	}
	records = nil
	if err := json.Unmarshal([]byte(out), &records); err != nil {
		t.Fatalf("decode list json after remove: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("records after remove = %+v", records)
	}
}

func TestTrustAddDuplicateIsIdempotent(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "trust.json")
	_, _, pubHex := testTrustKey(t)
	var lastStderr string
	for i := 0; i < 2; i++ {
		_, stderr, err := runEnvelopeCmdFull("", "trust", "--store", storePath, "add", testTrustDomain, "--key", pubHex)
		if err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
		lastStderr = stderr
	}
	records := readTrustRecords(t, storePath)
	if len(records) != 1 {
		t.Fatalf("duplicate add wrote %d records", len(records))
	}
	if !strings.Contains(lastStderr, "operator workflows until runtime trust-store loading is added") {
		t.Fatalf("duplicate add stderr = %q", lastStderr)
	}
}

func TestTrustAddUpdatesExistingRecord(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "trust.json")
	_, _, firstKey := testTrustKey(t)
	_, _, secondKey := testTrustKey(t)
	if _, err := runEnvelopeCmd("trust", "--store", storePath, "add", testTrustDomain, "--key", firstKey); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if _, err := runEnvelopeCmd("trust", "--store", storePath, "add", testTrustDomain, "--key", secondKey); err != nil {
		t.Fatalf("second add: %v", err)
	}
	records := readTrustRecords(t, storePath)
	if len(records) != 1 || records[0].KeyHex != secondKey {
		t.Fatalf("records after update = %+v", records)
	}
}

func TestTrustAddFromWellKnownSource(t *testing.T) {
	t.Parallel()

	_, _, pubHex := testTrustKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(domenvelope.Directory{Keys: []domenvelope.DirectoryKey{{
			KeyID:     testTrustDomain,
			Algorithm: directoryAlg,
			PublicKey: pubHex,
			Use:       directoryUse,
		}}})
	}))
	t.Cleanup(server.Close)

	storePath := filepath.Join(t.TempDir(), "trust.json")
	if _, err := runEnvelopeCmd("trust", "--store", storePath, "add", testTrustDomain, "--source", server.URL+domenvelope.WellKnownPath); err != nil {
		t.Fatalf("add source: %v", err)
	}
	records := readTrustRecords(t, storePath)
	if len(records) != 1 || records[0].KeyHex != pubHex || records[0].KeySource == "" {
		t.Fatalf("records = %+v", records)
	}
}

func TestTrustCommandErrorPaths(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "trust.json")
	_, _, pubHex := testTrustKey(t)
	cases := []struct {
		name string
		args []string
	}{
		{"malformed target", []string{"trust", "--store", storePath, "add", "https://bad.example", "--key", pubHex}},
		{"missing key", []string{"trust", "--store", storePath, "add", testTrustDomain}},
		{"key and source", []string{"trust", "--store", storePath, "add", testTrustDomain, "--key", pubHex, "--source", "https://partner.example/keys"}},
		{"bad key", []string{"trust", "--store", storePath, "add", testTrustDomain, "--key", "not-hex"}},
		{"nonlocal source", []string{"trust", "--store", storePath, "add", testTrustDomain, "--source", "http://not-local.example/keys"}},
		{"malformed remove target", []string{"trust", "--store", storePath, "remove", "https://bad.example"}},
		{"remove missing", []string{"trust", "--store", storePath, "remove", "missing.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := runEnvelopeCmd(tc.args...); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestTrustCommandStoreErrorPaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, _, pubHex := testTrustKey(t)
	badStore := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badStore, []byte("{"), 0o600); err != nil {
		t.Fatalf("write bad store: %v", err)
	}
	for _, args := range [][]string{
		{"trust", "--store", badStore, "add", testTrustDomain, "--key", pubHex},
		{"trust", "--store", badStore, "list"},
		{"trust", "--store", badStore, "remove", testTrustDomain},
		{"trust", "--store", badStore, "verify"},
	} {
		if _, err := runEnvelopeCmd(args...); err == nil {
			t.Fatalf("%v should fail on bad store", args)
		}
	}

	parentFile := filepath.Join(dir, "not-dir")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	if _, err := runEnvelopeCmd("trust", "--store", filepath.Join(parentFile, "trust.json"), "add", testTrustDomain, "--key", pubHex); err == nil {
		t.Fatal("add should fail when store parent is a file")
	}
	if _, err := runEnvelopeCmd("trust", "--store", dir, "list"); err == nil {
		t.Fatal("list should fail when store path is a directory")
	}
}

func TestTrustVerifyNoStdinExercisesTrustStore(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "trust.json")
	_, _, pubHex := testTrustKey(t)
	if _, err := runEnvelopeCmd("trust", "--store", storePath, "add", testTrustDomain, "--key", pubHex); err != nil {
		t.Fatalf("add: %v", err)
	}
	out, err := runEnvelopeCmd("trust", "--store", storePath, "verify")
	if err != nil {
		t.Fatalf("verify no stdin: %v", err)
	}
	if !strings.Contains(out, "trust store ready\t1 trusted peer") {
		t.Fatalf("verify no stdin output = %q", out)
	}
}

func TestTrustVerifyInputErrors(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "trust.json")
	if _, err := runEnvelopeCmd("trust", "--store", storePath, "verify"); err == nil {
		t.Fatal("empty trust store should fail verify")
	}
	_, _, pubHex := testTrustKey(t)
	if _, err := runEnvelopeCmd("trust", "--store", storePath, "add", testTrustDomain, "--key", pubHex); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := runEnvelopeCmdWithInput("not http", "trust", "--store", storePath, "verify", "--stdin"); err == nil {
		t.Fatal("bad HTTP stdin should fail")
	}
}

func TestTrustVerifyStdinKnownGoodAndForged(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "trust.json")
	_, priv, pubHex := testTrustKey(t)
	if _, err := runEnvelopeCmd("trust", "--store", storePath, "add", testTrustDomain, "--key", pubHex); err != nil {
		t.Fatalf("add: %v", err)
	}

	goodReq := signedTrustVerifyRequest(t, priv, testTrustDomain, "spiffe://partner.example/agent/proxy", "payload")
	out, err := runEnvelopeCmdWithInput(goodReq, "trust", "--store", storePath, "verify", "--stdin")
	if err != nil {
		t.Fatalf("verify good: %v", err)
	}
	if !strings.Contains(out, "verified\tactor=spiffe://partner.example/agent/proxy") {
		t.Fatalf("verify output = %q", out)
	}

	_, forgedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey forged: %v", err)
	}
	forgedReq := signedTrustVerifyRequest(t, forgedPriv, testTrustDomain, "spiffe://partner.example/agent/proxy", "payload")
	_, err = runEnvelopeCmdWithInput(forgedReq, "trust", "--store", storePath, "verify", "--stdin")
	if err == nil {
		t.Fatal("forged envelope should fail verification")
	}
	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != cliutil.ExitSecurity {
		t.Fatalf("forged error = %T %[1]v, want ExitSecurity", err)
	}
}

func TestTrustVerifyRejectsActorOutsideSpiffeRecord(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "trust.json")
	_, priv, pubHex := testTrustKey(t)
	if _, err := runEnvelopeCmd("trust", "--store", storePath, "add", "spiffe://partner.example/agent/allowed", "--key", pubHex); err != nil {
		t.Fatalf("add spiffe target: %v", err)
	}
	rawReq := signedTrustVerifyRequest(t, priv, testTrustDomain, "spiffe://partner.example/agent/other", "payload")
	if _, err := runEnvelopeCmdWithInput(rawReq, "trust", "--store", storePath, "verify", "--stdin"); err == nil {
		t.Fatal("actor outside exact SPIFFE trust record should fail")
	}
}

func TestTrustStoreHelpers(t *testing.T) {
	pub, _, pubHex := testTrustKey(t)
	now := time.Now().UTC()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	store, err := newTrustStore("")
	if err != nil {
		t.Fatalf("new default trust store: %v", err)
	}
	if !strings.HasSuffix(store.path, filepath.Join("pipelock", "envelope", "trust.json")) {
		t.Fatalf("default store path = %q", store.path)
	}
	if records, err := store.load(); err != nil || len(records) != 0 {
		t.Fatalf("missing store load = %+v, %v", records, err)
	}

	explicit := filepath.Join(t.TempDir(), "trust.json")
	store, err = newTrustStore(explicit)
	if err != nil {
		t.Fatalf("new explicit trust store: %v", err)
	}
	if err := store.save([]trustRecord{{
		TrustDomain: testTrustDomain,
		KeyHex:      pubHex,
		AddedAt:     now,
	}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	records, err := store.load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(records) != 1 || !records[0].AddedAt.Equal(now) {
		t.Fatalf("loaded records = %+v", records)
	}

	if _, _, err := parseTrustTarget(""); err == nil {
		t.Fatal("empty trust target should fail")
	}
	if _, _, err := parseTrustTarget("spiffe:///missing-domain"); err == nil {
		t.Fatal("bad SPIFFE trust target should fail")
	}
	domain, spiffeID, err := parseTrustTarget("spiffe://Partner.Example/agent/proxy")
	if err != nil {
		t.Fatalf("parse SPIFFE target: %v", err)
	}
	if domain != testTrustDomain || spiffeID == "" {
		t.Fatalf("parsed target = %q %q", domain, spiffeID)
	}
	if got := keySummary("short"); got != "short" {
		t.Fatalf("short key summary = %q", got)
	}
	if got := emptyDash("value"); got != "value" {
		t.Fatalf("emptyDash non-empty = %q", got)
	}
	if !bytes.Equal(pub, pub) {
		t.Fatal("unreachable")
	}

	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", t.TempDir())
	_, fallback, err := defaultTrustStorePath()
	if err != nil {
		t.Fatalf("fallback default path: %v", err)
	}
	if !strings.Contains(fallback, filepath.Join(".local", "state", "pipelock")) {
		t.Fatalf("fallback path = %q", fallback)
	}
}

func TestDefaultTrustStoreSaveWithinStateHome(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	store, err := newTrustStore("")
	if err != nil {
		t.Fatalf("new default store: %v", err)
	}
	_, _, pubHex := testTrustKey(t)
	now := time.Now().UTC()
	if err := store.save([]trustRecord{{
		TrustDomain: testTrustDomain,
		KeyHex:      pubHex,
		AddedAt:     now,
	}}); err != nil {
		t.Fatalf("save default store: %v", err)
	}
	records, err := store.load()
	if err != nil {
		t.Fatalf("load default store: %v", err)
	}
	if len(records) != 1 || records[0].TrustDomain != testTrustDomain {
		t.Fatalf("default store records = %+v", records)
	}
	info, err := os.Stat(filepath.Dir(store.path))
	if err != nil {
		t.Fatalf("stat default store dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("default store dir mode = %v, want 0o750", got)
	}
}

func TestTrustStoreValidationErrors(t *testing.T) {
	t.Parallel()

	_, _, pubHex := testTrustKey(t)
	pub, _, _ := testTrustKey(t)
	now := time.Now().UTC()
	cases := []trustRecord{
		{TrustDomain: "bad/domain", KeyHex: pubHex, AddedAt: now},
		{TrustDomain: testTrustDomain, SPIFFEID: "spiffe://other.example/agent/proxy", KeyHex: pubHex, AddedAt: now},
		{TrustDomain: testTrustDomain, SPIFFEID: "not-spiffe", KeyHex: pubHex, AddedAt: now},
		{TrustDomain: testTrustDomain, KeyHex: "not-hex", AddedAt: now},
		{TrustDomain: testTrustDomain, KeyHex: signing.EncodePublicKey(pub), AddedAt: now},
		{TrustDomain: testTrustDomain, KeyHex: pubHex, KeySource: "%", AddedAt: now},
		{TrustDomain: testTrustDomain, KeyHex: pubHex, KeySource: "http://not-local.example/keys", AddedAt: now},
		{TrustDomain: testTrustDomain, KeyHex: pubHex},
	}
	for _, rec := range cases {
		if err := validateTrustRecord(rec); err == nil {
			t.Fatalf("validateTrustRecord(%+v) succeeded", rec)
		}
	}

	parentFile := filepath.Join(t.TempDir(), "not-dir")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	store := &trustStore{path: filepath.Join(parentFile, "trust.json")}
	if err := store.save(nil); err == nil {
		t.Fatal("save under file parent should fail")
	}
	store = &trustStore{path: t.TempDir()}
	if err := store.save(nil); err == nil {
		t.Fatal("save over directory should fail")
	}
	store = &trustStore{path: filepath.Join(t.TempDir(), "trust.json")}
	if err := store.save([]trustRecord{{TrustDomain: "bad", KeyHex: "bad"}}); err == nil {
		t.Fatal("save should validate records")
	}

	target := filepath.Join(t.TempDir(), "target.json")
	link := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(target, []byte("[]\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink trust store: %v", err)
	}
	store = &trustStore{path: link}
	if err := store.save(nil); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("save over symlink error = %v, want symlink rejection", err)
	}
}

func TestDefaultTrustStoreRejectsEscapingSymlink(t *testing.T) {
	stateHome := t.TempDir()
	outside := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	if err := os.Symlink(outside, filepath.Join(stateHome, "pipelock")); err != nil {
		t.Fatalf("symlink state subdir: %v", err)
	}
	store, err := newTrustStore("")
	if err != nil {
		t.Fatalf("new default store: %v", err)
	}
	_, _, pubHex := testTrustKey(t)
	err = store.save([]trustRecord{{
		TrustDomain: testTrustDomain,
		KeyHex:      pubHex,
		AddedAt:     time.Now().UTC(),
	}})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("save through escaping symlink error = %v, want symlink rejection", err)
	}
}

func TestTrustStoreValidateWritePathErrors(t *testing.T) {
	missingRoot := filepath.Join(t.TempDir(), "missing-root")
	store := &trustStore{path: filepath.Join(t.TempDir(), "trust.json"), root: missingRoot}
	if err := store.validateWritePath(); err == nil || !strings.Contains(err.Error(), "resolving trust store root") {
		t.Fatalf("missing root error = %v", err)
	}

	root := t.TempDir()
	store = &trustStore{path: filepath.Join(root, "missing-parent", "trust.json"), root: root}
	if err := store.validateWritePath(); err == nil || !strings.Contains(err.Error(), "resolving trust store directory") {
		t.Fatalf("missing parent error = %v", err)
	}

	outside := t.TempDir()
	store = &trustStore{root: root}
	if err := store.validateContained(outside); err == nil || !strings.Contains(err.Error(), "escapes XDG state home") {
		t.Fatalf("outside containment error = %v, want escape rejection", err)
	}
}

func TestTrustStoreLoadErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	badJSON := &trustStore{path: filepath.Join(dir, "bad.json")}
	if err := os.WriteFile(badJSON.path, []byte("{"), 0o600); err != nil {
		t.Fatalf("write bad json: %v", err)
	}
	if _, err := badJSON.load(); err == nil {
		t.Fatal("bad json load should fail")
	}

	badRecord := &trustStore{path: filepath.Join(dir, "bad-record.json")}
	if err := os.WriteFile(badRecord.path, []byte(`[{"trust_domain":"bad","key_hex":"bad","added_at":"2026-05-01T00:00:00Z"}]`), 0o600); err != nil {
		t.Fatalf("write bad record: %v", err)
	}
	if _, err := badRecord.load(); err == nil {
		t.Fatal("bad record load should fail")
	}

	empty := &trustStore{path: filepath.Join(dir, "empty.json")}
	if err := os.WriteFile(empty.path, []byte(" \n"), 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	records, err := empty.load()
	if err != nil || len(records) != 0 {
		t.Fatalf("empty load = %+v, %v", records, err)
	}

	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "link.json")
	if err := os.WriteFile(target, []byte("[]\n"), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink trust store: %v", err)
	}
	if _, err := (&trustStore{path: link}).load(); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("load through symlink error = %v, want symlink rejection", err)
	}
}

func TestTrustStoreRejectsSymlinkedParent(t *testing.T) {
	outside := t.TempDir()
	linkParent := filepath.Join(t.TempDir(), "store-link")
	if err := os.Symlink(outside, linkParent); err != nil {
		t.Fatalf("symlink parent: %v", err)
	}
	store := &trustStore{path: filepath.Join(linkParent, "trust.json")}
	if err := store.save(nil); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("save through parent symlink error = %v, want symlink rejection", err)
	}

	target := filepath.Join(outside, "trust.json")
	if err := os.WriteFile(target, []byte("[]\n"), 0o600); err != nil {
		t.Fatalf("write parent symlink target: %v", err)
	}
	if _, err := store.load(); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("load through parent symlink error = %v, want symlink rejection", err)
	}
}

func TestDirectoryFetchErrors(t *testing.T) {
	t.Parallel()

	_, _, pubHex := testTrustKey(t)
	servers := []http.HandlerFunc{
		func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "nope", http.StatusTeapot) },
		func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{")) },
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(domenvelope.Directory{Keys: []domenvelope.DirectoryKey{{Algorithm: "rsa", Use: directoryUse, PublicKey: pubHex}}})
		},
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(domenvelope.Directory{Keys: []domenvelope.DirectoryKey{{KeyID: "bad", Algorithm: directoryAlg, Use: directoryUse, PublicKey: "bad"}}})
		},
	}
	for _, handler := range servers {
		server := httptest.NewServer(handler)
		_, err := fetchDirectoryKey(t.Context(), server.URL)
		server.Close()
		if err == nil {
			t.Fatal("fetchDirectoryKey should fail")
		}
	}
	if _, err := fetchDirectoryKey(t.Context(), "%"); err == nil {
		t.Fatal("bad source URL should fail")
	}
	if _, err := fetchDirectoryKey(t.Context(), "http://127.0.0.1:1"); err == nil {
		t.Fatal("unreachable loopback source should fail")
	}
}

func TestDirectoryFetchRejectsUnsafeRedirect(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://not-local.example/keys", http.StatusFound)
	}))
	t.Cleanup(server.Close)

	_, err := fetchDirectoryKey(t.Context(), server.URL+domenvelope.WellKnownPath)
	if err == nil || !strings.Contains(err.Error(), "directory URL must be https or loopback http") {
		t.Fatalf("redirect error = %v, want unsafe redirect rejection", err)
	}
}

func TestDirectoryFetchAllowsSafeRedirect(t *testing.T) {
	t.Parallel()

	_, _, pubHex := testTrustKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, domenvelope.WellKnownPath, http.StatusFound)
			return
		}
		_ = json.NewEncoder(w).Encode(domenvelope.Directory{Keys: []domenvelope.DirectoryKey{{
			KeyID:     testTrustDomain,
			Algorithm: directoryAlg,
			PublicKey: pubHex,
			Use:       directoryUse,
		}}})
	}))
	t.Cleanup(server.Close)

	got, err := fetchDirectoryKey(t.Context(), server.URL+"/redirect")
	if err != nil {
		t.Fatalf("fetch through safe redirect: %v", err)
	}
	if got != pubHex {
		t.Fatalf("redirect key = %q, want %q", got, pubHex)
	}
}

func TestVerifierFromTrustRecordsErrors(t *testing.T) {
	t.Parallel()

	_, _, firstKey := testTrustKey(t)
	_, _, secondKey := testTrustKey(t)
	now := time.Now().UTC()
	if _, err := verifierFromTrustRecords(nil); err == nil {
		t.Fatal("empty trust records should fail")
	}
	if _, err := verifierFromTrustRecords([]trustRecord{{TrustDomain: testTrustDomain, KeyHex: "bad", AddedAt: now}}); err == nil {
		t.Fatal("bad key should fail")
	}
	if _, err := verifierFromTrustRecords([]trustRecord{
		{TrustDomain: testTrustDomain, SPIFFEID: "spiffe://partner.example/agent/a", KeyHex: firstKey, AddedAt: now},
		{TrustDomain: testTrustDomain, SPIFFEID: "spiffe://partner.example/agent/b", KeyHex: secondKey, AddedAt: now},
	}); err == nil {
		t.Fatal("conflicting keys for one domain should fail")
	}
	if _, err := verifierFromTrustRecords([]trustRecord{
		{TrustDomain: testTrustDomain, SPIFFEID: "spiffe://partner.example/agent/a", KeyHex: firstKey, AddedAt: now},
		{TrustDomain: testTrustDomain, SPIFFEID: "spiffe://partner.example/agent/b", KeyHex: firstKey, AddedAt: now},
	}); err != nil {
		t.Fatalf("same key for one domain should build verifier: %v", err)
	}
}

func TestActorAndRequestHelpers(t *testing.T) {
	t.Parallel()

	actor, err := domenvelope.ParseActorStrict("spiffe://partner.example/agent/a")
	if err != nil {
		t.Fatalf("ParseActorStrict: %v", err)
	}
	records := []trustRecord{{TrustDomain: "other.example"}}
	if actorAllowedByTrustRecords(actor, records) {
		t.Fatal("different trust domain should not be allowed")
	}
	records = []trustRecord{{TrustDomain: testTrustDomain, SPIFFEID: "spiffe://partner.example/agent/a"}}
	if !actorAllowedByTrustRecords(actor, records) {
		t.Fatal("exact SPIFFE record should be allowed")
	}
	records = []trustRecord{{TrustDomain: testTrustDomain, SPIFFEID: "not-spiffe"}}
	if actorAllowedByTrustRecords(actor, records) {
		t.Fatal("invalid stored SPIFFE record should not match")
	}

	req, body, err := readHTTPRequest(strings.NewReader("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	if err != nil {
		t.Fatalf("readHTTPRequest no body: %v", err)
	}
	if req.Host != "example.test" || len(body) != 0 {
		t.Fatalf("request host/body = %q/%q", req.Host, body)
	}
	if _, _, err := readHTTPRequest(strings.NewReader("not http")); err == nil {
		t.Fatal("bad HTTP request should fail")
	}
	oversize := "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 16777217\r\n\r\n" +
		strings.Repeat("a", maxVerifyStdinBodyBytes+1)
	if _, _, err := readHTTPRequest(strings.NewReader(oversize)); err == nil || !strings.Contains(err.Error(), "request body exceeds") {
		t.Fatalf("oversize request error = %v, want body cap", err)
	}
	oversizeHeader := "GET / HTTP/1.1\r\nHost: example.test\r\nX-Large: " +
		strings.Repeat("a", maxVerifyRawRequestBytes) + "\r\n\r\n"
	if _, _, err := readHTTPRequest(strings.NewReader(oversizeHeader)); err == nil || !strings.Contains(err.Error(), "request exceeds") {
		t.Fatalf("oversize header error = %v, want raw request cap", err)
	}
	brokenBody := &chunkErrorReader{
		chunks: []string{
			"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 7\r\n\r\n",
			"part",
		},
		err: errors.New("body broke"),
	}
	if _, _, err := readHTTPRequest(brokenBody); err == nil || !strings.Contains(err.Error(), "reading request body") {
		t.Fatalf("broken body error = %v, want body read failure", err)
	}
}

func TestLocalHTTPSource(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"http://localhost/keys", "http://127.0.0.1/keys", "http://[::1]/keys"} {
		u := mustParseURL(t, raw)
		if !isLocalHTTPSource(u) {
			t.Fatalf("%s should be local HTTP", raw)
		}
	}
	if isLocalHTTPSource(mustParseURL(t, "https://127.0.0.1/keys")) {
		t.Fatal("https should not be classified as local HTTP")
	}
}

func testTrustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv, hex.EncodeToString(pub)
}

func signedTrustVerifyRequest(t *testing.T, priv ed25519.PrivateKey, keyID, actor, body string) string {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://upstream.example/api", strings.NewReader(body))
	env := domenvelope.Envelope{
		Version:   1,
		Action:    "write",
		Verdict:   config.ActionAllow,
		Actor:     actor,
		ActorAuth: domenvelope.ActorAuthBound,
		ReceiptID: "01961f3a-7b2c-7000-8000-000000000001",
		Timestamp: time.Now().UTC().Unix(),
	}
	if err := domenvelope.InjectHTTP(req.Header, env); err != nil {
		t.Fatalf("InjectHTTP: %v", err)
	}
	signer, err := domenvelope.NewSigner(domenvelope.SignerConfig{
		PrivKey:          priv,
		KeyID:            keyID,
		SignedComponents: config.DefaultEnvelopeSignedComponents(),
		Expires:          time.Minute,
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if err := signer.SignRequest(req, []byte(body)); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return buf.String()
}

func runEnvelopeCmd(args ...string) (string, error) {
	return runEnvelopeCmdWithInput("", args...)
}

type chunkErrorReader struct {
	chunks []string
	err    error
}

func (r *chunkErrorReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, r.err
	}
	chunk := r.chunks[0]
	n := copy(p, chunk)
	if n == len(chunk) {
		r.chunks = r.chunks[1:]
		return n, nil
	}
	r.chunks[0] = chunk[n:]
	return n, nil
}

func runEnvelopeCmdWithInput(input string, args ...string) (string, error) {
	out, _, err := runEnvelopeCmdFull(input, args...)
	return out, err
}

func runEnvelopeCmdFull(input string, args ...string) (string, string, error) {
	cmd := Cmd()
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), stderr.String(), err
}

func readTrustRecords(t *testing.T, path string) []trustRecord {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test-owned path.
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	var records []trustRecord
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatalf("decode store: %v", err)
	}
	return records
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}
