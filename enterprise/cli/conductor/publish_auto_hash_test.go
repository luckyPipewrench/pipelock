//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveAutoHash_WithHead(t *testing.T) {
	const headHash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"streams":[{"environment":"prod","audience":{"instance_ids":["*"]},"head_bundle_hash":"` + headHash + `"}],"stream_count":1}`))
	}))
	defer srv.Close()

	opts := publishOptions{
		conductorURL: srv.URL,
		orgID:        "org-main",
		fleetID:      "prod",
		environment:  "prod",
		audience:     []string{"*"},
		publisherTok: writePublisherTokenFile(t),
		insecure:     true,
	}
	hash, err := resolveAutoHash(t.Context(), opts)
	if err != nil {
		t.Fatalf("resolveAutoHash: %v", err)
	}
	if hash != headHash {
		t.Fatalf("hash = %q, want %q", hash, headHash)
	}
}

func TestResolveAutoHash_NoStreams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"streams":[],"stream_count":0}`))
	}))
	defer srv.Close()

	opts := publishOptions{
		conductorURL: srv.URL,
		orgID:        "org-main",
		fleetID:      "prod",
		environment:  "prod",
		audience:     []string{"*"},
		publisherTok: writePublisherTokenFile(t),
		insecure:     true,
	}
	hash, err := resolveAutoHash(t.Context(), opts)
	if err != nil {
		t.Fatalf("resolveAutoHash (empty): %v", err)
	}
	if hash != "" {
		t.Fatalf("hash = %q, want empty", hash)
	}
}

func TestResolveAutoHash_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer srv.Close()

	opts := publishOptions{
		conductorURL: srv.URL,
		orgID:        "org-main",
		fleetID:      "prod",
		environment:  "prod",
		audience:     []string{"*"},
		publisherTok: writePublisherTokenFile(t),
		insecure:     true,
	}
	_, err := resolveAutoHash(t.Context(), opts)
	if err == nil {
		t.Fatal("resolveAutoHash with server error: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %v, want 500 mention", err)
	}
}

func TestResolveAutoHash_SelectsMatchingEnvironmentAndAudience(t *testing.T) {
	wrongHash := "1111111111111111111111111111111111111111111111111111111111111111"
	rightHash := "2222222222222222222222222222222222222222222222222222222222222222"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"streams":[` +
			`{"environment":"prod","audience":{"labels":{"ring":"canary"}},"head_bundle_hash":"` + wrongHash + `"},` +
			`{"environment":"prod","audience":{"instance_ids":["pl-prod-2","pl-prod-1"]},"head_bundle_hash":"` + rightHash + `"}` +
			`],"stream_count":2}`))
	}))
	defer srv.Close()

	opts := publishOptions{
		conductorURL: srv.URL,
		orgID:        "org-main",
		fleetID:      "prod",
		environment:  "prod",
		audience:     []string{"pl-prod-1", "pl-prod-2"},
		publisherTok: writePublisherTokenFile(t),
		insecure:     true,
	}
	hash, err := resolveAutoHash(t.Context(), opts)
	if err != nil {
		t.Fatalf("resolveAutoHash: %v", err)
	}
	if hash != rightHash {
		t.Fatalf("hash = %q, want matching stream hash %q", hash, rightHash)
	}
}

func TestResolveAutoHash_NoMatchingStream(t *testing.T) {
	const existingHash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"streams":[{"environment":"staging","audience":{"instance_ids":["*"]},"head_bundle_hash":"` + existingHash + `"}],"stream_count":1}`))
	}))
	defer srv.Close()

	opts := publishOptions{
		conductorURL: srv.URL,
		orgID:        "org-main",
		fleetID:      "prod",
		environment:  "prod",
		audience:     []string{"*"},
		publisherTok: writePublisherTokenFile(t),
		insecure:     true,
	}
	hash, err := resolveAutoHash(t.Context(), opts)
	if err != nil {
		t.Fatalf("resolveAutoHash: %v", err)
	}
	if hash != "" {
		t.Fatalf("hash = %q, want empty for first matching stream", hash)
	}
}

func TestResolveAutoHash_MultipleMatchingStreams(t *testing.T) {
	hash1 := "1111111111111111111111111111111111111111111111111111111111111111"
	hash2 := "2222222222222222222222222222222222222222222222222222222222222222"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"streams":[` +
			`{"environment":"prod","audience":{"instance_ids":["*"]},"head_bundle_hash":"` + hash1 + `"},` +
			`{"environment":"prod","audience":{"instance_ids":["*"]},"head_bundle_hash":"` + hash2 + `"}` +
			`],"stream_count":2}`))
	}))
	defer srv.Close()

	opts := publishOptions{
		conductorURL: srv.URL,
		orgID:        "org-main",
		fleetID:      "prod",
		environment:  "prod",
		audience:     []string{"*"},
		publisherTok: writePublisherTokenFile(t),
		insecure:     true,
	}
	_, err := resolveAutoHash(t.Context(), opts)
	if err == nil {
		t.Fatal("resolveAutoHash with multiple matching streams: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "matching streams") {
		t.Fatalf("error = %v, want matching streams mention", err)
	}
}

func TestResolveAutoHash_MissingEnvironment(t *testing.T) {
	opts := publishOptions{
		conductorURL: "http://127.0.0.1:1",
		orgID:        "org-main",
		fleetID:      "prod",
		environment:  "  ",
		audience:     []string{"*"},
		publisherTok: writePublisherTokenFile(t),
		insecure:     true,
	}
	_, err := resolveAutoHash(t.Context(), opts)
	if err == nil {
		t.Fatal("resolveAutoHash with missing environment: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "--env") {
		t.Fatalf("error = %v, want --env mention", err)
	}
}

func TestPreviousHashAutoSentinelIgnoresCase(t *testing.T) {
	for _, val := range []string{"auto", "AUTO", "Auto", "  auto  "} {
		if !strings.EqualFold(strings.TrimSpace(val), previousHashAuto) {
			t.Fatalf("%q did not match sentinel %q", val, previousHashAuto)
		}
	}
}

func writePublisherTokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "publisher-token")
	if err := os.WriteFile(path, []byte("test-token\n"), 0o600); err != nil {
		t.Fatalf("write publisher token: %v", err)
	}
	return path
}
