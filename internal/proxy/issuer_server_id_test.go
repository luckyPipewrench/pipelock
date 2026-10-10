// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// Synthetic IDs in the shape mail and directory APIs return: long, mixed
// case, base64url with padding. Each scores above the default threshold.
const (
	serverIDListed  = "ANe1BmglugETAHWRiqgwKkow2QrNknpy1yV5Mw"
	serverIDCreated = "AAMkADIzNTA3ZDFlLWYyM2QtNDE3OS1hYTczLTdmMmRhYjFhOWFkMABGAAA="
	serverIDKeyOnly = "Qx7vPq2LmZ9tRw4KbNy8JsHd3FgUcVe6Ta1Mo5"
	serverIDOther   = "Zr8KmWq3NvXp6LbTy2HjDs9FgCuQa4Ve7Ro1Me"
	// agentBlob is the value an agent smuggles: ID-shaped, high entropy.
	agentBlob = "Kd93JqWm2Xv7RbLp4TzNy8HsQf6GcUaE1Vo5Mi"
)

func (h *webPlatformHarness) send(upstream *httptest.Server, method, path, agent, contentType, body string) int {
	h.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, upstream.URL+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp := interceptAndRequestWithRecorder(h.t, interceptRequestOptions{
		Upstream: upstream, Cache: h.cache, Pool: h.pool, Config: h.cfg, Scanner: h.sc,
		Logger: h.logger, Metrics: h.m, Request: req, Proxy: h.p,
		Agent: agent, ActorAuth: envelope.ActorAuthBound,
	})
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// newMailAPI serves a filter collection: list, create (which stores and later
// lists whatever criteria the agent sent), and delete by ID. Every request
// that reaches it is counted per path, so a test can tell forwarded from
// blocked.
func newMailAPI(t *testing.T) (*httptest.Server, func(string) int) {
	t.Helper()
	var mu sync.Mutex
	hits := map[string]int{}
	var stored []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.Method+" "+r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/filters":
			mu.Lock()
			items := []map[string]any{{"id": serverIDListed, "criteria": map[string]string{"from": "noreply@vendor.example"}}}
			for _, s := range stored {
				// The server echoes stored criteria back as the object's id,
				// the reflection a writable field can produce.
				items = append(items, map[string]any{"id": s})
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"filter": items,
				// An ID that appears only as an object key issues nothing.
				"index": map[string]string{serverIDKeyOnly: "x"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/filters":
			var in struct {
				Criteria struct{ Query string } `json:"criteria"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			mu.Lock()
			if in.Criteria.Query != "" {
				stored = append(stored, in.Criteria.Query)
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"id": serverIDCreated})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/filters/"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/secret-id":
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "AK" + "IA" + "Q9W8E7R6T5Y4U3I2"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, func(key string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits[key]
	}
}

// TestInterceptServerIssuedIDs drives a mail-style API through a real
// TLS-intercepted CONNECT. Each blocked row is an allowed row with exactly one
// piece of evidence taken away.
func TestInterceptServerIssuedIDs(t *testing.T) {
	const agent = "mail-agent"

	t.Run("an id names nothing until the origin issues it", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, hits := newMailAPI(t)
		if got := h.send(api, http.MethodDelete, "/filters/"+serverIDListed, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("delete before listing = %d, want 403", got)
		}
		if hits("DELETE /filters/"+serverIDListed) != 0 {
			t.Fatal("an unissued id reached upstream")
		}
	})

	t.Run("a listed id may be named back to its origin", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, hits := newMailAPI(t)
		if got := h.send(api, http.MethodGet, "/filters", agent, "", ""); got != http.StatusOK {
			t.Fatalf("list = %d", got)
		}
		if got := h.send(api, http.MethodDelete, "/filters/"+serverIDListed, agent, "", ""); got != http.StatusNoContent {
			t.Fatalf("delete listed id = %d, want 204", got)
		}
		if hits("DELETE /filters/"+serverIDListed) != 1 {
			t.Fatal("the issued id did not reach upstream")
		}
	})

	t.Run("an id a create response returned may be named back", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		if got := h.send(api, http.MethodPost, "/filters", agent, "application/json", `{"criteria":{"from":"a@vendor.example"}}`); got != http.StatusOK {
			t.Fatalf("create = %d", got)
		}
		if got := h.send(api, http.MethodDelete, "/filters/"+url.PathEscape(serverIDCreated), agent, "", ""); got != http.StatusNoContent {
			t.Fatalf("delete created id = %d, want 204", got)
		}
	})

	t.Run("a value the agent sent and the origin echoed is not issued", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, hits := newMailAPI(t)
		if got := h.send(api, http.MethodPost, "/filters", agent, "application/json", `{"criteria":{"query":"`+agentBlob+`"}}`); got != http.StatusOK {
			t.Fatalf("create with blob = %d", got)
		}
		if got := h.send(api, http.MethodGet, "/filters", agent, "", ""); got != http.StatusOK {
			t.Fatalf("list = %d", got)
		}
		if got := h.send(api, http.MethodDelete, "/filters/"+agentBlob, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("reflected blob as id = %d, want 403", got)
		}
		if hits("DELETE /filters/"+agentBlob) != 0 {
			t.Fatal("a reflected value reached upstream as an id")
		}
	})

	t.Run("a value escaped in the request body is still recorded as sent", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		escaped := `K` + agentBlob[1:] // "K" written as a JSON escape
		if got := h.send(api, http.MethodPost, "/filters", agent, "application/json", `{"criteria":{"query":"`+escaped+`"}}`); got != http.StatusOK {
			t.Fatalf("create = %d", got)
		}
		_ = h.send(api, http.MethodGet, "/filters", agent, "", "")
		if got := h.send(api, http.MethodDelete, "/filters/"+agentBlob, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("escaped reflection as id = %d, want 403", got)
		}
	})

	t.Run("an issued id does not cross to another origin", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		other, otherHits := newMailAPI(t)
		_ = h.send(api, http.MethodGet, "/filters", agent, "", "")
		if got := h.send(other, http.MethodDelete, "/filters/"+serverIDListed, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("id on another origin = %d, want 403", got)
		}
		if otherHits("DELETE /filters/"+serverIDListed) != 0 {
			t.Fatal("an id issued by one origin reached another")
		}
	})

	t.Run("an issued id does not cross to another agent", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		_ = h.send(api, http.MethodGet, "/filters", agent, "", "")
		if got := h.send(api, http.MethodDelete, "/filters/"+serverIDListed, "other-agent", "", ""); got != http.StatusForbidden {
			t.Fatalf("id for another agent = %d, want 403", got)
		}
	})

	t.Run("one changed character is a different value", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		_ = h.send(api, http.MethodGet, "/filters", agent, "", "")
		mutated := serverIDListed[:len(serverIDListed)-1] + "X"
		if got := h.send(api, http.MethodDelete, "/filters/"+mutated, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("mutated id = %d, want 403", got)
		}
	})

	t.Run("another high-entropy segment beside an issued id still blocks", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		_ = h.send(api, http.MethodGet, "/filters", agent, "", "")
		if got := h.send(api, http.MethodDelete, "/filters/"+serverIDListed+"/"+serverIDOther, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("issued id plus unissued segment = %d, want 403", got)
		}
	})

	t.Run("an object key issues nothing", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		_ = h.send(api, http.MethodGet, "/filters", agent, "", "")
		if got := h.send(api, http.MethodDelete, "/filters/"+serverIDKeyOnly, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("key-only id = %d, want 403", got)
		}
	})

	t.Run("an issued id that is a credential is still DLP-blocked", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, hits := newMailAPI(t)
		_ = h.send(api, http.MethodGet, "/secret-id", agent, "", "")
		secret := "AK" + "IA" + "Q9W8E7R6T5Y4U3I2"
		if got := h.send(api, http.MethodDelete, "/filters/"+secret, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("credential-shaped issued id = %d, want 403", got)
		}
		if hits("DELETE /filters/"+secret) != 0 {
			t.Fatal("a credential reached upstream")
		}
	})
}

func newTestServerIDStore(t *testing.T) *issuerQueryStore {
	t.Helper()
	s := newIssuerQueryStore()
	if s.disabled {
		t.Fatal("store disabled")
	}
	return s
}

func TestIssuerServerIDStore(t *testing.T) {
	origin, _ := url.Parse("https://api.vendor.example/v1/filters")
	now := time.Now()

	t.Run("an unread request body stops minting", func(t *testing.T) {
		s := newTestServerIDStore(t)
		s.recordSent("a", origin, nil, false, now)
		s.mintServerID("a", origin, serverIDListed, now)
		if s.serverIDIssued("a", origin, serverIDListed) {
			t.Fatal("minted after an unread body")
		}
	})

	t.Run("an unread body revokes ids minted before it", func(t *testing.T) {
		s := newTestServerIDStore(t)
		s.mintServerID("a", origin, serverIDListed, now)
		if !s.serverIDIssued("a", origin, serverIDListed) {
			t.Fatal("positive control: id not minted")
		}
		s.recordSent("a", origin, nil, false, now)
		if s.serverIDIssued("a", origin, serverIDListed) {
			t.Fatal("id survived an unread body")
		}
	})

	t.Run("a request over the token bound stops minting", func(t *testing.T) {
		s := newTestServerIDStore(t)
		var b strings.Builder
		for i := 0; i <= issuerSentMaxTokensPerRequest; i++ {
			b.WriteString(serverIDOther)
			b.WriteByte(' ')
			b.WriteString(strings.Repeat("Q", 16+i%7))
			b.WriteByte(' ')
		}
		s.recordSent("a", origin, []byte(b.String()), true, now)
		s.mintServerID("a", origin, serverIDListed, now)
		if s.serverIDIssued("a", origin, serverIDListed) {
			t.Fatal("minted after an over-bound request")
		}
	})

	t.Run("a value sent in a query is never minted", func(t *testing.T) {
		s := newTestServerIDStore(t)
		withQuery, _ := url.Parse("https://api.vendor.example/search?q=" + agentBlob)
		s.recordSent("a", withQuery, nil, true, now)
		s.mintServerID("a", origin, agentBlob, now)
		if s.serverIDIssued("a", origin, agentBlob) {
			t.Fatal("a query value was minted")
		}
	})

	t.Run("sent evidence is per origin", func(t *testing.T) {
		s := newTestServerIDStore(t)
		other, _ := url.Parse("https://other.vendor.example/upload")
		s.recordSent("a", other, []byte(agentBlob), true, now)
		s.mintServerID("a", origin, agentBlob, now)
		if !s.serverIDIssued("a", origin, agentBlob) {
			t.Fatal("a value sent to a different origin blocked minting on this one")
		}
	})

	t.Run("shape bounds", func(t *testing.T) {
		for _, v := range []string{"short", strings.Repeat("a", issuerServerIDMaxLen+1), "has/slash" + serverIDListed, "has space" + serverIDListed, "pct%41" + serverIDListed} {
			if issuerServerIDShaped(v) {
				t.Fatalf("%q accepted as an id", v)
			}
		}
		if !issuerServerIDShaped(serverIDCreated) {
			t.Fatal("padded base64url id rejected")
		}
	})

	t.Run("plain http origin is ignored", func(t *testing.T) {
		s := newTestServerIDStore(t)
		plain, _ := url.Parse("http://api.vendor.example/v1/filters")
		s.mintServerID("a", plain, serverIDListed, now)
		if s.serverIDIssued("a", plain, serverIDListed) {
			t.Fatal("plain http minted an id")
		}
	})
}
