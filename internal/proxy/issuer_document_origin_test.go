// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestIssuerQueryDocumentStore(t *testing.T) {
	now := time.Now()
	const origin = "https://login.vendor.example"
	tests := []struct {
		name    string
		store   func() *issuerQueryStore
		session string
		served  string
		ask     string
		want    bool
	}{
		{"same origin", newIssuerQueryStore, "s", origin + "/login", origin, true},
		{"explicit default port", newIssuerQueryStore, "s", origin + "/login", origin + ":443", true},
		{"upper case host and trailing dot", newIssuerQueryStore, "s", "https://LOGIN.vendor.example./x", origin, true},
		{"other host", newIssuerQueryStore, "s", origin, "https://other.vendor.example", false},
		{"other port", newIssuerQueryStore, "s", origin, "https://login.vendor.example:8443", false},
		{"cleartext origin is never recorded", newIssuerQueryStore, "s", "http://login.vendor.example/", "http://login.vendor.example", false},
		{"nil store", func() *issuerQueryStore { return nil }, "s", origin, origin, false},
		{"disabled store", func() *issuerQueryStore { return newIssuerQueryStoreWithReader(failingIssuerQueryReader{}) }, "s", origin, origin, false},
		{"empty session", newIssuerQueryStore, "", origin, origin, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := tt.store()
			store.rememberDocument(tt.session, mustIssuerQueryURL(t, tt.served), now)
			if got := store.documentServed(tt.session, mustIssuerQueryURL(t, tt.ask)); got != tt.want {
				t.Fatalf("documentServed = %v, want %v", got, tt.want)
			}
		})
	}
	t.Run("another session", func(t *testing.T) {
		store := newIssuerQueryStore()
		store.rememberDocument("s", mustIssuerQueryURL(t, origin), now)
		if store.documentServed("other", mustIssuerQueryURL(t, origin)) {
			t.Fatal("a document served to one session was visible to another")
		}
	})
}

// Served origins are bounded like the rest of the session evidence, and what
// falls out returns to ordinary scoring.
func TestIssuerQueryDocumentEviction(t *testing.T) {
	t.Run("session cap evicts the least recently used session", func(t *testing.T) {
		store := newIssuerQueryStore()
		now := time.Now()
		page := mustIssuerQueryURL(t, "https://login.vendor.example/")
		store.rememberDocument("first", page, now)
		for i := 0; i < issuerCookieMaxSessions; i++ {
			store.rememberDocument("session-"+strconv.Itoa(i), page, now.Add(time.Duration(i+1)*time.Second))
		}
		if store.documentServed("first", page) {
			t.Fatal("evicted session still holds its served origin")
		}
		if !store.documentServed("session-"+strconv.Itoa(issuerCookieMaxSessions-1), page) {
			t.Fatal("newest session lost its served origin")
		}
	})
	t.Run("entry cap drops the oldest origin", func(t *testing.T) {
		store := newIssuerQueryStore()
		now := time.Now()
		origin := func(i int) string { return fmt.Sprintf("https://host-%d.vendor.example/", i) }
		for i := 0; i <= issuerCookieMaxEntries; i++ {
			store.rememberDocument("s", mustIssuerQueryURL(t, origin(i)), now)
		}
		if store.documentServed("s", mustIssuerQueryURL(t, origin(0))) {
			t.Fatal("oldest origin survived the entry cap")
		}
		if !store.documentServed("s", mustIssuerQueryURL(t, origin(issuerCookieMaxEntries))) {
			t.Fatal("newest origin was dropped")
		}
	})
	t.Run("a repeated origin does not consume an entry", func(t *testing.T) {
		store := newIssuerQueryStore()
		page := mustIssuerQueryURL(t, "https://login.vendor.example/")
		for i := 0; i < 3; i++ {
			store.rememberDocument("s", page, time.Now())
		}
		store.mu.Lock()
		defer store.mu.Unlock()
		if n := len(store.documents["s"]); n != 1 {
			t.Fatalf("entries = %d, want 1", n)
		}
	})
}

// Only a delivered HTML document records its origin.
func TestRecordDeliveredDocumentOrigin(t *testing.T) {
	const page = "https://login.vendor.example/login"
	for _, tt := range []struct {
		name      string
		mediaType string
		body      string
		delivered bool
		want      bool
	}{
		{"html", "text/html; charset=utf-8", "<html><body>x</body></html>", true, true},
		{"xhtml", "application/xhtml+xml", "<html><body>x</body></html>", true, true},
		{"html not delivered", "text/html", "<html></html>", false, false},
		{"html with no body", "text/html", "", true, false},
		{"json", "application/json", `{"a":"b"}`, true, false},
		{"image", "image/png", "\x89PNG", true, false},
		{"script", "application/javascript", "var a=1;", true, false},
		{"plain text", "text/plain", "<html></html>", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ic, session := oauthTestStore(t)
			header := http.Header{"Content-Type": {tt.mediaType}}
			response := &http.Response{Request: &http.Request{URL: mustIssuerQueryURL(t, page)}, StatusCode: http.StatusOK, Header: header}
			recordDeliveredIssuerQuery(ic, response, []byte(tt.body), tt.delivered)
			got := ic.issuerQueryStore().documentServed(session, mustIssuerQueryURL(t, "https://login.vendor.example"))
			if got != tt.want {
				t.Fatalf("documentServed = %v, want %v", got, tt.want)
			}
		})
	}
}

// The reCAPTCHA shape: a frame whose query carries the origin of the page that
// embeds it. The Origin and Referer headers are written by the agent, so only
// an origin that served this session an HTML document is admitted. Every
// blocking row differs from the allowed one by a single thing.
func TestInterceptPageOriginRequiresServedDocument(t *testing.T) {
	frame := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer frame.Close()
	embed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<!doctype html><html><body>login</body></html>")
	}))
	defer embed.Close()
	scripted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"page":"not a document"}`)
	}))
	defer scripted.Close()
	// A local origin encodes to a short, lower-scoring value, so lower the bar
	// until every blocking row below is blocked by the entropy gate.
	h := newWebPlatformHarnessThreshold(t, 3.0)

	co := func(origin string) string { return webCaptchaPath + "?co=" + captchaOriginValue(origin) }
	// A lower-case origin the agent made up: 32 base32 symbols carry 160 bits.
	chosen := "https://q7xm2v9kb4zf8wc3yj6rd1ns5th0lp.vendor.example"
	chosenOther := "https://zyxwvutsrqponmlkjihgfedcba765432.vendor.example"

	type step struct {
		name    string
		server  *httptest.Server
		path    string
		agent   string
		headers http.Header
		want    int
	}
	var steps []step
	add := func(s ...step) { steps = append(steps, s...) }
	// Nothing was served yet, so no origin is admitted, however it is spelled.
	add(
		step{"caller chosen origin in Origin", frame, co(chosen), "agent-one", http.Header{"Origin": {chosen}}, http.StatusForbidden},
		step{"caller chosen origin in Referer", frame, co(chosen), "agent-one", http.Header{"Referer": {chosen + "/x"}}, http.StatusForbidden},
		step{"second caller chosen origin", frame, co(chosenOther), "agent-one", http.Header{"Origin": {chosenOther}}, http.StatusForbidden},
		step{"real origin before it served anything", frame, co(embed.URL), "agent-one", http.Header{"Referer": {embed.URL + "/login"}}, http.StatusForbidden},
		// A response that is not an HTML document does not count.
		step{"deliver JSON from another origin", scripted, "/", "agent-one", nil, http.StatusOK},
		step{"origin that only served JSON", frame, co(scripted.URL), "agent-one", http.Header{"Origin": {scripted.URL}}, http.StatusForbidden},
		// The document is served to agent-one.
		step{"deliver the embedding page", embed, "/", "agent-one", nil, http.StatusOK},
		step{"origin that served this session", frame, co(embed.URL), "agent-one", http.Header{"Referer": {embed.URL + "/login"}}, http.StatusOK},
		step{"caller chosen origin is still blocked", frame, co(chosen), "agent-one", http.Header{"Origin": {chosen}}, http.StatusForbidden},
		step{"origin served to another session", frame, co(embed.URL), "agent-two", http.Header{"Referer": {embed.URL + "/login"}}, http.StatusForbidden},
		step{"served origin but no header", frame, co(embed.URL), "agent-one", nil, http.StatusForbidden},
		step{"served origin in the value, another in the header", frame, co(embed.URL), "agent-one", http.Header{"Origin": {chosen}}, http.StatusForbidden},
		step{"value decoding to another origin than the served header", frame, co(chosen), "agent-one", http.Header{"Referer": {embed.URL + "/"}}, http.StatusForbidden},
		step{"value decoding to the header path", frame, co(embed.URL + "/login/session/12345"), "agent-one", http.Header{"Referer": {embed.URL + "/login/session/12345"}}, http.StatusForbidden},
		step{"two referer headers", frame, co(embed.URL), "agent-one", http.Header{"Referer": {embed.URL + "/", embed.URL + "/"}}, http.StatusForbidden},
	)
	// Enough other sessions to push agent-one out of the store.
	for i := 0; i <= issuerCookieMaxSessions; i++ {
		add(step{"another session loads a page " + strconv.Itoa(i), embed, "/", "other-agent-" + strconv.Itoa(i), nil, http.StatusOK})
	}
	add(
		step{"served then evicted", frame, co(embed.URL), "agent-one", http.Header{"Referer": {embed.URL + "/login"}}, http.StatusForbidden},
		step{"served again after eviction", embed, "/", "agent-one", nil, http.StatusOK},
		step{"admitted once more", frame, co(embed.URL), "agent-one", http.Header{"Referer": {embed.URL + "/login"}}, http.StatusOK},
	)
	for _, s := range steps {
		if got := h.do(s.server, s.path, s.agent, s.headers); got != s.want {
			t.Fatalf("%s: status=%d, want %d", s.name, got, s.want)
		}
	}
}
