// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const browserRedirectOtherHost = "other.fixture.example"

func TestBrowserForwardRedirectOriginIsolation(t *testing.T) {
	type observed struct{ host, path, cookie, authorization string }
	seen := make(chan observed, 8)
	// These owned plain-HTTP origins intentionally omit Secure so cookie
	// return and host isolation are exercised by the real client cookie jar.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- observed{r.Host, r.URL.Path, r.Header.Get("Cookie"), r.Header.Get("Authorization")}
		http.SetCookie(w, &http.Cookie{Name: "target_session", Value: "synthetic-target", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		_, _ = io.WriteString(w, "Synthetic target ready")
	}))
	t.Cleanup(target.Close)
	targetURL := browserRedirectOrigin(t, target.URL, browserRedirectOtherHost)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- observed{r.Host, r.URL.Path, r.Header.Get("Cookie"), r.Header.Get("Authorization")}
		http.SetCookie(w, &http.Cookie{Name: "source_session", Value: "synthetic-source", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		if r.URL.Path == "/start" {
			http.Redirect(w, r, targetURL+"/landing", http.StatusSeeOther)
			return
		}
		_, _ = io.WriteString(w, "Synthetic source ready")
	}))
	t.Cleanup(origin.Close)
	client, base, redirects, p := newBrowserContractProxyClient(t, origin.URL, allowBrowserRedirectOtherHost)
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		redirects.Add(1)
		return nil
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer synthetic-authorization")
	rawResp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(rawResp.Body, 4096))
	_ = rawResp.Body.Close()
	resp := browserContractResponseMetadata(rawResp)
	assertBrowserContractResponse(t, resp, string(body), readErr, "/landing", "Synthetic target ready")
	if resp.URL.String() != targetURL+"/landing" || redirects.Load() != 1 || p.client.Jar != nil {
		t.Fatalf("redirect ownership: URL=%s redirects=%d proxyJar=%v", resp.URL, redirects.Load(), p.client.Jar)
	}
	if len(seen) != 2 {
		t.Fatalf("origin requests=%d, want source and target", len(seen))
	}
	first, second := <-seen, <-seen
	if first.host != strings.TrimPrefix(base, "http://") || second.host != strings.TrimPrefix(targetURL, "http://") || first.path != "/start" || first.authorization != "Bearer synthetic-authorization" || second.path != "/landing" || second.authorization != "" || second.cookie != "" {
		t.Fatalf("cross-origin credential witnesses: source=%+v target=%+v", first, second)
	}
	for _, tc := range []struct{ target, cookie string }{
		{base + "/check", "source_session=synthetic-source"},
		{targetURL + "/check", "target_session=synthetic-target"},
	} {
		resp, _, err = browserContractRequest(t, client, http.MethodGet, tc.target, "")
		if err != nil || resp.StatusCode != http.StatusOK || len(seen) != 1 {
			t.Fatalf("cookie return: status=%d error=%v witnesses=%d", resp.StatusCode, err, len(seen))
		}
		got := <-seen
		if got.cookie != tc.cookie || got.authorization != "" {
			t.Fatalf("cookie origin isolation failed: %+v, want %q", got, tc.cookie)
		}
	}
}

func TestBrowserForwardRedirectResponseGuards(t *testing.T) {
	const marker = "SYNTHETIC_REDIRECT_RESPONSE_MARKER"
	for _, tc := range []struct {
		name, body string
		truncated  bool
		want       int
		reason     blockreason.Reason
	}{
		{name: "clean_headers_are_sanitized", body: "Synthetic redirect body", want: http.StatusSeeOther},
		{name: "response_marker_blocks_before_cookie_delivery", body: marker, want: http.StatusForbidden, reason: blockreason.PromptInjection},
		{name: "short_redirect_body_fails_closed", body: "Synthetic partial", truncated: true, want: http.StatusForbidden, reason: blockreason.ParseError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var initial, final atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/start" {
					final.Add(1)
					_, _ = io.WriteString(w, "Unexpected follow")
					return
				}
				initial.Add(1)
				w.Header().Set("Location", "/final")
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Set-Cookie", "synthetic_session=owned; Path=/; HttpOnly")
				w.Header().Set(blockreason.HeaderReason, "spoofed")
				w.Header().Set(blockreason.HeaderRecordedReceipt, "spoofed")
				w.Header().Set("Connection", "X-Hop-Synthetic")
				w.Header().Set("X-Hop-Synthetic", "must-not-cross")
				if tc.truncated {
					w.Header().Set("Content-Length", "1024")
					w.Header().Add("Connection", "close")
				}
				w.WriteHeader(http.StatusSeeOther)
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(origin.Close)
			client, base, _, _ := newBrowserContractProxyClient(t, origin.URL, func(cfg *config.Config) {
				cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, config.ResponseScanPattern{Name: "Synthetic redirect marker", Regex: marker})
			})
			resp, body, err := browserContractRequest(t, client, http.MethodGet, base+"/start", "")
			if err != nil || resp.StatusCode != tc.want || resp.Header.Get(blockreason.HeaderReason) != string(tc.reason) {
				t.Fatalf("status=%d reason=%q body=%q error=%v", resp.StatusCode, resp.Header.Get(blockreason.HeaderReason), body, err)
			}
			if initial.Load() != 1 || final.Load() != 0 || resp.Header.Get("X-Hop-Synthetic") != "" || resp.Header.Get(blockreason.HeaderRecordedReceipt) != "" {
				t.Fatalf("redirect dispatch/header witnesses: initial=%d final=%d headers=%v", initial.Load(), final.Load(), resp.Header)
			}
			if tc.want == http.StatusSeeOther {
				if resp.Header.Get("Location") != "/final" || len(resp.Cookies) != 1 || body != tc.body {
					t.Fatalf("clean redirect was not preserved: headers=%v body=%q", resp.Header, body)
				}
			} else if resp.Header.Get("Location") != "" || len(resp.Cookies) != 0 || len(client.Jar.Cookies(resp.URL)) != 0 || strings.Contains(body, tc.body) {
				t.Fatalf("blocked redirect released origin data: headers=%v body=%q", resp.Header, body)
			}
		})
	}
}

func TestBrowserForwardRedirectLocationProvenance(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		locations  []string
		unbuffered bool
		blocked    bool
	}{
		{name: "single_relative_301", status: http.StatusMovedPermanently, locations: []string{"/final"}},
		{name: "single_relative_302", status: http.StatusFound, locations: []string{"/final"}},
		{name: "single_absolute_303", status: http.StatusSeeOther, locations: []string{"absolute"}},
		{name: "encoded_space_is_not_literal_whitespace", status: http.StatusSeeOther, locations: []string{"/final%20segment"}},
		{name: "duplicate_301", status: http.StatusMovedPermanently, locations: []string{"/final", "/other"}, blocked: true},
		{name: "identical_duplicate_302", status: http.StatusFound, locations: []string{"/final", "/final"}, blocked: true},
		{name: "empty_first_duplicate_303", status: http.StatusSeeOther, locations: []string{"", "/other"}, blocked: true},
		{name: "unbuffered_duplicate_307", status: http.StatusTemporaryRedirect, locations: []string{"/final", "/other"}, unbuffered: true, blocked: true},
		{name: "unbuffered_empty_first_308", status: http.StatusPermanentRedirect, locations: []string{"", "/other"}, unbuffered: true, blocked: true},
		{name: "literal_space", status: http.StatusSeeOther, locations: []string{"/final segment"}, blocked: true},
		{name: "backslash", status: http.StatusSeeOther, locations: []string{`/final\segment`}, blocked: true},
		{name: "no_location", status: http.StatusSeeOther},
		{name: "empty_location", status: http.StatusSeeOther, locations: []string{""}},
		{name: "non_redirect_status_unchanged", status: http.StatusOK, locations: []string{"/final", "/other"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var initial, final atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/start" {
					final.Add(1)
					return
				}
				initial.Add(1)
				for _, location := range tc.locations {
					if location == "absolute" {
						location = "http://" + r.Host + "/final"
					}
					w.Header().Add("Location", location)
				}
				w.Header().Set("Set-Cookie", "synthetic_redirect=owned; Path=/; HttpOnly")
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, "Synthetic location response")
			}))
			t.Cleanup(origin.Close)
			client, base, _, p := newBrowserContractProxyClient(t, origin.URL, func(cfg *config.Config) {
				if tc.unbuffered {
					cfg.RequestBodyScanning.Enabled = false
					cfg.MediationEnvelope.Enabled = false
				}
			})
			rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(rph.emitter)
			resp, body, err := browserContractRequest(t, client, http.MethodPost, base+"/start", "synthetic body")
			want := tc.status
			if tc.blocked {
				want = http.StatusForbidden
			}
			if err != nil || resp.StatusCode != want || initial.Load() != 1 || final.Load() != 0 {
				t.Fatalf("Location handling: status=%d initial=%d final=%d body=%q error=%v", resp.StatusCode, initial.Load(), final.Load(), body, err)
			}
			recorded := rph.findReceipts(t)
			if tc.blocked {
				if resp.Header.Get(blockreason.HeaderReason) != string(blockreason.ParseError) || len(resp.Header.Values("Location")) != 0 || len(resp.Cookies) != 0 || len(client.Jar.Cookies(resp.URL)) != 0 {
					t.Fatalf("ambiguous redirect released headers or lost cause: %v", resp.Header)
				}
				found := false
				for _, rcpt := range recorded {
					if rcpt.ActionRecord.Verdict == config.ActionBlock && rcpt.ActionRecord.Target == base+"/start" && rcpt.ActionRecord.Pattern == "ambiguous redirect location" {
						if err := receipt.VerifyWithKey(rcpt, rph.pubHex); err != nil {
							t.Fatalf("verify redirect block receipt: %v", err)
						}
						found = true
					}
				}
				if !found {
					t.Fatal("ambiguous redirect block receipt missing")
				}
			} else {
				wantLocations := slices.Clone(tc.locations)
				if tc.name == "single_absolute_303" {
					wantLocations[0] = base + "/final"
				}
				if !slices.Equal(resp.Header.Values("Location"), wantLocations) || len(resp.Cookies) != 1 || body != "Synthetic location response" {
					t.Fatalf("ordinary response changed: headers=%v body=%q", resp.Header, body)
				}
			}
		})
	}
}

func TestBrowserForwardRedirectReplayAdmission(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, crossOrigin := range []bool{false, true} {
			t.Run(fmt.Sprintf("status_%d_cross_origin_%t", status, crossOrigin), func(t *testing.T) {
				var initial, final atomic.Int32
				const payload = "synthetic form body"
				location := "/final"
				origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/start" {
						initial.Add(1)
						http.Redirect(w, r, location, status)
						return
					}
					final.Add(1)
					body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
					if err != nil || r.Method != http.MethodPost || string(body) != payload {
						t.Errorf("replay method=%s body=%q error=%v", r.Method, body, err)
					}
					_, _ = io.WriteString(w, "Synthetic final")
				}))
				if crossOrigin {
					// Derive the target only from this owned listener and a
					// fixed fixture hostname, never an incoming Host header.
					location = browserRedirectOrigin(t, "http://"+origin.Listener.Addr().String(), browserRedirectOtherHost) + "/final"
				}
				origin.Start()
				t.Cleanup(origin.Close)
				client, base, _, _ := newBrowserContractProxyClient(t, origin.URL, allowBrowserRedirectOtherHost)
				resp, body, err := browserContractRequest(t, client, http.MethodPost, base+"/start", payload)
				want := status
				if crossOrigin {
					want = http.StatusForbidden
				}
				if err != nil || resp.StatusCode != want || initial.Load() != 1 || final.Load() != 0 {
					t.Fatalf("preflight: status=%d initial=%d final=%d body=%q error=%v", resp.StatusCode, initial.Load(), final.Load(), body, err)
				}
				if crossOrigin {
					if !strings.Contains(body, "redirect replay changes destination authority") || resp.Header.Get("Location") != "" {
						t.Fatalf("cross-authority replay guard lost: headers=%v body=%q", resp.Header, body)
					}
					return
				}
				if resp.Header.Get("Location") != "/final" {
					t.Fatal("same-origin replay did not return Location")
				}
				resp, body, err = browserContractRequest(t, client, http.MethodPost, base+"/final", payload)
				assertBrowserContractResponse(t, resp, body, err, "/final", "Synthetic final")
				if final.Load() != 1 {
					t.Fatalf("client-followed POST reached final %d times, want 1", final.Load())
				}
			})
		}
	}
}

func TestBrowserForwardRedirectActualRequestReadmitted(t *testing.T) {
	const marker = "SYNTHETIC_AUTH_MARKER"
	for _, change := range []string{"policy_reload", "new_header", "new_body", "receipt_unavailable"} {
		t.Run(change, func(t *testing.T) {
			var initial, final atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					initial.Add(1)
					http.Redirect(w, r, "/final", http.StatusSeeOther)
					return
				}
				final.Add(1)
				_, _ = io.WriteString(w, "Unexpected follow")
			}))
			t.Cleanup(origin.Close)
			client, base, _, p := newBrowserContractProxyClient(t, origin.URL, func(cfg *config.Config) {
				cfg.RequestBodyScanning.Action = config.ActionBlock
				cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Synthetic auth marker", Regex: marker})
				cfg.FlightRecorder.RequireReceipts = change == "receipt_unavailable"
			})
			if change == "receipt_unavailable" {
				rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
				p.receiptEmitterPtr.Store(rph.emitter)
				t.Cleanup(func() { _ = rph.rec.Close() })
			}
			resp, body, err := browserContractRequest(t, client, http.MethodGet, base+"/start", "")
			assertBrowserContractRedirect(t, resp, body, err, "/start", "/final")
			method, payload := http.MethodGet, ""
			switch change {
			case "policy_reload":
				cfg := *p.CurrentConfig()
				cfg.APIAllowlist = []string{browserRedirectOtherHost}
				if !p.Reload(&cfg, scanner.MustNew(&cfg)) {
					t.Fatal("reload failed")
				}
			case "new_body":
				method, payload = http.MethodPost, marker
			case "receipt_unavailable":
				if resp.Header.Get(blockreason.HeaderRecordedReceipt) == "" {
					t.Fatal("first request was not backed by a required receipt")
				}
				p.receiptEmitterPtr.Store(nil)
			}
			// A passed redirect preflight does not admit this later request
			// under changed policy, credentials, body, or receipt availability.
			req, err := http.NewRequestWithContext(t.Context(), method, base+"/final", strings.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "text/plain")
			if change == "new_header" {
				req.Header.Set("Authorization", "Bearer "+marker)
			}
			rawResp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			data, readErr := io.ReadAll(io.LimitReader(rawResp.Body, 4096))
			_ = rawResp.Body.Close()
			resp = browserContractResponseMetadata(rawResp)
			if readErr != nil || resp.StatusCode != http.StatusForbidden || resp.Header.Get(blockreason.HeaderReason) == "" || initial.Load() != 1 || final.Load() != 0 {
				t.Fatalf("later admission: status=%d initial=%d final=%d body=%q error=%v", resp.StatusCode, initial.Load(), final.Load(), data, readErr)
			}
			if change == "receipt_unavailable" && resp.Header.Get(blockreason.HeaderReason) != string(blockreason.ReceiptEmissionFailed) {
				t.Fatalf("receipt failure reason=%q", resp.Header.Get(blockreason.HeaderReason))
			}
			if (change == "new_header" || change == "new_body") && resp.Header.Get(blockreason.HeaderReason) != string(blockreason.DLPMatch) {
				t.Fatalf("new request content reason=%q", resp.Header.Get(blockreason.HeaderReason))
			}
		})
	}
}

func TestBrowserForwardRedirectAccountingAndFetchParity(t *testing.T) {
	for _, mode := range []string{TransportForward, TransportFetch} {
		t.Run(mode, func(t *testing.T) {
			type observed struct{ path, mediation, signatureInput, signature string }
			seen := make(chan observed, 16)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- observed{r.URL.Path, r.Header.Get(envelope.HeaderName), r.Header.Get("Signature-Input"), r.Header.Get("Signature")}
				n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
				if err != nil {
					t.Error(err)
				}
				if n < 2 {
					http.Redirect(w, r, fmt.Sprintf("/hop/%d", n+1), http.StatusFound)
					return
				}
				_, _ = io.WriteString(w, "Synthetic chain complete")
			}))
			t.Cleanup(origin.Close)
			keyPath := writeEnvelopeKey(t)
			privateKey, err := signing.LoadPrivateKeyFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			publicKey := privateKey.Public().(ed25519.PublicKey)
			client, base, _, p := newBrowserContractProxyClient(t, origin.URL, func(cfg *config.Config) {
				enableEnvelopeSigning(t, cfg, keyPath)
				// The owned recorder is installed immediately after New,
				// matching the existing required-receipt integration helpers.
				cfg.FlightRecorder.RequireReceipts = true
			})
			rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(rph.emitter)
			var responseIDs []string
			if mode == TransportForward {
				for n := 0; n < 3; n++ {
					path := fmt.Sprintf("/hop/%d", n)
					resp, body, err := browserContractRequest(t, client, http.MethodGet, base+path, "")
					want := http.StatusFound
					if n == 2 {
						want = http.StatusOK
					}
					if err != nil || resp.StatusCode != want || len(seen) != n+1 {
						t.Fatalf("client step %d: status=%d witnesses=%d body=%q error=%v", n, resp.StatusCode, len(seen), body, err)
					}
					responseIDs = append(responseIDs, resp.Header.Get(blockreason.HeaderRecordedReceipt))
				}
			} else {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(base+"/hop/0"), nil)
				rec := httptest.NewRecorder()
				p.handleFetch(rec, req)
				if rec.Code != http.StatusOK || len(seen) != 3 || !strings.Contains(rec.Body.String(), "Synthetic chain complete") {
					t.Fatalf("fetch chain: status=%d witnesses=%d body=%q", rec.Code, len(seen), rec.Body.String())
				}
				responseIDs = append(responseIDs, rec.Header().Get(blockreason.HeaderRecordedReceipt))
			}
			ids := make(map[string]bool)
			for n := 0; n < 3; n++ {
				got := <-seen
				env, err := envelope.Parse(got.mediation)
				if err != nil {
					t.Fatal(err)
				}
				wantHop, idIndex := n, 0
				if mode == TransportForward {
					wantHop, idIndex = 0, n
				}
				if got.path != fmt.Sprintf("/hop/%d", n) || env.Hop != wantHop || env.ReceiptID == "" || env.ReceiptID != responseIDs[idIndex] {
					t.Fatalf("%s request %d: path=%s hop=%d receipt=%q headers=%v", mode, n, got.path, env.Hop, env.ReceiptID, responseIDs)
				}
				if !soakVerifyAgainstAnyKey(t, []ed25519.PublicKey{publicKey}, http.MethodGet, base+got.path, got.mediation, got.signatureInput, got.signature) {
					t.Fatalf("%s request %d signature did not verify against its actual target", mode, n)
				}
				ids[env.ReceiptID] = true
			}
			if len(ids) != len(responseIDs) {
				t.Fatalf("unique action IDs=%d, want %d", len(ids), len(responseIDs))
			}
			recorded := rph.findReceipts(t)
			for n, id := range responseIDs {
				if id == "" {
					t.Fatal("required receipt header missing")
				}
				requireSignedRecordedReceipt(t, rph, recorded, id)
				found := false
				for _, rcpt := range recorded {
					ar := rcpt.ActionRecord
					if ar.ActionID == id && ar.Transport == mode && ar.Target == base+fmt.Sprintf("/hop/%d", n) && ar.Verdict == config.ActionAllow {
						found = true
					}
				}
				if !found {
					t.Fatalf("receipt %q missing own %s request target", id, mode)
				}
			}
		})
	}
}

func TestBrowserForwardRedirectClientOwnsHopLimit(t *testing.T) {
	for _, mode := range []string{TransportForward, TransportFetch} {
		t.Run(mode, func(t *testing.T) {
			var hits atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := hits.Add(1)
				http.Redirect(w, r, fmt.Sprintf("/hop/%d", n), http.StatusFound)
			}))
			t.Cleanup(origin.Close)
			client, base, redirects, p := newBrowserContractProxyClient(t, origin.URL)
			if mode == TransportForward {
				client.CheckRedirect = func(*http.Request, []*http.Request) error {
					if redirects.Add(1) >= 7 {
						return http.ErrUseLastResponse
					}
					return nil
				}
				resp, body, err := browserContractRequest(t, client, http.MethodGet, base+"/hop/0", "")
				if err != nil || resp.StatusCode != http.StatusFound || hits.Load() != 7 || redirects.Load() != 7 || resp.URL.Path != "/hop/6" {
					t.Fatalf("client cap: status=%d hits=%d redirects=%d URL=%s body=%q error=%v", resp.StatusCode, hits.Load(), redirects.Load(), resp.URL, body, err)
				}
			} else {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(base+"/hop/0"), nil)
				rec := httptest.NewRecorder()
				p.handleFetch(rec, req)
				if rec.Code != http.StatusBadGateway || hits.Load() != 5 || !strings.Contains(rec.Body.String(), "too many redirects") {
					t.Fatalf("fetch cap: status=%d hits=%d body=%q", rec.Code, hits.Load(), rec.Body.String())
				}
			}
		})
	}
}

func TestBrowserForwardRedirectNonReplayableAndMissingLocation(t *testing.T) {
	for _, status := range []int{http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var initial, final atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/start" {
					final.Add(1)
					return
				}
				initial.Add(1)
				if status != http.StatusSeeOther {
					_, port, err := net.SplitHostPort(r.Host)
					if err != nil {
						t.Error(err)
					}
					w.Header().Set("Location", "http://"+net.JoinHostPort(browserRedirectOtherHost, port)+"/final")
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "Synthetic non-followed redirect")
			}))
			t.Cleanup(origin.Close)
			client, base, _, _ := newBrowserContractProxyClient(t, origin.URL, func(cfg *config.Config) {
				// Preserve the existing streaming request-body mode: do not
				// add buffering merely to make a 307/308 replayable.
				cfg.RequestBodyScanning.Enabled = false
				cfg.MediationEnvelope.Enabled = false
			})
			resp, body, err := browserContractRequest(t, client, http.MethodPost, base+"/start", "synthetic body")
			if err != nil || resp.StatusCode != status || initial.Load() != 1 || final.Load() != 0 {
				t.Fatalf("non-followed response: status=%d initial=%d final=%d body=%q error=%v", resp.StatusCode, initial.Load(), final.Load(), body, err)
			}
			if status == http.StatusSeeOther {
				if resp.Header.Get("Location") != "" {
					t.Fatal("proxy synthesized a missing Location")
				}
				return
			}
			// Go did not invoke redirect preflight without GetBody. A
			// separately issued client request still faces the target policy.
			resp, body, err = browserContractRequest(t, client, http.MethodPost, resp.Header.Get("Location"), "synthetic body")
			if err != nil || resp.StatusCode != http.StatusForbidden || resp.Header.Get(blockreason.HeaderReason) == "" || final.Load() != 0 {
				t.Fatalf("actual redirected request: status=%d final=%d body=%q error=%v", resp.StatusCode, final.Load(), body, err)
			}
		})
	}
}

func allowBrowserRedirectOtherHost(cfg *config.Config) {
	cfg.APIAllowlist = append(cfg.APIAllowlist, browserRedirectOtherHost)
	cfg.TrustedDomains = append(cfg.TrustedDomains, browserRedirectOtherHost)
	cfg.DNS.HostOverrides[browserRedirectOtherHost] = []string{"127.0.0.1"}
}

func browserRedirectOrigin(t *testing.T, raw, host string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return "http://" + net.JoinHostPort(host, u.Port())
}
