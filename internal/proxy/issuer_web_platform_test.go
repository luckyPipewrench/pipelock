// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// The shapes below are the ordinary web-platform URLs that the entropy gate
// blocked on a real browsing session: an image optimizer whose query carries
// the asset path, a bundler asset file name, and a captcha frame whose query
// carries the embedding page's origin.
const (
	webImagePath   = "/_next/image/"
	webMediaPath   = "/_next/static/media/img-headshot-PriscillaMontgomery.Zk93mQ4vR7xT.webp"
	webCaptchaPath = "/recaptcha/api2/anchor"
)

func webImageQuery() string {
	return "url=" + url.QueryEscape("/_next/static/media/img-headshot-PriscillaMontgomery.Zk93mQ4vR7xT.webp") + "&w=640&q=75"
}

// captchaOriginValue spells an origin the way a captcha frame does: base64
// with "." for padding.
func captchaOriginValue(origin string) string {
	return strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(origin)), "=", ".")
}

const webHomeHTML = `<!doctype html><html><body>
<img src="` + webImagePath + `?url=%2F_next%2Fstatic%2Fmedia%2Fimg-headshot-PriscillaMontgomery.Zk93mQ4vR7xT.webp&amp;w=640&amp;q=75">
<link rel="preload" href="` + webMediaPath + `">
<p>https://elsewhere.example/` + "_next/static/media/img-headshot-PriscillaMontgomery.Zk93mQ4vR7xT.webp" + `</p>
</body></html>`

type webPlatformHarness struct {
	t      *testing.T
	p      *Proxy
	cfg    *config.Config
	sc     *scanner.Scanner
	logger *audit.Logger
	m      *metrics.Metrics
	cache  *certgen.CertCache
	pool   *x509.CertPool
}

func (h *webPlatformHarness) do(upstream *httptest.Server, path, agent string, headers http.Header) int {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL+path, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
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

func newWebPlatformHarness(t *testing.T) *webPlatformHarness {
	t.Helper()
	return newWebPlatformHarnessThreshold(t, 0)
}

// newWebPlatformHarnessThreshold lowers the URL entropy threshold when it is
// above zero. A local test server's origin (an IP literal and a port) encodes to
// a value that scores below the default threshold, so the page-origin rows need
// the lower bar for their blocking rows to exercise the entropy gate at all.
func newWebPlatformHarnessThreshold(t *testing.T, threshold float64) *webPlatformHarness {
	t.Helper()
	cache, pool, cfg, _, _, m := testInterceptSetup(t)
	issuerCookieTestConfig(t, cfg)
	if threshold > 0 {
		cfg.FetchProxy.Monitoring.EntropyThreshold = threshold
	}
	logger := audit.NewNop()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return &webPlatformHarness{t: t, p: p, cfg: cfg, sc: sc, logger: logger, m: m, cache: cache, pool: pool}
}

// TestInterceptWebPlatformEntropyShapes drives the four live shapes through a
// real TLS-intercepted CONNECT. Every row that must block is the same request
// as an allowed row with exactly one thing taken away, so a row that starts
// passing names the guard that stopped holding.
func TestInterceptWebPlatformEntropyShapes(t *testing.T) {
	var otherURL string
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, webHomeHTML)
		case "/mention":
			// A page on this host that merely names another host's URL.
			_, _ = io.WriteString(w, `<a href="`+otherURL+webImagePath+`?`+webImageQuery()+`">x</a><a href="`+otherURL+webMediaPath+`">y</a>`)
		case "/json":
			// Bare words in JSON are not links; a rooted path and an absolute
			// URL are.
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"name":"img-headshot-RosalindFranklinCrick.Qm27nB5wL9yP.webp","rooted":"/rooted/img-headshot-HenriettaLacksSmith.Tn84kC6xM2zR.webp"}`)
		case "/leak":
			_, _ = io.WriteString(w, `<a href="/credential?token=`+issuerUnissuedSecret()+`">k</a>`)
		default:
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer site.Close()
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer other.Close()
	otherURL = other.URL
	h := newWebPlatformHarness(t)

	image := webImagePath + "?" + webImageQuery()
	steps := []struct {
		name    string
		server  *httptest.Server
		path    string
		agent   string
		headers http.Header
		want    int
	}{
		// Nothing has been issued yet: every shape is blocked.
		{"image query before issuance", site, image, "agent-one", nil, http.StatusForbidden},
		{"media path before issuance", site, webMediaPath, "agent-one", nil, http.StatusForbidden},
		// The page that links them is delivered.
		{"deliver the page", site, "/", "agent-one", nil, http.StatusOK},
		{"image query once the page linked it", site, image, "agent-one", nil, http.StatusOK},
		{"media path once the page linked it", site, webMediaPath, "agent-one", nil, http.StatusOK},
		// One thing taken away from each allowed request.
		{"different session", site, image, "agent-two", nil, http.StatusForbidden},
		{"different session path", site, webMediaPath, "agent-two", nil, http.StatusForbidden},
		{"different host", other, image, "agent-one", nil, http.StatusForbidden},
		{"different host path", other, webMediaPath, "agent-one", nil, http.StatusForbidden},
		{"altered query value", site, webImagePath + "?" + strings.Replace(webImageQuery(), "Zk93", "Zk94", 1), "agent-one", nil, http.StatusForbidden},
		{"extra segment on an issued path", site, webMediaPath + "/Ab3xK9mZ2wQ7rL5y", "agent-one", nil, http.StatusForbidden},
		{"different path same query", site, "/other/?" + webImageQuery(), "agent-one", nil, http.StatusForbidden},
		{"unissued high entropy beside issued value", site, image + "&x=" + issuedTestToken(), "agent-one", nil, http.StatusForbidden},
		// A page that only mentions another host's URL issues nothing for it.
		{"deliver the page that mentions another host", site, "/mention", "agent-one", nil, http.StatusOK},
		{"mentioned host image", other, image, "agent-one", nil, http.StatusForbidden},
		{"mentioned host path", other, webMediaPath, "agent-one", nil, http.StatusForbidden},
		// A real credential in an issued URL is still a credential.
		{"deliver the page carrying a credential", site, "/leak", "agent-one", nil, http.StatusOK},
		{"issued credential value", site, "/credential?token=" + issuerUnissuedSecret(), "agent-one", nil, http.StatusForbidden},
		{"deliver the JSON body", site, "/json", "agent-one", nil, http.StatusOK},
		{"bare JSON word is not a link", site, "/img-headshot-RosalindFranklinCrick.Qm27nB5wL9yP.webp", "agent-one", nil, http.StatusForbidden},
		{"relative JSON word resolved under the response directory", site, "/json/img-headshot-RosalindFranklinCrick.Qm27nB5wL9yP.webp", "agent-one", nil, http.StatusForbidden},
		{"rooted JSON path is a link", site, "/rooted/img-headshot-HenriettaLacksSmith.Tn84kC6xM2zR.webp", "agent-one", nil, http.StatusOK},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			if got := h.do(step.server, step.path, step.agent, step.headers); got != step.want {
				t.Fatalf("status=%d, want %d", got, step.want)
			}
		})
	}
}

// TestInterceptWebPlatformSelfIssuedValue documents what a hostile origin
// buys. It may serve a high-entropy URL on its own host and the agent may then
// request it, so a value the origin already holds is no longer scored. That
// moves no information the origin lacked, and the same origin cannot issue a
// value for another host.
func TestInterceptWebPlatformSelfIssuedValue(t *testing.T) {
	var victimURL string
	attacker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<a href="/x?p=`+issuedTestToken()+`">own</a><a href="`+victimURL+`/x?p=`+issuedTestToken()+`">victim</a>`)
	}))
	defer attacker.Close()
	victim := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer victim.Close()
	victimURL = victim.URL
	h := newWebPlatformHarness(t)
	for _, step := range []struct {
		name   string
		server *httptest.Server
		path   string
		want   int
	}{
		{"before the attacker page", attacker, "/x?p=" + issuedTestToken(), http.StatusForbidden},
		{"attacker page delivered", attacker, "/", http.StatusOK},
		{"value the attacker issued to itself", attacker, "/x?p=" + issuedTestToken(), http.StatusOK},
		{"value the attacker issued for another host", victim, "/x?p=" + issuedTestToken(), http.StatusForbidden},
		{"value the agent composed for the attacker", attacker, "/x?p=" + issuedTestToken() + "Q", http.StatusForbidden},
		{"agent secret sent to the attacker", attacker, "/x?p=" + issuerUnissuedSecret(), http.StatusForbidden},
	} {
		t.Run(step.name, func(t *testing.T) {
			if got := h.do(step.server, step.path, "agent-one", nil); got != step.want {
				t.Fatalf("status=%d, want %d", got, step.want)
			}
		})
	}
}

// TestInterceptPageOriginEchoAddsNoChannel answers the objection that the
// Referer and Origin headers are agent-supplied. They are, and the destination
// receives them unchanged, so an agent that wants to hand the destination data
// can already put it there. The echo rule must therefore change nothing about
// what such a request gets: the same Referer with an unrelated query value
// gets the same status, and a credential in the Referer host stays blocked.
//
// The fixtures are lower case because the guard canonicalizes the host: a
// mixed-case host never matches its own encoding, so it would test nothing.
// The first two hosts are agent-chosen strings that never served a document;
// the guard is the served-document requirement, not the header.
func TestInterceptPageOriginEchoAddsNoChannel(t *testing.T) {
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer site.Close()
	h := newWebPlatformHarness(t)
	for _, referer := range []string{
		"https://" + strings.ToLower(issuerUnissuedSecret()) + ".vendor.example/",
		"https://" + strings.ToLower(issuedTestToken()) + ".vendor.example/",
		"https://q7xm2v9kb4zf8wc3yj6rd1ns5th0lp.vendor.example/",
	} {
		origin := strings.TrimSuffix(referer, "/") + ":443"
		withEcho := h.do(site, webCaptchaPath+"?co="+captchaOriginValue(origin), "agent-one", http.Header{"Referer": {referer}})
		withoutEcho := h.do(site, webCaptchaPath+"?co=aHR0cHM6Ly9leGFtcGxl", "agent-one", http.Header{"Referer": {referer}})
		// The Referer header alone is not entropy scored, so it passes on its
		// own; that channel exists with or without this rule. Echoing the same
		// data into the query must not be an easier way to send it.
		if withoutEcho != http.StatusOK {
			t.Fatalf("referer %q: control request got %d, want the header alone to pass", referer, withoutEcho)
		}
		if withEcho != http.StatusForbidden {
			t.Errorf("referer %q: echoing it into the query got %d, want %d", referer, withEcho, http.StatusForbidden)
		}
	}
}

// nonCanonicalBase64 sets the unused low bits of the last character of an
// unpadded encoding whose byte length is not a multiple of three. A lenient
// decoder reads the same bytes; a strict one refuses the spelling, so one
// origin cannot be written in 64 different ways.
func nonCanonicalBase64(canonical string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := strings.IndexByte(alphabet, canonical[len(canonical)-1])
	return canonical[:len(canonical)-1] + string(alphabet[last+1])
}

func TestPageOriginEchoed(t *testing.T) {
	origin := "https://login.auth.vendor.example"
	enc := func(s string, e *base64.Encoding) string { return e.EncodeToString([]byte(s)) }
	tests := []struct {
		name   string
		header http.Header
		value  string
		want   bool
	}{
		{"dot padded with explicit port", http.Header{"Referer": {origin + "/a?b=c#d"}}, captchaOriginValue(origin + ":443"), true},
		{"std padded without port", http.Header{"Referer": {origin + "/a"}}, enc(origin, base64.StdEncoding), true},
		{"url raw", http.Header{"Origin": {origin}}, enc(origin+":443", base64.RawURLEncoding), true},
		{"std raw", http.Header{"Origin": {origin}}, enc(origin, base64.RawStdEncoding), true},
		{"non default port", http.Header{"Referer": {origin + ":8443/x"}}, enc(origin+":8443", base64.StdEncoding), true},
		{"non default port elided", http.Header{"Referer": {origin + ":8443/x"}}, enc(origin, base64.StdEncoding), false},
		{"upper case host", http.Header{"Referer": {"https://LOGIN.auth.vendor.example/"}}, enc(origin+":443", base64.StdEncoding), true},
		{"no header", http.Header{}, enc(origin+":443", base64.StdEncoding), false},
		{"other origin", http.Header{"Referer": {origin + "/"}}, enc("https://evil.vendor.example:443", base64.StdEncoding), false},
		{"origin plus path", http.Header{"Referer": {origin + "/a"}}, enc(origin+"/a", base64.StdEncoding), false},
		{"origin plus secret suffix", http.Header{"Referer": {origin + "/a"}}, enc(origin+":443/"+issuedTestToken(), base64.StdEncoding), false},
		{"two referers", http.Header{"Referer": {origin + "/", origin + "/"}}, enc(origin+":443", base64.StdEncoding), false},
		{"userinfo referer", http.Header{"Referer": {"https://u:p@login.auth.vendor.example/"}}, enc(origin+":443", base64.StdEncoding), false},
		{"non http scheme", http.Header{"Referer": {"ftp://login.auth.vendor.example/"}}, enc("ftp://login.auth.vendor.example:21", base64.StdEncoding), false},
		{"not base64", http.Header{"Referer": {origin + "/"}}, "!!!not-base64!!!", false},
		{"non zero trailing bits", http.Header{"Referer": {origin + "/"}}, nonCanonicalBase64(enc(origin+":443", base64.RawStdEncoding)), false},
		{"canonical twin of the non zero trailing bits case", http.Header{"Referer": {origin + "/"}}, enc(origin+":443", base64.RawStdEncoding), true},
		{"too short", http.Header{"Referer": {"https://a.io/"}}, "aHR0", false},
		{"too long", http.Header{"Referer": {origin + "/"}}, strings.Repeat("A", 600), false},
		{"ipv6 referer", http.Header{"Referer": {"https://[2001:db8::1]/"}}, enc("https://[2001:db8::1]:443", base64.StdEncoding), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origin, got := pageOriginEchoed(tt.header, tt.value)
			if got != tt.want {
				t.Fatalf("pageOriginEchoed = %v, want %v", got, tt.want)
			}
			if got != (origin != nil) {
				t.Fatalf("origin = %v for result %v", origin, got)
			}
			if got && origin.Scheme != "https" && origin.Scheme != "http" {
				t.Fatalf("origin scheme = %q", origin.Scheme)
			}
		})
	}
}

func TestHTMLLinkValues(t *testing.T) {
	body := `<!doctype html><!-- <a href="/comment"> --><html><head>
<style>.x{background:url(/style-only)}</style><script>var u="/script-only";</script>
<link rel="preload" as="image" imagesrcset="/a.png 1x, /b.png 2x" href="/c.png">
</head><body><IMG SRC=" /d.png " srcset="/e.png 640w,/f.png 1280w"><a HREF=/g>g</a>
<source data-srcset="/h.png 1x"><video poster=/i.png data-src=/j.mp4></video><a href="">empty</a><p title="/title-only"></p></body></html>`
	got := htmlLinkValues([]byte(body), 100)
	want := []string{"/a.png", "/b.png", "/c.png", "/d.png", "/e.png", "/f.png", "/g", "/h.png", "/i.png", "/j.mp4"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("links = %q, want %q", got, want)
	}
	if capped := htmlLinkValues([]byte(body), 2); len(capped) != 2 {
		t.Fatalf("limit not enforced: %q", capped)
	}
	if htmlLinkValues([]byte(body), 0) != nil || htmlLinkValues(nil, 5) != nil {
		t.Fatal("empty input or limit must yield nothing")
	}
	big := make([]byte, issuerQueryMaxHTMLBytes+10)
	copy(big, "<a href=/early>")
	for i := len("<a href=/early>"); i < len(big)-len("<a href=/late>")-1; i++ {
		big[i] = ' '
	}
	copy(big[len(big)-len("<a href=/late>"):], "<a href=/late>")
	if links := htmlLinkValues(big, 10); len(links) != 1 || links[0] != "/early" {
		t.Fatalf("size bound not enforced: %q", links)
	}
}

func TestIssuerQueryPathStore(t *testing.T) {
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	ic := &InterceptContext{Proxy: p, Config: cfg, ActorAuth: envelope.ActorAuthBound}
	store := ic.issuerQueryStore()
	link := mustIssuerQueryURL(t, "https://www.vendor.example"+webMediaPath)
	store.rememberPath("session", link, time.Unix(0, 0))
	if !store.pathIssued("session", link) {
		t.Fatal("positive issuance control missing")
	}
	for name, target := range map[string]*url.URL{
		"other host":   mustIssuerQueryURL(t, "https://cdn.vendor.example"+webMediaPath),
		"other port":   mustIssuerQueryURL(t, "https://www.vendor.example:8443"+webMediaPath),
		"other path":   mustIssuerQueryURL(t, "https://www.vendor.example"+webMediaPath+"x"),
		"cleartext":    mustIssuerQueryURL(t, "http://www.vendor.example"+webMediaPath),
		"userinfo":     mustIssuerQueryURL(t, "https://u@www.vendor.example"+webMediaPath),
		"path as name": mustIssuerQueryURL(t, "https://www.vendor.example/?"+webMediaPath),
	} {
		if store.pathIssued("session", target) {
			t.Errorf("%s: path allowed", name)
		}
	}
	if store.pathIssued("other-session", link) || store.pathIssued("", link) {
		t.Error("path allowed for another or empty session")
	}
	// A value digest and a path digest never collide.
	store.remember("session", link, "a", "b", time.Unix(0, 0))
	if len(store.paths["session"]) != 1 {
		t.Fatal("remembering a value must not add a path")
	}
	// Eviction returns the oldest path to the ordinary gate.
	for i := 0; i < issuerCookieMaxEntries; i++ {
		store.rememberPath("session", mustIssuerQueryURL(t, "https://www.vendor.example/p/"+strings.Repeat("a", 5)+time.Unix(int64(i), 0).Format("150405")+string(rune('a'+i%26))+strings.Repeat("b", i%7)+url.PathEscape(strings.Repeat("c", i%11))+"/"+time.Duration(i).String()), time.Unix(int64(i), 0))
	}
	if len(store.paths["session"]) != issuerCookieMaxEntries {
		t.Fatalf("path cap not enforced: %d", len(store.paths["session"]))
	}
	if store.pathIssued("session", link) {
		t.Fatal("evicted path still allowed")
	}
	blocked := link.String()
	allowCtx := scanner.WithIssuerPathAllowance(context.Background(), func(string) bool { return store.pathIssued("session", link) })
	if result := sc.Scan(allowCtx, blocked); result.Allowed || result.Scanner != scanner.ScannerEntropy {
		t.Fatalf("evicted path did not return to entropy scanning: %+v", result)
	}
	// Oversized paths are never kept.
	huge := mustIssuerQueryURL(t, "https://www.vendor.example/"+strings.Repeat("z", issuerCookieMaxPairBytes+1))
	store.rememberPath("session", huge, time.Now())
	if store.pathIssued("session", huge) {
		t.Fatal("oversized path kept")
	}
	// A nil or disabled store and an empty session issue nothing.
	var nilStore *issuerQueryStore
	nilStore.rememberPath("session", link, time.Now())
	if nilStore.pathIssued("session", link) {
		t.Fatal("nil store issued a path")
	}
	store.rememberPath("", link, time.Now())
	disabled := newIssuerQueryStoreWithReader(failingIssuerQueryReader{})
	disabled.rememberPath("session", link, time.Now())
	if disabled.pathIssued("session", link) {
		t.Fatal("disabled store issued a path")
	}
	// Session eviction drops paths with the session.
	store.rememberPath("victim", link, time.Unix(1, 0))
	for i := 0; i < issuerCookieMaxSessions+1; i++ {
		store.rememberPath("s"+strings.Repeat("x", i), link, time.Unix(int64(i+10), 0))
	}
	if len(store.paths["victim"]) != 0 {
		t.Fatal("oldest session kept its paths after the session cap evicted it")
	}
}

func TestIssuerQueryPathReload(t *testing.T) {
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	store := (&InterceptContext{Proxy: p, Config: cfg, ActorAuth: envelope.ActorAuthBound}).issuerQueryStore()
	link := mustIssuerQueryURL(t, "https://www.vendor.example"+webMediaPath)
	store.rememberPath("session", link, time.Now())
	same := cfg.Clone()
	if !p.Reload(same, scanner.MustNew(same)) {
		t.Fatal("enabled reload failed")
	}
	kept := (&InterceptContext{Proxy: p, Config: same, ActorAuth: envelope.ActorAuthBound}).issuerQueryStore()
	if kept != store || !kept.pathIssued("session", link) {
		t.Fatal("enabled reload lost an issued path")
	}
	off := same.Clone()
	off.TLSInterception.Enabled = false
	if !p.Reload(off, scanner.MustNew(off)) {
		t.Fatal("disabled reload failed")
	}
	if (&InterceptContext{Proxy: p, Config: off, ActorAuth: envelope.ActorAuthBound}).issuerQueryStore() != nil {
		t.Fatal("interception disabled but store available")
	}
	again := off.Clone()
	again.TLSInterception.Enabled = true
	if !p.Reload(again, scanner.MustNew(again)) {
		t.Fatal("re-enable reload failed")
	}
	fresh := (&InterceptContext{Proxy: p, Config: again, ActorAuth: envelope.ActorAuthBound}).issuerQueryStore()
	if fresh == nil || fresh.pathIssued("session", link) {
		t.Fatal("a store rebuilt after interception was off must start empty")
	}
}

// TestWebPlatformIssuerEvidenceIsInterceptOnly states the transport boundary:
// plain-HTTP forward proxying and /fetch never hold issuer evidence, because
// the only response bodies recorded are those a TLS-intercepted HTTPS origin
// delivered to a trusted session. A page they fetched issues nothing, so the
// same high-entropy shapes keep the ordinary gate there. That is the
// fail-closed side of the boundary.
func TestWebPlatformIssuerEvidenceIsInterceptOnly(t *testing.T) {
	var origin, tlsOrigin string
	handler := func(self *string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			if r.URL.Path == "/" {
				_, _ = io.WriteString(w, `<img src="`+*self+webImagePath+`?`+webImageQuery()+`"><link href="`+*self+webMediaPath+`">`)
				return
			}
			_, _ = io.WriteString(w, "ok")
		})
	}
	upstream := newIPv4Server(t, handler(&origin))
	defer upstream.Close()
	origin = upstream.URL
	// An HTTPS origin the fetch client trusts: the only kind whose body could
	// yield issuer evidence, so /fetch must still record none from it.
	tlsUpstream := httptest.NewTLSServer(handler(&tlsOrigin))
	defer tlsUpstream.Close()
	tlsOrigin = tlsUpstream.URL
	_, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.TLSInterception.Enabled = true
	})
	defer cleanup()
	transport, ok := p.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("fetch client transport is %T", p.client.Transport)
	}
	trusting := transport.Clone()
	trusting.TLSClientConfig = &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
	trusting.TLSClientConfig.RootCAs.AddCert(tlsUpstream.Certificate())
	p.client.Transport = trusting
	type route struct {
		send   func(*httptest.ResponseRecorder, string)
		server *httptest.Server
	}
	fetchVia := func(w *httptest.ResponseRecorder, target string) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fetch?url="+url.QueryEscape(target), nil)
		p.handleFetch(w, req)
	}
	serve := map[string]route{
		"forward": {func(w *httptest.ResponseRecorder, target string) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			p.handleForwardHTTP(w, req)
		}, upstream},
		"fetch":       {fetchVia, upstream},
		"fetch-https": {fetchVia, tlsUpstream},
	}
	for transport, rt := range serve {
		send, upstream := rt.send, rt.server
		for _, step := range []struct {
			name, path string
			want       int
		}{
			{"page", "/", http.StatusOK},
			{"ordinary path", "/plain/path?x=1", http.StatusOK},
			{"linked image query", webImagePath + "?" + webImageQuery(), http.StatusForbidden},
			{"linked media path", webMediaPath, http.StatusForbidden},
		} {
			t.Run(transport+"/"+step.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				send(w, upstream.URL+step.path)
				if w.Code != step.want {
					t.Fatalf("status=%d, want %d", w.Code, step.want)
				}
				// The gate above is only reachable from the intercept path,
				// so a recording bug would not change a status. Look at the
				// evidence itself: nothing may have been stored.
				runtime := p.issuerCookieRuntime.Load()
				if runtime == nil || runtime.query == nil {
					t.Fatal("issuer evidence runtime is not configured; the test would be vacuous")
				}
				store := runtime.query
				store.mu.Lock()
				held := len(store.sessions) + len(store.paths) + len(store.documents) + len(store.redirects)
				store.mu.Unlock()
				if held != 0 {
					t.Fatalf("%s recorded issuer evidence (%d buckets)", transport, held)
				}
			})
		}
	}
}

// TestInterceptIssuerPathBudgetDoesNotStarveQueryValues pins that path
// evidence has its own per-response budget. A JSON listing that links more
// rooted paths than the budget before its paging link must still have the
// paging token recorded, and the path budget must still cap path records.
func TestInterceptIssuerPathBudgetDoesNotStarveQueryValues(t *testing.T) {
	token := issuedTestToken()
	lateMedia := "/_next/static/media/img-headshot-HenriettaLacksSmith.Tn84kC6xM2zR.webp"
	paths := make([]string, 0, issuerCookieMaxSetCookies+44)
	paths = append(paths, webMediaPath)
	for i := 1; i < issuerCookieMaxSetCookies+43; i++ {
		paths = append(paths, "/p/"+strconv.Itoa(i))
	}
	paths = append(paths, lateMedia)
	listing, err := json.Marshal(map[string]any{"items": paths, "next": "/page?%24skiptoken=" + token})
	if err != nil {
		t.Fatal(err)
	}
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/list" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(listing)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer site.Close()
	h := newWebPlatformHarness(t)
	page := "/page?%24skiptoken=" + token
	if got := h.do(site, page, "agent-one", nil); got != http.StatusForbidden {
		t.Fatalf("paging request before the listing: status=%d, want 403", got)
	}
	if got := h.do(site, "/list", "agent-one", nil); got != http.StatusOK {
		t.Fatalf("listing status=%d", got)
	}
	if got := h.do(site, page, "agent-one", nil); got != http.StatusOK {
		t.Fatalf("paging token after %d paths: status=%d, want 200", len(paths), got)
	}
	if got := h.do(site, webMediaPath, "agent-one", nil); got != http.StatusOK {
		t.Fatalf("path inside the budget: status=%d, want 200", got)
	}
	if got := h.do(site, lateMedia, "agent-one", nil); got != http.StatusForbidden {
		t.Fatalf("path past the budget: status=%d, want 403", got)
	}
}
