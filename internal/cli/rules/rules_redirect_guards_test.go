package rules

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestBundleClients_StopAfterRedirectLoop proves the hop cap on BOTH clients.
// Setting CheckRedirect at all replaces net/http's default callback, and the
// ten-hop bound lives inside that default, so a custom callback that never
// inspects via silently removes it. Without the cap a redirect loop spins until
// the request context expires instead of failing fast.
func TestBundleClients_StopAfterRedirectLoop(t *testing.T) {
	// NOT parallel: mutates the shared clients.
	originalOfficial := officialRegistryClient
	originalHTTPS := httpsOnlyClient
	t.Cleanup(func() {
		officialRegistryClient = originalOfficial
		httpsOnlyClient = originalHTTPS
	})

	// Each client redirects to itself forever. Only the hop cap can end it.
	loop := func(host string) rulesRoundTripper {
		return func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"https://" + host + req.URL.Path}},
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}
	}
	officialRegistryClient = &http.Client{
		Transport:     loop("pipelab.org"),
		CheckRedirect: originalOfficial.CheckRedirect,
	}
	httpsOnlyClient = &http.Client{
		Transport:     loop("source.example"),
		CheckRedirect: originalHTTPS.CheckRedirect,
	}

	if _, _, err := fetchOfficialRegistryBundle(t.Context(), officialRegistryURL+testBundlePath); err == nil ||
		!strings.Contains(err.Error(), "stopped after") {
		t.Fatalf("official client error = %v, want the redirect hop cap to stop the loop", err)
	}
	if _, _, err := fetchRemoteBundle(t.Context(), "https://source.example/bundle.yaml"); err == nil ||
		!strings.Contains(err.Error(), "stopped after") {
		t.Fatalf("general client error = %v, want the redirect hop cap to stop the loop", err)
	}
}

// TestIsOfficialRegistryURL_EdgesFailClosed locks in the origin comparison.
// Every deviation must refuse rather than match, including an unparseable
// target, embedded credentials, and a lookalike host that merely contains or
// extends the official one.
func TestIsOfficialRegistryURL_EdgesFailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		url  string
		want bool
	}{
		{"exact official path", officialRegistryURL + testBundlePath, true},
		{"unparseable", "https://pipelab.org/%zz", false},
		{"empty", "", false},
		{"userinfo smuggled", "https://user:pass@pipelab.org/rules/x/bundle.yaml", false},
		{"suffix lookalike host", "https://pipelab.org.rules-attacker.example/rules/x", false},
		{"prefix lookalike host", "https://evilpipelab.org/rules/x", false},
		{"subdomain", "https://cdn.pipelab.org/rules/x", false},
		{"scheme downgrade", "http://pipelab.org/rules/x", false},
		{"explicit port", "https://pipelab.org:443/rules/x", false},
	} {
		if got := isOfficialRegistryURL(tc.url); got != tc.want {
			t.Errorf("%s: isOfficialRegistryURL(%q) = %v, want %v", tc.name, tc.url, got, tc.want)
		}
	}
}
