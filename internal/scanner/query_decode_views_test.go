// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestQueryDecodeViewsCredentialViews(t *testing.T) {
	sc := newEncodedCredentialScanner(t, false)
	credential := githubClassicToken()
	h := hex.EncodeToString([]byte(credential))
	b := base64.StdEncoding.EncodeToString([]byte(credential))
	forms := map[string]string{
		"plain control":        credential,
		"hex control":          h,
		"hex notation control": "0x" + strings.Join(splitBytePairs(h), "0x"),
		"base64 control":       b,
		"partial percent":      "%67" + credential[1:] + "%ZZ",
	}
	for name, value := range forms {
		t.Run(name, func(t *testing.T) {
			if r := sc.Scan(t.Context(), "https://api.vendor.example/?q="+url.QueryEscape(value)); r.Allowed || !strings.Contains(r.Reason, "DLP") {
				t.Errorf("URL: allowed=%v scanner=%s", r.Allowed, r.Scanner)
			}
			if r := sc.ScanTextForDLP(t.Context(), value); r.Clean {
				t.Error("text: credential was not detected")
			}
			if r := sc.ScanRequestBodyTextForDLP(t.Context(), `{"note":"`+value+`"}`); r.Clean {
				t.Error("body: credential was not detected")
			}
		})
	}
}

func splitBytePairs(s string) []string {
	var out []string
	for i := 0; i < len(s); i += 2 {
		out = append(out, s[i:min(i+2, len(s))])
	}
	return out
}

func TestQueryDecodeViewsRawQuery(t *testing.T) {
	sc := newEncodedCredentialScanner(t, true)
	for _, value := range []string{hex.EncodeToString([]byte(githubClassicToken())), base64.StdEncoding.EncodeToString([]byte(githubClassicToken()))} {
		for _, query := range []string{"q=" + value + ";x=1", "q=" + value + "%ZZ", "x=1;" + value + "=ok"} {
			if r := sc.Scan(context.Background(), "https://api.vendor.example/?"+query); r.Allowed || !strings.Contains(r.Reason, "DLP") {
				t.Errorf("query recovery: allowed=%v scanner=%s", r.Allowed, r.Scanner)
			}
		}
	}
}

func TestQueryDecodeViewsDNSNames(t *testing.T) {
	sc := newEncodedCredentialScanner(t, true)
	h := githubClassicToken()
	labels := []string{h[:20], h[20:], "vendor", "example"}
	if r := sc.Scan(t.Context(), "https://"+strings.Join(labels, ".")+"/"); r.Allowed || !strings.Contains(r.Reason, "DLP") {
		t.Errorf("hostname: allowed=%v scanner=%s", r.Allowed, r.Scanner)
	}
	wire := dnsQueryWire(t, labels)
	if r := sc.Scan(t.Context(), "https://api.vendor.example/dns-query?x=%ZZ;dns="+base64.RawURLEncoding.EncodeToString(wire)); r.Allowed || !strings.Contains(r.Reason, "DLP") {
		t.Errorf("DoH query: allowed=%v scanner=%s", r.Allowed, r.Scanner)
	}
	inspection := sc.InspectDNSPayload(wire)
	if !inspection.Parsed {
		t.Fatal("DNS positive control did not parse")
	}
	if r := sc.ScanRequestBodyTextPartsForDLP(t.Context(), inspection.DLPTexts, "\n"); r.Clean {
		t.Error("DoH body: credential was not detected")
	}
}

func TestQueryDecodeViewsKnownSecrets(t *testing.T) {
	secret := "Zq7Lm2Xc9Vb4" + "Nn8Kp3Rt6Wy1"
	sc := knownSecretEncodingScanner(t, []string{secret})
	for _, prefix := range []string{"a", "ab", "user:"} {
		value := base64.StdEncoding.EncodeToString([]byte(prefix + secret))
		for _, nested := range []string{value, hex.EncodeToString([]byte(value)), base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte(prefix + secret))))} {
			if r := sc.ScanTextForDLP(t.Context(), nested); r.Clean {
				t.Errorf("known secret: prefix %q was not detected", prefix)
			}
			if r := sc.ScanRequestBodyTextForDLP(t.Context(), `{"note":"`+nested+`"}`); r.Clean {
				t.Errorf("known secret body: prefix %q was not detected", prefix)
			}
			if r := sc.Scan(t.Context(), "https://api.vendor.example/?q="+url.QueryEscape(nested)); r.Allowed {
				t.Errorf("known secret URL: prefix %q was not detected", prefix)
			}
		}
	}
}

func TestQueryDecodeViewsParserFloor(t *testing.T) {
	sc := newEncodedCredentialScanner(t, true)
	for _, value := range []string{hex.EncodeToString([]byte(githubClassicToken())), base64.RawURLEncoding.EncodeToString([]byte(githubClassicToken()))} {
		if r := sc.ScanURLCoreFloor("https://api.vendor.example/?q=" + value + "#%zz"); r.Allowed {
			t.Error("malformed URL discarded credential view")
		}
	}
}

func TestQueryDecodeViewsConfiguredQuery(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.IncludeDefaults = ptrBool(false)
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Recovery Marker", Regex: `recovery_[A-Z0-9]{24}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	marker := "recovery_" + "ABCDEFGHIJKLMNOPQRSTUVWX"
	encoded := hex.EncodeToString([]byte(marker))
	for _, query := range []string{"q=" + encoded + ";x=1", "q=" + encoded + "%ZZ", "x=1;" + encoded + "=ok"} {
		r := sc.Scan(t.Context(), "https://api.vendor.example/?"+query)
		if r.Allowed || r.Scanner != ScannerDLP || !strings.Contains(r.Reason, "Recovery Marker") {
			t.Errorf("configured query: allowed=%v scanner=%s", r.Allowed, r.Scanner)
		}
	}
}
