// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
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

func TestQueryDecodeViewsKnownSecretCasePreservation(t *testing.T) {
	secret := "Zq7Lm2Xc9Vb4" + "Nn8Kp3Rt6Wy1"
	sc := knownSecretEncodingScanner(t, []string{secret})
	changed := strings.ToLower(secret)
	for name, tc := range map[string]struct {
		value string
		clean bool
	}{
		"exact plaintext":          {secret, false},
		"different plaintext":      {changed, true},
		"uppercase hex spelling":   {strings.ToUpper(hex.EncodeToString([]byte(secret))), false},
		"exact nested carrier":     {hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte("user:" + secret)))), false},
		"different nested carrier": {hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte("user:" + changed)))), true},
	} {
		t.Run(name, func(t *testing.T) {
			if result := sc.ScanTextForDLP(t.Context(), tc.value); result.Clean != tc.clean {
				t.Errorf("text: clean=%v, want %v", result.Clean, tc.clean)
			}
			if result := sc.ScanRequestBodyTextForDLP(t.Context(), `{"note":"`+tc.value+`"}`); result.Clean != tc.clean {
				t.Errorf("body: clean=%v, want %v", result.Clean, tc.clean)
			}
			parsed, err := url.Parse("https://api.vendor.example/?q=" + url.QueryEscape(tc.value))
			if err != nil {
				t.Fatal(err)
			}
			if result := sc.checkSecretsInURL(sc.fileSecrets, parsed, "test secret"); result.Allowed != tc.clean {
				t.Errorf("URL secret check: allowed=%v, want %v", result.Allowed, tc.clean)
			}
		})
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

func TestQueryDecodeViewsEncodedHostname(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	credential := "AKIA" + "Q3ZT7XKP2M5RN8WB"
	for name, form := range map[string]struct {
		encoded string
		width   int
	}{
		"h4 base32": {strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(credential))), 8},
		"h5 base64": {base64.RawURLEncoding.EncodeToString([]byte(credential)), 6},
	} {
		t.Run(name, func(t *testing.T) {
			var labels []string
			for start := 0; start < len(form.encoded); start += form.width {
				labels = append(labels, form.encoded[start:min(start+form.width, len(form.encoded))])
			}
			result := sc.Scan(t.Context(), "https://"+strings.Join(labels, ".")+".vendor.example/")
			if result.Allowed || (result.Scanner != ScannerDLP && result.Scanner != ScannerCoreDLP) || !strings.Contains(result.Reason, "AWS") {
				t.Fatalf("encoded hostname escaped DLP: allowed=%v scanner=%s reason=%s", result.Allowed, result.Scanner, result.Reason)
			}
		})
	}
	if result := sc.Scan(t.Context(), "https://ordinary.status.vendor.example/"); !result.Allowed {
		t.Fatalf("benign hostname blocked: %s", result.Reason)
	}
}

func TestQueryDecodeViewsKnownSecretMinimum(t *testing.T) {
	secret := "aB3" + "dE6"
	path := filepath.Join(t.TempDir(), "secrets.txt")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.MinEnvSecretLength = len(secret)
	cfg.DLP.SecretsFile = path
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	if len(sc.fileSecrets) != 1 {
		t.Fatal("operator-configured short secret was not loaded")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("u:" + secret))
	if len(encoded) >= minKnownSecretSubstringLen {
		t.Fatal("fixture does not exercise the configured minimum")
	}
	body := "Basic " + encoded
	if result := sc.ScanTextForDLP(t.Context(), body); result.Clean {
		t.Error("text lost short secret carrier")
	}
	if result := sc.ScanRequestBodyTextForDLP(t.Context(), body); result.Clean {
		t.Error("body lost short secret carrier")
	}
	if result := sc.Scan(t.Context(), "https://api.vendor.example/?q="+url.QueryEscape(body)); result.Allowed {
		t.Error("URL lost short secret carrier")
	}
	views := sc.decodedKnownSecretViews(encoded, nil)
	if len(views) == 0 {
		t.Fatal("short configured secret candidate was skipped")
	}
	if len(sc.decodedKnownSecretViews("tiny", nil)) != 0 {
		t.Error("impossible short candidate was decoded")
	}
}
