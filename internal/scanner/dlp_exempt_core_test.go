package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const corePatternExemptHost = "api.vendor.example"

// corePatternExemptCases exercise each configured-DLP view that consults a
// pattern's exempt_domains. The AWS shape reaches the per-view match; the
// private-key shape splits its literal spaces across query values with a
// same-class decoy between them, so only the query-subsequence concatenation
// reassembles it and the noise-stripped views cannot.
var corePatternExemptCases = []struct {
	name    string
	pattern string
	regex   string
	url     string
}{
	{
		name:    "path view",
		pattern: "AWS Access ID",
		regex:   `AKIA[0-9A-Z]{16}`,
		url:     "https://" + corePatternExemptHost + "/upload/" + "AKIA" + "IOSFODNN7EXAMPLE",
	},
	{
		name:    "query value view",
		pattern: "AWS Access ID",
		regex:   `AKIA[0-9A-Z]{16}`,
		url:     "https://" + corePatternExemptHost + "/upload?key=" + "AKIA" + "IOSFODNN7EXAMPLE",
	},
	{
		name:    "query subsequence view",
		pattern: "Private Key Header",
		regex:   "-----BEGIN" + " PRIVATE" + " KEY-----",
		url:     "https://" + corePatternExemptHost + "/upload?a=-----BEGIN%20" + "PRIVATE&x=%3D&b=%20KEY-----",
	},
}

func newCorePatternExemptScanner(t *testing.T, pattern, regex string) *Scanner {
	t.Helper()
	cfg := testConfig()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	cfg.DLP.Patterns = []config.DLPPattern{{
		Name:          pattern,
		Regex:         regex,
		Severity:      config.SeverityCritical,
		ExemptDomains: []string{corePatternExemptHost},
	}}
	return MustNew(cfg)
}

// A custom DLP pattern that reuses a core pattern's name must not be able to
// carry a domain exemption for that credential class. The core floor blocks
// first regardless, and the configured scanner must also refuse to honor the
// exemption so the two layers never disagree about a core credential.
func TestScan_DLPExemptDomainsIgnoredForCorePatternName(t *testing.T) {
	for _, tc := range corePatternExemptCases {
		t.Run(tc.name, func(t *testing.T) {
			s := newCorePatternExemptScanner(t, tc.pattern, tc.regex)
			defer s.Close()
			if r := s.Scan(context.Background(), tc.url); r.Allowed {
				t.Fatalf("core credential to exempted host was allowed; exemption on a core pattern name must be ignored")
			}
		})
	}
}

// The configured scanner's own guard must hold even when the core floor is
// absent, otherwise the guard is vacuous and the floor is the only defense.
func TestScan_DLPExemptDomainsIgnoredForCorePatternNameWithoutCoreFloor(t *testing.T) {
	for _, tc := range corePatternExemptCases {
		t.Run(tc.name, func(t *testing.T) {
			s := newCorePatternExemptScanner(t, tc.pattern, tc.regex)
			defer s.Close()
			s.core = nil
			r := s.Scan(context.Background(), tc.url)
			if r.Allowed {
				t.Fatalf("configured scanner honored an exemption on a core pattern name")
			}
			if r.Scanner != ScannerDLP {
				t.Fatalf("block came from %q, so the configured DLP guard was not exercised", r.Scanner)
			}
		})
	}
}

// A non-core custom pattern keeps its exemption: the guard must not widen into
// refusing every exemption, or operators disable the knob.
func TestScan_DLPExemptDomainsStillHonoredForCustomPattern(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	cfg.DLP.Patterns = []config.DLPPattern{{
		Name:          "Vendor Bot Token",
		Regex:         `[0-9]{8,10}:[A-Za-z0-9_-]{35}`,
		Severity:      config.SeverityCritical,
		ExemptDomains: []string{corePatternExemptHost},
	}}
	s := MustNew(cfg)
	defer s.Close()
	token := "1234567890:" + strings.Repeat("A", 35)
	if r := s.Scan(context.Background(), "https://"+corePatternExemptHost+"/bot"+token+"/getMe"); !r.Allowed {
		t.Fatalf("custom pattern exemption no longer honored: %s", r.Reason)
	}
}
