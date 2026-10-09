// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"strings"
	"testing"
)

const (
	releaseEntropyTestVersion  = "0.0.46-nightly.20261009.2873"
	releaseEntropyTestFilename = "Example-Code-" + releaseEntropyTestVersion + "-x86_64.AppImage"
)

func TestReleaseFilenameEntropySubject(t *testing.T) {
	for _, tc := range []struct {
		name, tag, filename, want string
	}{
		{"bare version", "1.2.3", "app-1.2.3.bin", "app-.bin"},
		{"tag prefix", "v1.2.3", "app-v1.2.3.bin", "app-.bin"},
		{"bare filename version", "v1.2.3", "app-1.2.3.bin", "app-.bin"},
		{"one occurrence", "v1.2.3", "app-1.2.3-1.2.3.bin", "app--1.2.3.bin"},
		{"prefer complete tag", "v1.2.3", "app-1.2.3-v1.2.3.bin", "app-1.2.3-.bin"},
		{"embedded longer number", "v1.2.3", "app-1.2.30.bin", "app-0.bin"},
		{"embedded preceding digit", "1.2.3", "app-11.2.3.bin", "app-1.bin"},
		{"embedded prerelease", "v1.2.3", "app-1.2.3-rc.1.bin", "app--rc.1.bin"},
		{"prerelease and build", "v1.2.3-beta.1+build.2", "app-1.2.3-beta.1+build.2.bin", "app-.bin"},
		{"numeric build leading zero", "1.2.3+01", "app-1.2.3+01.bin", "app-.bin"},
		{"zero core", "0.0.0", "app-0.0.0.bin", "app-.bin"},
		{"numeric prerelease zero", "1.2.3-0", "app-1.2.3-0.bin", "app-.bin"},
		{"no matching copy", "1.2.3", "app-1.2.4.bin", "app-1.2.4.bin"},
		{"empty tag", "", "app-1.2.3.bin", "app-1.2.3.bin"},
		{"empty filename", "1.2.3", "", ""},
		{"upper case prefix", "V1.2.3", "app-1.2.3.bin", "app-1.2.3.bin"},
		{"repeated prefix", "vv1.2.3", "app-1.2.3.bin", "app-1.2.3.bin"},
		{"named tag", "nightly", "app-nightly.bin", "app-nightly.bin"},
		{"major leading zero", "01.2.3", "app-01.2.3.bin", "app-01.2.3.bin"},
		{"minor leading zero", "1.02.3", "app-1.02.3.bin", "app-1.02.3.bin"},
		{"patch leading zero", "1.2.03", "app-1.2.03.bin", "app-1.2.03.bin"},
		{"numeric prerelease leading zero", "1.2.3-01", "app-1.2.3-01.bin", "app-1.2.3-01.bin"},
		{"zero prerelease leading zero", "1.2.3-00", "app-1.2.3-00.bin", "app-1.2.3-00.bin"},
		{"four core parts", "1.2.3.4", "app-1.2.3.4.bin", "app-1.2.3.4.bin"},
		{"missing core part", "1.2", "app-1.2.bin", "app-1.2.bin"},
		{"empty prerelease", "1.2.3-", "app-1.2.3-.bin", "app-1.2.3-.bin"},
		{"empty prerelease component", "1.2.3-a..b", "app-1.2.3-a..b.bin", "app-1.2.3-a..b.bin"},
		{"empty build", "1.2.3+", "app-1.2.3+.bin", "app-1.2.3+.bin"},
		{"unicode identifier", "1.2.3-β", "app-1.2.3-β.bin", "app-1.2.3-β.bin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := releaseFilenameEntropySubject(tc.tag, tc.filename); got != tc.want {
				t.Fatalf("subject = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReleaseFilenameEntropy(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	if _, blocked := s.pathSegmentEntropy(releaseEntropyTestFilename); !blocked {
		t.Fatal("release fixture must trip the whole-segment gate")
	}
	for _, tc := range []struct {
		name, path string
		allow      bool
	}{
		{"bare tag", "/download/" + releaseEntropyTestVersion + "/" + releaseEntropyTestFilename, true},
		{"prefixed tag", "/download/v" + releaseEntropyTestVersion + "/" + releaseEntropyTestFilename, true},
		{"prefixed filename", "/download/v" + releaseEntropyTestVersion + "/Example-Code-v" + releaseEntropyTestVersion + "-x86_64.AppImage", true},
		{"missing version", "/download/" + releaseEntropyTestFilename, false},
		{"nonadjacent tag", "/v" + releaseEntropyTestVersion + "/download/" + releaseEntropyTestFilename, false},
		{"nonfinal filename", "/v" + releaseEntropyTestVersion + "/" + releaseEntropyTestFilename + "/tail", false},
		{"trailing slash", "/v" + releaseEntropyTestVersion + "/" + releaseEntropyTestFilename + "/", false},
		{"upper case tag", "/V" + releaseEntropyTestVersion + "/" + releaseEntropyTestFilename, false},
		{"other version", "/v1.2.3/" + releaseEntropyTestFilename, false},
		{"latest alias", "/releases/latest/download/" + releaseEntropyTestFilename, false},
		{"benign unversioned", "/download/app.bin", true},
		{"empty path", "", true},
		{"opaque filename", "/download/v1.2.3/" + entropyTestMixed, false},
		{"opaque remainder", "/download/v1.2.3/" + entropyTestMixed[:20] + "1.2.3" + entropyTestMixed[20:], false},
		{"opaque prior segment", "/" + entropyTestMixed + "/v" + releaseEntropyTestVersion + "/" + releaseEntropyTestFilename, false},
		{"second version copy stays scored", "/v" + releaseEntropyTestVersion + "/Example-Code-" + releaseEntropyTestVersion + "-" + releaseEntropyTestVersion + "-x86_64.AppImage", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, blocked := s.pathEntropy(tc.path); blocked == tc.allow {
				t.Fatalf("path blocked = %v, want %v", blocked, !tc.allow)
			}
			raw := "https://assets.vendor.example" + tc.path
			if got := s.Scan(t.Context(), raw); got.Allowed != tc.allow {
				t.Fatalf("outer allowed = %v, reason %q", got.Allowed, got.Reason)
			}
			nested := "https://api.vendor.example/start?redirect=" + url.QueryEscape(raw)
			if got := s.Scan(t.Context(), nested); got.Allowed != tc.allow {
				t.Fatalf("nested allowed = %v, reason %q", got.Allowed, got.Reason)
			}
		})
	}
}

func TestReleaseFilenameEntropyEncoding(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	for _, tc := range []struct {
		name, path  string
		nestedAllow bool
	}{
		{"encoded tag prefix", "/download/%76" + releaseEntropyTestVersion + "/" + releaseEntropyTestFilename, true},
		{"decoded segment separator", "/download/v" + releaseEntropyTestVersion + "%2F" + releaseEntropyTestFilename, true},
		{"build metadata", "/download/v" + releaseEntropyTestVersion + "+b/Example-Code-" + releaseEntropyTestVersion + "+b-x86_64.AppImage", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "https://assets.vendor.example" + tc.path
			if got := s.Scan(t.Context(), raw); !got.Allowed {
				t.Fatalf("outer denied: %s", got.Reason)
			}
			// Nested URLs retain the existing iterative query decoding. A plus
			// becomes a space, so that decoded predecessor gets no version relief.
			nested := "https://api.vendor.example/start?redirect=" + url.QueryEscape(raw)
			if got := s.Scan(t.Context(), nested); got.Allowed != tc.nestedAllow {
				t.Fatalf("nested allowed = %v, want %v: %s", got.Allowed, tc.nestedAllow, got.Reason)
			}
		})
	}
}

func TestReleaseFilenameEntropyOriginalScore(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	const filename = "tool-1.4.2-beta.3-linux-x64-36b3216fdaeeb975729fae923d5a4fd1.tar.gz"
	if _, blocked := s.pathSegmentEntropy(filename); blocked {
		t.Fatal("original fixture must pass")
	}
	subject := releaseFilenameEntropySubject("v1.4.2-beta.3", filename)
	if _, blocked := s.pathSegmentEntropy(subject); !blocked {
		t.Fatal("version removal must raise this fixture above the gate")
	}
	if _, blocked := s.pathEntropy("/v1.4.2-beta.3/" + filename); blocked {
		t.Fatal("normalization introduced a block")
	}
}

func TestReleaseFilenameEntropyPreservesOtherChecks(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	base := "https://assets.vendor.example/download/v" + releaseEntropyTestVersion + "/"
	credential := "gh" + "p_" + strings.Repeat("Ab3C", 9)
	dictionary := "/" + strings.Join(strings.Split(entropyTestMixed, ""), "/") + "/"
	for _, tc := range []struct {
		name, raw, scanner string
	}{
		{"raw credential", base + "Example-Code-" + releaseEntropyTestVersion + "-" + credential + ".bin", ScannerCoreDLP},
		{"credential in version", "https://assets.vendor.example/v1.2.3-" + credential + "/app-1.2.3-" + credential + ".bin", ScannerCoreDLP},
		{"query value", base + releaseEntropyTestFilename + "?ref=" + entropyTestMixed, ScannerEntropy},
		{"query key", base + releaseEntropyTestFilename + "?" + entropyTestMixed + "=1", ScannerEntropy},
		{"nested query", "https://api.vendor.example/start?redirect=" + url.QueryEscape(base+releaseEntropyTestFilename+"?ref="+entropyTestMixed), ScannerEntropy},
		{"dictionary path", "https://assets.vendor.example" + dictionary + entropyTestMixed, ScannerEntropy},
		{"dictionary with version", "https://assets.vendor.example" + dictionary + "v1.2.3/" + entropyTestMixed[:20] + "1.2.3" + entropyTestMixed[20:], ScannerEntropy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Scan(t.Context(), tc.raw)
			if got.Allowed || got.Scanner != tc.scanner {
				t.Fatalf("allowed = %v, scanner = %q, want denial by %q", got.Allowed, got.Scanner, tc.scanner)
			}
		})
	}
}
