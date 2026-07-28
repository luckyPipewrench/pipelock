// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contententropy

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Finding describes an opaque high-entropy body/frame value.
type Finding struct {
	Encoding  string
	Entropy   float64
	Threshold float64
	Length    int
}

// Options configures per-message opaque content entropy scanning.
type Options struct {
	Enabled    bool
	Action     string
	Threshold  float64
	MinLength  int
	Host       string
	Trusted    []string
	Exclusions []string
	Separator  string
}

// ScanTexts checks individual string leaves first, then a stable joined view
// so split fields still trip without making the result depend on map order.
func ScanTexts(texts []string, opts Options) *Finding {
	if !opts.Enabled || opts.Threshold <= 0 || opts.MinLength <= 0 {
		return nil
	}
	if isDomainExempt(opts.Host, opts.Trusted) || isDomainExempt(opts.Host, opts.Exclusions) {
		return nil
	}
	for _, text := range texts {
		if finding := Find(text, opts.Threshold, opts.MinLength); finding != nil {
			return finding
		}
	}
	// The separator-bearing view below is useful for preserving field
	// boundaries, but separators can dominate when an attacker shards an opaque
	// payload into many tiny fields. Scan a stable separatorless view first so
	// field-count amplification cannot dilute the payload's entropy. Shannon
	// entropy depends only on character frequency, so this view is independent
	// of field order: a sharded opaque hex blob reassembles here whatever order
	// the fields arrived in, and no separate reassembly pass is needed.
	sorted := sortedTexts(texts)
	if finding := Find(strings.Join(sorted, ""), opts.Threshold, opts.MinLength); finding != nil {
		return finding
	}
	// Repeated low-entropy structural values (for example, A2A part kinds) must
	// not swamp a payload split across many small fields. A stable deduplicated
	// view preserves the opaque alphabet while bounding each repeated filler's
	// influence. With no repeats this view is byte-identical to the one already
	// scanned above, so skip the redundant entropy pass over the whole payload.
	if unique := uniqueSortedTexts(sorted); len(unique) != len(sorted) {
		if finding := Find(strings.Join(unique, ""), opts.Threshold, opts.MinLength); finding != nil {
			return finding
		}
	}
	separator := opts.Separator
	if separator == "" {
		separator = "."
	}
	joined := strings.Join(sorted, separator)
	return Find(joined, opts.Threshold, opts.MinLength)
}

func uniqueSortedTexts(sorted []string) []string {
	unique := make([]string, 0, len(sorted))
	for _, text := range sorted {
		if len(unique) == 0 || unique[len(unique)-1] != text {
			unique = append(unique, text)
		}
	}
	return unique
}

// Find checks one string for opaque high entropy content.
func Find(text string, threshold float64, minLen int) *Finding {
	text = strings.TrimSpace(text)
	if len(text) < minLen {
		return nil
	}
	entropy := scanner.ShannonEntropy(text)
	if entropy <= threshold && !looksOpaqueHexContent(text, entropy, minLen) {
		return nil
	}
	finding := &Finding{
		Entropy:   entropy,
		Threshold: threshold,
		Length:    len(text),
	}
	if entropy <= threshold {
		finding.Encoding = "hex"
	}
	return finding
}

// Reason returns the operator/audit reason text used by request body and A2A
// entropy enforcement.
func Reason(f *Finding) string {
	if f == nil {
		return "high entropy request body content"
	}
	if f.Encoding != "" {
		return fmt.Sprintf("opaque %s request body content (entropy %.2f, threshold %.2f, %d bytes)", f.Encoding, f.Entropy, f.Threshold, f.Length)
	}
	return fmt.Sprintf("high entropy request body content (%.2f > %.2f threshold, %d bytes)", f.Entropy, f.Threshold, f.Length)
}

func looksOpaqueHexContent(text string, entropy float64, minLen int) bool {
	if len(text) < minLen || len(text) < 32 || entropy < 3.5 {
		return false
	}
	hexChars := 0
	for _, r := range text {
		switch {
		case r >= '0' && r <= '9':
			hexChars++
		case r >= 'a' && r <= 'f':
			hexChars++
		case r >= 'A' && r <= 'F':
			hexChars++
		default:
			return false
		}
	}
	return hexChars == len(text)
}

func isDomainExempt(hostname string, exemptDomains []string) bool {
	hostname = canonicalHost(hostname)
	for _, pattern := range exemptDomains {
		if scanner.MatchDomain(hostname, pattern) {
			return true
		}
	}
	return false
}

func canonicalHost(hostname string) string {
	host := strings.TrimSpace(strings.ToLower(hostname))
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	}
	return strings.TrimSuffix(host, ".")
}

func sortedTexts(texts []string) []string {
	out := make([]string, len(texts))
	for i, text := range texts {
		// Find normalizes each individual leaf. Apply the same normalization to
		// synthetic joined views so padding every shard cannot reintroduce
		// low-entropy whitespace only after the per-leaf minimum-length check.
		out[i] = strings.TrimSpace(text)
	}
	sort.Strings(out)
	return out
}
