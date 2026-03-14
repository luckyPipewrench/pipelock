// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package addressprotect

import (
	"strings"
	"testing"
)

const (
	testActionBlock = "block"
	testActionWarnC = "warn" // compare_test constant (testActionWarn is in checker_test.go)
)

func TestIsSimilar(t *testing.T) {
	tests := []struct {
		name   string
		a, b   string
		prefix int
		suffix int
		want   bool
	}{
		{
			name:   "lookalike: same prefix/suffix, different middle",
			a:      "abcd" + "XXXX" + "wxyz",
			b:      "abcd" + "YYYY" + "wxyz",
			prefix: 4, suffix: 4,
			want: true,
		},
		{
			name:   "exact match: not similar",
			a:      "abcdXXXXwxyz",
			b:      "abcdXXXXwxyz",
			prefix: 4, suffix: 4,
			want: false,
		},
		{
			name:   "different length: not similar",
			a:      "abcdXXXwxyz",
			b:      "abcdXXXXwxyz",
			prefix: 4, suffix: 4,
			want: false,
		},
		{
			name:   "different prefix: not similar",
			a:      "abcdXXXXwxyz",
			b:      "EFGHXXXXwxyz",
			prefix: 4, suffix: 4,
			want: false,
		},
		{
			name:   "different suffix: not similar",
			a:      "abcdXXXXwxyz",
			b:      "abcdXXXXEFGH",
			prefix: 4, suffix: 4,
			want: false,
		},
		{
			name:   "guard: prefix+suffix >= len",
			a:      "abcdefgh",
			b:      "abcdXXgh",
			prefix: 4, suffix: 4,
			want: false, // 4+4 = 8 >= 8
		},
		{
			name:   "prefix+suffix < len: works",
			a:      "abcXXXXXyz",
			b:      "abcYYYYYyz",
			prefix: 3, suffix: 2,
			want: true, // 3+2 = 5 < 10
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSimilar(tt.a, tt.b, tt.prefix, tt.suffix)
			if got != tt.want {
				t.Errorf("isSimilar(%q, %q, %d, %d) = %v, want %v",
					tt.a, tt.b, tt.prefix, tt.suffix, got, tt.want)
			}
		})
	}
}

func TestTruncateAddr(t *testing.T) {
	ev := ethValidator{}

	// ETH: 0x + 40 hex = 42 chars. Truncation shows 0x + first6...last6.
	addr := "0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"
	trunc := truncateAddr(addr, ev)
	if !strings.HasPrefix(trunc, "0x") {
		t.Errorf("ETH truncation should keep 0x prefix, got %q", trunc)
	}
	if !strings.Contains(trunc, "...") {
		t.Errorf("ETH truncation should contain ..., got %q", trunc)
	}
	if len(trunc) >= len(addr) {
		t.Errorf("truncated should be shorter than original: %q vs %q", trunc, addr)
	}
}

func TestTruncateAddrShort(t *testing.T) {
	ev := ethValidator{}

	// Short string: show full (below minTruncLen).
	short := "0x1234567890"
	trunc := truncateAddr(short, ev)
	if trunc != short {
		t.Errorf("short address should not be truncated, got %q", trunc)
	}
}

func TestCompareHitExactMatch(t *testing.T) {
	ev := ethValidator{}
	hit := Hit{Chain: ChainETH, Raw: "0x742d35cc6634c0532925a3b844bc9e7595f2bd3e", Normalized: "0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}
	allowed := []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}

	finding := compareHit(hit, allowed, 4, 4, testActionBlock, "allow", ev)
	if finding != nil {
		t.Error("exact match should return nil (allow through)")
	}
}

func TestCompareHitLookalike(t *testing.T) {
	ev := ethValidator{}
	// Same first 4 and last 4 hex payload chars, different middle.
	// Must be exactly 42 chars: 0x + 40 hex (4 prefix + 30 middle + 6 suffix).
	hit := Hit{
		Chain:      ChainETH,
		Raw:        "0x742dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAf2bd3e",
		Normalized: "0x742daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf2bd3e",
	}
	allowed := []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}

	finding := compareHit(hit, allowed, 4, 4, testActionBlock, "allow", ev)
	if finding == nil {
		t.Fatal("lookalike should return a Finding")
	}
	if finding.Verdict != VerdictLookalike {
		t.Errorf("verdict: got %d, want VerdictLookalike", finding.Verdict)
	}
	if finding.MatchedAddr == "" {
		t.Error("MatchedAddr should be set for lookalike")
	}
	if !strings.Contains(finding.Explanation, "address poisoning") {
		t.Error("explanation should mention address poisoning")
	}
}

func TestCompareHitUnknownAllow(t *testing.T) {
	ev := ethValidator{}
	hit := Hit{Chain: ChainETH, Raw: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", Normalized: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	allowed := []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}

	// unknown_action: allow → no Finding.
	finding := compareHit(hit, allowed, 4, 4, testActionBlock, "allow", ev)
	if finding != nil {
		t.Error("unknown with allow action should return nil")
	}
}

func TestCompareHitUnknownWarn(t *testing.T) {
	ev := ethValidator{}
	hit := Hit{Chain: ChainETH, Raw: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", Normalized: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	allowed := []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}

	// unknown_action: warn → Finding with VerdictUnknown.
	finding := compareHit(hit, allowed, 4, 4, testActionBlock, testActionWarnC, ev)
	if finding == nil {
		t.Fatal("unknown with warn action should return a Finding")
	}
	if finding.Verdict != VerdictUnknown {
		t.Errorf("verdict: got %d, want VerdictUnknown", finding.Verdict)
	}
}

func TestCompareHitLookalikePrefixThree(t *testing.T) {
	ev := ethValidator{}
	// With prefix=3 and suffix=3, the first/last 3 hex payload chars must match.
	hit := Hit{
		Chain:      ChainETH,
		Raw:        "0x742AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAd3e",
		Normalized: "0x742aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad3e",
	}
	allowed := []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}

	finding := compareHit(hit, allowed, 3, 3, testActionBlock, "allow", ev)
	if finding == nil {
		t.Fatal("lookalike with prefix=3, suffix=3 should return a Finding")
	}
	if finding.Verdict != VerdictLookalike {
		t.Errorf("verdict: got %d, want VerdictLookalike", finding.Verdict)
	}
}

func TestCompareHitLookalineCarriesAction(t *testing.T) {
	ev := ethValidator{}
	hit := Hit{
		Chain:      ChainETH,
		Raw:        "0x742daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf2bd3e",
		Normalized: "0x742daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf2bd3e",
	}
	allowed := []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}

	// Lookalike finding should carry action="warn" when configured as warn.
	finding := compareHit(hit, allowed, 4, 4, testActionWarnC, "allow", ev)
	if finding == nil {
		t.Fatal("expected finding")
	}
	if finding.Action != testActionWarnC {
		t.Errorf("lookalike Action: got %q, want %q", finding.Action, "warn")
	}
}

func TestCompareHitUnknownCarriesAction(t *testing.T) {
	ev := ethValidator{}
	hit := Hit{Chain: ChainETH, Raw: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", Normalized: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	allowed := []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}

	// Unknown finding with unknown_action=block should carry action="block".
	finding := compareHit(hit, allowed, 4, 4, testActionWarnC, testActionBlock, ev)
	if finding == nil {
		t.Fatal("expected finding")
	}
	if finding.Action != testActionBlock {
		t.Errorf("unknown Action: got %q, want %q", finding.Action, "block")
	}
}

func TestCompareHitBTCExactMatch(t *testing.T) {
	bv := btcValidator{}
	hit := Hit{
		Chain:      ChainBTC,
		Raw:        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		Normalized: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
	}
	allowed := []string{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}

	finding := compareHit(hit, allowed, 4, 4, testActionBlock, "allow", bv)
	if finding != nil {
		t.Error("exact BTC bech32 match should return nil")
	}
}

func TestCompareHitEmptyAllowlist(t *testing.T) {
	ev := ethValidator{}
	hit := Hit{Chain: ChainETH, Raw: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", Normalized: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}

	// Empty allowlist with allow action → no Finding (inert).
	finding := compareHit(hit, nil, 4, 4, testActionBlock, "allow", ev)
	if finding != nil {
		t.Error("empty allowlist with allow action should return nil")
	}
}
