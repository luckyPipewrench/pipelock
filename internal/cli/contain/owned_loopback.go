// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"fmt"
	"strings"
)

const (
	// ownedLoopbackSlice is a shallow, Pipelock-owned cgroup-v2 anchor. nft
	// resolves this path when it loads a rule, so install starts the anchor
	// before it validates or loads the ruleset.
	ownedLoopbackSlice      = "pipelock-contained.slice"
	ownedLoopbackInputChain = "pipelock_owned_loopback_input"

	// ownedLoopbackConntrackMark is reserved for a loopback flow whose source
	// socket is in ownedLoopbackSlice. It is set only in OUTPUT, before INPUT
	// loses source-process identity, and is denied at INPUT unless the receiving
	// socket is also in the owned slice.
	ownedLoopbackConntrackMark = "0x504c4b01"
)

// nftOwnedLoopbackOutputRules permits a contained process to originate a
// loopback connection without selecting a destination port. INPUT remains the
// authority for the receiver: a marked flow is dropped there unless its
// receiving socket belongs to the same Pipelock-owned cgroup.
func nftOwnedLoopbackOutputRules(agentUID int) string {
	return fmt.Sprintf("\t        meta skuid %d oifname \"lo\" ip daddr 127.0.0.1 socket cgroupv2 level 1 \"%s\" ct state new ct mark set %s accept\n\t        meta skuid %d oifname \"lo\" ip6 daddr ::1 socket cgroupv2 level 1 \"%s\" ct state new ct mark set %s accept\n\t        ct mark %s ct state established oifname \"lo\" socket cgroupv2 level 1 \"%s\" ct direction original accept\n\t        ct mark %s ct state established oifname \"lo\" socket cgroupv2 level 1 \"%s\" ct direction reply accept\n", agentUID, ownedLoopbackSlice, ownedLoopbackConntrackMark, agentUID, ownedLoopbackSlice, ownedLoopbackConntrackMark, ownedLoopbackConntrackMark, ownedLoopbackSlice, ownedLoopbackConntrackMark, ownedLoopbackSlice)
}

// nftOwnedLoopbackInputChain is intentionally a separate base chain. The
// final drop is load-bearing: accepting a marked flow at OUTPUT without this
// receiver-side cgroup check would expose every host loopback listener.
func nftOwnedLoopbackInputChain() string {
	return fmt.Sprintf("\n    chain %s {\n        type filter hook input priority filter; policy accept;\n\n        ct mark %s socket cgroupv2 level 1 \"%s\" accept\n        ct mark %s drop\n    }\n", ownedLoopbackInputChain, ownedLoopbackConntrackMark, ownedLoopbackSlice, ownedLoopbackConntrackMark)
}

// ownedLoopbackInputChainLooksManaged requires the receiver gate to be EXACTLY
// the chain this package renders: the base-chain declaration, then the
// cgroup-scoped accept, then the terminal drop, and nothing else.
//
// Substring checks are not sufficient here and the difference is a bypass
// rather than a style point. nftables evaluates a chain in order, so a rule
// added BEFORE the managed accept decides the packet first. A chain carrying an
// extra `ct mark <mark> accept` with no cgroup predicate still contains all four
// expected substrings, so a substring matcher reports it as managed while every
// marked loopback flow reaches any socket on the host. That is the precise
// boundary the owned-loopback design exists to enforce, and both install
// validation and the containment probe read this one function.
func ownedLoopbackInputChainLooksManaged(out string) bool {
	body, ok := ownedLoopbackInputChainBody(out)
	if !ok {
		return false
	}
	want := []string{
		"type filter hook input priority filter; policy accept;",
		"ct mark " + ownedLoopbackConntrackMark + " socket cgroupv2 level 1 \"" + ownedLoopbackSlice + "\" accept",
		"ct mark " + ownedLoopbackConntrackMark + " drop",
	}
	if len(body) != len(want) {
		return false
	}
	for i, line := range body {
		if line != want[i] {
			return false
		}
	}
	return true
}

// ownedLoopbackInputChainBody returns the receiver chain's non-empty statement
// lines, in order, or ok=false when the chain is absent or unterminated. An
// unterminated chain is refused rather than matched on what was read so far,
// because truncated output must never satisfy an exact-match check.
func ownedLoopbackInputChainBody(out string) ([]string, bool) {
	open := "chain " + ownedLoopbackInputChain + " {"
	start := strings.Index(out, open)
	if start < 0 {
		return nil, false
	}
	rest := out[start+len(open):]
	end := strings.Index(rest, "}")
	if end < 0 {
		return nil, false
	}
	var body []string
	for _, line := range strings.Split(rest[:end], "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			body = append(body, trimmed)
		}
	}
	return body, true
}

// ownedLoopbackRulesReferenceCurrentAnchor relies on nft's cgroup-v2
// formatter: it prints a path only when the rule's stored kernel cgroup ID
// still resolves to that path. After a removed-and-recreated cgroup, nft
// prints the stale ID numerically. Requiring the path here makes that state a
// visible failed verification rather than a misleading healthy result.
func ownedLoopbackRulesReferenceCurrentAnchor(out string, minimum int) bool {
	return strings.Count(out, `socket cgroupv2 level 1 "`+ownedLoopbackSlice+`"`) >= minimum
}

func renderOwnedLoopbackInputChainTable(table string) string {
	return fmt.Sprintf("table inet %s {%s}\n", table, nftOwnedLoopbackInputChain())
}

func renderOwnedLoopbackAnchorUnit() string {
	return `[Unit]
Description=Pipelock contained loopback cgroup anchor
Before=pipelock-containment-nft.service

[Service]
Type=simple
Slice=pipelock-contained.slice
ExecStart=/usr/bin/sleep infinity
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
`
}

// chainLinesHaveOwnedLoopbackOutputRules reports whether the live OUTPUT chain
// carries the owned-loopback marking block for the agent. Install-time drift
// detection needs this: the marking rules live in OUTPUT, and a live chain that
// lost them looks unchanged to a comparison that only knows the legacy rules.
func chainLinesHaveOwnedLoopbackOutputRules(lines []string, agentUID int) bool {
	wantMark := "ct mark set " + ownedLoopbackConntrackMark
	wantSlice := `socket cgroupv2 level 1 "` + ownedLoopbackSlice + `"`
	// Track the two families SEPARATELY. Counting matches and requiring two
	// accepts a chain with duplicate IPv4 rules and no IPv6 rule at all, which
	// leaves ::1 loopback unmarked while the count says the block is complete.
	var haveV4, haveV6 bool
	for _, line := range lines {
		if !strings.Contains(line, fmt.Sprintf("skuid %d", agentUID)) ||
			!strings.Contains(line, wantSlice) ||
			!strings.Contains(line, wantMark) {
			continue
		}
		switch {
		case strings.Contains(line, "ip6 daddr"):
			haveV6 = true
		case strings.Contains(line, "ip daddr"):
			haveV4 = true
		}
	}
	return haveV4 && haveV6
}

// ownedLoopbackAnchorState reports the unit's enabled and active state before
// install changes it. Both reads are string comparisons rather than exit-code
// checks: `systemctl is-enabled` exits 0 for `enabled-runtime`, which lives
// under /run and does not survive a reboot, so treating a zero exit as
// "enabled" would record a state the host will not have after restart.
func ownedLoopbackAnchorState(ctx context.Context, env *installEnv, unit string) (enabled, active bool) {
	if out, _, err := env.runCmd(ctx, "systemctl", "is-enabled", unit); err == nil {
		enabled = strings.TrimSpace(out) == systemctlEnabled
	}
	if out, _, err := env.runCmd(ctx, "systemctl", "is-active", unit); err == nil {
		active = strings.TrimSpace(out) == systemctlActive
	}
	return enabled, active
}
