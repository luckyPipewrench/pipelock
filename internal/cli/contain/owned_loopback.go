// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
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

func ownedLoopbackInputChainLooksManaged(out string) bool {
	return strings.Contains(out, "chain "+ownedLoopbackInputChain+" {") &&
		strings.Contains(out, "type filter hook input priority filter; policy accept;") &&
		strings.Contains(out, "ct mark "+ownedLoopbackConntrackMark+" socket cgroupv2 level 1 \""+ownedLoopbackSlice+"\" accept") &&
		strings.Contains(out, "ct mark "+ownedLoopbackConntrackMark+" drop")
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
