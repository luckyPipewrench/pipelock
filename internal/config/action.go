// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

// StrongestAction returns the strongest enforcement action in block > warn >
// default order. Unknown and empty actions have default rank.
func StrongestAction(actions ...string) string {
	strongest := ""
	strongestRank := 0
	for _, action := range actions {
		rank := actionRank(action)
		if rank > strongestRank {
			strongest = action
			strongestRank = rank
		}
	}
	return strongest
}

func actionRank(action string) int {
	switch action {
	case ActionBlock:
		return 2
	case ActionWarn:
		return 1
	default:
		return 0
	}
}
