// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestStrongestAction(t *testing.T) {
	tests := []struct {
		name    string
		actions []string
		want    string
	}{
		{name: "none", want: ""},
		{name: "unknown only", actions: []string{"allow", ""}, want: ""},
		{name: "warn beats default", actions: []string{"", ActionWarn}, want: ActionWarn},
		{name: "block beats warn regardless of order", actions: []string{ActionWarn, ActionBlock}, want: ActionBlock},
		{name: "block beats warn when first", actions: []string{ActionBlock, ActionWarn}, want: ActionBlock},

		// allow and forward mean no enforcement. They must never be selected
		// over a real action, and must not be reported as a chosen action on
		// their own, or a caller combining a permissive default with a real
		// finding action would enforce the permissive one.
		{name: "forward alone is no enforcement", actions: []string{ActionForward}, want: ""},
		// Both orders, because selection walks the arguments in order: a
		// regression that picked forward over a ranked action would survive a
		// test that only ever passed forward second.
		{name: "forward does not override strip", actions: []string{ActionForward, ActionStrip}, want: ActionStrip},
		{name: "strip is not lost when forward comes after", actions: []string{ActionStrip, ActionForward}, want: ActionStrip},
		// An unrecognized value on its own must not be returned as if it were
		// a chosen action. Pairing it with a real action, as the strip case
		// below does, cannot catch that regression.
		{name: "unrecognized only", actions: []string{"not-an-action"}, want: ""},
		{name: "warn beats allow", actions: []string{ActionAllow, ActionWarn}, want: ActionWarn},
		{name: "block beats allow", actions: []string{ActionAllow, ActionBlock}, want: ActionBlock},

		// Actions that are not block or warn were previously unranked, so a
		// weaker action would win against them. These fix that ordering.
		{name: "strip beats warn", actions: []string{ActionWarn, ActionStrip}, want: ActionStrip},
		{name: "redirect beats strip", actions: []string{ActionStrip, ActionRedirect}, want: ActionRedirect},
		{name: "ask beats redirect", actions: []string{ActionRedirect, ActionAsk}, want: ActionAsk},
		{name: "defer beats ask", actions: []string{ActionAsk, ActionDefer}, want: ActionDefer},
		{name: "block beats defer", actions: []string{ActionDefer, ActionBlock}, want: ActionBlock},
		{name: "block wins against every other action", actions: []string{ActionWarn, ActionStrip, ActionRedirect, ActionAsk, ActionDefer, ActionBlock}, want: ActionBlock},
		{name: "strip is not lost to an unknown value", actions: []string{"not-an-action", ActionStrip}, want: ActionStrip},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StrongestAction(tt.actions...); got != tt.want {
				t.Fatalf("StrongestAction(%v) = %q, want %q", tt.actions, got, tt.want)
			}
		})
	}
}

// rankedActionsAscending is every action that carries enforcement weight, in
// increasing strength. nonEnforcingActions carry none: they must never be
// selected over a ranked action and must never be returned alone.
var (
	rankedActionsAscending = []string{ActionWarn, ActionStrip, ActionRedirect, ActionAsk, ActionDefer, ActionBlock}
	nonEnforcingActions    = []string{ActionAllow, ActionForward, "", "not-an-action"}
)

// TestStrongestAction_ContractHoldsForEveryCombination asserts the whole
// contract exhaustively instead of enumerating hand-picked pairs.
//
// The property is that StrongestAction returns the highest-ranked argument
// regardless of argument order, and returns empty when no argument carries
// enforcement weight. Enumerating that by hand invites an endless series of
// "add the reverse of this pair too" rounds and still leaves gaps, because the
// table only ever covers the combinations somebody thought to write down.
func TestStrongestAction_ContractHoldsForEveryCombination(t *testing.T) {
	// Every ordered pair of ranked actions, both directions. The stronger one
	// wins no matter which position it occupies.
	t.Run("ranked pairs are order independent", func(t *testing.T) {
		for i, a := range rankedActionsAscending {
			for j, b := range rankedActionsAscending {
				want := a
				if j > i {
					want = b
				}
				if got := StrongestAction(a, b); got != want {
					t.Errorf("StrongestAction(%q, %q) = %q, want %q", a, b, got, want)
				}
			}
		}
	})

	// A non-enforcing value never beats a ranked action, in either position.
	t.Run("non-enforcing never overrides a ranked action", func(t *testing.T) {
		for _, n := range nonEnforcingActions {
			for _, r := range rankedActionsAscending {
				if got := StrongestAction(n, r); got != r {
					t.Errorf("StrongestAction(%q, %q) = %q, want %q", n, r, got, r)
				}
				if got := StrongestAction(r, n); got != r {
					t.Errorf("StrongestAction(%q, %q) = %q, want %q", r, n, got, r)
				}
			}
		}
	})

	// Nothing to enforce means nothing is returned, however many permissive or
	// unrecognized values are combined.
	t.Run("non-enforcing combinations select nothing", func(t *testing.T) {
		if got := StrongestAction(nonEnforcingActions...); got != "" {
			t.Errorf("StrongestAction(%v) = %q, want empty", nonEnforcingActions, got)
		}
		for _, a := range nonEnforcingActions {
			for _, b := range nonEnforcingActions {
				if got := StrongestAction(a, b); got != "" {
					t.Errorf("StrongestAction(%q, %q) = %q, want empty", a, b, got)
				}
			}
		}
	})

	// The full set, in both directions and with the strongest action first,
	// still selects block.
	t.Run("full set selects block in any order", func(t *testing.T) {
		ascending := append([]string{}, rankedActionsAscending...)
		descending := make([]string, 0, len(ascending))
		for i := len(ascending) - 1; i >= 0; i-- {
			descending = append(descending, ascending[i])
		}
		withNonEnforcing := append(append([]string{}, nonEnforcingActions...), ascending...)

		for _, set := range [][]string{ascending, descending, withNonEnforcing} {
			if got := StrongestAction(set...); got != ActionBlock {
				t.Errorf("StrongestAction(%v) = %q, want %q", set, got, ActionBlock)
			}
		}
	})
}
