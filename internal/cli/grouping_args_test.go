// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// A command that only groups subcommands used to accept any word, print help,
// and exit 0. cobra checks for an unknown subcommand on the ROOT command only,
// so `pipelock contain instal` reported success while nothing was installed.
//
// These tests walk the assembled tree rather than naming commands, so a group
// added later is covered without anyone remembering to add a case. Naming them
// individually is what let 24 of them drift in the first place.

// commandsWithTheirOwnAction are the three commands that have subcommands AND
// do real work themselves, so they take positional arguments legitimately and
// were never part of this defect. Each already rejects a word it does not
// recognise through its own validation, verified by running the binary:
//
//	pipelock audit zzz      -> "cannot access zzz"        exit 1
//	pipelock explain zzz    -> explain target validation  exit 1
//	pipelock guard zzz      -> "usage: pipelock guard..." exit 1
//
// Listing them by name rather than detecting them keeps this test strict: a NEW
// grouping command that nobody guarded fails here instead of being explained
// away by a heuristic. If one of these three genuinely stops taking arguments,
// delete its line and the test will start covering it.
var commandsWithTheirOwnAction = map[string]bool{
	"pipelock audit":   true,
	"pipelock explain": true,
	"pipelock guard":   true,
}

// groupingCommands returns every command in the tree that exists only to group
// subcommands, by the same definition the guard uses.
func groupingCommands(t *testing.T) []*cobra.Command {
	t.Helper()
	var found []*cobra.Command
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		if !c.HasSubCommands() || !c.HasParent() {
			return
		}
		if commandsWithTheirOwnAction[c.CommandPath()] {
			return
		}
		found = append(found, c)
	}
	walk(rootCmd())
	if len(found) == 0 {
		t.Fatal("found no grouping commands; the walk is broken, not the tree")
	}
	return found
}

func TestGroupingCommandsRejectAnUnknownSubcommand(t *testing.T) {
	for _, group := range groupingCommands(t) {
		path := group.CommandPath()
		if group.Args == nil {
			t.Errorf("%s: no argument constraint, so a mistyped subcommand would be accepted", path)
			continue
		}
		// Call the constraint the way cobra does. An unrecognised word arrives
		// as a positional argument once Find fails to match a subcommand.
		if err := group.Args(group, []string{"zzz_not_a_real_subcommand"}); err == nil {
			t.Errorf("%s: accepted an unknown subcommand instead of rejecting it", path)
		}
		// The group must also be runnable, or cobra returns help before it ever
		// reaches the constraint above and the whole guard is inert.
		if !group.Runnable() {
			t.Errorf("%s: not runnable, so cobra returns help before validating arguments "+
				"and the argument constraint is never consulted", path)
		}
	}
}

func TestGroupingCommandsStillAcceptNoArguments(t *testing.T) {
	// Running a group bare is legitimate and prints its help. Breaking that
	// would trade a silent success for a broken discovery path.
	for _, group := range groupingCommands(t) {
		if err := group.Args(group, nil); err != nil {
			t.Errorf("%s: rejected being run with no arguments: %v", group.CommandPath(), err)
		}
	}
}

func TestUnknownSubcommandFailsThroughTheRealCLI(t *testing.T) {
	// The checks above inspect the tree. This one drives the binary, because a
	// constraint that is set and never reached is exactly the defect that made
	// the first attempt at this fix inert.
	cases := [][]string{
		{"contain", "zzz_not_a_real_subcommand"},
		{"signing", "zzz_not_a_real_subcommand"},
		{"cursor", "zzz_not_a_real_subcommand"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, code := runCLI(t, args...)
			if code == 0 {
				t.Errorf("reported success for a subcommand that does not exist.\nstdout: %q", stdout)
			}
			if !strings.Contains(stderr, "unknown command") {
				t.Errorf("did not say what was wrong.\nstderr: %q", stderr)
			}
		})
	}
}
