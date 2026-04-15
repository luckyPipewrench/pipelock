// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"strings"
	"testing"
)

func TestCmd_RegistersAllSubcommands(t *testing.T) {
	cmd := Cmd()
	want := []string{"list", "inspect", "explain", "release", "terminate", "recover"}
	for _, name := range want {
		_, _, err := cmd.Find([]string{name})
		if err != nil {
			t.Errorf("subcommand %q not registered: %v", name, err)
		}
	}
}

func TestCmd_UseAndShortAreSet(t *testing.T) {
	cmd := Cmd()
	if cmd.Use != "session" {
		t.Errorf("Use: got %q, want %q", cmd.Use, "session")
	}
	if cmd.Short == "" {
		t.Error("Short description is empty")
	}
	if !strings.Contains(cmd.Long, "airlock") {
		t.Errorf("Long description should mention airlock: %q", cmd.Long)
	}
}

func TestAddCommonFlags_BindsSharedFlags(t *testing.T) {
	cmd := Cmd()
	sub, _, err := cmd.Find([]string{"list"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{flagAPIURL, flagAPIToken, flagConfig, flagJSON} {
		if sub.Flag(name) == nil {
			t.Errorf("subcommand list missing flag %q", name)
		}
	}
}
