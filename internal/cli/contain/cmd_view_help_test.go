// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"strings"
	"testing"
)

func TestContainHelpListsOperatorViewCommand(t *testing.T) {
	help := Cmd().Long
	if !strings.Contains(help, "  view        Connect a VNC client") {
		t.Fatal("operator view command is absent from contain help")
	}
	if strings.Contains(help, "  viewer ") {
		t.Fatal("hidden viewer service command appears in contain help")
	}
}
