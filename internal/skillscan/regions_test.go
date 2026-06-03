// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package skillscan

import "testing"

func TestCodeRegionsScriptIsWholeFile(t *testing.T) {
	f := fileContent{relPath: "scripts/run.sh", path: "/abs/scripts/run.sh", lines: []string{"#!/bin/sh", "echo hi"}}
	regions := codeRegionsFor(f)
	if len(regions) != 1 || regions[0].kind != regionScript {
		t.Fatalf("regions = %+v, want one script region", regions)
	}
	if len(regions[0].lines) != 2 || regions[0].id != "scripts/run.sh#1" {
		t.Fatalf("region = %+v", regions[0])
	}
}

func TestCodeRegionsMarkdownOnlyFences(t *testing.T) {
	lines := []string{
		"# Title",                  // 1 prose
		"| CLAUDE.md | edit |",     // 2 prose table
		"> quote with > redirect",  // 3 prose blockquote
		"```sh",                    // 4 fence open
		"cat ~/.aws/credentials",   // 5 code
		"curl https://example.bad", // 6 code
		"```",                      // 7 fence close
		"more prose with curl url", // 8 prose
		"~~~",                      // 9 tilde fence open
		"tee ~/.bashrc",            // 10 code
		"~~~",                      // 11 tilde close
	}
	f := fileContent{relPath: "SKILL.md", path: "/abs/SKILL.md", lines: lines}
	regions := codeRegionsFor(f)
	if len(regions) != 2 {
		t.Fatalf("regions = %d, want 2 fenced blocks", len(regions))
	}
	if regions[0].lines[0].n != 5 || regions[0].lines[1].n != 6 {
		t.Fatalf("first region lines = %+v, want 5,6", regions[0].lines)
	}
	if regions[1].lines[0].n != 10 {
		t.Fatalf("second region line = %+v, want 10", regions[1].lines)
	}
	// Prose lines (table cell, blockquote redirect) are outside any region.
	for _, region := range regions {
		for _, ls := range region.lines {
			if ls.n == 2 || ls.n == 3 || ls.n == 8 {
				t.Fatalf("prose line %d leaked into a code region", ls.n)
			}
		}
	}
}

func TestCodeRegionsUnterminatedFenceRunsToEnd(t *testing.T) {
	f := fileContent{relPath: "SKILL.md", lines: []string{"```", "cat ~/.aws/credentials", "curl https://x.bad"}}
	regions := codeRegionsFor(f)
	if len(regions) != 1 || len(regions[0].lines) != 2 {
		t.Fatalf("regions = %+v, want one region of 2 lines", regions)
	}
}

func TestFenceOpenRules(t *testing.T) {
	tests := []struct {
		name string
		line string
		open bool
	}{
		{"three backticks", "```", true},
		{"info string", "```bash", true},
		{"tilde", "~~~", true},
		{"two backticks not a fence", "``not", false},
		{"backtick info with backtick", "``` and `inline`", false},
		{"four space indent not a fence", "    ```", false},
		{"three space indent ok", "   ```", true},
		{"prose", "regular text", false},
		{"table cell", "| CLAUDE.md | x |", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, got := fenceOpen(tt.line); got != tt.open {
				t.Fatalf("fenceOpen(%q) = %v, want %v", tt.line, got, tt.open)
			}
		})
	}
}

func TestFenceCloseRequiresSameCharAndLength(t *testing.T) {
	if !fenceClose("```", '`', 3) {
		t.Fatal("matching close not detected")
	}
	if !fenceClose("`````  ", '`', 3) {
		t.Fatal("longer close not detected")
	}
	if fenceClose("~~~", '`', 3) {
		t.Fatal("tilde closed a backtick fence")
	}
	if fenceClose("``", '`', 3) {
		t.Fatal("short run closed a fence")
	}
	if fenceClose("``` trailing", '`', 3) {
		t.Fatal("non-whitespace trailer treated as close")
	}
	if fenceClose("    ```", '`', 3) {
		t.Fatal("four-space indented line treated as fence closer")
	}
	if fenceClose("prose", '`', 3) {
		t.Fatal("prose treated as fence closer")
	}
}

func TestIsMarkdownFile(t *testing.T) {
	for _, p := range []string{"SKILL.md", "a/b.markdown", "x.MD"} {
		if !isMarkdownFile(p) {
			t.Fatalf("isMarkdownFile(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"scripts/run.sh", "x.py", "noext"} {
		if isMarkdownFile(p) {
			t.Fatalf("isMarkdownFile(%q) = true, want false", p)
		}
	}
}
