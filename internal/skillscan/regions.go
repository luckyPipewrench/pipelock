// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package skillscan

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Code-region scoping. Combination findings are only generated from executable
// context: fenced code blocks inside Markdown skill files and the full body of
// referenced script files. Prose, tables, headings, and blockquotes are never
// treated as command context, which is what keeps a Markdown table cell like
// "| CLAUDE.md |" or a blockquote "> note" from being read as a guard-file
// target or a filesystem write. Fence rules follow CommonMark fenced code
// blocks (https://spec.commonmark.org/0.31.2/#fenced-code-blocks) closely
// enough for this purpose, with no Markdown dependency.

type regionKind string

const (
	regionScript regionKind = "script"
	regionFence  regionKind = "code_fence"

	// maxFenceIndent is the CommonMark limit: a fence opener/closer may be
	// indented at most three spaces before it stops being a fence.
	maxFenceIndent = 3
	// minFenceLen is the CommonMark minimum run length for a fence.
	minFenceLen = 3
)

type lineSpan struct {
	n    int // 1-based line number within the file
	text string
}

// codeRegion is a contiguous run of executable lines within a single file.
type codeRegion struct {
	relPath string
	kind    regionKind
	id      string // stable identifier: "<relPath>#<startLine>"
	lines   []lineSpan
}

// codeRegionsFor returns the executable regions of a scanned file. Script files
// are a single region covering every line; Markdown files yield one region per
// fenced code block (prose between fences is excluded).
func codeRegionsFor(f fileContent) []codeRegion {
	if !isMarkdownFile(f.relPath) {
		return []codeRegion{scriptRegion(f)}
	}
	return fencedRegions(f)
}

func isMarkdownFile(relPath string) bool {
	switch strings.ToLower(filepath.Ext(relPath)) {
	case ".md", ".markdown", ".mdown", ".mkd":
		return true
	default:
		return false
	}
}

func scriptRegion(f fileContent) codeRegion {
	region := codeRegion{relPath: f.relPath, kind: regionScript, id: f.relPath + "#1"}
	for i, line := range f.lines {
		region.lines = append(region.lines, lineSpan{n: i + 1, text: line})
	}
	return region
}

func fencedRegions(f fileContent) []codeRegion {
	var (
		regions   []codeRegion
		cur       *codeRegion
		fenceChar byte
		fenceLen  int
	)
	for i, line := range f.lines {
		n := i + 1
		if cur == nil {
			if ch, ln, ok := fenceOpen(line); ok {
				fenceChar, fenceLen = ch, ln
				cur = &codeRegion{
					relPath: f.relPath,
					kind:    regionFence,
					id:      fmt.Sprintf("%s#%d", f.relPath, n),
				}
			}
			continue
		}
		if fenceClose(line, fenceChar, fenceLen) {
			if len(cur.lines) > 0 {
				regions = append(regions, *cur)
			}
			cur = nil
			continue
		}
		cur.lines = append(cur.lines, lineSpan{n: n, text: line})
	}
	// An unterminated fence runs to end of file (CommonMark behavior).
	if cur != nil && len(cur.lines) > 0 {
		regions = append(regions, *cur)
	}
	return regions
}

// fenceOpen reports whether line opens a fenced code block and, if so, the
// fence character and run length.
func fenceOpen(line string) (byte, int, bool) {
	body, ok := trimFenceIndent(line)
	if !ok {
		return 0, 0, false
	}
	ch, run, rest := leadingFenceRun(body)
	if run < minFenceLen {
		return 0, 0, false
	}
	// A backtick info string may not itself contain a backtick (CommonMark);
	// a line like "``` and `inline`" is therefore not a fence opener.
	if ch == '`' && strings.ContainsRune(rest, '`') {
		return 0, 0, false
	}
	return ch, run, true
}

// fenceClose reports whether line closes a fence opened with openCh/openLen: a
// run of at least openLen of the same character, followed only by whitespace.
func fenceClose(line string, openCh byte, openLen int) bool {
	body, ok := trimFenceIndent(line)
	if !ok {
		return false
	}
	ch, run, rest := leadingFenceRun(body)
	if ch != openCh || run < openLen {
		return false
	}
	return strings.TrimSpace(rest) == ""
}

// trimFenceIndent strips up to maxFenceIndent leading spaces. A line indented
// four or more spaces is an indented code block boundary, not a fence.
func trimFenceIndent(line string) (string, bool) {
	indent := 0
	for indent < len(line) && line[indent] == ' ' {
		indent++
	}
	if indent > maxFenceIndent {
		return "", false
	}
	return line[indent:], true
}

func leadingFenceRun(body string) (byte, int, string) {
	if body == "" || (body[0] != '`' && body[0] != '~') {
		return 0, 0, body
	}
	ch := body[0]
	run := 0
	for run < len(body) && body[run] == ch {
		run++
	}
	return ch, run, body[run:]
}
