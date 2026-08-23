// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package filescan

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// zw builds a string containing the given codepoint. Test inputs are assembled
// from codepoints rather than literal invisible characters so this source file
// stays pure ASCII - reviewable, and not flagged by the very scanner it tests.
func zw(r rune) string { return string(r) }

func TestScanText(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantCount int
		wantFirst string // CodePoint of first finding
		wantCat   Category
		wantSev   Severity
		wantLine  int
		wantCol   int
	}{
		{name: "clean ascii", content: "hello world\nsecond line", wantCount: 0},
		{name: "clean with tabs and cr", content: "a\tb\r\nc", wantCount: 0},
		{
			name: "zero-width space is high", content: "hel" + zw(0x200B) + "lo",
			wantCount: 1, wantFirst: "U+200B", wantCat: CategoryZeroWidth, wantSev: SeverityHigh, wantLine: 1, wantCol: 4,
		},
		{
			name: "bidi override is high", content: "abc" + zw(0x202E) + "def",
			wantCount: 1, wantFirst: "U+202E", wantCat: CategoryBidi, wantSev: SeverityHigh, wantLine: 1, wantCol: 4,
		},
		{
			name: "tag char is high", content: "x" + zw(0xE0041) + "y",
			wantCount: 1, wantFirst: "U+E0041", wantCat: CategoryTag, wantSev: SeverityHigh, wantLine: 1, wantCol: 2,
		},
		{
			name: "emoji ZWJ is low", content: "a" + zw(0x200D) + "b",
			wantCount: 1, wantFirst: "U+200D", wantCat: CategoryZeroWidth, wantSev: SeverityLow, wantLine: 1, wantCol: 2,
		},
		{
			name: "variation selector is low", content: "x" + zw(0xFE0F),
			wantCount: 1, wantFirst: "U+FE0F", wantCat: CategoryZeroWidth, wantSev: SeverityLow, wantLine: 1, wantCol: 2,
		},
		{
			name: "soft hyphen is low", content: "co" + zw(0x00AD) + "op",
			wantCount: 1, wantFirst: "U+00AD", wantCat: CategoryZeroWidth, wantSev: SeverityLow, wantLine: 1, wantCol: 3,
		},
		{
			name: "leading BOM downgraded to low", content: zw(0xFEFF) + "content",
			wantCount: 1, wantFirst: "U+FEFF", wantCat: CategoryZeroWidth, wantSev: SeverityLow, wantLine: 1, wantCol: 1,
		},
		{
			name: "non-leading BOM is medium", content: "x" + zw(0xFEFF),
			wantCount: 1, wantFirst: "U+FEFF", wantCat: CategoryZeroWidth, wantSev: SeverityMed, wantLine: 1, wantCol: 2,
		},
		{
			name: "arabic letter mark flagged (outside InvisibleRanges)", content: "a" + zw(0x061C) + "b",
			wantCount: 1, wantFirst: "U+061C", wantCat: CategoryBidi, wantSev: SeverityMed, wantLine: 1, wantCol: 2,
		},
		{
			name: "mongolian vowel sep flagged (outside InvisibleRanges)", content: "a" + zw(0x180E) + "b",
			wantCount: 1, wantFirst: "U+180E", wantCat: CategoryZeroWidth, wantSev: SeverityMed, wantLine: 1, wantCol: 2,
		},
		{
			name: "C1 control flagged", content: "a" + zw(0x0085) + "b",
			wantCount: 1, wantFirst: "U+0085", wantCat: CategoryControl, wantSev: SeverityMed, wantLine: 1, wantCol: 2,
		},
		{
			name: "position on second line", content: "line one\nli" + zw(0x200B) + "ne",
			wantCount: 1, wantFirst: "U+200B", wantCat: CategoryZeroWidth, wantSev: SeverityHigh, wantLine: 2, wantCol: 3,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ScanText("f", tc.content)
			if len(got) != tc.wantCount {
				t.Fatalf("count = %d, want %d (%+v)", len(got), tc.wantCount, got)
			}
			if tc.wantCount == 0 {
				return
			}
			f := got[0]
			if f.CodePoint != tc.wantFirst {
				t.Errorf("codepoint = %s, want %s", f.CodePoint, tc.wantFirst)
			}
			if f.Category != tc.wantCat {
				t.Errorf("category = %s, want %s", f.Category, tc.wantCat)
			}
			if f.Severity != tc.wantSev {
				t.Errorf("severity = %s, want %s", f.Severity, tc.wantSev)
			}
			if f.Line != tc.wantLine || f.Col != tc.wantCol {
				t.Errorf("pos = %d:%d, want %d:%d", f.Line, f.Col, tc.wantLine, tc.wantCol)
			}
		})
	}
}

func TestIsControl(t *testing.T) {
	for _, r := range []rune{'\t', '\n', '\r', 'a', ' '} {
		if isControl(r) {
			t.Errorf("isControl(%#U) = true, want false", r)
		}
	}
	for _, r := range []rune{0x00, 0x07, 0x1F, 0x7F, 0x85, 0x9F} {
		if !isControl(r) {
			t.Errorf("isControl(%#U) = false, want true", r)
		}
	}
}

func TestClassifyContent(t *testing.T) {
	// A NUL byte alone used to mean "binary, do not scan", so appending one to an
	// agent-context file suppressed scanning of the whole file and the scan
	// reported clean. Sparse NULs in otherwise-text content must classify as text
	// so the hidden-instruction scan still runs.
	longText := []byte(strings.Repeat("ordinary instruction text.\n", 200))
	sparseInLong := append(append([]byte{}, longText...), 0)

	// ASCII UTF-16LE is also valid UTF-8, which is why UTF-16 has to be tested
	// first and why a UTF-8 check alone cannot be the guard.
	utf16LE := []byte{'A', 0, 'B', 0, 'C', 0, 'D', 0}
	utf16WithBOM := append([]byte{0xFF, 0xFE}, utf16LE...)

	// Dense NULs spread across both parities: binary, not alternating text.
	dense := make([]byte, 400)
	for i := range dense {
		if i%3 == 0 {
			dense[i] = 0
		} else {
			dense[i] = byte(i % 251)
		}
	}

	for _, tc := range []struct {
		name string
		in   []byte
		want contentClass
	}{
		{name: "empty", in: nil, want: classText},
		{name: "plain_text", in: []byte("plain text\n"), want: classText},
		{name: "one_nul_short", in: []byte{'a', 0, 'b'}, want: classText},
		{name: "two_nuls_short", in: []byte{'a', 0, 'b', 0, 'c', 'd', 'e'}, want: classText},
		{name: "trailing_nul_long_text", in: sparseInLong, want: classText},
		{name: "leading_nul_long_text", in: append([]byte{0}, longText...), want: classText},
		{name: "utf16le_no_bom", in: utf16LE, want: classUTF16},
		{name: "utf16_with_bom", in: utf16WithBOM, want: classUTF16},
		{name: "dense_nuls_binary", in: dense, want: classBinary},
		{name: "invalid_utf8", in: []byte{0xC3, 0x28, 0xC3, 0x28, 0xC3, 0x28}, want: classBinary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyContent(tc.in); got != tc.want {
				t.Fatalf("classifyContent = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestClassifyContentNULPositionDoesNotMatter pins the property that makes this
// a classification rather than a heuristic an attacker can steer: moving a NUL
// within otherwise-text content must not change the verdict.
func TestClassifyContentNULPositionDoesNotMatter(t *testing.T) {
	base := []byte(strings.Repeat("instruction text line.\n", 40))
	for _, pos := range []int{0, 1, len(base) / 3, len(base) / 2, len(base) - 1} {
		withNUL := append([]byte{}, base...)
		withNUL[pos] = 0
		if got := classifyContent(withNUL); got != classText {
			t.Fatalf("NUL at offset %d classified %v, want classText", pos, got)
		}
	}
}

func TestScanFile(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.md")
	mustWrite(t, clean, "no hidden chars\n")
	planted := filepath.Join(dir, "planted.md")
	mustWrite(t, planted, "inject"+zw(0x200B)+"ed")
	binary := filepath.Join(dir, "bin.dat")
	if err := os.WriteFile(binary, binaryFixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.txt")
	mustWrite(t, big, "0123456789")

	t.Run("clean file scanned", func(t *testing.T) {
		f, scanned, reason, err := ScanFile(clean, 0)
		if err != nil || !scanned || reason != "" || len(f) != 0 {
			t.Fatalf("findings=%d scanned=%v reason=%q err=%v", len(f), scanned, reason, err)
		}
	})
	t.Run("planted file flagged", func(t *testing.T) {
		f, scanned, _, err := ScanFile(planted, 0)
		if err != nil || !scanned || len(f) != 1 {
			t.Fatalf("findings=%d scanned=%v err=%v", len(f), scanned, err)
		}
	})
	t.Run("binary skipped with reason", func(t *testing.T) {
		_, scanned, reason, err := ScanFile(binary, 0)
		if err != nil || scanned || !strings.Contains(reason, "binary") {
			t.Fatalf("scanned=%v reason=%q err=%v", scanned, reason, err)
		}
	})
	t.Run("oversized skipped with reason", func(t *testing.T) {
		_, scanned, reason, err := ScanFile(big, 1)
		if err != nil || scanned || !strings.Contains(reason, "limit") {
			t.Fatalf("scanned=%v reason=%q err=%v", scanned, reason, err)
		}
	})
	t.Run("missing file errors", func(t *testing.T) {
		if _, _, _, err := ScanFile(filepath.Join(dir, "nope.md"), 0); err == nil {
			t.Fatal("expected error for missing file")
		}
	})
	t.Run("symlink not followed", func(t *testing.T) {
		link := filepath.Join(dir, "link.md")
		if err := os.Symlink("/dev/zero", link); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		_, scanned, reason, err := ScanFile(link, 0)
		if err != nil || scanned || !strings.Contains(reason, "symlink") {
			t.Fatalf("symlink to /dev/zero must be skipped unread: scanned=%v reason=%q err=%v", scanned, reason, err)
		}
	})
	t.Run("device is not regular", func(t *testing.T) {
		if _, err := os.Stat("/dev/null"); err != nil {
			t.Skip("/dev/null unavailable")
		}
		_, scanned, reason, err := ScanFile("/dev/null", 0)
		if err != nil || scanned || !strings.Contains(reason, "regular") {
			t.Fatalf("device must be skipped: scanned=%v reason=%q err=%v", scanned, reason, err)
		}
	})
}

func TestScanPaths(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "CLAUDE.md"), "trust"+zw(0x200B)+"me")
	mustWrite(t, filepath.Join(dir, "ok.txt"), "all good")
	if err := os.WriteFile(filepath.Join(dir, "blob.bin"), []byte{0, 1, 2}, 0o600); err != nil {
		t.Fatal(err)
	}
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o750); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(gitDir, "config"), "hidden"+zw(0x202E)+"here")
	skipDir := filepath.Join(dir, "testdata")
	if err := os.MkdirAll(skipDir, 0o750); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(skipDir, "fixture.md"), "fix"+zw(0x200B)+"ture")

	t.Run("directory walk respects excludes and reports skips", func(t *testing.T) {
		res, err := ScanPaths([]string{dir}, Options{ExtraExcludeDirs: []string{"testdata"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("findings = %d, want 1 (only CLAUDE.md); got %+v", len(res.Findings), res.Findings)
		}
		if len(res.Skipped) == 0 {
			t.Error("expected the binary blob to be reported as a skip with a reason")
		}
		var sawBinSkip bool
		for _, sk := range res.Skipped {
			if strings.Contains(sk.Path, "blob.bin") && sk.Reason != "" {
				sawBinSkip = true
			}
		}
		if !sawBinSkip {
			t.Errorf("binary skip not reported with path+reason: %+v", res.Skipped)
		}
	})

	t.Run("include-deps scans .git", func(t *testing.T) {
		res, err := ScanPaths([]string{dir}, Options{IncludeDepDirs: true, ExtraExcludeDirs: []string{"testdata"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) < 2 {
			t.Errorf("expected CLAUDE.md + .git/config findings with include-deps, got %d", len(res.Findings))
		}
	})

	t.Run("single file arg", func(t *testing.T) {
		res, err := ScanPaths([]string{filepath.Join(dir, "CLAUDE.md")}, Options{})
		if err != nil || len(res.Findings) != 1 || res.FilesScanned != 1 {
			t.Fatalf("findings=%d scanned=%d err=%v", len(res.Findings), res.FilesScanned, err)
		}
	})

	t.Run("missing root errors", func(t *testing.T) {
		if _, err := ScanPaths([]string{filepath.Join(dir, "ghost")}, Options{}); err == nil {
			t.Fatal("expected error for missing root")
		}
	})
}

func TestScanPaths_ReadErrors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses permission denial")
	}
	t.Run("unreadable file reported as read-error skip", func(t *testing.T) {
		dir := t.TempDir()
		bad := filepath.Join(dir, "locked.md")
		mustWrite(t, bad, "data")
		if err := os.Chmod(bad, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(bad, 0o600) })
		res, err := ScanPaths([]string{dir}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		var saw bool
		for _, sk := range res.Skipped {
			if strings.Contains(sk.Path, "locked.md") && strings.Contains(sk.Reason, "read error") {
				saw = true
			}
		}
		if !saw {
			t.Errorf("unreadable file not reported as read-error skip: %+v", res.Skipped)
		}
	})
	t.Run("unreadable subdir reported as walk-error skip", func(t *testing.T) {
		dir := t.TempDir()
		sub := filepath.Join(dir, "locked")
		if err := os.MkdirAll(sub, 0o750); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(sub, "x.md"), "data")
		blockDirAccess(t, sub)
		res, err := ScanPaths([]string{dir}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		// Assert on the PATH, not on the wording. A directory reports "directory
		// not traversable" rather than the generic walk-error text now, and a test
		// pinned to prose fails on a message change while proving nothing about
		// whether the directory was reported at all.
		var saw bool
		for _, sk := range res.Skipped {
			if sk.Path == sub {
				saw = true
			}
		}
		if !saw {
			t.Errorf("unreadable subdir not reported as a skip: %+v", res.Skipped)
		}
		for _, r := range res.Refused {
			if r.Path == sub {
				t.Errorf("a directory was refused as an uninspectable context file: %+v", r)
			}
		}
	})
}

func TestHighFindings(t *testing.T) {
	// mix: ZWSP (high) + soft hyphen (low)
	res := Result{Findings: ScanText("f", "a"+zw(0x200B)+"b"+zw(0x00AD)+"c")}
	if len(res.Findings) != 2 {
		t.Fatalf("setup: want 2 findings, got %d", len(res.Findings))
	}
	high := res.HighFindings()
	if len(high) != 1 || high[0].Severity != SeverityHigh {
		t.Errorf("HighFindings = %+v, want exactly the ZWSP", high)
	}
}

func TestResultReporting(t *testing.T) {
	t.Run("empty summary", func(t *testing.T) {
		if s := (Result{}).Summary(); s != "" {
			t.Errorf("empty summary = %q, want empty", s)
		}
	})
	t.Run("summary lists findings with severity", func(t *testing.T) {
		res := Result{Findings: ScanText("x.md", "a"+zw(0x200B)+"b"), FilesScanned: 1}
		s := res.Summary()
		if !strings.Contains(s, "U+200B") || !strings.Contains(s, "x.md:1:2") || !strings.Contains(s, "high") {
			t.Errorf("summary missing detail: %q", s)
		}
	})
	t.Run("write report includes skips and tally", func(t *testing.T) {
		var sb strings.Builder
		w := bufio.NewWriter(&sb)
		res := Result{
			Findings:     ScanText("y.md", "z"+zw(0x200B)+"z"),
			Skipped:      []Skip{{Path: "big.md", Reason: "exceeds limit"}},
			FilesScanned: 2,
		}
		res.WriteReport(w)
		out := sb.String()
		if !strings.Contains(out, "scanned 2 file(s)") || !strings.Contains(out, "skipped big.md: exceeds limit") {
			t.Errorf("report missing skip/tally: %q", out)
		}
	})
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// binaryFixture returns bytes that are genuinely binary rather than text
// containing a stray NUL. The old fixtures used "a\x00b", which was only
// "binary" under the previous rule that any NUL meant binary; that input is now
// correctly classified as scannable text, so testing the skip policy needs
// content that is actually not text.
func binaryFixture() []byte {
	out := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	for i := range 256 {
		if i%3 == 0 {
			out = append(out, 0)
			continue
		}
		out = append(out, byte(128+(i%127)))
	}
	return out
}

// TestScanPaths_RefusesUninspectableContextFile is the regression for the
// original bypass and for the fallback that closes its padded variant.
//
// The bypass: one NUL appended to an AGENTS.md routed the file to a skip before
// the scan ran, and because a directory scan accepts skips the command exited 0.
// Classification now scans that file, so the planted characters are found.
//
// The fallback: an attacker can answer that by padding the file until it really
// is binary, or writing it as UTF-16. Those cannot be scanned, so a declared
// context path becomes a refusal instead of a skip.
func TestScanPaths_RefusesUninspectableContextFile(t *testing.T) {
	zeroWidth := "x\u200By"

	for _, tc := range []struct {
		name        string
		file        string
		content     []byte
		wantScanned int
		wantFinding bool
		wantRefused bool
		wantSkipped bool
	}{
		{
			name:        "context_file_with_stray_nul_is_scanned",
			file:        "AGENTS.md",
			content:     append([]byte(zeroWidth), 0),
			wantScanned: 1,
			wantFinding: true,
		},
		{
			name:        "context_file_padded_to_binary_is_refused",
			file:        "CLAUDE.md",
			content:     append([]byte(zeroWidth), binaryFixture()...),
			wantRefused: true,
		},
		{
			name:        "context_file_in_utf16_is_refused",
			file:        "SKILL.md",
			content:     []byte{'A', 0, 'B', 0, 'C', 0, 'D', 0},
			wantRefused: true,
		},
		{
			name:        "ordinary_binary_asset_is_only_skipped",
			file:        "logo.png",
			content:     binaryFixture(),
			wantSkipped: true,
		},
		{
			name:        "non_context_utf16_is_only_skipped",
			file:        "strings.dat",
			content:     []byte{'A', 0, 'B', 0, 'C', 0, 'D', 0},
			wantSkipped: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), tc.content, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			res, err := ScanPaths([]string{dir}, Options{})
			if err != nil {
				t.Fatalf("ScanPaths: %v", err)
			}
			if res.FilesScanned != tc.wantScanned {
				t.Fatalf("FilesScanned = %d, want %d", res.FilesScanned, tc.wantScanned)
			}
			if got := len(res.Findings) > 0; got != tc.wantFinding {
				t.Fatalf("findings present = %v, want %v (%+v)", got, tc.wantFinding, res.Findings)
			}
			if got := len(res.Refused) > 0; got != tc.wantRefused {
				t.Fatalf("refused = %v, want %v (%+v)", got, tc.wantRefused, res.Refused)
			}
			if got := len(res.Skipped) > 0; got != tc.wantSkipped {
				t.Fatalf("skipped = %v, want %v (%+v)", got, tc.wantSkipped, res.Skipped)
			}
		})
	}
}

// TestScanPaths_ContextMatchIsCaseInsensitiveAndExtensible pins the two properties
// the list needs to be usable: these names are written inconsistently in the
// wild, and an operator must be able to add one without waiting for a release.
func TestScanPaths_ContextMatchIsCaseInsensitiveAndExtensible(t *testing.T) {
	for _, tc := range []struct {
		name  string
		file  string
		extra []string
		want  bool
	}{
		{name: "exact", file: "AGENTS.md", want: true},
		{name: "lowercase", file: "agents.md", want: true},
		{name: "mixed_case", file: "Claude.MD", want: true},
		{name: "unknown_name", file: "house-rules.md", want: false},
		{name: "unknown_name_declared", file: "house-rules.md", extra: []string{"house-rules.md"}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), binaryFixture(), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			res, err := ScanPaths([]string{dir}, Options{ExtraContextFiles: tc.extra})
			if err != nil {
				t.Fatalf("ScanPaths: %v", err)
			}
			if got := len(res.Refused) > 0; got != tc.want {
				t.Fatalf("refused = %v, want %v for %q", got, tc.want, tc.file)
			}
		})
	}
}

// TestScanPaths_UnreadableContextFileIsRefused covers the operator case behind the
// walk-error routing: a context file the scanner cannot read. Its content is just
// as unknown as binary content, so it must be refused rather than reported as an
// advisory skip that a directory scan accepts.
//
// Note on scope, so a later reader does not over-read this test. Permission
// failures on a FILE surface through the read path rather than the directory walk,
// because lstat still succeeds. Routing the walk callback through the same refusal
// decision is defensive: a walk error that names a context file needs a filesystem
// race or error this test cannot provoke deterministically, and leaving that branch
// appending straight to skips would have been the one inconsistent path.
func TestScanPaths_UnreadableContextFileIsRefused(t *testing.T) {
	// Windows does not enforce a Unix read-denial from chmod(0o000), so the
	// unreadable state this test depends on cannot be created there.
	if runtime.GOOS == "windows" {
		t.Skip("chmod read-denial is not enforced on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file, so the failure cannot be provoked")
	}
	root := t.TempDir()
	path := filepath.Join(root, "AGENTS.md")
	if err := os.WriteFile(path, []byte("ordinary guidance\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	res, err := ScanPaths([]string{root}, Options{})
	if err != nil {
		t.Fatalf("ScanPaths: %v", err)
	}
	if len(res.Refused) != 1 {
		t.Fatalf("refused = %+v, want the unreadable context file; skipped = %+v",
			res.Refused, res.Skipped)
	}
	if len(res.Skipped) != 0 {
		t.Fatalf("skipped = %+v, want the unreadable context file refused instead", res.Skipped)
	}
}

// TestClassifyContent_SparseNULsAreNotUTF16 pins the two NUL rules against each
// other. maxSparseNULs keeps a file with a couple of NULs scannable, and the
// UTF-16 probe used to override that: it needed only two parity-aligned NULs, a
// shape ordinary prose produces by chance, so a file carrying exactly the
// tolerated number of NULs was refused before the tolerance was consulted.
//
// The direction is what makes this worth a test. The scanner refused a file it
// could have read, which on a context file means a real finding inside it is
// reported as unknown content instead of being found.
func TestClassifyContent_SparseNULsAreNotUTF16(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content []byte
	}{
		{name: "two NULs both on even offsets", content: []byte{'a', 'b', 0, 'c', 'd', 'e', 0, 'f'}},
		{name: "two NULs both on odd offsets", content: []byte{'a', 0, 'b', 'c', 'd', 0, 'e', 'f'}},
		{
			name:    "a NUL in longer prose",
			content: []byte("read the instructions in this file\x00 and then continue as normal.."),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyContent(tc.content); got != classText {
				t.Fatalf("classifyContent = %v, want classText; a readable context file is refused", got)
			}
		})
	}
}

// TestLooksUTF16_StillDetectsRealUTF16 is the other direction of the same change.
// Tightening the NUL requirement must not stop recognising the encoding, or the
// scanner would try to read UTF-16 as UTF-8 and report noise.
func TestLooksUTF16_StillDetectsRealUTF16(t *testing.T) {
	// UTF-16LE "hello world", no BOM: one NUL per ASCII code unit.
	var noBOM []byte
	for _, c := range []byte("hello world") {
		noBOM = append(noBOM, c, 0)
	}
	if !looksUTF16(noBOM) {
		t.Fatalf("BOM-less UTF-16LE ASCII no longer detected")
	}
	if got := classifyContent(noBOM); got != classUTF16 {
		t.Fatalf("classifyContent = %v, want classUTF16", got)
	}

	for _, bom := range [][]byte{{0xFF, 0xFE}, {0xFE, 0xFF}} {
		withBOM := append(append([]byte{}, bom...), noBOM...)
		if !looksUTF16(withBOM) {
			t.Fatalf("UTF-16 with BOM %x no longer detected", bom)
		}
	}
}

// TestScanPaths_UnreadableDirectoryIsNotARefusedContextFile covers the walk-error
// path, where WalkDir supplies no entry and the base name was the only signal. A
// DIRECTORY named CLAUDE.md was reported as a refused context FILE, so an exit
// code meaning "an agent-context file could not be inspected" fired for something
// that has no content to inspect.
func TestScanPaths_UnreadableDirectoryIsNotARefusedContextFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod traversal-denial is not enforced on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root traverses regardless of mode")
	}

	root := t.TempDir()
	blocked := filepath.Join(root, "CLAUDE.md")
	if err := os.Mkdir(blocked, 0o750); err != nil {
		t.Fatal(err)
	}
	blockDirAccess(t, blocked)

	res, err := ScanPaths([]string{root}, Options{})
	if err != nil {
		t.Fatalf("ScanPaths: %v", err)
	}
	for _, r := range res.Refused {
		if r.Path == blocked {
			t.Fatalf("an unreadable directory was refused as a context file: %+v", r)
		}
	}
	var found bool
	for _, sk := range res.Skipped {
		if sk.Path == blocked {
			found = true
		}
	}
	if !found {
		t.Fatalf("the unreadable directory was not reported at all; skipped=%+v refused=%+v", res.Skipped, res.Refused)
	}
}

// TestScanPaths_UnreadableContextFileStillRefusedAfterDirectoryFix guards the
// fail-closed half: narrowing the walk-error branch must not stop an actual
// unreadable context FILE from being refused.
func TestScanPaths_UnreadableContextFileStillRefusedAfterDirectoryFix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod read-denial is not enforced on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads regardless of mode")
	}

	root := t.TempDir()
	target := filepath.Join(root, "AGENTS.md")
	if err := os.WriteFile(target, []byte("be helpful"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(target, 0o600) })

	res, err := ScanPaths([]string{root}, Options{})
	if err != nil {
		t.Fatalf("ScanPaths: %v", err)
	}
	for _, r := range res.Refused {
		if r.Path == target {
			return
		}
	}
	t.Fatalf("an unreadable context file was not refused; skipped=%+v refused=%+v", res.Skipped, res.Refused)
}

// blockDirAccess makes a directory untraversable and restores the exec bit at
// cleanup, since TempDir's RemoveAll cannot descend into a 0o000 directory.
//
// The restore is the only reason a permission suppression is needed at all, so it
// lives here once rather than being repeated at every test that blocks a
// directory.
func blockDirAccess(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o750) //nolint:gosec // cleanup only: RemoveAll needs the exec bit back
	})
}
