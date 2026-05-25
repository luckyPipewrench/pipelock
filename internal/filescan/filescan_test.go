package filescan

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// zw builds a string containing the given codepoint. Test inputs are assembled
// from codepoints rather than literal invisible characters so this source file
// stays pure ASCII — reviewable, and not flagged by the very scanner it tests.
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

func TestLooksBinary(t *testing.T) {
	if !looksBinary([]byte{'a', 0, 'b'}) {
		t.Error("NUL byte should be binary")
	}
	if looksBinary([]byte("plain text")) {
		t.Error("plain text should not be binary")
	}
}

func TestScanFile(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.md")
	mustWrite(t, clean, "no hidden chars\n")
	planted := filepath.Join(dir, "planted.md")
	mustWrite(t, planted, "inject"+zw(0x200B)+"ed")
	binary := filepath.Join(dir, "bin.dat")
	if err := os.WriteFile(binary, []byte{'a', 0, ' '}, 0o600); err != nil {
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
		if err := os.Chmod(sub, 0o000); err != nil {
			t.Fatal(err)
		}
		// dir needs the exec bit restored so TempDir's RemoveAll can clean up.
		t.Cleanup(func() { _ = os.Chmod(sub, 0o750) }) //nolint:gosec // test cleanup, dir requires exec bit
		res, err := ScanPaths([]string{dir}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		var saw bool
		for _, sk := range res.Skipped {
			if strings.Contains(sk.Reason, "walk error") {
				saw = true
			}
		}
		if !saw {
			t.Errorf("unreadable subdir not reported as walk-error skip: %+v", res.Skipped)
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
