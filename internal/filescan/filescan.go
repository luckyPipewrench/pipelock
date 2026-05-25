// Package filescan detects invisible-Unicode and bidi-control characters
// embedded in files. This is the product surface for the supply-chain injection
// vector where an attacker plants hidden instructions in agent-context files
// (CLAUDE.md, .cursorrules, AGENTS.md, skill definitions) using zero-width or
// bidi-override characters that a human reviewer cannot see — the technique used
// by campaigns such as TrapDoor.
//
// Detection is seeded from normalize.InvisibleRanges (the set pipelock strips in
// its scanning paths) but is NOT a flat reuse of it: stripping in network
// traffic and gating on files at rest are different decisions. File gating
// produces developer-facing failures, so each flagged rune carries a severity by
// class and context (a leading BOM or an emoji ZWJ is far less alarming than a
// right-to-left override inside an instruction file). Detection is free-tier.
package filescan

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Category classifies an invisible-character finding by attack relevance.
type Category string

const (
	// CategoryBidi covers directional embedding/override/isolate controls used
	// to reorder displayed text so the rendered line differs from byte order.
	CategoryBidi Category = "bidi-control"
	// CategoryTag covers the Unicode Tags block, which can smuggle a hidden
	// ASCII payload that renders as nothing.
	CategoryTag Category = "tag-char"
	// CategoryZeroWidth covers zero-width and other non-rendering characters.
	CategoryZeroWidth Category = "zero-width"
	// CategoryControl covers C0/C1/DEL control characters (excluding the
	// whitespace controls \t \n \r) — pipelock strips these in DLP paths too.
	CategoryControl Category = "control-char"
)

// Severity ranks how alarming a finding is for repo gating. Not every invisible
// character is equally suspicious in a file: a leading BOM is routine, an RLO
// inside an instruction file is an attack.
type Severity string

const (
	SeverityHigh Severity = "high"
	SeverityMed  Severity = "medium"
	SeverityLow  Severity = "low"
)

// Finding is one invisible/control character located in a scanned file.
type Finding struct {
	Path      string   `json:"path"`
	Line      int      `json:"line"`
	Col       int      `json:"col"` // 1-based rune column within the line
	CodePoint string   `json:"code_point"`
	Name      string   `json:"name"`
	Category  Category `json:"category"`
	Severity  Severity `json:"severity"`
}

// Skip records a file that was not scanned, with the reason, so the operator can
// see exactly what went uninspected rather than only a count.
type Skip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Result aggregates a scan over one or more paths.
type Result struct {
	Findings     []Finding `json:"findings"`
	Skipped      []Skip    `json:"skipped"`
	FilesScanned int       `json:"files_scanned"`
}

// Options tune a path scan. The zero value scans every readable text file under
// the given paths, skipping common dependency/VCS directories.
type Options struct {
	// MaxFileBytes skips files larger than this (0 = default 5 MiB). Oversized
	// files are reported as skips so a padded agent-context file cannot silently
	// evade scanning.
	MaxFileBytes int64
	// ExtraExcludeDirs are directory names skipped in addition to the defaults.
	ExtraExcludeDirs []string
	// IncludeDepDirs scans dependency/VCS dirs that are skipped by default
	// (node_modules, vendor, .git, ...). Off by default for speed; on when a
	// supply-chain audit must cover vendored context files.
	IncludeDepDirs bool
}

const defaultMaxFileBytes = 5 << 20 // 5 MiB

// defaultExcludeDirs are large/noisy and rarely injectable agent context.
var defaultExcludeDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, "vendor": {}, "dist": {},
	".venv": {}, "__pycache__": {}, ".cache": {},
}

// suspectRune holds the policy for one flagged code point.
type suspectRune struct {
	name string
	cat  Category
	sev  Severity
}

// suspects is the file-scan policy table. Seeded from normalize.InvisibleRanges
// plus deceptive characters that set omits (U+061C, U+180E, U+034F, U+2800), with
// a severity assigned per class. Built once at init from rune ranges.
var suspects = buildSuspects()

func buildSuspects() map[rune]suspectRune {
	m := map[rune]suspectRune{}
	put := func(lo, hi rune, name string, cat Category, sev Severity) {
		for r := lo; r <= hi; r++ {
			m[r] = suspectRune{name: name, cat: cat, sev: sev}
		}
	}
	// High: zero-width splitters and bidi controls — the core injection set.
	put(0x200B, 0x200B, "ZERO WIDTH SPACE", CategoryZeroWidth, SeverityHigh)
	put(0x200C, 0x200C, "ZERO WIDTH NON-JOINER", CategoryZeroWidth, SeverityLow) // legit in Persian/Arabic
	put(0x200D, 0x200D, "ZERO WIDTH JOINER", CategoryZeroWidth, SeverityLow)     // legit in emoji
	put(0x200E, 0x200F, "DIRECTIONAL MARK", CategoryBidi, SeverityMed)           // legit in bilingual text
	put(0x202A, 0x202E, "BIDI EMBEDDING/OVERRIDE", CategoryBidi, SeverityHigh)
	put(0x2066, 0x2069, "BIDI ISOLATE", CategoryBidi, SeverityHigh)
	put(0x2060, 0x2060, "WORD JOINER", CategoryZeroWidth, SeverityHigh)
	put(0x2061, 0x2064, "INVISIBLE OPERATOR", CategoryZeroWidth, SeverityMed)
	put(0xFEFF, 0xFEFF, "ZERO WIDTH NO-BREAK SPACE (BOM)", CategoryZeroWidth, SeverityMed)
	put(0x00AD, 0x00AD, "SOFT HYPHEN", CategoryZeroWidth, SeverityLow) // legit in prose
	put(0x061C, 0x061C, "ARABIC LETTER MARK", CategoryBidi, SeverityMed)
	put(0x034F, 0x034F, "COMBINING GRAPHEME JOINER", CategoryZeroWidth, SeverityLow)
	put(0x180E, 0x180E, "MONGOLIAN VOWEL SEPARATOR", CategoryZeroWidth, SeverityMed)
	put(0x2800, 0x2800, "BRAILLE PATTERN BLANK", CategoryZeroWidth, SeverityLow)
	put(0x115F, 0x1160, "HANGUL FILLER", CategoryZeroWidth, SeverityMed)
	put(0x3164, 0x3164, "HANGUL FILLER", CategoryZeroWidth, SeverityMed)
	put(0xFFF9, 0xFFFB, "INTERLINEAR ANNOTATION", CategoryZeroWidth, SeverityMed)
	put(0xFE00, 0xFE0F, "VARIATION SELECTOR", CategoryZeroWidth, SeverityLow) // legit in emoji
	put(0xE0100, 0xE01EF, "VARIATION SELECTOR SUPPLEMENT", CategoryZeroWidth, SeverityLow)
	put(0xE0000, 0xE007F, "TAG CHARACTER", CategoryTag, SeverityHigh) // can smuggle hidden ASCII
	return m
}

// classifyRune returns the policy for r, plus whether r is flagged at all.
// C0/C1/DEL controls (excluding \t \n \r) are flagged as medium even though they
// are outside the suspect table — pipelock strips them in DLP paths and they have
// no business in agent-context files.
func classifyRune(r rune) (suspectRune, bool) {
	if s, ok := suspects[r]; ok {
		return s, true
	}
	if isControl(r) {
		return suspectRune{name: "CONTROL CHARACTER", cat: CategoryControl, sev: SeverityMed}, true
	}
	return suspectRune{}, false
}

func isControl(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	return r <= 0x1F || r == 0x7F || (r >= 0x80 && r <= 0x9F)
}

// ScanText finds suspect characters in content, attributing each to a line and
// rune column. A newline (\n) advances the line and resets the column; every
// other rune (including \t and \r) advances the column by one — column counts
// are byte-accurate for locating the injection. A BOM (U+FEFF) at the very start
// of a file is routine and downgraded to low severity.
func ScanText(path, content string) []Finding {
	var out []Finding
	line, col := 1, 0
	first := true
	for _, r := range content {
		if r == '\n' {
			line++
			col = 0
			first = false
			continue
		}
		col++
		s, flagged := classifyRune(r)
		isFirstRune := first && col == 1
		first = false
		if !flagged {
			continue
		}
		sev := s.sev
		if r == 0xFEFF && isFirstRune {
			sev = SeverityLow // leading BOM is a routine encoding artifact
		}
		out = append(out, Finding{
			Path:      path,
			Line:      line,
			Col:       col,
			CodePoint: fmt.Sprintf("U+%04X", r),
			Name:      s.name,
			Category:  s.cat,
			Severity:  sev,
		})
	}
	return out
}

// readRegularFile safely reads a regular file, bounded to maxBytes. It rejects
// symlinks, devices, FIFOs, sockets, and directories so a symlink to /dev/zero
// cannot hang the scanner or exhaust memory, and refuses anything larger than
// the cap by reading maxBytes+1 through an io.LimitReader. Returns a skip reason
// (non-empty) instead of content when the file should not be scanned as text.
func readRegularFile(path string, maxBytes int64) (content string, skipReason string, err error) {
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean) // Lstat: do NOT follow symlinks
	if err != nil {
		return "", "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", "symlink (not followed)", nil
	}
	if !info.Mode().IsRegular() {
		return "", "not a regular file", nil
	}
	if info.Size() > maxBytes {
		return "", fmt.Sprintf("exceeds %d-byte limit (size %d)", maxBytes, info.Size()), nil
	}
	f, err := os.Open(clean)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = f.Close() }()
	// Read at most maxBytes+1 so a file that grew past the cap between Lstat and
	// read (TOCTOU) is caught rather than read unbounded.
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return "", "", err
	}
	if int64(len(data)) > maxBytes {
		return "", fmt.Sprintf("exceeds %d-byte limit (grew during read)", maxBytes), nil
	}
	if looksBinary(data) {
		return "", "binary (NUL byte)", nil
	}
	return string(data), "", nil
}

// looksBinary reports whether b contains a NUL byte, the cheap heuristic for a
// binary file we should not scan as text. Known limitations: (1) an attacker who
// can write a NUL into an otherwise-text file suppresses scanning of that file —
// this matches git's binary heuristic and an attacker planting NULs in tracked
// text files is already past this control; (2) UTF-16 text is NUL-rich and is
// therefore skipped (reported as a skip), since pipelock's context files are
// UTF-8. Both are surfaced as skips, never silent.
func looksBinary(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

// ScanFile scans a single file. scanned is false (with no error) when the file
// was skipped; reason explains why so the caller can report it.
func ScanFile(path string, maxBytes int64) (findings []Finding, scanned bool, reason string, err error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxFileBytes
	}
	content, skipReason, err := readRegularFile(path, maxBytes)
	if err != nil {
		return nil, false, "", err
	}
	if skipReason != "" {
		return nil, false, skipReason, nil
	}
	return ScanText(path, content), true, "", nil
}

// ScanPaths walks each path (file or directory) and scans every text file,
// skipping dependency/VCS directories and binary/oversized/non-regular files. A
// read error on an individual file is recorded as a skip with its reason, so one
// unreadable file cannot abort a directory scan.
func ScanPaths(paths []string, opts Options) (Result, error) {
	excl := map[string]struct{}{}
	if !opts.IncludeDepDirs {
		for d := range defaultExcludeDirs {
			excl[d] = struct{}{}
		}
	}
	for _, d := range opts.ExtraExcludeDirs {
		excl[d] = struct{}{}
	}

	var res Result
	scanOne := func(p string) {
		findings, scanned, reason, err := ScanFile(p, opts.MaxFileBytes)
		if err != nil {
			res.Skipped = append(res.Skipped, Skip{Path: p, Reason: "read error: " + err.Error()})
			return
		}
		if !scanned {
			res.Skipped = append(res.Skipped, Skip{Path: p, Reason: reason})
			return
		}
		res.FilesScanned++
		res.Findings = append(res.Findings, findings...)
	}

	for _, root := range paths {
		info, err := os.Lstat(root)
		if err != nil {
			return res, fmt.Errorf("stat %s: %w", root, err)
		}
		if !info.IsDir() {
			scanOne(root)
			continue
		}
		walkErr := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				res.Skipped = append(res.Skipped, Skip{Path: p, Reason: "walk error: " + err.Error()})
				return nil
			}
			if d.IsDir() {
				if _, skip := excl[d.Name()]; skip {
					return filepath.SkipDir
				}
				return nil
			}
			scanOne(p)
			return nil
		})
		if walkErr != nil {
			return res, fmt.Errorf("walk %s: %w", root, walkErr)
		}
	}
	return res, nil
}

// HighFindings returns only the high-severity findings, for callers that gate on
// the alarming set rather than every routine BOM or emoji ZWJ.
func (r Result) HighFindings() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == SeverityHigh {
			out = append(out, f)
		}
	}
	return out
}

// Summary renders a one-line-per-finding human report. Empty when no findings.
func (r Result) Summary() string {
	if len(r.Findings) == 0 {
		return ""
	}
	var b strings.Builder
	for _, f := range r.Findings {
		_, _ = fmt.Fprintf(&b, "%s:%d:%d  [%s] %s %s (%s)\n",
			f.Path, f.Line, f.Col, f.Severity, f.CodePoint, f.Name, f.Category)
	}
	return b.String()
}

// WriteReport writes the human report, any skips, and a tally line to w.
func (r Result) WriteReport(w *bufio.Writer) {
	if s := r.Summary(); s != "" {
		_, _ = w.WriteString(s)
	}
	for _, sk := range r.Skipped {
		_, _ = fmt.Fprintf(w, "skipped %s: %s\n", sk.Path, sk.Reason)
	}
	_, _ = fmt.Fprintf(w, "scanned %d file(s), %d skipped, %d finding(s)\n",
		r.FilesScanned, len(r.Skipped), len(r.Findings))
	_ = w.Flush()
}

// ErrFindings is returned by callers (e.g. the CLI) to signal that findings were
// detected, distinct from an operational error.
var ErrFindings = errors.New("invisible-character findings detected")
