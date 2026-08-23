// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package filescan detects invisible-Unicode and bidi-control characters
// embedded in files. This is the product surface for the supply-chain injection
// vector where an attacker plants hidden instructions in agent-context files
// (CLAUDE.md, .cursorrules, AGENTS.md, skill definitions) using zero-width or
// bidi-override characters that a human reviewer cannot see - the technique used
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
	"unicode"
	"unicode/utf8"
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
	// whitespace controls \t \n \r) - pipelock strips these in DLP paths too.
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
	Findings []Finding `json:"findings"`
	Skipped  []Skip    `json:"skipped"`
	// Refused are declared agent-context paths whose content could not be
	// inspected. They are separate from Skipped because a skip is advisory,
	// while an uninspected context file is a coverage failure: the scanner
	// cannot say anything about the one class of file this command exists to
	// check, so reporting clean would be a false statement rather than a
	// tradeoff.
	Refused      []Skip `json:"refused,omitempty"`
	FilesScanned int    `json:"files_scanned"`
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
	// ExtraContextFiles are additional base names treated as agent context, in
	// addition to the built-in set. The built-in list is a FALLBACK and not the
	// definition of what gets scanned: every readable text file is scanned
	// whatever it is called, so a newly named context file written in ordinary
	// UTF-8 is still inspected. This list only decides whose UNINSPECTABLE
	// content is a refusal rather than an advisory skip, which is why it can stay
	// short without becoming a coverage gate that rots.
	ExtraContextFiles []string
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
	// High: zero-width splitters and bidi controls - the core injection set.
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
// are outside the suspect table - pipelock strips them in DLP paths and they have
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
// other rune (including \t and \r) advances the column by one - column counts
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
	switch classifyContent(data) {
	case classUTF16:
		return "", "UTF-16 text (this scanner reads UTF-8)", nil
	case classBinary:
		return "", "binary content", nil
	case classText:
	}
	return string(data), "", nil
}

// Byte-classification thresholds. A NUL byte alone used to mean "binary, do not
// scan", which let one appended NUL suppress scanning of an otherwise ordinary
// text file. Classification now asks whether the content is text that happens to
// contain a NUL, which is scannable, or genuinely binary, which is not.
const (
	// maxSparseNULs and maxNULFraction bound how much NUL a file may contain and
	// still count as text. Either bound satisfies it, so a short file with one or
	// two stray NULs passes without needing a fraction, and a long file is judged
	// on proportion.
	maxSparseNULs   = 2
	maxNULFraction  = 0.05
	minPrintablePct = 0.95

	// utf16SampleBytes bounds the BOM-less UTF-16 probe; a document's encoding is
	// decided by its opening bytes, not by reading all of it.
	utf16SampleBytes = 4096
	// minUTF16NULs is the smallest number of parity-aligned NULs worth treating
	// as UTF-16 rather than as noise. It is a floor for tiny samples only; the
	// ratio below is what actually decides.
	minUTF16NULs = 2
	// minUTF16NULFraction is the share of sampled bytes that must be NUL. UTF-16
	// in the ASCII range carries one NUL per code unit, so almost exactly half the
	// bytes, and this sits just below that.
	//
	// A quarter was tried first and was still too weak: an eight-byte sample with
	// two NULs is 25% NUL, so the very fixture this bound exists to reject slipped
	// through. The lesson is that a ratio over a short sample is barely different
	// from a count, so the bound has to sit near the real value rather than at some
	// comfortable distance below it.
	minUTF16NULFraction = 0.4
)

// contentClass is how the scanner classified a file's bytes.
type contentClass int

const (
	// classText is scannable as text, including text carrying a stray NUL.
	classText contentClass = iota
	// classUTF16 is text in an encoding this scanner does not decode.
	classUTF16
	// classBinary is not text at all.
	classBinary
)

// classifyContent decides whether bytes are scannable text, undecodable UTF-16,
// or binary. UTF-16 is tested BEFORE UTF-8 because ASCII UTF-16LE such as
// "A\x00B\x00" is also valid UTF-8, so a UTF-8 check alone would accept it and a
// NUL-count check alone would reject ordinary text.
//
// A NUL's position is deliberately not special beyond the UTF-16 parity probe.
// Treating a trailing NUL differently would mean moving one byte changed the
// verdict, which is a bypass rather than a heuristic.
func classifyContent(b []byte) contentClass {
	if len(b) == 0 {
		return classText
	}
	if looksUTF16(b) {
		return classUTF16
	}
	nulCount := 0
	for _, c := range b {
		if c == 0 {
			nulCount++
		}
	}
	if nulCount > maxSparseNULs && float64(nulCount)/float64(len(b)) > maxNULFraction {
		return classBinary
	}
	if !utf8.Valid(b) {
		return classBinary
	}
	if printableFraction(b) < minPrintablePct {
		return classBinary
	}
	return classText
}

// looksUTF16 reports whether bytes look like UTF-16, by BOM or by NUL bytes
// landing consistently on one parity within a bounded opening sample. Real
// UTF-16 ASCII alternates value and NUL, so the NULs share a parity; binary data
// and NUL-bearing UTF-8 do not.
func looksUTF16(b []byte) bool {
	if len(b) >= 2 {
		if (b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF) {
			return true
		}
	}
	sample := b
	if len(sample) > utf16SampleBytes {
		sample = sample[:utf16SampleBytes]
	}
	if len(sample) < 4 || len(sample)%2 != 0 {
		return false
	}
	var even, odd int
	for i, c := range sample {
		if c != 0 {
			continue
		}
		if i%2 == 0 {
			even++
		} else {
			odd++
		}
	}
	total := even + odd
	if total < minUTF16NULs {
		return false
	}
	// All the NULs sit on one parity: the alternating shape of UTF-16 ASCII.
	if even != 0 && odd != 0 {
		return false
	}
	// Parity alone is far too weak. Two NULs that happen to share a parity occur
	// readily in ordinary UTF-8 prose, and treating that as UTF-16 refused text
	// this classifier explicitly keeps scannable: it contradicted maxSparseNULs
	// directly, since a file carrying exactly the tolerated number of NULs could
	// be rejected before the tolerance was ever consulted.
	//
	// UTF-16 in this range is about half NUL bytes, one per ASCII code unit, so
	// require a real share of the sample rather than a count. UTF-16 that is
	// mostly non-ASCII carries few NULs and is not recognised here; it still fails
	// the UTF-8 validity check in classifyContent and is skipped as binary, so it
	// stays uninspectable either way and only the reported reason differs.
	return float64(total) >= float64(len(sample))*minUTF16NULFraction
}

// printableFraction is the share of decoded runes that are text-like: printable,
// ordinary whitespace, a NUL, or one of the characters this scanner hunts.
//
// That last clause is load-bearing and was missing at first, which inverted the
// whole control. Zero-width and bidi characters are Unicode format characters, so
// unicode.IsPrint reports false for them. Counting them against text-ness meant a
// file containing a planted zero-width space looked less like text, and a small
// file containing one looked like binary and was refused. The scanner would have
// declined to inspect precisely the files carrying the evidence it exists to find.
//
// NUL counts as acceptable because the bounds in classifyContent have already
// judged how much of it there is; counting it twice would reject the sparse-NUL
// text this classification exists to keep scanning.
func printableFraction(b []byte) float64 {
	var total, ok int
	for _, r := range string(b) {
		total++
		switch {
		case r == 0:
			ok++
		case r == '\n' || r == '\r' || r == '\t':
			ok++
		case unicode.IsPrint(r):
			ok++
		default:
			// A character this scanner classifies as suspect is evidence, not a
			// sign the file is binary.
			if _, suspect := suspects[r]; suspect {
				ok++
			}
		}
	}
	if total == 0 {
		return 1
	}
	return float64(ok) / float64(total)
}

// defaultContextFiles are the base names this project documents as agent context.
// Being on this list does not decide whether a file is scanned; it decides that
// failing to inspect one is a refusal rather than a skip.
var defaultContextFiles = map[string]struct{}{
	"CLAUDE.md":      {},
	"AGENTS.md":      {},
	"GEMINI.md":      {},
	"SKILL.md":       {},
	".cursorrules":   {},
	".clinerules":    {},
	".windsurfrules": {},
}

// isContextFile reports whether a path's base name is treated as agent context.
// Matching is on the base name so a context file anywhere in the tree counts,
// and it is case-insensitive because these names are written inconsistently in
// the wild and a case difference is not a reason to downgrade a refusal.
func isContextFile(path string, extra []string) bool {
	base := filepath.Base(path)
	for name := range defaultContextFiles {
		if strings.EqualFold(base, name) {
			return true
		}
	}
	for _, name := range extra {
		if strings.EqualFold(base, name) {
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
	// record routes an uninspected path. A declared agent-context file becomes a
	// refusal, because the scanner cannot report on the one file class this
	// command exists to check. Everything else stays an advisory skip, so an
	// ordinary binary asset in a tree does not fail a scan.
	record := func(p, reason string) {
		entry := Skip{Path: p, Reason: reason}
		if isContextFile(p, opts.ExtraContextFiles) {
			res.Refused = append(res.Refused, entry)
			return
		}
		res.Skipped = append(res.Skipped, entry)
	}

	scanOne := func(p string) {
		findings, scanned, reason, err := ScanFile(p, opts.MaxFileBytes)
		if err != nil {
			record(p, "read error: "+err.Error())
			return
		}
		if !scanned {
			record(p, reason)
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
				// Through record, not straight to Skipped: a stat or permission
				// error on a context file leaves its content just as unknown as
				// binary or UTF-16 content does, and appending here bypassed the
				// refusal decision so the scan exited 0.
				//
				// WalkDir supplies no entry alongside an error, so the base name
				// was the only signal and a DIRECTORY named CLAUDE.md was reported
				// as a refused context file. Ask the filesystem first: refusal is
				// for content that should have been readable text, and a directory
				// has none. When the stat also fails the type is genuinely unknown,
				// and then the base name is all there is, so refusing stays as the
				// fail-closed answer.
				if info, statErr := os.Lstat(p); statErr == nil && info.IsDir() {
					res.Skipped = append(res.Skipped, Skip{
						Path:   p,
						Reason: "directory not traversable: " + err.Error(),
					})
					return nil
				}
				record(p, "walk error: "+err.Error())
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
	for _, rf := range r.Refused {
		_, _ = fmt.Fprintf(w, "REFUSED %s: %s (agent-context file, content unknown)\n", rf.Path, rf.Reason)
	}
	for _, sk := range r.Skipped {
		_, _ = fmt.Fprintf(w, "skipped %s: %s\n", sk.Path, sk.Reason)
	}
	if len(r.Refused) > 0 {
		_, _ = fmt.Fprintf(w, "scanned %d file(s), %d skipped, %d refused, %d finding(s)\n",
			r.FilesScanned, len(r.Skipped), len(r.Refused), len(r.Findings))
	} else {
		_, _ = fmt.Fprintf(w, "scanned %d file(s), %d skipped, %d finding(s)\n",
			r.FilesScanned, len(r.Skipped), len(r.Findings))
	}
	_ = w.Flush()
}

// ErrFindings is returned by callers (e.g. the CLI) to signal that findings were
// detected, distinct from an operational error.
var ErrFindings = errors.New("invisible-character findings detected")
