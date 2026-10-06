// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonrpc

import (
	"encoding/binary"
	"sync"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// MaxMediaTextBytes bounds the normalized text one response may carry out of
// recognized media payloads. It equals the message limit, so a framed message
// can spend as much text as it could have carried bytes, and no more.
const MaxMediaTextBytes = transport.MaxLineSize

// mediaTextBudgetExceeded is the reason reported when media inspection could
// not finish. It is a failure to inspect, not a finding.
const mediaTextBudgetExceeded = "media text normalization budget exceeded"

// MediaTextBudget is the per-response allowance for text recovered from media
// payloads. One value is shared by every extraction over one response (result,
// error, params, structured content and the envelope pass), so splitting a
// payload across fields cannot reset it. The zero value is ready to use. It is
// not safe for concurrent use and carries no state past the response.
type MediaTextBudget struct {
	used   int
	reason string
}

// Reason returns why media inspection stopped, or "" when every payload seen so
// far was inspected in full. Callers must treat a non-empty reason as an
// incomplete scan and block; text extracted after it is partial.
func (b *MediaTextBudget) Reason() string {
	if b == nil {
		return ""
	}
	return b.reason
}

func (b *MediaTextBudget) exhaust() {
	b.reason = mediaTextBudgetExceeded
}

// mediaRuneClass says what a scalar does to a text run in a decoded media view.
type mediaRuneClass uint8

const (
	// mediaRuneBreak ends the run: no scanner stage removes it, so text on
	// either side can never match across it.
	mediaRuneBreak mediaRuneClass = iota
	// mediaRuneText is kept and counts toward the minimum run length.
	mediaRuneText
	// mediaRuneSpace is kept as one ASCII space and counts.
	mediaRuneSpace
	// mediaRuneKeep is deleted by the scanner (zero-width and format
	// characters, combining marks). It is kept so the scanner sees what it
	// would see in the clear, but does not count and does not end the run.
	mediaRuneKeep
	// mediaRuneDrop is a control the scanner deletes. It neither counts nor
	// ends the run, and is not emitted.
	mediaRuneDrop
)

// classifyMediaRune is the reference classifier; mediaBMPClasses precomputes it
// for the Basic Multilingual Plane. Everything the scanner deletes is
// transparent, because an attacker can interleave such scalars to cut an
// instruction into runs shorter than the minimum while the scanner still reads
// it whole.
func classifyMediaRune(r rune) mediaRuneClass {
	switch {
	case r >= 0xD800 && r <= 0xDFFF:
		return mediaRuneBreak
	case r == ' ' || r == '\t' || r == '\n' || r == '\r':
		return mediaRuneSpace
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
		return mediaRuneDrop
	case normalize.Whitespace(string(r)) == " ":
		return mediaRuneSpace
	case unicode.Is(normalize.InvisibleRanges, r), unicode.Is(unicode.Mn, r):
		return mediaRuneKeep
	case unicode.Is(mediaTextRanges, r):
		return mediaRuneText
	default:
		return mediaRuneBreak
	}
}

var mediaBMPClasses = sync.OnceValue(func() *[1 << 16]mediaRuneClass {
	var table [1 << 16]mediaRuneClass
	for u := range table {
		table[u] = classifyMediaRune(rune(u))
	}
	return &table
})

// mediaTextWriter builds the additive views of one decoded payload. A run is
// kept only when it holds minSmuggledTextRun counted scalars. Size is checked
// as the run grows, so a payload cannot allocate past the response budget even
// transiently.
type mediaTextWriter struct {
	budget *MediaTextBudget
	out    []byte
	run    []byte
	counts int
	// marked records that the run held a scalar a plain printable-ASCII read
	// would have broken on. A view that otherwise equals that read is a
	// duplicate and is not emitted again.
	marked         bool
	needMark       bool
	spaceUncounted bool
	failed         bool
	// scratch is controlView's joined-text buffer, reused across runs.
	scratch []byte
}

func (w *mediaTextWriter) room(n int) bool {
	// A run in a view that only emits what the plain view could not read is, so
	// far, a duplicate that will be discarded. It is bounded by the payload
	// itself, so it is checked only once it has something to emit.
	if w.needMark && !w.marked {
		return true
	}
	if w.budget.used+len(w.out)+len(w.run)+n+1 > MaxMediaTextBytes {
		w.budget.exhaust()
		w.failed = true
		return false
	}
	return true
}

func (w *mediaTextWriter) add(r rune, counted bool) {
	if w.failed || !w.room(utf8.RuneLen(r)) {
		return
	}
	w.run = utf8.AppendRune(w.run, r)
	if counted {
		w.counts++
	}
}

func (w *mediaTextWriter) end() {
	if !w.failed && w.counts >= minSmuggledTextRun && (!w.needMark || w.marked) {
		w.out = append(w.out, w.run...)
		w.out = append(w.out, '\n')
	}
	w.run = w.run[:0]
	w.counts = 0
	w.marked = false
}

func (w *mediaTextWriter) addClassified(r rune, class mediaRuneClass) {
	switch class {
	case mediaRuneText:
		w.add(r, true)
	case mediaRuneSpace:
		w.add(' ', !w.spaceUncounted)
	case mediaRuneKeep:
		w.add(r, false)
	case mediaRuneDrop:
	default:
		w.end()
	}
}

// asciiView emits runs of printable ASCII, the reading the extractor has always
// had.
func (w *mediaTextWriter) asciiView(b []byte) {
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e {
			w.add(rune(c), true)
			continue
		}
		w.end()
		if w.failed {
			return
		}
	}
	w.end()
}

// mediaBridgeContext is how much joined text controlView keeps on each side of
// a bridge, counted in units: a run of spaces is one unit, because the scanner
// collapses whitespace and padding must not push the rest of a pattern out of
// the window. It covers the widest bounded gap in the built-in patterns: the
// 240 scalar gaps in internal/config/defaults.go and the 600 scalar URL
// candidate in internal/scanner/external_transfer.go:17, the longest of them.
// The one unbounded built-in tail (the URL after "https://") matches as soon
// as its prefix is contiguous, so its length does not matter. An operator
// pattern with an unbounded gap can reach past this width across a fused
// control; that is the price of not re-emitting every run whole.
const mediaBridgeContext = 600

// mediaSpan is a half-open range of joined text.
type mediaSpan struct{ lo, hi int }

// controlView reads ASCII with the scanner's control stripping applied:
// non-whitespace C0 controls and DEL vanish, tab, CR and LF become spaces, and
// a byte at or above 0x80 ends the run rather than vanishing, so unrelated
// fragments are never joined. NUL-interleaved and control-interleaved text
// reads straight through here.
//
// Only text the plain view could not already show is emitted. A bridge is a
// stretch of control bytes between two printable segments. When it holds a line
// feed and both segments are long enough for the plain view to emit, the plain
// view's line break is the scanner's own and the bridge adds nothing. A tab or
// CR alone is not a line break to the scanner, so it is not redundant. Every
// other bridge (a vanishing control that fuses its neighbours, a tab, or a
// segment the plain view dropped for being too short) is emitted with
// mediaBridgeContext of joined text on each side. Windows that touch merge, so
// dense input costs no more than the run itself and still reaches the budget.
func (w *mediaTextWriter) controlView(b []byte) {
	start := 0
	for i := 0; i <= len(b); i++ {
		if i < len(b) && b[i] <= 0x7e {
			continue
		}
		w.controlRun(b[start:i])
		if w.failed {
			break
		}
		start = i + 1
	}
	w.scratch = nil
}

// controlRun reads one run of bytes with no byte above 0x7e.
func (w *mediaTextWriter) controlRun(run []byte) {
	joined := w.scratch[:0]
	var spans []mediaSpan
	type bridge struct {
		lo, hi  int
		newline bool
		leftLen int
	}
	var (
		cur      bridge
		haveCur  bool
		pending  bool
		segLen   int
		bridgeLo int
		bridgeWS int
		sawNL    bool
		leftLen  int
		// fwd is how many context units the last window may still take from
		// text appended after it was resolved.
		fwd int
		// unit reports whether joined[i] starts a context unit: a space run
		// counts once.
		unit = func(i int) bool { return joined[i] != ' ' || i == 0 || joined[i-1] != ' ' }
	)
	resolve := func(rightLen int) {
		if !haveCur {
			return
		}
		haveCur = false
		if cur.newline && cur.leftLen >= minSmuggledTextRun && rightLen >= minSmuggledTextRun {
			return
		}
		floor := 0
		if n := len(spans); n > 0 {
			floor = spans[n-1].hi
		}
		lo, units := cur.lo, 0
		for lo > floor && units < mediaBridgeContext {
			lo--
			if unit(lo) {
				units++
			}
		}
		hi, units := cur.hi, 0
		for hi < len(joined) && units < mediaBridgeContext {
			if unit(hi) {
				units++
			}
			hi++
		}
		fwd = mediaBridgeContext - units
		if n := len(spans); n > 0 && lo <= spans[n-1].hi {
			spans[n-1].hi = hi
			return
		}
		spans = append(spans, mediaSpan{lo: lo, hi: hi})
	}
	for _, c := range run {
		if c >= 0x20 && c <= 0x7e {
			if pending {
				for ; bridgeWS > 0; bridgeWS-- {
					joined = append(joined, ' ')
				}
				cur = bridge{lo: bridgeLo, hi: len(joined), newline: sawNL, leftLen: leftLen}
				haveCur, pending = true, false
			}
			joined = append(joined, c)
			segLen++
			if fwd > 0 && len(spans) > 0 {
				spans[len(spans)-1].hi = len(joined)
				if unit(len(joined) - 1) {
					fwd--
				}
			}
			continue
		}
		if segLen > 0 {
			resolve(segLen)
			leftLen, segLen = segLen, 0
			pending, bridgeLo, bridgeWS, sawNL = true, len(joined), 0, false
		}
		if pending && (c == '\t' || c == '\n' || c == '\r') {
			bridgeWS++
			if c == '\n' {
				sawNL = true
			}
		}
	}
	resolve(segLen)
	w.scratch = joined
	for _, s := range spans {
		for _, c := range joined[s.lo:min(s.hi, len(joined))] {
			w.add(rune(c), true)
		}
		w.end()
		if w.failed {
			return
		}
	}
}

// utf8View reads b as UTF-8. Text in the Latin-script and homoglyph ranges is
// as natural in UTF-8 as in UTF-16, and the plain views break on its non-ASCII
// bytes. A run is emitted only when it holds a non-ASCII scalar, so ASCII text
// is not repeated; invalid bytes end the run. Controls are transparent, as in
// every other view: the scanner deletes them, so text split by them is still
// text to it. Whitespace does not count toward the minimum here: bridging
// controls would otherwise let the line-break and NUL bytes of an ordinary
// container header pad its few printable letters up to a run.
func (w *mediaTextWriter) utf8View(b []byte) {
	classes := mediaBMPClasses()
	w.needMark = true
	w.spaceUncounted = true
	defer func() { w.needMark = false; w.spaceUncounted = false }()
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		i += size
		if r == utf8.RuneError && size <= 1 {
			w.end()
		} else {
			var class mediaRuneClass
			if r <= 0xFFFF {
				class = classes[r]
			} else {
				class = classifyMediaRune(r)
			}
			if r > 0x7f && (class == mediaRuneText || class == mediaRuneSpace || class == mediaRuneKeep) {
				w.marked = true
			}
			w.addClassified(r, class)
		}
		if w.failed {
			return
		}
	}
	w.end()
}

// utf16View reads b as UTF-16 starting at offset, in the given byte order. No
// byte-order mark or encoding guess is required: all four orderings and
// alignments are read. A well-formed surrogate pair decodes to one scalar; an
// unpaired surrogate ends the run; an odd trailing byte is ignored, which keeps
// every valid prefix.
func (w *mediaTextWriter) utf16View(b []byte, offset int, order binary.ByteOrder) {
	classes := mediaBMPClasses()
	for i := offset; i+1 < len(b); i += 2 {
		u := order.Uint16(b[i:])
		r := rune(u)
		if utf16.IsSurrogate(r) {
			if u < 0xDC00 && i+3 < len(b) {
				if low := order.Uint16(b[i+2:]); low >= 0xDC00 && low <= 0xDFFF {
					r = utf16.DecodeRune(r, rune(low))
					w.addClassified(r, classifyMediaRune(r))
					i += 2
					if w.failed {
						return
					}
					continue
				}
			}
			w.end()
		} else {
			w.addClassified(r, classes[u])
		}
		if w.failed {
			return
		}
	}
	w.end()
}

// normalizedMediaText returns the text readable inside a decoded media payload,
// one run per line. It inspects the whole payload, claimed header bytes
// included, in seven independent views: printable ASCII, control-stripped
// ASCII, UTF-8, and UTF-16 in both byte orders at both alignments. Every view
// is additive; no view is chosen by guessing the encoding. Empty text means
// none of the views held a run, not that the container is structurally sound.
//
// When the response budget runs out it records that on the budget and returns
// nothing: the caller must block, never scan the prefix that fit.
func normalizedMediaText(decoded []byte, budget *MediaTextBudget) string {
	if budget.reason != "" {
		return ""
	}
	w := &mediaTextWriter{budget: budget}
	w.asciiView(decoded)
	if !w.failed {
		w.controlView(decoded)
	}
	if !w.failed {
		w.utf8View(decoded)
	}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for offset := 0; offset < 2 && !w.failed; offset++ {
			w.utf16View(decoded, offset, order)
		}
	}
	if w.failed {
		return ""
	}
	budget.used += len(w.out)
	return string(w.out)
}
