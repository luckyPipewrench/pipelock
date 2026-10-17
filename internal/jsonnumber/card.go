// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonnumber

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

// NumberBoundary marks a typed scalar join in the card-only view. It is not
// forwarded content. A comma remains the ordinary view's number barrier;
// this marker lets the separate candidate pass recover only typed joins.
const NumberBoundary = ",\x1f,"

// Mixed boundaries retain which side came from a string. NumberBoundary is
// reserved for two numeric pieces in extractor-produced views.
const (
	NumberStringBoundary = ",\x1fs,"
	StringNumberBoundary = ",\x1fn,"
	StringBoundary       = ",\x1ft,"
)

var boundarySeparator = regexp.MustCompile(`,\x1f([sntu]?),`)

// CardRun retains the provenance of a candidate as well as its digits.
// NumberOnly requires at least two pieces, all JSON number integer components.
type CardRun struct {
	Digits         string
	SpaceCandidate string // complete pieces joined by one ASCII space, or an exact WINDOW hit
	NumberOnly     bool
}

// ShippedCardPattern is the canonical generic card rule. Config and the
// structured redactor share it; the scanner applies the configured luhn rule.
const ShippedCardPattern = `\b\d{4}(?:[- ]?\d){11,15}\b`

var shippedCardRule = regexp.MustCompile(ShippedCardPattern)

// Enforces applies UNION to a validated candidate: either a complete-piece
// rule match or a shipped-rule WINDOW hit. Number-only runs stay informational.
func (run CardRun) Enforces(pattern *regexp.Regexp) bool {
	if run.NumberOnly {
		return false
	}
	loc := pattern.FindStringIndex(run.SpaceCandidate)
	return loc != nil && loc[0] == 0 && loc[1] == len(run.SpaceCandidate)
}

// EnforcesShippedRule shares the scanner's default criterion with consumers
// that cannot import the scanner, such as the structured redactor.
func (run CardRun) EnforcesShippedRule() bool { return run.Enforces(shippedCardRule) }

type cardPiece struct {
	digits    string
	spelling  string // string piece as written when it contains rule separators
	number    bool
	untrusted bool
}

// stringCardPiece accepts a whole string value made of digit groups joined by
// single separators from the shipped rule's [- ] class. Any other character
// leaves the value outside every typed run, as before.
func stringCardPiece(value string) (cardPiece, bool) {
	if !groupedDigits.MatchString(value) {
		return cardPiece{}, false
	}
	digits := strings.NewReplacer(" ", "", "-", "").Replace(value)
	if digits == value {
		return cardPiece{digits: digits}, true
	}
	return cardPiece{digits: digits, spelling: value}, true
}

var groupedDigits = regexp.MustCompile(`^[0-9]+(?:[- ][0-9]+)*$`)

// EscapeCardBoundaries retains scans of input markers without granting type
// provenance. The u marker retains untrusted spelling without granting
// synthetic-piece classification to input control bytes.
func EscapeCardBoundaries(text string) string {
	return strings.NewReplacer("\x1fn,", "\x1fu,", "\x1fs,", "\x1fu,", "\x1ft,", "\x1fu,", "\x1f,", "\x1fu,").Replace(text)
}

// CardBoundary encodes the types at a join in an extractor-produced view.
func CardBoundary(leftNumber, rightNumber bool) string {
	if leftNumber && rightNumber {
		return NumberBoundary
	}
	if leftNumber {
		return NumberStringBoundary
	}
	if rightNumber {
		return StringNumberBoundary
	}
	return StringBoundary
}

// These are the existing validateLuhn length bounds. Run enumeration uses
// them only to cap work; the configured regex and validator decide findings.
const (
	cardRunMinDigits = 15
	cardRunMaxDigits = 19
)

// ValidCardNumber applies the card issuer ranges and Luhn checksum used by
// the scanner's luhn validator. The JSON run pass and redactor share it.
func ValidCardNumber(s string) bool {
	var digits [cardRunMaxDigits]byte
	n := 0
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			continue
		}
		if n >= len(digits) {
			return false
		}
		digits[n] = s[i] - '0'
		n++
	}
	if n < cardRunMinDigits || !ValidCardIssuer(digits[:n], n) {
		return false
	}
	sum := 0
	for i := n - 1; i >= 0; i-- {
		d := int(digits[i])
		if (n-i)%2 == 0 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// ValidCardIssuer checks the established card network prefixes and lengths.
func ValidCardIssuer(digits []byte, n int) bool {
	// Every issuer length below is at least cardRunMinDigits, so shorter
	// input is never a card; the guard also keeps the prefix reads in bounds.
	if n < cardRunMinDigits || len(digits) < cardRunMinDigits {
		return false
	}
	prefix4 := int(digits[0])*1000 + int(digits[1])*100 + int(digits[2])*10 + int(digits[3])
	prefix6 := prefix4*100 + int(digits[4])*10 + int(digits[5])
	switch digits[0] {
	case 4:
		return n == 16 || n == 19
	case 5:
		return digits[1] >= 1 && digits[1] <= 5 && n == 16
	case 3:
		if digits[1] == 4 || digits[1] == 7 {
			return n == 15
		}
		return prefix4 >= 3528 && prefix4 <= 3589 && n >= 16 && n <= 19
	case 6:
		if prefix4 == 6011 || (prefix4 >= 6440 && prefix4 <= 6499) ||
			(prefix6 >= 622126 && prefix6 <= 622925) || digits[1] == 5 {
			return n == 16 || n == 19
		}
	case 2:
		return prefix4 >= 2221 && prefix4 <= 2720 && n == 16
	}
	return false
}

func appendCardSubruns(runs []CardRun, pieces []cardPiece) []CardRun {
	for start, first := range pieces {
		var candidate strings.Builder
		var spaced strings.Builder
		numberOnly := true
		untrusted := false
		for end := start; end < len(pieces); end++ {
			candidate.WriteString(pieces[end].digits)
			if end > start {
				spaced.WriteByte(' ')
			}
			if pieces[end].spelling != "" {
				spaced.WriteString(pieces[end].spelling)
			} else {
				spaced.WriteString(pieces[end].digits)
			}
			numberOnly = numberOnly && pieces[end].number
			untrusted = untrusted || pieces[end].untrusted
			size := candidate.Len()
			if size > cardRunMaxDigits {
				break
			}
			if (end > start || first.number) && size >= cardRunMinDigits {
				if value := candidate.String(); ValidCardNumber(value) {
					spaceCandidate := spaced.String()
					if untrusted {
						spaceCandidate = value
					}
					runs = append(runs, CardRun{Digits: value, SpaceCandidate: spaceCandidate, NumberOnly: numberOnly && end > start && !untrusted})
				}
			}
		}
	}
	return runs
}

// appendCardWindows applies the shipped rule's ordinary greedy FindAll to the
// typed scalar sequence. Keep literal string context and separators: compacting
// them would invent matches outside that rule. Only hits crossing a typed join
// belong here; whole-leaf matching remains the caller's ordinary scan.
func appendCardWindows(runs []CardRun, pieces []cardPiece) []CardRun {
	if len(pieces) < 2 {
		return runs
	}
	var joined strings.Builder
	type span struct {
		start, end int
		number     bool
	}
	spans := make([]span, 0, len(pieces))
	for i, piece := range pieces {
		if i > 0 {
			joined.WriteByte(' ')
		}
		start := joined.Len()
		if piece.spelling != "" {
			joined.WriteString(piece.spelling)
		} else {
			joined.WriteString(piece.digits)
		}
		spans = append(spans, span{start, joined.Len(), piece.number})
	}
	text := joined.String()
	seen := make(map[CardRun]struct{}, len(runs))
	for _, run := range runs {
		seen[run] = struct{}{}
	}
	next := 0
	for _, loc := range shippedCardRule.FindAllStringIndex(text, -1) {
		candidate := text[loc[0]:loc[1]]
		if !ValidCardNumber(candidate) {
			continue
		}
		for next < len(spans) && spans[next].end <= loc[0] {
			next++
		}
		count, stringHit := 0, false
		for i := next; i < len(spans) && spans[i].start < loc[1]; i++ {
			if spans[i].end > loc[0] {
				count++
				stringHit = stringHit || !spans[i].number
			}
		}
		if count > 1 {
			digits := strings.NewReplacer(" ", "", "-", "").Replace(candidate)
			run := CardRun{Digits: digits, SpaceCandidate: candidate, NumberOnly: !stringHit}
			if _, exists := seen[run]; !exists {
				seen[run] = struct{}{}
				runs = append(runs, run)
			}
		}
	}
	return runs
}

// BoundaryCardRuns returns runs made by joining typed scalar atoms. A run
// needs a typed boundary, so ordinary comma-separated prose is not promoted.
func BoundaryCardRuns(view string) []CardRun {
	boundaries := boundarySeparator.FindAllStringSubmatch(view, -1)
	if len(boundaries) == 0 {
		return nil
	}
	parts := boundarySeparator.Split(view, -1)
	var runs []CardRun
	var pieces []cardPiece
	var windows []cardPiece
	flush := func() {
		if len(pieces) > 1 {
			runs = appendCardSubruns(runs, pieces)
		}
		pieces = nil
	}
	for i, part := range parts {
		number := true
		if i > 0 && (boundaries[i-1][1] == "s" || boundaries[i-1][1] == "t") {
			number = false
		}
		if i < len(boundaries) && (boundaries[i][1] == "n" || boundaries[i][1] == "t") {
			number = false
		}
		untrusted := i > 0 && boundaries[i-1][1] == "u" || i < len(boundaries) && boundaries[i][1] == "u"
		// Only numeric atoms carry IntegralView's trailing comma mask. A string
		// prefix, suffix, sign or comma must not be cropped into a new piece.
		if number || untrusted {
			part = strings.TrimRight(part, ",")
		}
		windows = append(windows, cardPiece{spelling: part, number: number && !untrusted})
		piece := cardPiece{digits: part}
		if number && !untrusted {
			if !allDigits(part) {
				flush()
				continue
			}
		} else if grouped, ok := stringCardPiece(part); ok {
			piece = grouped
		} else {
			flush()
			continue
		}
		piece.number = number && !untrusted
		piece.untrusted = untrusted
		pieces = append(pieces, piece)
	}
	flush()
	return appendCardWindows(runs, windows)
}

// CardRuns returns adjacent scalar candidates and single numeric cards.
// NumberOnly is true only for at least two numeric pieces. Object keys are
// skipped; arrays and nesting do not break a run. A non-digit scalar value
// interrupts complete-piece candidates and remains literal WINDOW context.
// Each number contributes
// only its written integer component, preserving the single-number fraction
// policy while still examining separate numbers together. Callers apply their
// existing card rule to these candidates. Invalid, over-depth or over-budget
// documents have no typed run and retain the caller's conservative raw scan.
func CardRuns(text string, maxDepth int) []CardRun {
	runs, _ := CardRunsWithLimit(text, maxDepth)
	return runs
}

// CardRunLimit identifies why a valid JSON document could not be inspected.
type CardRunLimit uint8

const (
	CardRunWithinBudget CardRunLimit = iota
	CardRunDepthLimit
	CardRunNumberLimit
)

// CardRunsWithLimit also reports a valid document whose number or nesting
// exceeds the typed inspection budget. Callers must refuse that document.
// Invalid JSON is left to the transport parser or the ordinary text scan.
func CardRunsWithLimit(text string, maxDepth int) ([]CardRun, CardRunLimit) {
	if !json.Valid([]byte(text)) {
		return nil, CardRunWithinBudget
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	type frame struct {
		object    bool
		expectKey bool
	}
	var stack []frame
	var runs []CardRun
	var pieces []cardPiece
	var windows []cardPiece
	flush := func() {
		runs = appendCardSubruns(runs, pieces)
		pieces = nil
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			flush()
			return appendCardWindows(runs, windows), CardRunWithinBudget
		}
		if err != nil {
			return nil, CardRunNumberLimit
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				stack = append(stack, frame{object: v == '{', expectKey: v == '{'})
				if len(stack) > maxDepth {
					return nil, CardRunDepthLimit
				}
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
				stack[len(stack)-1].expectKey = false
				continue
			}
			windows = append(windows, cardPiece{spelling: v})
			if piece, ok := stringCardPiece(v); ok {
				pieces = append(pieces, piece)
			} else {
				flush()
			}
		case json.Number:
			if _, ok := boundedComponents(v.String()); !ok {
				return nil, CardRunNumberLimit
			}
			integer, _, _ := strings.Cut(v.String(), ".")
			integer, _, _ = strings.Cut(integer, "e")
			integer, _, _ = strings.Cut(integer, "E")
			windows = append(windows, cardPiece{spelling: integer, number: true})
			if allDigits(integer) {
				pieces = append(pieces, cardPiece{digits: integer, number: true})
			} else {
				flush()
				// A minus sign ends adjacency, but does not exempt a single card.
				if unsigned, signed := strings.CutPrefix(integer, "-"); signed && allDigits(unsigned) {
					runs = appendCardSubruns(runs, []cardPiece{{digits: unsigned, number: true}})
				}
			}
		default:
			// Booleans and null must retain their place in the scalar sequence.
			barrier, _ := json.Marshal(v)
			windows = append(windows, cardPiece{spelling: string(barrier)})
			flush()
		}
		if len(stack) > 0 && stack[len(stack)-1].object && !stack[len(stack)-1].expectKey {
			stack[len(stack)-1].expectKey = true
		}
	}
}

// ScalarIntegerCardRuns returns the single-number card candidate of one bare
// JSON number that exceeds the typed budget. It only cuts the written
// spelling, so no exponent is evaluated and the budget is not needed; an
// oversized exponent or fraction cannot hide an integer component card.
func ScalarIntegerCardRuns(number string) []CardRun {
	integer, _, _ := strings.Cut(strings.TrimSpace(number), ".")
	integer, _, _ = strings.Cut(integer, "e")
	integer, _, _ = strings.Cut(integer, "E")
	integer = strings.TrimPrefix(integer, "-")
	if !allDigits(integer) || len(integer) > cardRunMaxDigits {
		return nil
	}
	return appendCardSubruns(nil, []cardPiece{{digits: integer, number: true}})
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// IntegralView retains the written integer component of a bounded RFC 8259
// number. Pipelock's card policy excludes fraction and exponent syntax; it
// neither evaluates exponents nor rounds numbers. Invalid or over-budget
// spellings retain their original conservative scan view.
//
// Commas preserve byte coordinates and the numeric-leaf channel's value
// separation convention (jsonrpc.ExtractNumericLeaves). Unlike whitespace,
// they survive DLP compaction, so masked numbers cannot fabricate a card by
// joining their integer components. This internal scan view is never parsed
// as JSON or forwarded; known values and other detectors use the original.
func IntegralView(n json.Number) string {
	s := n.String()
	if _, ok := boundedComponents(s); !ok {
		return s
	}
	end := strings.IndexAny(s, ".eE")
	if end < 0 {
		return s
	}
	return s[:end] + strings.Repeat(",", len(s)-end)
}

// CardView applies IntegralView only to numeric tokens in one complete JSON
// document. Strings and keys keep their original spelling; JSON-looking string
// values are never parsed recursively. Malformed or over-depth documents retain
// the original view. maxDepth comes from the consuming JSON extractor's contract.
func CardView(text string, maxDepth int) string {
	if !strings.ContainsAny(text, ".eE") || !json.Valid([]byte(text)) {
		return text
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var view []byte
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return text
		}
		switch v := tok.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				depth++
				if depth > maxDepth {
					return text
				}
			} else {
				depth--
			}
		case json.Number:
			if _, ok := boundedComponents(v.String()); !ok {
				return text
			}
			projected := IntegralView(v)
			if projected != v.String() {
				if view == nil {
					view = []byte(text)
				}
				end := int(dec.InputOffset())
				copy(view[end-len(projected):end], projected)
			}
		}
	}
	if view == nil {
		return text
	}
	return string(view)
}

// StructuredCardView applies the numeric policy only to complete JSON objects
// and arrays. Text transports retain ordinary card scanning for scalar payloads.
func StructuredCardView(text string, maxDepth int) string {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return text
	}
	return CardView(text, maxDepth)
}
