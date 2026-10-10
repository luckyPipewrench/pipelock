// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Detector is the receipt detector: the recorder's own text DLP function.
// Production passes a quiet scanner method so repeated views do not repeat
// warn telemetry.
type Detector func(ctx context.Context, text string) scanner.TextDLPResult

// View names the scan view or projection step that produced a finding.
type View string

const (
	// ViewAtom scans every decoded atom (value or member name) alone, through
	// all of the detector's encoded views.
	ViewAtom View = "atom"
	// ViewValues scans all value atoms joined in projection order, so a token
	// split across adjacent values is reassembled.
	ViewValues View = "values_join"
	// ViewFragments scans ordered 2..4-part subsequences of the atoms, so a
	// token split across non-adjacent fields is reassembled.
	ViewFragments View = "fragments"
	// ViewStructured scans the content-only JSON, preserving the field
	// context that structured detector rules depend on.
	ViewStructured View = "structured"
	// ViewBudget means a projection or reconstruction bound was exceeded.
	ViewBudget View = "budget"
	// ViewMalformed means the detail could not be projected.
	ViewMalformed View = "malformed"
)

// maxFragmentWorkBytes bounds the total bytes the fragment view would build
// across every combination. It is checked before any combination is built.
const maxFragmentWorkBytes = 4 << 20

// ErrRejected is the errors.Is target for every content rejection. A content
// rejection is deterministic for its input and distinct from storage failure:
// it must not poison a stream, and a later clean receipt still succeeds.
var ErrRejected = errors.New("receipt content rejected")

// RejectionError reports why content was refused. It names the view, the
// JSON path, and the detector pattern, never the matched value.
type RejectionError struct {
	Kind     string
	View     View
	Path     string
	Pattern  string
	Identity bool
	Reason   string
}

func (e *RejectionError) Error() string {
	var b strings.Builder
	b.WriteString(ErrRejected.Error())
	if e.Kind != "" {
		_, _ = fmt.Fprintf(&b, ": kind %s", e.Kind)
	}
	_, _ = fmt.Fprintf(&b, ": %s view", e.View)
	if e.Path != "" {
		_, _ = fmt.Fprintf(&b, ": field %q", e.Path)
	}
	if e.Identity {
		b.WriteString(" (identity field, never redacted)")
	}
	if e.Pattern != "" {
		_, _ = fmt.Fprintf(&b, ": matched %s", e.Pattern)
	}
	if e.Reason != "" {
		_, _ = fmt.Fprintf(&b, ": %s", e.Reason)
	}
	return b.String()
}

// Is makes every RejectionError match ErrRejected.
func (e *RejectionError) Is(target error) bool { return target == ErrRejected }

// Finding is one detector hit. Atom findings name one path; joint findings
// name every participating path. Paths are concrete and may contain caller
// member names, so they are for redaction only; Fields are schema paths and
// are what errors report.
type Finding struct {
	View     View
	Paths    []string
	Fields   []string
	Pattern  string
	Identity bool
	Key      bool
}

// Report is the result of Scan. When any atom finding exists the joint views
// were not run: the producer must redact or reject first, then rescan.
type Report struct {
	kind     string
	Findings []Finding
}

// Clean reports whether no view matched.
func (r Report) Clean() bool { return len(r.Findings) == 0 }

// Redactable reports whether every finding is a non-identity value atom, so
// a producer may replace those values before signing and rescan.
func (r Report) Redactable() bool {
	if len(r.Findings) == 0 {
		return false
	}
	for _, f := range r.Findings {
		if f.View != ViewAtom || f.Identity || f.Key {
			return false
		}
	}
	return true
}

// Err returns the first finding as a *RejectionError, or nil when clean.
func (r Report) Err() error {
	if len(r.Findings) == 0 {
		return nil
	}
	f := r.Findings[0]
	return &RejectionError{Kind: r.kind, View: f.View, Path: strings.Join(f.Fields, ","), Pattern: f.Pattern, Identity: f.Identity}
}

func firstPattern(res scanner.TextDLPResult) string {
	if len(res.Matches) > 0 {
		return res.Matches[0].PatternName
	}
	return "detector"
}

// Scan runs the union of views over p. It returns a *RejectionError only for
// a budget refusal; detector hits are returned in the Report.
func Scan(ctx context.Context, det Detector, p *Projection) (Report, error) {
	rep := Report{kind: p.kind}
	if det == nil {
		return rep, errors.New("receiptcontent: scan requires a detector")
	}

	// (i) Every atom alone. Distinct texts are scanned once.
	verdict := make(map[string]string, len(p.atoms))
	for _, a := range p.atoms {
		pattern, seen := verdict[a.Text]
		if !seen {
			if res := det(ctx, a.Text); !res.Clean {
				pattern = firstPattern(res)
			}
			verdict[a.Text] = pattern
		}
		if pattern != "" {
			rep.Findings = append(rep.Findings, Finding{View: ViewAtom, Paths: []string{a.Path}, Fields: []string{a.Field}, Pattern: pattern, Identity: a.Identity, Key: a.Kind == AtomKey})
		}
	}
	if len(rep.Findings) > 0 {
		return rep, nil
	}

	// (iv) The structured content projection, for context-dependent rules.
	if res := det(ctx, string(p.structured)); !res.Clean {
		rep.Findings = append(rep.Findings, Finding{View: ViewStructured, Pattern: firstPattern(res)})
		return rep, nil
	}

	// (ii) Values only, in projection order, joined without a separator.
	var values strings.Builder
	var valuePaths, valueFields []string
	for _, a := range p.atoms {
		if a.Kind == AtomValue {
			values.WriteString(a.Text)
			valuePaths = append(valuePaths, a.Path)
			valueFields = append(valueFields, a.Field)
		}
	}
	if values.Len() > 0 {
		if res := det(ctx, values.String()); !res.Clean {
			rep.Findings = append(rep.Findings, Finding{View: ViewValues, Paths: valuePaths, Fields: valueFields, Pattern: firstPattern(res)})
			return rep, nil
		}
	}

	// (iii) Bounded fragment-aware reconstruction.
	f, err := scanFragments(ctx, det, p)
	if err != nil {
		return rep, err
	}
	if f != nil {
		rep.Findings = append(rep.Findings, *f)
	}
	return rep, nil
}

// scanFragments reuses the scanner's ordered-subsequence combination order.
// Client-influenced atoms combine freely. A fixed value or derived mirror can
// carry no client fragment, so it joins a combination only as the single
// bridge piece (see bridgeFragments), and repeated fixed text counts once.
// A projection with at most scanner.SubsequenceMaxParts candidates is searched at sizes
// 2..scanner.SubsequenceMaxSize, the same sizes the request path combines,
// and is refused before any candidate is built when that work exceeds
// maxFragmentWorkBytes. A taint list plus a shield summary already has more
// parts than that cap. Refusing the receipt for width drops ordinary evidence.
// The wide path runs the largest complete search in
// {3, 2} whose byte total and candidate count stay inside the limits of the
// 20-part search, and refuses before building a candidate when even the pairs
// do not fit. It never scans a prefix of a larger combination set. Joins of
// 4 stay inside the 20-part receipt.
func scanFragments(ctx context.Context, det Detector, p *Projection) (*Finding, error) {
	var parts, paths, fields []string
	var positions []int
	var bridges []fragmentPiece
	bridged := make(map[string]struct{})
	// Equal fragments at different positions are distinct candidates. A token
	// can need the same bytes twice, so deduplication would lose its shape.
	// A fixed value is public text, so repeating it adds nothing: it joins the
	// bridge set once, at its first position.
	for i, a := range p.atoms {
		if a.Fixed {
			if _, dup := bridged[a.Text]; !dup {
				bridged[a.Text] = struct{}{}
				bridges = append(bridges, fragmentPiece{text: a.Text, path: a.Path, field: a.Field, pos: i})
			}
			continue
		}
		parts = append(parts, a.Text)
		paths = append(paths, a.Path)
		fields = append(fields, a.Field)
		positions = append(positions, i)
	}
	n := len(parts)
	maxSize := scanner.SubsequenceMaxSize
	if n <= scanner.SubsequenceMaxParts {
		if work := fragmentWorkBytes(parts); work > maxFragmentWorkBytes {
			return nil, &RejectionError{Kind: p.kind, View: ViewBudget, Reason: fmt.Sprintf("reconstruction work %d bytes exceeds %d", work, maxFragmentWorkBytes)}
		}
	} else {
		size, ok := widestFragmentSearch(parts)
		if !ok {
			return nil, &RejectionError{Kind: p.kind, View: ViewBudget, Reason: fmt.Sprintf("%d content atoms exceed the reconstruction work bound", n)}
		}
		maxSize = size
	}
	if n >= 2 {
		if f := combineFragments(ctx, det, parts, paths, fields, maxSize); f != nil {
			return f, nil
		}
	}
	if n == 0 || len(bridges) == 0 {
		return nil, nil
	}
	cands := make([]fragmentPiece, len(parts))
	for i := range cands {
		cands[i] = fragmentPiece{text: parts[i], path: paths[i], field: fields[i], pos: positions[i]}
	}
	return bridgeFragments(ctx, det, p.kind, cands, bridges, maxSize)
}

// fragmentPiece is one fixed value standing in a bridged combination. pos is
// its place in projection order, which the 4-part forward and reverse orders
// are defined over.
type fragmentPiece struct {
	text, path, field string
	pos               int
}

// bridgeFragments completes the search over combinations that hold exactly one
// fixed value. A fixed value cannot carry a client fragment, but the text a
// detector matches may contain one: a credential with "local" inside it, split
// as the client text before and after, reassembles only through the receipt's
// own "local". Combinations of fixed values alone, or with two or more of
// them, are not searched; they hold no client text or need a secret that
// contains two separate constants. The search size is the one the client-only
// search used, lowered to the widest that fits the same limits. It is never a
// prefix of a larger combination set, and a receipt whose pairs do not fit is
// refused, which the client-only search would also have done.
func bridgeFragments(ctx context.Context, det Detector, kind string, cands, bridges []fragmentPiece, maxSize int) (*Finding, error) {
	size := widestBridgedSearch(cands, bridges, maxSize)
	if size < 2 {
		return nil, &RejectionError{Kind: kind, View: ViewBudget, Reason: fmt.Sprintf("%d content atoms and %d fixed values exceed the reconstruction work bound", len(cands), len(bridges))}
	}
	var b strings.Builder
	seen := make(map[string]struct{})
	piece := make([]fragmentPiece, 0, size)
	for k := 2; k <= size && k-1 <= len(cands); k++ {
		idx := make([]int, k-1)
		for i := range idx {
			idx[i] = i
		}
		for {
			for _, br := range bridges {
				piece = piece[:0]
				for _, i := range idx {
					piece = append(piece, cands[i])
				}
				piece = append(piece, br)
				sort.SliceStable(piece, func(i, j int) bool { return piece[i].pos < piece[j].pos })
				for _, order := range fragmentOrders[k] {
					b.Reset()
					for _, o := range order {
						b.WriteString(piece[o].text)
					}
					text := b.String()
					if _, ok := seen[text]; ok {
						continue
					}
					seen[text] = struct{}{}
					if res := det(ctx, text); !res.Clean {
						hit, hitFields := make([]string, 0, k), make([]string, 0, k)
						for _, o := range order {
							hit = append(hit, piece[o].path)
							hitFields = append(hitFields, piece[o].field)
						}
						return &Finding{View: ViewFragments, Paths: hit, Fields: hitFields, Pattern: firstPattern(res)}, nil
					}
				}
			}
			if !scanner.NextSubsequence(idx, len(cands)) {
				break
			}
		}
	}
	return nil, nil
}

// widestBridgedSearch returns the largest size in maxSize..2 whose bridged
// combinations fit the byte budget and the candidate count of a full 20-part
// search, or 0 when even pairs do not fit.
func widestBridgedSearch(cands, bridges []fragmentPiece, maxSize int) int {
	limit, ok := combinationCandidates(scanner.SubsequenceMaxParts, scanner.SubsequenceMaxSize)
	if !ok || limit <= 0 {
		return 0
	}
	for size := maxSize; size >= 2; size-- {
		if size-1 > len(cands) {
			continue
		}
		work, wok := bridgedWork(cands, bridges, size)
		calls, cok := bridgedCandidates(len(cands), len(bridges), size)
		if wok && cok && work <= maxFragmentWorkBytes && calls <= limit {
			return size
		}
	}
	return 0
}

// bridgedCandidates is the number of detector calls a bridged search of sizes
// 2..maxSize makes: each combination of k-1 candidates takes each fixed value
// in every tried order of k pieces. The bool is false on overflow.
func bridgedCandidates(c, f, maxSize int) (int64, bool) {
	var total int64
	for k := 2; k <= maxSize && k-1 <= c; k++ {
		ways, ok := binomial64(c, k-1)
		if !ok {
			return 0, false
		}
		prod, ok := mul64(ways, int64(f))
		if !ok {
			return 0, false
		}
		prod, ok = mul64(prod, int64(len(fragmentOrders[k])))
		if !ok {
			return 0, false
		}
		if total > math.MaxInt64-prod {
			return 0, false
		}
		total += prod
	}
	return total, true
}

// bridgedWork is the total length of every text the bridged search builds.
// Each candidate lies in C(c-1, k-2) combinations of k-1 candidates, and each
// fixed value in C(c, k-1), every one of them taken with each of the other
// side and in every tried order. The bool is false on overflow.
func bridgedWork(cands, bridges []fragmentPiece, maxSize int) (int64, bool) {
	c, f := len(cands), len(bridges)
	var total int64
	add := func(plen, ways, mult int64) bool {
		prod, ok := mul64(plen, ways)
		if !ok {
			return false
		}
		if prod, ok = mul64(prod, mult); !ok {
			return false
		}
		if total > math.MaxInt64-prod {
			return false
		}
		total += prod
		return true
	}
	for k := 2; k <= maxSize && k-1 <= c; k++ {
		orders := int64(len(fragmentOrders[k]))
		candWays, ok := binomial64(c-1, k-2)
		if !ok {
			return 0, false
		}
		bridgeWays, ok := binomial64(c, k-1)
		if !ok {
			return 0, false
		}
		for _, part := range cands {
			mult, ok := mul64(int64(f), orders)
			if !ok || !add(int64(len(part.text)), candWays, mult) {
				return 0, false
			}
		}
		for _, br := range bridges {
			if !add(int64(len(br.text)), bridgeWays, orders) {
				return 0, false
			}
		}
	}
	return total, true
}

// combineFragments scans every combination of size 2..maxSize. Every order of
// 2 and 3 fragments is tried, and both directions of 4. Projection order is
// fixed by the schema's sorted keys, so a caller choosing which field holds
// which fragment controls the order.
func combineFragments(ctx context.Context, det Detector, parts, paths, fields []string, maxSize int) *Finding {
	n := len(parts)
	var b strings.Builder
	// Repeated occurrences retain their combination positions, but equal
	// candidate texts need only one detector call in this immutable scan.
	seen := make(map[string]struct{})
	for size := 2; size <= maxSize && size <= n; size++ {
		idx := make([]int, size)
		for i := range idx {
			idx[i] = i
		}
		for {
			for _, order := range fragmentOrders[size] {
				b.Reset()
				for _, o := range order {
					b.WriteString(parts[idx[o]])
				}
				text := b.String()
				if _, ok := seen[text]; ok {
					continue
				}
				seen[text] = struct{}{}
				if res := det(ctx, text); !res.Clean {
					hit, hitFields := make([]string, 0, size), make([]string, 0, size)
					for _, o := range order {
						hit = append(hit, paths[idx[o]])
						hitFields = append(hitFields, fields[idx[o]])
					}
					return &Finding{View: ViewFragments, Paths: hit, Fields: hitFields, Pattern: firstPattern(res)}
				}
			}
			if !scanner.NextSubsequence(idx, n) {
				break
			}
		}
	}
	return nil
}

// widestFragmentSearch returns the largest size in {3, 2} whose complete
// search fits the byte budget and the candidate count of a full 20-part
// search. Size 4 is not a wide-path size. ok is false when even pairs do not
// fit, which the caller refuses before building a candidate.
func widestFragmentSearch(parts []string) (int, bool) {
	limit, ok := combinationCandidates(scanner.SubsequenceMaxParts, scanner.SubsequenceMaxSize)
	if !ok || limit <= 0 {
		return 0, false
	}
	n := len(parts)
	for size := 3; size >= 2; size-- {
		if size > n {
			continue
		}
		work, wok := combinationWork(parts, size)
		cands, cok := combinationCandidates(n, size)
		if wok && cok && work <= maxFragmentWorkBytes && cands <= limit {
			return size, true
		}
	}
	return 0, false
}

// fragmentOrders lists the fragment orders tried for each combination size.
var fragmentOrders = map[int][][]int{
	2: {{0, 1}, {1, 0}},
	3: {{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}},
	4: {{0, 1, 2, 3}, {3, 2, 1, 0}},
}

// fragmentWorkBytes is the total length of every candidate a full size-2..4
// search would build. Each part appears in C(n-1, k-1) combinations of size
// k, once per tried order. Overflow is reported as the maximum int64 so the
// caller treats it as over budget.
func fragmentWorkBytes(parts []string) int64 {
	total, ok := combinationWork(parts, scanner.SubsequenceMaxSize)
	if !ok {
		return math.MaxInt64
	}
	return total
}

// combinationWork is fragmentWorkBytes limited to sizes 2..maxSize. The bool
// is false when the total does not fit in int64.
func combinationWork(parts []string, maxSize int) (int64, bool) {
	n := len(parts)
	var total int64
	for _, part := range parts {
		plen := int64(len(part))
		if plen == 0 {
			continue
		}
		for k := 2; k <= maxSize && k <= n; k++ {
			ways, ok := binomial64(n-1, k-1)
			if !ok {
				return 0, false
			}
			orders := int64(len(fragmentOrders[k]))
			prod, ok := mul64(plen, ways)
			if !ok {
				return 0, false
			}
			prod, ok = mul64(prod, orders)
			if !ok {
				return 0, false
			}
			if total > math.MaxInt64-prod {
				return 0, false
			}
			total += prod
		}
	}
	return total, true
}

// combinationCandidates is the number of detector calls a complete search of
// sizes 2..maxSize makes. The bool is false when the count does not fit in
// int64.
func combinationCandidates(n, maxSize int) (int64, bool) {
	var total int64
	for k := 2; k <= maxSize && k <= n; k++ {
		ways, ok := binomial64(n, k)
		if !ok {
			return 0, false
		}
		prod, ok := mul64(ways, int64(len(fragmentOrders[k])))
		if !ok {
			return 0, false
		}
		if total > math.MaxInt64-prod {
			return 0, false
		}
		total += prod
	}
	return total, true
}

func mul64(a, b int64) (int64, bool) {
	if a < 0 || b < 0 {
		return 0, false
	}
	if a != 0 && b > math.MaxInt64/a {
		return 0, false
	}
	return a * b, true
}

func binomial(n, k int) int {
	v, ok := binomial64(n, k)
	if !ok || v > math.MaxInt {
		return math.MaxInt
	}
	return int(v)
}

func binomial64(n, k int) (int64, bool) {
	if k < 0 || k > n {
		return 0, true
	}
	if k > n-k {
		k = n - k
	}
	var r int64 = 1
	for i := 1; i <= k; i++ {
		num := int64(n - k + i)
		prod, ok := mul64(r, num)
		if !ok {
			return 0, false
		}
		r = prod / int64(i)
	}
	return r, true
}
