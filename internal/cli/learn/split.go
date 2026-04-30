// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
)

// Sentinel errors returned by the split / pin operator-affordance
// commands. Tests assert via errors.Is.
var (
	// ErrRuleNotFound is returned when the requested rule_id is absent
	// from the candidate document.
	ErrRuleNotFound = errors.New("learn: rule not found in candidate")

	// ErrCollapsedSegmentNotFound is returned when --index targets a
	// segment that is not present in the rule's collapsed_segments
	// list. Returned by split only.
	ErrCollapsedSegmentNotFound = errors.New("learn: collapsed segment not found")

	// ErrInvalidCandidate is returned when the candidate file cannot be
	// read or parsed as YAML, or has no rules to mutate.
	ErrInvalidCandidate = errors.New("learn: invalid candidate file")

	// ErrEmptySegment is returned when --segment is empty after
	// trimming. Cobra's MarkFlagRequired only catches "flag missing",
	// not "flag value is empty string", so we enforce non-empty
	// explicitly.
	ErrEmptySegment = errors.New("learn: pin segment must be non-empty")

	// ErrInvalidSegment is returned when a segment literal (whether
	// from --segment input on pin or from a YAML retained/pinned entry
	// on split) fails the segment grammar: empty after trim, contains
	// a path separator, control character, wildcard glyph, or exceeds
	// the bounded length. Both code paths share the validator so CLI
	// input and YAML-carried values are constrained identically.
	ErrInvalidSegment = errors.New("learn: invalid segment literal")
)

// maxSegmentLiteralLen bounds the length of a path segment literal.
// 256 bytes is generous for real-world API segments (usernames, repo
// names, IDs) while keeping a malicious YAML from blowing up the
// rebuilt path string. Aligns with the 2048-char path-canonical cap in
// internal/contract/inference/normalize: a 2048-char path with 256-char
// segments is at most 8 segments, comfortably realistic.
const maxSegmentLiteralLen = 256

// reasonOperatorSplit / reasonOperatorPin label segments that an
// operator manually demoted or pinned. The future compile pipeline
// treats these as authoritative: a segment with reason=operator_split
// is retained even if its entropy would otherwise collapse it; a
// segment in pinned_segments is reserved-equivalent for the rule.
const (
	reasonOperatorSplit = "operator_split"
	reasonOperatorPin   = "operator_pin"
)

// splitCmd returns the `pipelock learn split` subcommand. It rewrites
// a candidate contract YAML to demote one or more collapsed segments
// back into their constituent literal values, so the operator can
// preserve a path family the algorithm wanted to wildcard. The command
// is idempotent: splitting an already-literal segment is a no-op with
// a clear stdout note.
//
// Trust model: candidate paths are operator-controlled. We require an
// absolute path and `filepath.Clean` every input. The candidate file
// is rewritten in place via atomic temp-file-then-rename, preserving
// 0o600 permission floor.
//
// Usage:
//
//	pipelock learn split --candidate <path> --rule <rule_id> [--index N] [--out <path>]
//
// If --index is omitted (or 0), all collapsed segments for the rule
// are split. If --out is omitted, the candidate file is rewritten in
// place via atomic rename.
func splitCmd() *cobra.Command {
	var (
		candidatePath string
		ruleID        string
		index         int
		outPath       string
	)
	cmd := &cobra.Command{
		Use:   "split",
		Short: "Demote collapsed path segments back to literals before contract ratification",
		Long: `Operator affordance: rewrite a candidate contract YAML so a
collapsed normalization segment is restored as a literal value. Use this
when the path-normalization algorithm collapsed a segment you wanted to
keep distinct (e.g., a path that should stay /api/v1/users instead of
collapsing to /api/v1/*).

The command is idempotent and writes atomically (temp file + rename).
The candidate is not signed or activated by this command; that is the
job of pipelock learn ratify (future PR).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSplit(cmd, candidatePath, ruleID, index, outPath)
		},
	}
	cmd.Flags().StringVar(&candidatePath, "candidate", "", "path to candidate YAML (required, absolute)")
	cmd.Flags().StringVar(&ruleID, "rule", "", "rule_id to split (required)")
	cmd.Flags().IntVar(&index, "index", 0, "specific segment index to split; 0 = split all collapsed")
	cmd.Flags().StringVar(&outPath, "out", "", "output path; empty = rewrite candidate in place")
	_ = cmd.MarkFlagRequired("candidate")
	_ = cmd.MarkFlagRequired("rule")
	return cmd
}

// runSplit reads the candidate YAML at candidatePath, finds the rule
// matching ruleID, demotes one or all collapsed segments back to
// retained_segments with reason=operator_split, rebuilds the path
// value strings, and writes back atomically. If outPath is non-empty,
// the result is written there and candidatePath is left untouched.
//
// The rebuilt path value reflects the segment ledger after the split:
// retained-by-index becomes the literal at that position, and any
// segment still in collapsed_segments is rendered as `*`. Pinned
// segments are joined by their (input-position) index when present,
// otherwise treated as supplemental and not assigned a slot.
func runSplit(cmd *cobra.Command, candidatePath, ruleID string, index int, outPath string) error {
	cleanCandidate, doc, err := loadCandidate(candidatePath)
	if err != nil {
		return err
	}

	rule, err := findRule(doc, ruleID)
	if err != nil {
		return fmt.Errorf("learn split: %w", err)
	}

	if err := validateRuleSegments(rule); err != nil {
		return fmt.Errorf("learn split: %w", err)
	}

	moved, err := splitRule(rule, index)
	if err != nil {
		return fmt.Errorf("learn split: %w", err)
	}

	dest, err := resolveOut(cleanCandidate, outPath)
	if err != nil {
		return err
	}
	if err := writeCandidate(dest, doc); err != nil {
		return err
	}

	emitAuditEvent(cmd, auditEvent{
		Event:           "learn_split",
		Candidate:       cleanCandidate,
		Dest:            dest,
		Rule:            ruleID,
		Index:           index,
		SegmentsChanged: moved,
		NoOp:            moved == 0,
	})

	if moved == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"split: rule %s, no collapsed segments to demote, written to %s\n",
			ruleID, dest)
		return nil
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"split: rule %s, %d segments demoted, written to %s\n",
		ruleID, moved, dest)
	return nil
}

// loadCandidate cleans the path, validates it is absolute, reads the
// file, and parses it as YAML. Returns the cleaned path and the parsed
// document.
//
// Absolute-path validation, symlink rejection, and regular-file
// confirmation form the trust boundary on the candidate input. A
// relative path is operator-controlled and could be interpreted
// against a surprising cwd; a symlink could redirect reads to a file
// outside the intended candidate area; a non-regular file is a sign of
// pipe / device confusion that the rewrite path cannot handle safely.
// All three reject up front rather than guess.
func loadCandidate(path string) (string, *yaml.Node, error) {
	if path == "" {
		return "", nil, fmt.Errorf("%w: empty candidate path", ErrInvalidCandidate)
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", nil, fmt.Errorf("%w: candidate path must be absolute, got %q",
			ErrInvalidCandidate, path)
	}

	data, err := safeReadCandidate(clean)
	if err != nil {
		return "", nil, err
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", nil, fmt.Errorf("yaml parse: %w: %w", ErrInvalidCandidate, err)
	}
	if doc.Kind == 0 || (doc.Kind == yaml.DocumentNode && len(doc.Content) == 0) {
		return "", nil, fmt.Errorf("%w: candidate is empty", ErrInvalidCandidate)
	}
	return clean, &doc, nil
}

// safeReadCandidate reads the file at clean (already filepath.Clean'd
// and absolute) with two-step symlink protection:
//
//   - Lstat rejects symlinks and non-regular files at the directory
//     entry level.
//   - Open with O_RDONLY|O_NOFOLLOW so a between-stat-and-open swap
//     also fails closed on Unix. Windows lacks O_NOFOLLOW (noFollowFlag
//     is zero); the Lstat regular-file check still runs and is the
//     primary defense, since Go's os.Lstat maps Windows reparse points
//     to ModeSymlink.
//
// Errors wrap ErrInvalidCandidate so callers detect the trust-boundary
// failure with errors.Is.
func safeReadCandidate(clean string) ([]byte, error) {
	li, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("read candidate: %w: %w", ErrInvalidCandidate, err)
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: candidate must not be a symlink: %s", ErrInvalidCandidate, clean)
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: candidate must be a regular file: %s", ErrInvalidCandidate, clean)
	}
	// G304: clean is filepath.Clean'd by the caller and Lstat-validated
	// above; symlinks and non-regular files are already rejected.
	f, err := os.OpenFile(filepath.Clean(clean), os.O_RDONLY|noFollowFlag, 0) //nolint:gosec // path is operator-supplied and validated
	if err != nil {
		if errors.Is(err, errELOOP) {
			return nil, fmt.Errorf("%w: symlink raced into place: %s", ErrInvalidCandidate, clean)
		}
		return nil, fmt.Errorf("read candidate: %w: %w", ErrInvalidCandidate, err)
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// resolveOut returns the destination path for the rewrite. If outPath
// is empty, the candidate is rewritten in place. Both paths must be
// absolute. If outPath points to an existing file, it must already be
// a regular file (not a symlink, device, or directory) so the atomic
// rename does not redirect through a symlink to write outside the
// intended directory.
func resolveOut(candidatePath, outPath string) (string, error) {
	if outPath == "" {
		return candidatePath, nil
	}
	clean := filepath.Clean(outPath)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("%w: --out must be absolute, got %q",
			ErrInvalidCandidate, outPath)
	}
	li, err := os.Lstat(clean)
	switch {
	case err == nil:
		if li.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: --out must not be a symlink: %s", ErrInvalidCandidate, clean)
		}
		if !li.Mode().IsRegular() {
			return "", fmt.Errorf("%w: --out must be a regular file when it exists: %s", ErrInvalidCandidate, clean)
		}
	case os.IsNotExist(err):
		// Creation case is fine; atomicfile.Write creates a sibling
		// temp file in the parent directory and renames over the
		// target name, never resolving a symlink at the dest position.
	default:
		return "", fmt.Errorf("%w: --out lstat: %w", ErrInvalidCandidate, err)
	}
	return clean, nil
}

// writeCandidate marshals doc back to YAML and writes it to dest
// atomically with 0o600 permission floor. Marshal failure is rare
// (would mean the in-memory tree was corrupted); we surface it as
// ErrInvalidCandidate.
func writeCandidate(dest string, doc *yaml.Node) error {
	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("yaml marshal: %w: %w", ErrInvalidCandidate, err)
	}
	if err := atomicfile.Write(dest, out, 0o600); err != nil {
		return fmt.Errorf("learn: writing candidate: %w", err)
	}
	return nil
}

// findRule walks the candidate document looking for a rule with the
// given rule_id. Returns the rule's mapping node so callers can mutate
// in place. Returns ErrRuleNotFound if absent.
//
// Schema (subset of the candidate-contract YAML emitted by the future
// compile pipeline):
//
//	rules:
//	  - rule_id: r-...
//	    selector:
//	      paths: [...]
func findRule(doc *yaml.Node, ruleID string) (*yaml.Node, error) {
	root := documentRoot(doc)
	if root == nil {
		return nil, fmt.Errorf("%w: candidate has no top-level mapping", ErrInvalidCandidate)
	}
	rules := mappingValue(root, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%w: candidate has no rules sequence", ErrInvalidCandidate)
	}
	for _, rule := range rules.Content {
		if rule.Kind != yaml.MappingNode {
			continue
		}
		idNode := mappingValue(rule, "rule_id")
		if idNode != nil && idNode.Value == ruleID {
			return rule, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrRuleNotFound, ruleID)
}

// splitRule moves collapsed segments to retained for every path in
// the rule. If index is 0, all collapsed segments move; otherwise
// only the entry whose `index:` field matches. Returns the count of
// segments moved across all paths, and ErrCollapsedSegmentNotFound if
// a specific index was requested but not found anywhere.
func splitRule(rule *yaml.Node, index int) (int, error) {
	selector := mappingValue(rule, "selector")
	if selector == nil {
		return 0, nil
	}
	paths := mappingValue(selector, "paths")
	if paths == nil || paths.Kind != yaml.SequenceNode {
		return 0, nil
	}

	moved := 0
	specificFound := false
	for _, p := range paths.Content {
		if p.Kind != yaml.MappingNode {
			continue
		}
		norm := mappingValue(p, "normalization")
		if norm == nil {
			continue
		}
		n, found := splitNormalization(norm, index)
		moved += n
		if found {
			specificFound = true
		}
		// Rebuild the path's `value:` to mirror the new segment
		// ledger, keeping wildcards for whatever stays collapsed.
		rebuildPathValue(p)
	}
	if index > 0 && !specificFound {
		return moved, fmt.Errorf("%w: index=%d", ErrCollapsedSegmentNotFound, index)
	}
	return moved, nil
}

// splitNormalization moves matching collapsed entries to the retained
// list with reason=operator_split. Returns (movedCount, foundSpecific).
// foundSpecific is true if a specific index was requested AND matched
// in this normalization block.
func splitNormalization(norm *yaml.Node, index int) (int, bool) {
	collapsed := mappingValue(norm, "collapsed_segments")
	if collapsed == nil || collapsed.Kind != yaml.SequenceNode {
		return 0, false
	}

	keep := make([]*yaml.Node, 0, len(collapsed.Content))
	move := make([]*yaml.Node, 0, len(collapsed.Content))
	specificFound := false
	for _, entry := range collapsed.Content {
		if entry.Kind != yaml.MappingNode {
			keep = append(keep, entry)
			continue
		}
		idxNode := mappingValue(entry, "index")
		idxVal, ok := nodeIntValue(idxNode)
		if index == 0 || (ok && idxVal == index) {
			move = append(move, entry)
			if index > 0 {
				specificFound = true
			}
			continue
		}
		keep = append(keep, entry)
	}
	if len(move) == 0 {
		return 0, specificFound
	}

	collapsed.Content = keep

	// Demote the moved entries: reason -> operator_split. Other
	// fields (index, value, distinct_values, ...) are preserved as
	// audit context.
	for _, entry := range move {
		setMappingScalar(entry, "reason", reasonOperatorSplit)
	}

	retained := ensureMappingSeq(norm, "retained_segments")
	retained.Content = append(retained.Content, move...)

	return len(move), specificFound
}

// rebuildPathValue regenerates the path's `value` from the ordered
// union of retained_segments + pinned_segments (by index) plus `*`
// for whatever indices remain collapsed.
//
// Index discovery is bounded: we read every segment list, take the
// max index seen, and walk 1..max emitting either the retained
// literal, the pinned literal, or `*`. Segments without an index
// (e.g. value-only pins) are skipped at this stage; they affect the
// pinned ledger but not the rendered path.
func rebuildPathValue(p *yaml.Node) {
	norm := mappingValue(p, "normalization")
	if norm == nil {
		return
	}

	type slot struct {
		value     string
		wildcard  bool
		hasLitVal bool
	}
	slots := make(map[int]slot)
	maxIdx := 0

	addLit := func(seg *yaml.Node) {
		idxNode := mappingValue(seg, "index")
		idx, ok := nodeIntValue(idxNode)
		if !ok || idx <= 0 {
			return
		}
		val := mappingScalar(seg, "value")
		// Defense-in-depth: validateRuleSegments runs before mutation
		// and rejects malformed literals at the entry boundary, but if
		// a future caller invokes rebuildPathValue on a tree that did
		// not pass through that gate we want the slot to render as a
		// wildcard rather than embed a path-corrupting value. Empty
		// values are common (operator-split entries with no original
		// literal recorded) and intentionally render as wildcards.
		if val == "" || validateSegmentLiteral(val) != nil {
			if idx > maxIdx {
				maxIdx = idx
			}
			if _, exists := slots[idx]; !exists {
				slots[idx] = slot{wildcard: true}
			}
			return
		}
		if idx > maxIdx {
			maxIdx = idx
		}
		// Retained beats pinned beats nothing for the rendered slot,
		// but in practice retained-by-index and pinned-by-index don't
		// collide because pin is value-keyed. Use first-write-wins.
		if _, exists := slots[idx]; !exists {
			slots[idx] = slot{value: val, hasLitVal: true}
		}
	}
	addWild := func(seg *yaml.Node) {
		idxNode := mappingValue(seg, "index")
		idx, ok := nodeIntValue(idxNode)
		if !ok || idx <= 0 {
			return
		}
		if idx > maxIdx {
			maxIdx = idx
		}
		if _, exists := slots[idx]; !exists {
			slots[idx] = slot{wildcard: true}
		}
	}

	if retained := mappingValue(norm, "retained_segments"); retained != nil && retained.Kind == yaml.SequenceNode {
		for _, seg := range retained.Content {
			addLit(seg)
		}
	}
	if pinned := mappingValue(norm, "pinned_segments"); pinned != nil && pinned.Kind == yaml.SequenceNode {
		for _, seg := range pinned.Content {
			addLit(seg)
		}
	}
	if collapsed := mappingValue(norm, "collapsed_segments"); collapsed != nil && collapsed.Kind == yaml.SequenceNode {
		for _, seg := range collapsed.Content {
			addWild(seg)
		}
	}

	if maxIdx == 0 {
		return
	}

	// Rebuild "/seg1/seg2/...". Missing indices in [1..maxIdx] are
	// rendered as wildcards so the path string stays well-formed even
	// if a segment was removed from every list.
	rebuilt := ""
	for i := 1; i <= maxIdx; i++ {
		s, present := slots[i]
		switch {
		case !present:
			rebuilt += "/*"
		case s.hasLitVal:
			rebuilt += "/" + s.value
		case s.wildcard:
			rebuilt += "/*"
		default:
			rebuilt += "/*"
		}
	}
	setMappingScalar(p, "value", rebuilt)
}

// documentRoot returns the top-level mapping node of a yaml.Node
// document, or nil if the document is malformed.
func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc == nil {
		return nil
	}
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return nil
		}
		return doc.Content[0]
	}
	return doc
}

// mappingValue returns the value node for a given key on a mapping
// node, or nil if absent / non-mapping.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// mappingScalar returns the string value of a scalar field on a
// mapping, or "" if absent / non-scalar.
func mappingScalar(m *yaml.Node, key string) string {
	v := mappingValue(m, key)
	if v == nil || v.Kind != yaml.ScalarNode {
		return ""
	}
	return v.Value
}

// setMappingScalar sets or replaces a scalar field on a mapping node.
// Adds the key if absent.
func setMappingScalar(m *yaml.Node, key, value string) {
	if m == nil || m.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1].Kind = yaml.ScalarNode
			m.Content[i+1].Tag = "!!str"
			m.Content[i+1].Value = value
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value},
	)
}

// ensureMappingSeq returns the existing sequence node at key on m, or
// creates an empty one and appends it before returning.
func ensureMappingSeq(m *yaml.Node, key string) *yaml.Node {
	existing := mappingValue(m, key)
	if existing != nil && existing.Kind == yaml.SequenceNode {
		return existing
	}
	if existing != nil {
		// Field exists but is not a sequence (e.g. !!null). Replace
		// in place.
		existing.Kind = yaml.SequenceNode
		existing.Tag = "!!seq"
		existing.Value = ""
		existing.Content = nil
		return existing
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		seq,
	)
	return seq
}

// nodeIntValue parses a scalar yaml.Node as an int. Returns (val, true)
// on success, (0, false) on absent / non-scalar / parse error.
func nodeIntValue(n *yaml.Node) (int, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return 0, false
	}
	v, err := strconv.Atoi(n.Value)
	if err != nil {
		return 0, false
	}
	return v, true
}

// validateSegmentLiteral enforces the segment grammar that both
// CLI-side --segment input on `pin` and YAML-side retained/pinned
// values on `split` must satisfy. Used to keep policy artifacts
// well-formed against operator typos and against YAML smuggled in
// from a less-trusted source.
//
// Rejected:
//   - empty after TrimSpace (pin enforces this separately as
//     ErrEmptySegment for the precise CLI error; here it folds in)
//   - any byte 0x00-0x1F or 0x7F (control characters)
//   - the path separator '/' (would smuggle one segment as multiple)
//   - the wildcard glyphs '*' and '?' (have meaning in the contract
//     grammar; an operator pinning literal "*" is almost certainly a
//     mistake and would silently broaden compile-time matching)
//   - bracket glyphs '[' and ']' (set / range characters in path
//     globs; same hazard)
//   - more than maxSegmentLiteralLen bytes
func validateSegmentLiteral(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty", ErrInvalidSegment)
	}
	if len(s) > maxSegmentLiteralLen {
		return fmt.Errorf("%w: length %d exceeds %d", ErrInvalidSegment, len(s), maxSegmentLiteralLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c < 0x20 || c == 0x7F:
			return fmt.Errorf("%w: control character at offset %d", ErrInvalidSegment, i)
		case c == '/':
			return fmt.Errorf("%w: path separator '/' at offset %d", ErrInvalidSegment, i)
		case c == '*' || c == '?':
			return fmt.Errorf("%w: wildcard glyph %q at offset %d", ErrInvalidSegment, c, i)
		case c == '[' || c == ']':
			return fmt.Errorf("%w: bracket glyph %q at offset %d", ErrInvalidSegment, c, i)
		}
	}
	return nil
}

// validateRuleSegments walks every selector.paths[].normalization on
// the rule and validates retained_segments[].value and
// pinned_segments[].value against validateSegmentLiteral. Empty
// values, missing values, or absent normalization blocks are skipped
// (the rebuilder handles those cases). Returns the first failure as
// an ErrInvalidSegment-wrapped error so the operator sees a precise
// path-and-offset message.
//
// Run before mutation in both runSplit and runPin so an operator
// invocation against a candidate carrying an attacker-supplied
// segment literal fails closed without rewriting the file.
func validateRuleSegments(rule *yaml.Node) error {
	selector := mappingValue(rule, "selector")
	if selector == nil {
		return nil
	}
	paths := mappingValue(selector, "paths")
	if paths == nil || paths.Kind != yaml.SequenceNode {
		return nil
	}
	for pi, p := range paths.Content {
		if p.Kind != yaml.MappingNode {
			continue
		}
		norm := mappingValue(p, "normalization")
		if norm == nil {
			continue
		}
		for _, listKey := range []string{"retained_segments", "pinned_segments"} {
			lst := mappingValue(norm, listKey)
			if lst == nil || lst.Kind != yaml.SequenceNode {
				continue
			}
			for ei, entry := range lst.Content {
				if entry.Kind != yaml.MappingNode {
					continue
				}
				val := mappingScalar(entry, "value")
				if val == "" {
					continue
				}
				if err := validateSegmentLiteral(val); err != nil {
					return fmt.Errorf("%w (path %d, %s[%d])", err, pi, listKey, ei)
				}
			}
		}
	}
	return nil
}

// auditEvent is the structured audit-log payload emitted on stderr by
// learn split / learn pin. It is JSON-encoded one event per line so
// log shippers can parse it without buffering. Fields mirror the
// minimum information needed for incident reconstruction: the command
// name, the candidate path (input), the destination path (output,
// which differs from candidate when --out is set), the rule_id, the
// segment-or-index target, the count of entries actually changed,
// and whether the call was a no-op.
type auditEvent struct {
	Event             string   `json:"event"`
	Candidate         string   `json:"candidate,omitempty"`
	Dest              string   `json:"dest,omitempty"`
	Rule              string   `json:"rule,omitempty"`
	Segment           string   `json:"segment,omitempty"`
	Index             int      `json:"index,omitempty"`
	SegmentsChanged   int      `json:"segments_changed,omitempty"`
	Agent             string   `json:"agent,omitempty"`
	SignerKeyID       string   `json:"signer_key_id,omitempty"`
	Since             string   `json:"since,omitempty"`
	Inputs            []string `json:"inputs,omitempty"`
	Output            string   `json:"output,omitempty"`
	Review            string   `json:"review,omitempty"`
	Manifest          string   `json:"manifest,omitempty"`
	EventsIngested    int      `json:"events_ingested,omitempty"`
	EventsDropped     int      `json:"events_dropped,omitempty"`
	RulesEmitted      int      `json:"rules_emitted,omitempty"`
	CrossAgentSigning bool     `json:"cross_agent_signing,omitempty"`
	NoOp              bool     `json:"noop"`
}

// emitAuditEvent writes an auditEvent as a single JSON line to stderr.
// Marshal failures are swallowed: an audit-log emit failing must never
// block the operator command, and json.Marshal of a fully-typed struct
// only fails on programming errors (channels, functions, cycles)
// which the auditEvent shape cannot produce.
func emitAuditEvent(cmd *cobra.Command, ev auditEvent) {
	out, err := json.Marshal(ev)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(cmd.ErrOrStderr(), string(out))
}
