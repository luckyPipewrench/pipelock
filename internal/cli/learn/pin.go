// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// pinCmd returns the `pipelock learn pin` subcommand. It rewrites a
// candidate contract YAML to add a per-rule pinned segment, ensuring
// that subsequent recompile passes treat the literal value as
// reserved-equivalent for that rule. Idempotent: pinning the same
// (rule, segment) twice has no effect after the first.
//
// Trust model and atomic-write semantics are identical to splitCmd:
// see split.go loadCandidate / writeCandidate.
//
// Usage:
//
//	pipelock learn pin --candidate <path> --rule <rule_id> --segment <value> [--out <path>]
func pinCmd() *cobra.Command {
	var (
		candidatePath string
		ruleID        string
		segment       string
		outPath       string
	)
	cmd := &cobra.Command{
		Use:   "pin",
		Short: "Pin a literal segment value as reserved for a candidate rule",
		Long: `Operator affordance: add a pinned segment to a candidate
contract rule. Pinned segments behave like the canonical reserved
blocklist (admin/auth/...) but are scoped to the rule. Subsequent
compile passes will not collapse a pinned literal regardless of
entropy. Use this to lock in a path family the algorithm should keep
distinct on every recompile.

The command is idempotent and writes atomically (temp file + rename).
Pinning is value-keyed: the same literal applies to any segment
position where it occurs in the rule's paths.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPin(cmd, candidatePath, ruleID, segment, outPath)
		},
	}
	cmd.Flags().StringVar(&candidatePath, "candidate", "", "path to candidate YAML (required, absolute)")
	cmd.Flags().StringVar(&ruleID, "rule", "", "rule_id to pin within (required)")
	cmd.Flags().StringVar(&segment, "segment", "", "literal segment value to pin (required)")
	cmd.Flags().StringVar(&outPath, "out", "", "output path; empty = rewrite candidate in place")
	_ = cmd.MarkFlagRequired("candidate")
	_ = cmd.MarkFlagRequired("rule")
	_ = cmd.MarkFlagRequired("segment")
	return cmd
}

// runPin reads the candidate YAML at candidatePath, finds the rule
// matching ruleID, appends a pinned segment with reason=operator_pin
// across every path's normalization block (idempotent per path), and
// writes the result back atomically. If outPath is non-empty, the
// result is written there and candidatePath is left untouched.
//
// Pinning is value-keyed (no `index:` field on the entry) so the
// compile pipeline can reserve the literal regardless of which
// position it appears in. This matches how the canonical reserved
// list (admin/auth/login/...) is consulted.
func runPin(cmd *cobra.Command, candidatePath, ruleID, segment, outPath string) error {
	trimmed := strings.TrimSpace(segment)
	if trimmed == "" {
		return fmt.Errorf("learn pin: %w", ErrEmptySegment)
	}
	// Apply the same grammar that split-side validateRuleSegments
	// enforces on YAML literals so CLI input and YAML-carried values
	// share one rejection surface. Catches operator typos like passing
	// "/admin" or "*" before the value reaches the candidate file.
	if err := validateSegmentLiteral(trimmed); err != nil {
		return fmt.Errorf("learn pin: %w", err)
	}

	cleanCandidate, doc, err := loadCandidate(candidatePath)
	if err != nil {
		return err
	}

	rule, err := findRule(doc, ruleID)
	if err != nil {
		return fmt.Errorf("learn pin: %w", err)
	}

	if err := validateRuleSegments(rule); err != nil {
		return fmt.Errorf("learn pin: %w", err)
	}

	added := pinRule(rule, trimmed)

	dest, err := resolveOut(cleanCandidate, outPath)
	if err != nil {
		return err
	}
	if err := writeCandidate(dest, doc); err != nil {
		return err
	}

	emitAuditEvent(cmd, auditEvent{
		Event:           "learn_pin",
		Candidate:       cleanCandidate,
		Dest:            dest,
		Rule:            ruleID,
		Segment:         trimmed,
		SegmentsChanged: added,
		NoOp:            added == 0,
	})

	if added == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"pin: rule %s, segment %q already pinned, no-op (written to %s)\n",
			ruleID, trimmed, dest)
		return nil
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"pin: rule %s, segment %q pinned, written to %s\n",
		ruleID, trimmed, dest)
	return nil
}

// pinRule appends a pinned-segments entry per path normalization
// block, skipping blocks where the segment value already exists in
// pinned_segments. Returns the number of normalization blocks that
// received a new pin (0 when fully idempotent across the rule).
func pinRule(rule *yaml.Node, segment string) int {
	selector := mappingValue(rule, "selector")
	if selector == nil {
		return 0
	}
	paths := mappingValue(selector, "paths")
	if paths == nil || paths.Kind != yaml.SequenceNode {
		return 0
	}

	added := 0
	for _, p := range paths.Content {
		if p.Kind != yaml.MappingNode {
			continue
		}
		norm := mappingValue(p, "normalization")
		if norm == nil {
			continue
		}
		if pinNormalization(norm, segment) {
			added++
		}
	}
	return added
}

// pinNormalization appends {value, reason} to pinned_segments unless
// segment is already present. Returns true if a new entry was added.
//
// Existing entries are matched by their `value:` scalar, so adding a
// pin twice with the same segment is a no-op even if the previous
// entry's other fields differ.
func pinNormalization(norm *yaml.Node, segment string) bool {
	pinned := ensureMappingSeq(norm, "pinned_segments")
	for _, entry := range pinned.Content {
		if entry.Kind != yaml.MappingNode {
			continue
		}
		if mappingScalar(entry, "value") == segment {
			return false
		}
	}
	entry := newPinEntry(segment)
	pinned.Content = append(pinned.Content, entry)
	return true
}

// newPinEntry constructs a pinned_segments YAML entry for the given
// literal value. The entry has no `index` field on purpose: pin is
// value-keyed and reserves the literal across any segment position.
func newPinEntry(segment string) *yaml.Node {
	return &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "value"},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: segment},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "reason"},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: reasonOperatorPin},
		},
	}
}
