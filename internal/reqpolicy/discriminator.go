// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// discOutcome is the result of evaluating a discriminator predicate against a
// parsed JSON body. It is intentionally three-valued: a present-but-unmatched
// string and an absent field are both "no match" (the allow-by-default rail
// forwards), but a present-but-non-string value - or a non-object body - is
// opaque so the caller can fail closed per on_opaque_operation rather than let
// a type the upstream might still dispatch on slip through unmatched.
type discOutcome uint8

const (
	discNoMatch discOutcome = iota
	discMatch
	discOpaque
)

// discPredicate is the compiled form of a rule's JSON discriminator predicate:
// a top-level object key and the RE2 patterns its string value must match.
type discPredicate struct {
	field    string
	valueRes []*regexp.Regexp
}

// compileDiscriminatorPredicate compiles a rule's discriminator predicate,
// returning nil when the rule has none. Field and patterns are validated at
// config load, so a compile failure here is defense in depth.
func compileDiscriminatorPredicate(d *config.RequestPolicyDiscriminator) (*discPredicate, error) {
	if d == nil {
		return nil, nil
	}
	p := &discPredicate{field: strings.TrimSpace(d.Field)}
	for _, pat := range d.ValuePatterns {
		re, err := regexp.Compile(strings.TrimSpace(pat))
		if err != nil {
			return nil, err
		}
		p.valueRes = append(p.valueRes, re)
	}
	return p, nil
}

// eval classifies the request body against the predicate. It is evaluated only
// when meta.JSONBodyParsed is true; the not-read and invalid-JSON cases are the
// caller's fail-closed responsibility (on_opaque_operation / on_parse_error),
// so an unparsed body is reported as no match here and handled there.
func (d *discPredicate) eval(meta RequestMeta) discOutcome {
	if !meta.JSONBodyParsed {
		return discNoMatch
	}
	obj, ok := meta.JSONBody.(map[string]any)
	if !ok {
		// Valid JSON but a non-object top level (array, scalar): the targeted
		// field cannot exist, yet the upstream may still dispatch on the body,
		// so treat it as opaque rather than a benign no-match.
		return discOpaque
	}
	if _, dup := meta.JSONDupKeys[d.field]; dup {
		// The targeted field appears more than once at the top level. Go keeps
		// the last value, but a first-wins upstream could dispatch on a
		// different one, so we cannot trust the collapsed value: fail closed.
		return discOpaque
	}
	v, present := obj[d.field]
	if !present {
		return discNoMatch
	}
	s, ok := v.(string)
	if !ok {
		// Present but null / number / bool / array / object: unclassifiable
		// against string value patterns. Fail closed via opaque.
		return discOpaque
	}
	for _, re := range d.valueRes {
		if re.MatchString(s) {
			return discMatch
		}
	}
	return discNoMatch
}
