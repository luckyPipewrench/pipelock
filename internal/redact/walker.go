// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"bytes"
	"encoding/json"
)

// Report summarises the outcome of a Rewrite call.
type Report struct {
	// Applied is true when redaction ran to completion. False when the
	// request was blocked; in that case the accompanying error is a
	// *BlockError and Body is nil.
	Applied bool
	// TotalRedactions is the count of unique redactions applied.
	TotalRedactions int
	// ByClass is the per-class count of unique redactions.
	ByClass map[Class]int
}

// Limits configures the defensive caps Rewrite enforces.
type Limits struct {
	// MaxBodyBytes is the largest request body Rewrite will process. Zero
	// disables the check (not recommended outside tests).
	MaxBodyBytes int
	// MaxRedactionsPerRequest caps the number of unique redactions. Zero
	// defaults to DefaultMaxRedactions.
	MaxRedactionsPerRequest int
	// MaxDepth bounds JSON nesting depth to prevent stack exhaustion on
	// pathological input. Zero defaults to DefaultMaxDepth.
	MaxDepth int
}

// Default limits tuned to typical LLM request sizes.
const (
	DefaultMaxBodyBytes  = 10 * 1024 * 1024 // 10 MB
	DefaultMaxRedactions = 10_000
	DefaultMaxDepth      = 64
	absoluteBodyCapBytes = 64 * 1024 * 1024 // hard ceiling, never exceeded
	absoluteRedactionCap = 1_000_000        // safety net above operator config
	absoluteDepthCap     = 256              // safety net above operator config
)

// RewriteJSON parses body as JSON, walks every string scalar, applies m +
// r, and returns a rewritten JSON body. Fail-closed: any error during
// parsing, any scalar that cannot be decoded/re-encoded, or any cap
// exceeded results in a *BlockError with the matched originals left in r.
//
// The Redactor r is mutated: its counters and dedup state reflect every
// placeholder generated during this call. Callers should pass a fresh
// Redactor per request.
func RewriteJSON(body []byte, m *Matcher, r *Redactor, lim Limits) ([]byte, *Report, error) {
	lim = normaliseLimits(lim)

	if lim.MaxBodyBytes > 0 && len(body) > lim.MaxBodyBytes {
		return nil, nil, newBlock(ReasonBodyTooLarge, 0, "")
	}
	if !json.Valid(body) {
		return nil, nil, newBlock(ReasonBodyUnparseable, 0, "")
	}

	var root interface{}
	dec := json.NewDecoder(bytes.NewReader(body))
	// UseNumber to preserve numeric fidelity on re-encode.
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, nil, newBlock(ReasonBodyUnparseable, 0, err.Error())
	}

	w := walker{matcher: m, redactor: r, limits: lim}
	rewritten, err := w.walk(root, 0)
	if err != nil {
		return nil, nil, err
	}

	// Disable HTML escaping so `<pl:CLASS:N>` placeholders appear as
	// literal characters in the output bytes, not `\u003cpl:...\u003e`.
	// This is API traffic, not HTML; the upstream provider parses the
	// JSON and sees the same string either way, but literal form keeps
	// byte-level inspection and telemetry readable.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rewritten); err != nil {
		// Should not happen for inputs decoded via encoding/json, but
		// fail-closed if it does.
		return nil, nil, newBlock(ReasonBodyUnparseable, r.Total(), "remarshal: "+err.Error())
	}
	// Encoder appends a trailing newline; trim it so the output is a bare
	// JSON value, matching what callers get from json.Marshal.
	out := bytes.TrimRight(buf.Bytes(), "\n")

	return out, &Report{
		Applied:         true,
		TotalRedactions: r.Total(),
		ByClass:         r.ByClass(),
	}, nil
}

// walker carries scan state across recursive calls.
type walker struct {
	matcher  *Matcher
	redactor *Redactor
	limits   Limits
}

func (w *walker) walk(node interface{}, depth int) (interface{}, error) {
	if depth > w.limits.MaxDepth {
		return nil, newBlock(ReasonDepthExceeded, w.redactor.Total(), "")
	}
	switch v := node.(type) {
	case string:
		return w.rewriteScalar(v)
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for k, child := range v {
			// Scan and redact the key too. An adversarial agent can stuff
			// a secret into a JSON key name (e.g. {"AKIA...": "safe"}); if
			// we only scanned values, that path would bypass redaction.
			// Rewriting the key preserves the fail-closed invariant that
			// every string scalar at any position is scanned.
			rewrittenKey, err := w.rewriteScalar(k)
			if err != nil {
				return nil, err
			}
			rewritten, err := w.walk(child, depth+1)
			if err != nil {
				return nil, err
			}
			out[rewrittenKey] = rewritten
		}
		return out, nil
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, child := range v {
			rewritten, err := w.walk(child, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = rewritten
		}
		return out, nil
	default:
		// Numbers (json.Number), bools, nil, etc. Pass through untouched.
		return v, nil
	}
}

func (w *walker) rewriteScalar(s string) (string, error) {
	matches := w.matcher.Scan(s)
	if len(matches) == 0 {
		return s, nil
	}
	// Overflow check counts only net-new (class, original) pairs after dedup
	// against both earlier fields and repeated values within this scalar.
	if w.limits.MaxRedactionsPerRequest > 0 {
		projected := w.redactor.Total() + countNewPairs(matches, w.redactor)
		if projected > w.limits.MaxRedactionsPerRequest {
			return "", newBlock(ReasonOverflow, w.redactor.Total(), "")
		}
	}
	return RewriteString(s, matches, w.redactor), nil
}

func countNewPairs(matches []Match, r *Redactor) int {
	if len(matches) == 0 {
		return 0
	}
	seen := make(map[Class]map[string]struct{})
	newPairs := 0
	for _, m := range matches {
		if r.seen(m.Class, m.Original) {
			continue
		}
		bucket, ok := seen[m.Class]
		if !ok {
			bucket = make(map[string]struct{})
			seen[m.Class] = bucket
		}
		if _, ok := bucket[m.Original]; ok {
			continue
		}
		bucket[m.Original] = struct{}{}
		newPairs++
	}
	return newPairs
}

// normaliseLimits applies defaults and clamps to safety ceilings.
func normaliseLimits(lim Limits) Limits {
	if lim.MaxBodyBytes <= 0 {
		lim.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if lim.MaxBodyBytes > absoluteBodyCapBytes {
		lim.MaxBodyBytes = absoluteBodyCapBytes
	}
	if lim.MaxRedactionsPerRequest <= 0 {
		lim.MaxRedactionsPerRequest = DefaultMaxRedactions
	}
	if lim.MaxRedactionsPerRequest > absoluteRedactionCap {
		lim.MaxRedactionsPerRequest = absoluteRedactionCap
	}
	if lim.MaxDepth <= 0 {
		lim.MaxDepth = DefaultMaxDepth
	}
	if lim.MaxDepth > absoluteDepthCap {
		lim.MaxDepth = absoluteDepthCap
	}
	return lim
}
