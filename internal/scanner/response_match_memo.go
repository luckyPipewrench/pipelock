// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

// responseMatchMemo reuses only proven empty pattern results within one response
// scan. Core and configured patterns often repeat the same regex on the exact
// same normalized bytes. Positive results, attribution, spans, suppression and
// redaction are never cached here. The existing cross-request verdict cache is
// independent of this request-local optimization.
//
// Calls are sequential; the underlying matcher joins its workers before this
// object is read or written again. A Scanner never retains or shares the memo.
type responseMatchMemo struct {
	views   map[string]map[responseNegativeKey]struct{}
	bytes   int
	entries int
}

type responseNegativeKey struct {
	regex      string
	companions bool
}

const (
	responseMemoMinBytes   = 4096
	responseMemoMaxBytes   = 16 << 20
	responseMemoMaxViews   = 8
	responseMemoMaxEntries = 512
)

func newResponseMatchMemo(size int) *responseMatchMemo {
	if size < responseMemoMinBytes || size > responseMemoMaxBytes {
		return nil
	}
	return &responseMatchMemo{views: make(map[string]map[responseNegativeKey]struct{})}
}

func responseNegativePatternKey(p *compiledPattern) (responseNegativeKey, bool) {
	// Equal expression text alone does not establish the same syntax mode for
	// arbitrary regex objects. Only immutable response regexes built by our
	// regexp.Compile path can participate. Extra required-literal state stays
	// on the ordinary path instead of widening the key.
	if p.responseMemoRegexp == nil || p.responseMemoRegexp != p.re || len(p.requiredLiteralsAny) != 0 {
		return responseNegativeKey{}, false
	}
	return responseNegativeKey{regex: p.re.String(), companions: hasExternalTransferCompanions(p)}, true
}

func (m *responseMatchMemo) match(pf *responsePreFilter, patterns []*compiledPattern, content string) []ResponseMatch {
	if m == nil || len(content) < responseMemoMinBytes || len(content) > responseMemoMaxBytes {
		return matchPatternsPreFiltered(pf, patterns, content)
	}
	// String keys compare exact bytes, with no digest collision assumption.
	known := m.views[content]
	remaining := patterns
	remainingFilter := pf
	if len(known) > 0 {
		remaining = make([]*compiledPattern, 0, len(patterns))
		if pf != nil {
			remainingFilter = &responsePreFilter{}
		}
		for i, p := range patterns {
			key, eligible := responseNegativePatternKey(p)
			_, clean := known[key]
			if eligible && clean {
				continue
			}
			remaining = append(remaining, p)
			if pf != nil {
				remainingFilter.gates = append(remainingFilter.gates, pf.gates[i])
				if i < len(pf.proofs) {
					remainingFilter.proofs = append(remainingFilter.proofs, pf.proofs[i])
				} else {
					remainingFilter.proofs = append(remainingFilter.proofs, nil)
				}
			}
		}
	}
	if len(remaining) == 0 {
		return nil
	}
	result := matchPatternsPreFiltered(remainingFilter, remaining, content)
	if len(result) != 0 {
		return result
	}
	// Record only an entirely empty raw match result, before any caller can
	// remove defensive, suppressed or observed findings. A filtered finding
	// must never become evidence that the underlying regex had no match.
	if known == nil {
		if len(m.views) >= responseMemoMaxViews || m.bytes+len(content) > responseMemoMaxBytes || m.entries >= responseMemoMaxEntries {
			return nil
		}
		known = make(map[responseNegativeKey]struct{})
		m.views[content] = known
		m.bytes += len(content)
	}
	for _, p := range remaining {
		key, eligible := responseNegativePatternKey(p)
		if !eligible {
			continue
		}
		if _, exists := known[key]; exists {
			continue
		}
		if m.entries >= responseMemoMaxEntries {
			break
		}
		known[key] = struct{}{}
		m.entries++
	}
	return nil
}
