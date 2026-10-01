// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "github.com/luckyPipewrench/pipelock/internal/normalize"

type decodingMemoKey struct {
	text       string
	includeURL bool
}

// decodingMemo shares immutable decoded and normalized views within one scan. It never
// stores findings, policy decisions or state on the Scanner. Reaching either
// existing decoder work bound stops retention, not decoding or detection.
type decodingMemo struct {
	views         map[decodingMemoKey][]decodedResult
	normalized    map[string]string
	retainedBytes int
}

func (m *decodingMemo) decode(text string, includeURL bool) []decodedResult {
	if m == nil {
		return decodeEncodingsFixpoint(text, includeURL)
	}
	key := decodingMemoKey{text: text, includeURL: includeURL}
	if decoded, ok := m.views[key]; ok {
		return decoded
	}
	decoded := decodeEncodingsFixpoint(text, includeURL)
	if text == "" || len(m.views)+len(m.normalized) >= maxDecodeCandidates {
		return decoded
	}
	remaining := maxDecodeTotalBytes - m.retainedBytes
	cost := len(text)
	if cost > remaining {
		return decoded
	}
	for _, view := range decoded {
		if len(view.text) > remaining-cost {
			return decoded
		}
		cost += len(view.text)
	}
	if m.views == nil {
		m.views = make(map[decodingMemoKey][]decodedResult)
	}
	m.views[key] = decoded
	m.retainedBytes += cost
	return decoded
}

// normalize preserves each call's exact input and normalization depth. A
// normalized output is not treated as already normalized on a later call.
func (m *decodingMemo) normalize(text string) string {
	if m == nil {
		return normalize.ForDLP(text)
	}
	if normalized, ok := m.normalized[text]; ok {
		return normalized
	}
	normalized := normalize.ForDLP(text)
	if text == "" || len(m.views)+len(m.normalized) >= maxDecodeCandidates {
		return normalized
	}
	remaining := maxDecodeTotalBytes - m.retainedBytes
	if len(text) > remaining || len(normalized) > remaining-len(text) {
		return normalized
	}
	if m.normalized == nil {
		m.normalized = make(map[string]string)
	}
	m.normalized[text] = normalized
	m.retainedBytes += len(text) + len(normalized)
	return normalized
}
