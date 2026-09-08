// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"bytes"
	"encoding/json"
	"testing"
)

// The three JSON walkers each refuse a delimiter they do not recognize rather
// than treating the value as consumed. A caller reached through the exported
// entry points cannot produce that state, because encoding/json reports a
// stray closing brace as a parse error, so these drive the walkers directly
// with a decoder already positioned on one.
//
// This matters beyond coverage: the refusal is what stops a walker from
// reporting a document as fully represented when it stopped early. Reporting
// success there would leave the body on the raw concatenated stream alone,
// which cannot rejoin a split separated by unrelated padding.
func TestJSONWalkersRefuseAnUnrecognizedDelimiter(t *testing.T) {
	t.Parallel()

	// positioned returns a decoder whose next token is the closing brace of an
	// empty object, which is a delimiter none of the walkers accept as a value.
	positioned := func(t *testing.T) *json.Decoder {
		t.Helper()
		decoder := json.NewDecoder(bytes.NewReader([]byte(`{}`)))
		decoder.UseNumber()
		open, err := decoder.Token()
		if err != nil {
			t.Fatalf("priming the decoder failed: %v", err)
		}
		if open != json.Delim('{') {
			t.Fatalf("primed token = %v, want an opening brace", open)
		}
		return decoder
	}

	limits := JSONLeafLimits{MaxDepth: 8, MaxStreams: 8, MaxPathBytes: 256}

	t.Run("bucket walker", func(t *testing.T) {
		t.Parallel()
		state := jsonLeafBucketState{payloads: make(map[string][]byte), bucketCount: 8, key: []byte("k")}
		if appendJSONLeafBucketPayload(positioned(t), &state, []byte("$"), 0, limits) {
			t.Fatal("bucket walker accepted a closing delimiter as a value")
		}
	})

	t.Run("partial walker", func(t *testing.T) {
		t.Parallel()
		state := jsonLeafPartialState{payloads: make(map[string][]byte)}
		if appendJSONLeafPayloadPartial(positioned(t), &state, []byte("$"), 0, limits) {
			t.Fatal("partial walker accepted a closing delimiter as a value")
		}
	})

	t.Run("value skipper", func(t *testing.T) {
		t.Parallel()
		if skipJSONValue(positioned(t)) {
			t.Fatal("value skipper accepted a closing delimiter as a skipped value")
		}
	})
}

// An exhausted decoder must also refuse rather than report an empty value as
// consumed, which is the same failure direction one token earlier.
func TestJSONWalkersRefuseAnExhaustedDecoder(t *testing.T) {
	t.Parallel()

	exhausted := func() *json.Decoder {
		decoder := json.NewDecoder(bytes.NewReader(nil))
		decoder.UseNumber()
		return decoder
	}

	if skipJSONValue(exhausted()) {
		t.Fatal("value skipper accepted an exhausted decoder")
	}
}
