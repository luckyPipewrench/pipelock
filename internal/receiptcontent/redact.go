// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// RedactValues returns detail with each string value at the given concrete
// paths replaced by replace(path, value). It is for producers sanitizing an
// unsigned template before signing; it never touches signed bytes. Only
// redactable atom findings (see Report.Redactable) may be passed. A path that
// names a non-string value, or that does not exist, is a rejection: a number
// or member name cannot be replaced without changing the schema.
func (p *Producer) RedactValues(detail []byte, paths []string, replace func(path, value string) string) ([]byte, error) {
	reject := func(path string) error {
		return &RejectionError{Kind: p.schema.Kind, View: ViewAtom, Path: path, Reason: "value cannot be redacted"}
	}
	want := make(map[string]bool, len(paths))
	for _, path := range paths {
		want[path] = false
	}
	dec := json.NewDecoder(bytes.NewReader(detail))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, &RejectionError{Kind: p.schema.Kind, View: ViewMalformed, Reason: "detail is not valid JSON"}
	}
	var rewrite func(v any, path string) any
	rewrite = func(v any, path string) any {
		switch val := v.(type) {
		case map[string]any:
			for k, child := range val {
				val[k] = rewrite(child, joinPath(path, k))
			}
		case []any:
			for i, child := range val {
				val[i] = rewrite(child, path+"["+strconv.Itoa(i)+"]")
			}
		case string:
			if _, ok := want[path]; ok {
				want[path] = true
				return replace(path, val)
			}
		}
		return v
	}
	root = rewrite(root, "")
	for path, done := range want {
		if !done {
			return nil, reject(path)
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(root); err != nil {
		return nil, &RejectionError{Kind: p.schema.Kind, View: ViewMalformed, Reason: "redacted detail cannot be encoded"}
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
