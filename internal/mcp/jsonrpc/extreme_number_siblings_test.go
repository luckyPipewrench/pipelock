// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonrpc

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestExtremeNumberKeepsVisibleAndScopedStrings(t *testing.T) {
	pattern := regexp.MustCompile(`^command$`)
	for _, num := range []string{"1.5", "1e999", "-1e999", "1E+400", "[1e999]"} {
		t.Run(num, func(t *testing.T) {
			raw := json.RawMessage(`{"command":{"text":"inspect me"},"n":` + num + `}`)
			for name, result := range map[string]ExtractStringsResult{
				"scoped":  ExtractStringsForKeysResult(raw, pattern),
				"visible": ExtractVisibleStringsFromJSONResult(raw),
			} {
				if result.Truncated || !slices.Contains(result.Strings, "inspect me") {
					t.Errorf("%s extraction lost string: %+v", name, result)
				}
			}
			deep := json.RawMessage(`{"n":` + num + `,"nested":` + strings.Repeat(`[`, MaxExtractDepth+1) + `0` + strings.Repeat(`]`, MaxExtractDepth+1) + `}`)
			if !jsonDepthTruncated(deep) {
				t.Error("depth accounting lost")
			}
			for _, suffix := range []string{` trailing`, ` {}`} {
				if got := ExtractVisibleStringsFromJSONResult(append(append(json.RawMessage(nil), raw...), suffix...)); len(got.Strings) != 0 {
					t.Error("partial document extracted")
				}
			}
		})
	}
}
