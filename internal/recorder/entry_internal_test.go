// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestDecodeEntryDetailRejectsMalformedRawJSON(t *testing.T) {
	t.Parallel()

	if _, err := decodeEntryDetail(json.RawMessage(`{"unterminated":`)); err == nil {
		t.Fatal("decodeEntryDetail accepted malformed raw detail")
	}
}

func TestReadEntriesFromReaderRejectsUnrepresentableRawDetail(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	line := fmt.Sprintf(
		`{"v":2,"seq":0,"ts":%q,"session_id":"s1","type":"request","transport":"fetch","summary":"bad detail","detail":1e10000,"prev_hash":"genesis","hash":"abc"}`+"\n",
		ts,
	)

	_, err := ReadEntriesFromReader(bytes.NewBufferString(line))
	if err == nil {
		t.Fatal("ReadEntriesFromReader accepted detail that cannot decode into the public Detail view")
	}
}
