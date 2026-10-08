// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVerifyAELFieldsRejectsMalformedLifecycleAndContent(t *testing.T) {
	base := map[string]json.RawMessage{
		"key": json.RawMessage(`"key"`), "prev": json.RawMessage(`"prev"`),
		"recorder": json.RawMessage(`"pipelock"`), "run": json.RawMessage(`"run"`),
		"seq": json.RawMessage(`0`), "ts": json.RawMessage(`"time"`),
		"type": json.RawMessage(`"open"`), "v": json.RawMessage(`1`),
	}
	clone := func(extra map[string]string) map[string]json.RawMessage {
		fields := make(map[string]json.RawMessage, len(base)+len(extra))
		for key, value := range base {
			fields[key] = value
		}
		for key, value := range extra {
			fields[key] = json.RawMessage(value)
		}
		return fields
	}
	for _, tc := range []struct {
		name, kind, want string
		seq, count       uint64
		head, prev       string
		fields           map[string]json.RawMessage
	}{
		{"open after genesis", "open", "not first", 1, 0, "", "", clone(map[string]string{"hmax": `30`, "htol": `10`})},
		{"unknown type", "other", "unknown native AEL record type", 1, 0, "", "", clone(nil)},
		{"close count", "close", "close head or count differs", 1, 1, "previous", "previous", clone(map[string]string{"count": `1`, "head": `"previous"`})},
		{"close head", "close", "close head or count differs", 1, 2, "wrong", "previous", clone(map[string]string{"count": `2`, "head": `"wrong"`})},
		{"activity first", "activity", "invalid native AEL lifecycle order", 0, 0, "", "", clone(map[string]string{"event": `{"class":"read","dir":"in","id":"one"}`})},
		{"missing open field", "open", "record fields differ", 0, 0, "", "", clone(map[string]string{"hmax": `30`})},
		{"unexpected open field", "open", "unexpected native AEL field", 0, 0, "", "", clone(map[string]string{"hmax": `30`, "rogue": `10`})},
		{"invalid heartbeat maximum", "open", "invalid native AEL heartbeat maximum", 0, 0, "", "", clone(map[string]string{"hmax": `"bad"`, "htol": `10`})},
		{"invalid heartbeat tolerance", "open", "invalid native AEL heartbeat bounds", 0, 0, "", "", clone(map[string]string{"hmax": `30`, "htol": `"bad"`})},
		{"negative heartbeat maximum", "open", "invalid native AEL heartbeat bounds", 0, 0, "", "", clone(map[string]string{"hmax": `-1`, "htol": `0`})},
		{"negative heartbeat tolerance", "open", "invalid native AEL heartbeat bounds", 0, 0, "", "", clone(map[string]string{"hmax": `30`, "htol": `-1`})},
		{"excess heartbeat tolerance", "open", "invalid native AEL heartbeat bounds", 0, 0, "", "", clone(map[string]string{"hmax": `30`, "htol": `31`})},
		{"duplicate activity field", "activity", "duplicate", 1, 0, "", "", clone(map[string]string{"event": `{"class":"read","class":"write","dir":"in","id":"one"}`})},
		{"invalid activity", "activity", "invalid native AEL activity", 1, 0, "", "", clone(map[string]string{"event": `{"class":"read","dir":"sideways","id":"one"}`})},
		{"incomplete activity", "activity", "invalid native AEL activity fields", 1, 0, "", "", clone(map[string]string{"event": `{"class":"read","dir":"in","id":"one","extra":1}`})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyAELFields(tc.kind, tc.seq, tc.fields, tc.count, tc.head, tc.prev)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("verifyAELFields() = %v, want %q", err, tc.want)
			}
		})
	}
	if err := verifyAELFields("heartbeat", 1, clone(nil), 0, "", ""); err != nil {
		t.Fatalf("valid heartbeat rejected: %v", err)
	}
	if err := verifyAELFields("open", 0, clone(map[string]string{"hmax": `30`, "htol": `10`}), 0, "", ""); err != nil {
		t.Fatalf("valid opening rejected: %v", err)
	}
}
