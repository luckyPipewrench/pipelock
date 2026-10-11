// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// TestCanonicalAndWireNestedParity extends the top-level parity check to
// every nested signed object. A wire field missing from its canonical form
// would be persisted but not signed, and a field the content schema does not
// classify would be persisted without a content decision.
func TestCanonicalAndWireNestedParity(t *testing.T) {
	classes := actionReceiptProducer.Classification()
	// covered reports whether path is classified, or sits under a generated
	// subtree or a dynamic object whose members are all scanned.
	covered := func(path string) bool {
		for p := path; p != ""; {
			if c, ok := classes[p]; ok {
				return p == path || c == receiptcontent.Generated || c == receiptcontent.Dynamic
			}
			i := strings.LastIndex(p, ".")
			if i < 0 {
				break
			}
			p = p[:i]
		}
		return false
	}
	for _, pair := range []struct {
		prefix          string
		wire, canonical any
	}{
		{"action_record", ActionRecord{}, actionRecordCanonicalV1{}},
		{"action_record.recent_taint_sources[]", session.TaintSourceRef{}, taintSourceRefCanonicalV1{}},
		{"action_record.key_transition", KeyTransition{}, keyTransitionCanonicalV1{}},
		{"action_record.session_control", SessionControl{}, sessionControlCanonicalV1{}},
		{"action_record.session_control.open", SessionOpen{}, sessionOpenCanonicalV1{}},
		{"action_record.session_control.heartbeat", SessionHeartbeat{}, sessionHeartbeatCanonicalV1{}},
		{"action_record.session_control.close", SessionClose{}, sessionCloseCanonicalV1{}},
		{"action_record.redaction", RedactionSummary{}, redactionSummaryCanonicalV1{}},
		{"action_record.shield", ShieldSummary{}, shieldSummaryCanonicalV1{}},
	} {
		wire := jsonTags(reflect.TypeOf(pair.wire))
		canonical := jsonTags(reflect.TypeOf(pair.canonical))
		for name := range wire {
			if !canonical[name] {
				t.Errorf("%s: wire field %q is not signed by the canonical form", pair.prefix, name)
			}
			if !covered(pair.prefix + "." + name) {
				t.Errorf("%s: wire field %q has no content classification", pair.prefix, name)
			}
		}
		for name := range canonical {
			if !wire[name] {
				t.Errorf("%s: canonical field %q has no wire field", pair.prefix, name)
			}
		}
	}
}
