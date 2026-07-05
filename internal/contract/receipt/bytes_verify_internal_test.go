// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEmittedPayloadBytesRejectsUnknownKind(t *testing.T) {
	t.Parallel()

	_, err := emittedPayloadBytes(PayloadKind("unknown_payload"), json.RawMessage(`{}`))
	if !errors.Is(err, ErrUnknownPayloadKind) {
		t.Fatalf("emittedPayloadBytes unknown kind error = %v, want ErrUnknownPayloadKind", err)
	}
}

func TestMarshalStrictPayloadRejectsMalformedPayloadBytes(t *testing.T) {
	t.Parallel()

	_, err := marshalStrictPayload[PayloadProxyDecisionStruct](json.RawMessage(`{"action_type":"block","unknown":true}`))
	if err == nil {
		t.Fatal("marshalStrictPayload accepted unknown payload field")
	}
	if !strings.Contains(err.Error(), "decode v2 receipt payload bytes") {
		t.Fatalf("marshalStrictPayload error = %q, want decode context", err)
	}
}
