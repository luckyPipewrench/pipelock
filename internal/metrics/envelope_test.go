// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordEnvelopeVerify_AllResultLabels(t *testing.T) {
	t.Parallel()
	m := New()

	for _, result := range []EnvelopeVerifyResult{
		EnvelopeVerifyDisabled,
		EnvelopeVerifyVerified,
		EnvelopeVerifyMissing,
		EnvelopeVerifyFailed,
	} {
		m.RecordEnvelopeVerify(result)
	}
	m.RecordEnvelopeVerify(EnvelopeVerifyFailed)

	cases := map[string]float64{
		"disabled": 1,
		"verified": 1,
		"missing":  1,
		"failed":   2,
	}
	for result, want := range cases {
		if got := testutil.ToFloat64(m.envelopeVerifyTotal.WithLabelValues(result)); got != want {
			t.Errorf("result=%s counter = %v, want %v", result, got, want)
		}
	}
}

func TestRecordEnvelopeVerify_DropsNonCanonical(t *testing.T) {
	t.Parallel()
	m := New()

	m.RecordEnvelopeVerify(EnvelopeVerifyResult("signature_error_with_user_input"))
	m.RecordEnvelopeVerify(EnvelopeVerifyResult(""))

	for _, result := range []string{"disabled", "verified", "missing", "failed"} {
		if got := testutil.ToFloat64(m.envelopeVerifyTotal.WithLabelValues(result)); got != 0 {
			t.Errorf("result=%s counter = %v, want 0 after non-canonical inputs", result, got)
		}
	}
}

func TestRecordEnvelopeVerify_NilSafe(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordEnvelopeVerify(EnvelopeVerifyVerified)
}
