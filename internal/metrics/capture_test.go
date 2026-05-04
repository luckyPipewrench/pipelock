// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordCaptureSessionIDSanitized(t *testing.T) {
	t.Parallel()
	m := New()

	m.RecordCaptureSessionIDSanitized("unsafe_path")
	m.RecordCaptureSessionIDSanitized("unsafe_path")
	m.RecordCaptureSessionIDSanitized("overlength")
	m.RecordCaptureSessionIDSanitized("unknown")

	if got := testutil.ToFloat64(m.captureSessionIDSanitized.WithLabelValues("unsafe_path")); got != 2 {
		t.Errorf("unsafe_path counter = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.captureSessionIDSanitized.WithLabelValues("overlength")); got != 1 {
		t.Errorf("overlength counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.captureSessionIDSanitized.WithLabelValues("unknown")); got != 1 {
		t.Errorf("unknown counter = %v, want 1", got)
	}
}

func TestRecordCaptureSessionIDSanitized_DropsNonCanonical(t *testing.T) {
	t.Parallel()
	m := New()

	m.RecordCaptureSessionIDSanitized("../../../etc/passwd")
	m.RecordCaptureSessionIDSanitized("")

	for _, label := range []string{"unsafe_path", "overlength", "unknown"} {
		if got := testutil.ToFloat64(m.captureSessionIDSanitized.WithLabelValues(label)); got != 0 {
			t.Errorf("%s counter = %v, want 0 after non-canonical inputs", label, got)
		}
	}
}

func TestRecordCaptureActionClassSanitized(t *testing.T) {
	t.Parallel()
	m := New()

	m.RecordCaptureActionClassSanitized("missing")
	m.RecordCaptureActionClassSanitized("normalized")
	m.RecordCaptureActionClassSanitized("normalized")
	m.RecordCaptureActionClassSanitized("non_canonical")

	if got := testutil.ToFloat64(m.captureActionClassSanitized.WithLabelValues("missing")); got != 1 {
		t.Errorf("missing counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.captureActionClassSanitized.WithLabelValues("normalized")); got != 2 {
		t.Errorf("normalized counter = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.captureActionClassSanitized.WithLabelValues("non_canonical")); got != 1 {
		t.Errorf("non_canonical counter = %v, want 1", got)
	}
}

func TestRecordCaptureActionClassSanitized_DropsNonCanonical(t *testing.T) {
	t.Parallel()
	m := New()

	m.RecordCaptureActionClassSanitized("read")
	m.RecordCaptureActionClassSanitized("")

	for _, label := range []string{"missing", "normalized", "non_canonical"} {
		if got := testutil.ToFloat64(m.captureActionClassSanitized.WithLabelValues(label)); got != 0 {
			t.Errorf("%s counter = %v, want 0 after non-canonical inputs", label, got)
		}
	}
}

func TestRecordCaptureDrop_NilSafe(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordCaptureDrop()
}
