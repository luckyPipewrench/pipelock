//go:build !enterprise

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func (m *Metrics) registerSIEMForwarderMetrics(_ *prometheus.Registry) {
	if m == nil {
		return
	}
	_ = m.siemForwarderQueued
	_ = m.siemForwarderDelivered
	_ = m.siemForwarderFailed
	_ = m.siemForwarderDropped
	_ = m.siemForwarderLastSuccess
	_ = m.siemForwarderSpoolBytes
}

func (*Metrics) SetQueued(float64)        {}
func (*Metrics) RecordDelivered()         {}
func (*Metrics) RecordFailed()            {}
func (*Metrics) RecordDropped()           {}
func (*Metrics) SetLastSuccess(time.Time) {}
func (*Metrics) SetSpoolBytes(float64)    {}
