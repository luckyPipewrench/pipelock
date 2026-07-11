//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func (m *Metrics) registerSIEMForwarderMetrics(reg *prometheus.Registry) {
	m.siemForwarderQueued = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pipelock_siem_forwarder_queued",
		Help: "Current number of audit events waiting in the in-memory SIEM forwarder queue.",
	})
	m.siemForwarderDelivered = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pipelock_siem_forwarder_delivered_total",
		Help: "Audit events acknowledged by the configured SIEM forwarding endpoint.",
	})
	m.siemForwarderFailed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pipelock_siem_forwarder_failed_total",
		Help: "SIEM forwarding persistence or delivery failures.",
	})
	m.siemForwarderDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pipelock_siem_forwarder_dropped_total",
		Help: "Audit events dropped because the SIEM forwarder queue was full.",
	})
	m.siemForwarderLastSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pipelock_siem_forwarder_last_success_timestamp_seconds",
		Help: "Unix timestamp of the last SIEM forwarder delivery acknowledged by the endpoint.",
	})
	m.siemForwarderSpoolBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pipelock_siem_forwarder_spool_bytes",
		Help: "Current on-disk size of the durable SIEM forwarder spool, bounded by max_spool_bytes.",
	})
	reg.MustRegister(m.siemForwarderQueued, m.siemForwarderDelivered, m.siemForwarderFailed, m.siemForwarderDropped, m.siemForwarderLastSuccess, m.siemForwarderSpoolBytes)
}

func (m *Metrics) SetQueued(value float64) { m.siemForwarderQueued.Set(value) }
func (m *Metrics) RecordDelivered()        { m.siemForwarderDelivered.Inc() }
func (m *Metrics) RecordFailed()           { m.siemForwarderFailed.Inc() }
func (m *Metrics) RecordDropped()          { m.siemForwarderDropped.Inc() }
func (m *Metrics) SetLastSuccess(at time.Time) {
	m.siemForwarderLastSuccess.Set(float64(at.Unix()))
}
func (m *Metrics) SetSpoolBytes(value float64) { m.siemForwarderSpoolBytes.Set(value) }
