// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// registerKillSwitchMetrics builds and registers the kill switch denial
// counter. The custom kill-switch state collector is registered separately
// via RegisterKillSwitchState once the controller is wired in.
func (m *Metrics) registerKillSwitchMetrics(reg *prometheus.Registry) {
	m.killSwitchDenials = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "kill_switch_denials_total",
		Help:      "Total requests denied by the kill switch.",
	}, []string{"transport", "endpoint"})

	reg.MustRegister(m.killSwitchDenials)
}

// RecordKillSwitchDenial increments the kill switch denial counter.
func (m *Metrics) RecordKillSwitchDenial(transport, endpoint string) {
	m.killSwitchDenials.WithLabelValues(transport, endpoint).Inc()
}

// RegisterKillSwitchState registers a custom collector that reports the
// current kill switch state as pipelock_kill_switch_active{source=...}
// gauges. The sourceFunc is called once per Prometheus scrape and should
// return the active/inactive state of each source (e.g. Controller.Sources).
func (m *Metrics) RegisterKillSwitchState(sourceFunc func() map[string]bool) {
	if sourceFunc == nil {
		return
	}
	m.registry.MustRegister(&killSwitchCollector{sourceFunc: sourceFunc})
}

// killSwitchCollector implements prometheus.Collector to report kill switch
// source states on each scrape. This avoids stale gauge values: the state
// is read fresh from the Controller on every Prometheus scrape request.
type killSwitchCollector struct {
	sourceFunc func() map[string]bool
}

var killSwitchActiveDesc = prometheus.NewDesc(
	"pipelock_kill_switch_active",
	"Whether a kill switch source is currently active (1) or inactive (0).",
	[]string{"source"}, nil,
)

func (c *killSwitchCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- killSwitchActiveDesc
}

func (c *killSwitchCollector) Collect(ch chan<- prometheus.Metric) {
	for source, active := range c.sourceFunc() {
		val := 0.0
		if active {
			val = 1.0
		}
		ch <- prometheus.MustNewConstMetric(killSwitchActiveDesc, prometheus.GaugeValue, val, source)
	}
}
