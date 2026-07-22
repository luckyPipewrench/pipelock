// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import "sort"

const (
	SinkWebhook = "webhook"
	SinkSyslog  = "syslog"
	SinkOTLP    = "otlp"
)

// SinkHealth is the transport-neutral delivery-health snapshot exposed to
// observability surfaces. LastErrorPresent deliberately records only state,
// never error text, so metrics cannot leak endpoint secrets or create
// attacker-controlled label cardinality.
type SinkHealth struct {
	Sink             string
	Delivered        uint64
	Failed           uint64
	Dropped          uint64
	Abandoned        uint64
	QueueLen         int
	QueueCap         int
	Degraded         bool
	LastErrorPresent bool
}

// sinkStats is the common delivery-health shape reported by built-in sinks.
// The exported per-sink Stats names remain aliases so callers keep their
// transport-specific vocabulary while health mapping stays centralized.
type sinkStats struct {
	Delivered uint64
	Failed    uint64
	Dropped   uint64
	Abandoned uint64
	Degraded  bool
	// LastError is the most recent failure, drop, or abandonment reason while
	// the sink is degraded. Built-in sinks clear it after successful delivery.
	LastError string
	QueueLen  int
	QueueCap  int
}

type sinkHealthProvider interface {
	SinkHealth() SinkHealth
}

// SinkHealth returns an aggregate snapshot of the emitter's built-in audit
// sinks. Delivery counters include retired generations so they remain
// process-lifetime monotonic across reloads; gauges include current and actively
// draining sinks only. It is pull-based and is never called from Emit.
// Same-type sinks are aggregated to keep the Prometheus label set unique.
func (e *Emitter) SinkHealth() []SinkHealth {
	if e == nil {
		return nil
	}

	e.mu.RLock()
	sinks := append([]Sink(nil), e.sinks...)
	for _, generation := range e.retiring {
		sinks = append(sinks, generation.sinks...)
	}
	retired := make([]SinkHealth, 0, len(e.retired))
	for _, health := range e.retired {
		retired = append(retired, health)
	}
	e.mu.RUnlock()

	bySink := make(map[string]SinkHealth, len(sinks)+len(retired))
	for _, health := range retired {
		bySink[health.Sink] = health
	}
	for _, sink := range sinks {
		provider, ok := sink.(sinkHealthProvider)
		if !ok {
			continue
		}
		current := provider.SinkHealth()
		if current.Sink == "" {
			continue
		}
		total := bySink[current.Sink]
		total.Sink = current.Sink
		total.Delivered += current.Delivered
		total.Failed += current.Failed
		total.Dropped += current.Dropped
		total.Abandoned += current.Abandoned
		total.QueueLen += current.QueueLen
		total.QueueCap += current.QueueCap
		total.Degraded = total.Degraded || current.Degraded
		total.LastErrorPresent = total.LastErrorPresent || current.LastErrorPresent
		bySink[current.Sink] = total
	}

	result := make([]SinkHealth, 0, len(bySink))
	for _, health := range bySink {
		result = append(result, health)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Sink < result[j].Sink })
	return result
}

func (w *WebhookSink) SinkHealth() SinkHealth {
	return sinkHealthFromStats(SinkWebhook, w.Stats())
}

func (s *SyslogSink) SinkHealth() SinkHealth {
	return sinkHealthFromStats(SinkSyslog, s.Stats())
}

func (s *OTLPSink) SinkHealth() SinkHealth {
	return sinkHealthFromStats(SinkOTLP, s.Stats())
}

func sinkHealthFromStats(sink string, stats sinkStats) SinkHealth {
	return SinkHealth{
		Sink:             sink,
		Delivered:        stats.Delivered,
		Failed:           stats.Failed,
		Dropped:          stats.Dropped,
		Abandoned:        stats.Abandoned,
		QueueLen:         stats.QueueLen,
		QueueCap:         stats.QueueCap,
		Degraded:         stats.Degraded,
		LastErrorPresent: stats.LastError != "",
	}
}

func (s *FilteringSink) SinkHealth() SinkHealth {
	if s == nil {
		return SinkHealth{}
	}
	provider, ok := s.sink.(sinkHealthProvider)
	if !ok {
		return SinkHealth{}
	}
	return provider.SinkHealth()
}
