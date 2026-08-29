// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package emit

func syslogHealthTestSink() (*SyslogSink, SinkHealth) {
	sink := &SyslogSink{queue: make(chan syslogMessage, 5)}
	sink.dropped.Store(3)
	sink.degraded.Store(true)
	sink.lastErr = "queue_full"
	return sink, SinkHealth{
		Sink:             SinkSyslog,
		Dropped:          3,
		QueueCap:         5,
		Degraded:         true,
		LastErrorPresent: true,
	}
}
