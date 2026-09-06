//go:build !windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import "errors"

func syslogHealthTransitionCases() []sinkHealthTransitionCase {
	newSink := func() *SyslogSink { return &SyslogSink{queue: make(chan syslogMessage, 1)} }

	failure := newSink()
	drop := newSink()
	abandon := newSink()
	return []sinkHealthTransitionCase{
		{
			name: "syslog failure", lock: failure.lastErrMu.Lock, unlock: failure.lastErrMu.Unlock,
			transition: func() { failure.recordFailure("write_error", syslogMessage{}, errors.New("write failed")) }, blockedOn: "(*SyslogSink).recordFailure", count: failure.failed.Load, stats: failure.Stats, health: failure.SinkHealth,
		},
		{
			name: "syslog drop", lock: drop.lastErrMu.Lock, unlock: drop.lastErrMu.Unlock,
			transition: func() { drop.recordDropped() }, blockedOn: "(*SyslogSink).recordDropped", count: drop.dropped.Load, stats: drop.Stats, health: drop.SinkHealth,
		},
		{
			name: "syslog abandon", lock: abandon.lastErrMu.Lock, unlock: abandon.lastErrMu.Unlock,
			transition: func() { abandon.recordAbandoned("close_timeout", syslogMessage{}, 1) }, blockedOn: "(*SyslogSink).recordAbandoned", count: abandon.abandoned.Load, stats: abandon.Stats, health: abandon.SinkHealth,
		},
	}
}
