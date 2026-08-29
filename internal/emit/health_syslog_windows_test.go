// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package emit

func syslogHealthTestSink() (*SyslogSink, SinkHealth) {
	return &SyslogSink{}, SinkHealth{Sink: SinkSyslog}
}
