// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package emit

import "testing"

// Windows has no syslog transport; its unsupported-constructor tests remain
// authoritative. This adapter exercises the Unix writer acknowledgement.
type lifecycleSyslogWriter struct{ deliver func() error }

func (w lifecycleSyslogWriter) Info(string) error    { return w.deliver() }
func (w lifecycleSyslogWriter) Warning(string) error { return w.deliver() }
func (w lifecycleSyslogWriter) Crit(string) error    { return w.deliver() }
func (lifecycleSyslogWriter) Close() error           { return nil }

func TestSyslogAsyncSinkLifecycle(t *testing.T) {
	runAsyncSinkLifecycle(t, func(_ *testing.T, deliver func() error) lifecycleSink {
		s := newSyslogSink(lifecycleSyslogWriter{deliver}, &syslogConfig{queueLen: 1, minSev: SeverityWarn})
		return lifecycleSink{s, s.Stats, ErrSyslogQueueFull, ErrSyslogDegraded}
	})
}
