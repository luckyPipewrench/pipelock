// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package emit

import (
	"context"
	"errors"
)

// ErrSyslogUnavailable is returned on platforms where log/syslog is not available.
var ErrSyslogUnavailable = errors.New("emit: syslog is not available on Windows")

// SyslogSink is a stub on Windows where log/syslog is not available.
type SyslogSink struct{}

// SyslogStats reports delivery health for a SyslogSink.
type SyslogStats struct {
	Delivered uint64
	Failed    uint64
	Dropped   uint64
	Abandoned uint64
	Degraded  bool
	LastError string
	QueueLen  int
	QueueCap  int
}

// NewSyslogSink returns an error on Windows.
func NewSyslogSink(_ string, _ ...any) (*SyslogSink, error) {
	return nil, ErrSyslogUnavailable
}

// NewSyslogSinkFromConfig returns an error on Windows.
func NewSyslogSinkFromConfig(_, _, _, _ string) (*SyslogSink, error) {
	return nil, ErrSyslogUnavailable
}

// Emit is a stub that always returns an error on Windows.
func (s *SyslogSink) Emit(_ context.Context, _ Event) error {
	return ErrSyslogUnavailable
}

// Close is a stub that always returns an error on Windows.
func (s *SyslogSink) Close() error {
	return ErrSyslogUnavailable
}

// Stats returns an empty health snapshot on Windows.
func (s *SyslogSink) Stats() SyslogStats {
	return SyslogStats{}
}
