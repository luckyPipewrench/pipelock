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
