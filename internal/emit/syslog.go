// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package emit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/syslog"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultSyslogQueueSize = 64
	MaxSyslogQueueSize     = 4096
)

var syslogDrainTimeout = 10 * time.Second

// ErrSyslogQueueFull is returned when the syslog event queue is at capacity.
var ErrSyslogQueueFull = errors.New("emit: syslog queue full, event dropped")

// ErrSyslogCloseTimeout is returned when Close cannot drain the worker before the timeout.
var ErrSyslogCloseTimeout = errors.New("emit: syslog close timed out before drain completed")

// ErrSyslogDegraded is returned after a prior async delivery failure.
// The event may still be accepted for queueing; this error signals that the
// sink is not currently proving successful delivery.
var ErrSyslogDegraded = errors.New("emit: syslog sink degraded")

const errSyslogClosed = "emit: syslog sink closed"

type syslogWriter interface {
	Crit(string) error
	Warning(string) error
	Info(string) error
	Close() error
}

type syslogMessage struct {
	severity  Severity
	eventType string
	message   string
}

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

// SyslogSink sends audit events to a syslog server.
// It maps emit.Severity to syslog priority levels.
type SyslogSink struct {
	writer        syslogWriter
	minSev        Severity
	format        string
	deviceVersion string
	queue         chan syslogMessage
	done          chan struct{}
	closed        bool // guarded by closeMu
	closeMu       sync.Mutex
	closeWG       sync.WaitGroup
	closeOnce     sync.Once
	closeErr      error

	delivered atomic.Uint64
	failed    atomic.Uint64
	dropped   atomic.Uint64
	abandoned atomic.Uint64
	degraded  atomic.Bool
	lastErrMu sync.Mutex
	lastErr   string
}

// SyslogOption configures a SyslogSink.
type SyslogOption func(*syslogConfig)

type syslogConfig struct {
	facility      syslog.Priority
	tag           string
	minSev        Severity
	queueLen      int
	format        string
	deviceVersion string
}

// WithSyslogFacility sets the syslog facility (default LOG_LOCAL0).
func WithSyslogFacility(f syslog.Priority) SyslogOption {
	return func(c *syslogConfig) {
		c.facility = f
	}
}

// WithSyslogTag sets the syslog tag (default "pipelock").
func WithSyslogTag(tag string) SyslogOption {
	return func(c *syslogConfig) {
		c.tag = tag
	}
}

// WithSyslogMinSeverity sets the minimum severity for events to be emitted.
func WithSyslogMinSeverity(sev Severity) SyslogOption {
	return func(c *syslogConfig) {
		c.minSev = sev
	}
}

// WithSyslogQueueSize sets the buffered channel capacity for pending events.
func WithSyslogQueueSize(n int) SyslogOption {
	return func(c *syslogConfig) {
		c.queueLen = normalizeSyslogQueueSize(n)
	}
}

// WithSyslogFormat sets the wire format for syslog messages.
func WithSyslogFormat(format, deviceVersion string) SyslogOption {
	return func(c *syslogConfig) {
		c.format = format
		c.deviceVersion = deviceVersion
	}
}

// parseSyslogAddress parses "udp://host:port" or "tcp://host:port" into
// (network, address) suitable for syslog.Dial.
func parseSyslogAddress(addr string) (string, string, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return "", "", fmt.Errorf("emit: invalid syslog address %q: %w", addr, err)
	}
	network := strings.ToLower(u.Scheme)
	if network != networkUDP && network != "tcp" {
		return "", "", fmt.Errorf("emit: unsupported syslog address %q (use udp://host:port or tcp://host:port)", addr)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("emit: invalid syslog address %q (expected udp://host:port or tcp://host:port)", addr)
	}
	if _, _, splitErr := net.SplitHostPort(u.Host); splitErr != nil {
		return "", "", fmt.Errorf("emit: invalid syslog host:port %q: %w", u.Host, splitErr)
	}
	return network, u.Host, nil
}

// NewSyslogSink creates a SyslogSink connected to the given address.
// Address format: "udp://host:port" or "tcp://host:port".
func NewSyslogSink(address string, opts ...SyslogOption) (*SyslogSink, error) {
	cfg := &syslogConfig{
		facility: syslog.LOG_LOCAL0,
		tag:      "pipelock",
		queueLen: DefaultSyslogQueueSize,
		format:   FormatJSON,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if err := validateSyslogFormat(cfg.format); err != nil {
		return nil, err
	}

	network, addr, err := parseSyslogAddress(address)
	if err != nil {
		return nil, err
	}

	writer, err := syslog.Dial(network, addr, cfg.facility, cfg.tag)
	if err != nil {
		return nil, fmt.Errorf("emit: syslog dial: %w", err)
	}

	return newSyslogSink(writer, cfg), nil
}

func validateSyslogFormat(format string) error {
	if format == "" || format == FormatJSON || format == FormatCEF {
		return nil
	}
	return fmt.Errorf("emit: unsupported syslog format %q", format)
}

func newSyslogSink(writer syslogWriter, cfg *syslogConfig) *SyslogSink {
	cfg.queueLen = normalizeSyslogQueueSize(cfg.queueLen)
	if cfg.format == "" {
		cfg.format = FormatJSON
	}
	s := &SyslogSink{
		writer:        writer,
		minSev:        cfg.minSev,
		format:        cfg.format,
		deviceVersion: cfg.deviceVersion,
		queue:         make(chan syslogMessage, cfg.queueLen),
		done:          make(chan struct{}),
	}
	s.closeWG.Add(1)
	go s.run()
	return s
}

func normalizeSyslogQueueSize(n int) int {
	switch {
	case n <= 0:
		return DefaultSyslogQueueSize
	case n > MaxSyslogQueueSize:
		return MaxSyslogQueueSize
	default:
		return n
	}
}

// parseFacility converts a facility name string to a syslog.Priority.
// Supports: kern, user, mail, daemon, auth, syslog, lpr, news, uucp,
// local0 through local7. Returns LOG_LOCAL0 for unrecognized values.
func parseFacility(name string) syslog.Priority {
	switch strings.ToLower(name) {
	case "kern":
		return syslog.LOG_KERN
	case "user":
		return syslog.LOG_USER
	case "mail":
		return syslog.LOG_MAIL
	case "daemon":
		return syslog.LOG_DAEMON
	case "auth":
		return syslog.LOG_AUTH
	case "syslog":
		return syslog.LOG_SYSLOG
	case "lpr":
		return syslog.LOG_LPR
	case "news":
		return syslog.LOG_NEWS
	case "uucp":
		return syslog.LOG_UUCP
	case "local0":
		return syslog.LOG_LOCAL0
	case "local1":
		return syslog.LOG_LOCAL1
	case "local2":
		return syslog.LOG_LOCAL2
	case "local3":
		return syslog.LOG_LOCAL3
	case "local4":
		return syslog.LOG_LOCAL4
	case "local5":
		return syslog.LOG_LOCAL5
	case "local6":
		return syslog.LOG_LOCAL6
	case "local7":
		return syslog.LOG_LOCAL7
	default:
		fmt.Fprintf(os.Stderr, "emit: unrecognized syslog facility %q, using LOG_LOCAL0\n", name)
		return syslog.LOG_LOCAL0
	}
}

// NewSyslogSinkFromConfig creates a SyslogSink from string config values.
// This is a cross-platform entry point used by cli/run.go; on Windows it returns
// ErrSyslogUnavailable (defined in syslog_windows.go).
func NewSyslogSinkFromConfig(address, facility, tag, minSeverity string, extraOpts ...SyslogOption) (*SyslogSink, error) {
	var opts []SyslogOption
	opts = append(opts, WithSyslogMinSeverity(ParseSeverity(minSeverity)))
	if facility != "" {
		opts = append(opts, WithSyslogFacility(parseFacility(facility)))
	}
	if tag != "" {
		opts = append(opts, WithSyslogTag(tag))
	}
	opts = append(opts, extraOpts...)
	return NewSyslogSink(address, opts...)
}

// Emit enqueues an event for async delivery.
// Events below the minimum severity are silently dropped.
// Returns ErrSyslogQueueFull if the queue is at capacity, ErrSyslogDegraded if
// a prior async delivery failed, or an error if the sink is closed.
func (s *SyslogSink) Emit(_ context.Context, event Event) error {
	if s == nil || s.writer == nil || s.queue == nil {
		return errors.New("emit: syslog sink not initialized")
	}
	if event.Severity < s.minSev {
		return nil
	}
	msg, err := makeSyslogMessage(event, s.format, s.deviceVersion)
	if err != nil {
		return err
	}

	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return errors.New(errSyslogClosed)
	}
	degraded := s.degraded.Load()
	select {
	case s.queue <- msg:
		s.closeMu.Unlock()
		if degraded {
			return ErrSyslogDegraded
		}
		return nil
	default:
		s.closeMu.Unlock()
		s.recordDropped("queue_full", msg, nil)
		return ErrSyslogQueueFull
	}
}

func (s *SyslogSink) run() {
	defer s.closeWG.Done()

	for {
		select {
		case msg := <-s.queue:
			s.safeSend(msg)
		case <-s.done:
			s.drain()
			return
		}
	}
}

func (s *SyslogSink) drain() {
	deadline := time.Now().Add(syslogDrainTimeout)
	for {
		select {
		case msg := <-s.queue:
			if time.Now().After(deadline) {
				s.recordAbandoned("drain_timeout", msg, len(s.queue)+1)
				return
			}
			s.safeSend(msg)
		default:
			return
		}
	}
}

func (s *SyslogSink) safeSend(msg syslogMessage) {
	defer func() {
		if r := recover(); r != nil {
			s.recordFailure("panic", msg, fmt.Errorf("%v", r))
		}
	}()
	s.send(msg)
}

func makeSyslogMessage(event Event, format, deviceVersion string) (syslogMessage, error) {
	if format == "" {
		format = FormatJSON
	}
	if format == FormatCEF {
		msg := FormatCEFEvent(event, deviceVersion)
		return syslogMessage{
			severity:  event.Severity,
			eventType: event.Type,
			message:   msg,
		}, nil
	}
	if format != FormatJSON {
		return syslogMessage{}, fmt.Errorf("emit: unsupported syslog format %q", format)
	}

	payload := webhookPayload{
		Severity:  event.Severity.String(),
		Type:      event.Type,
		Timestamp: event.Timestamp.UTC().Format(time.RFC3339Nano),
		Instance:  event.InstanceID,
		Fields:    event.Fields,
	}

	msg, err := json.Marshal(payload)
	if err != nil {
		return syslogMessage{}, fmt.Errorf("emit: syslog marshal: %w", err)
	}

	return syslogMessage{
		severity:  event.Severity,
		eventType: event.Type,
		message:   string(msg),
	}, nil
}

func (s *SyslogSink) send(msg syslogMessage) {
	var writeErr error

	switch msg.severity {
	case SeverityCritical:
		writeErr = s.writer.Crit(msg.message)
	case SeverityWarn:
		writeErr = s.writer.Warning(msg.message)
	default:
		writeErr = s.writer.Info(msg.message)
	}
	if writeErr != nil {
		s.recordFailure("write_error", msg, writeErr)
		return
	}
	s.delivered.Add(1)
	s.degraded.Store(false)
}

// Close closes the syslog writer. Safe to call on a nil or already-closed writer.
func (s *SyslogSink) Close() error {
	if s == nil || s.writer == nil {
		return nil
	}

	s.closeOnce.Do(func() {
		writerClosed := false
		if s.done != nil {
			s.closeMu.Lock()
			s.closed = true
			s.closeMu.Unlock()
			close(s.done)

			drained := make(chan struct{})
			go func() {
				s.closeWG.Wait()
				close(drained)
			}()
			select {
			case <-drained:
			case <-time.After(syslogDrainTimeout):
				s.closeErr = ErrSyslogCloseTimeout
				s.recordAbandoned("close_timeout", syslogMessage{eventType: "unknown"}, len(s.queue)+1)
				if err := s.writer.Close(); err != nil {
					s.closeErr = errors.Join(s.closeErr, err)
				}
				writerClosed = true
				select {
				case <-drained:
				case <-time.After(syslogDrainTimeout):
				}
			}
		}
		if !writerClosed {
			err := s.writer.Close()
			s.closeErr = errors.Join(s.closeErr, err)
		}
	})
	return s.closeErr
}

// Stats returns a consistent snapshot of syslog sink delivery health.
func (s *SyslogSink) Stats() SyslogStats {
	if s == nil {
		return SyslogStats{}
	}
	s.lastErrMu.Lock()
	lastErr := s.lastErr
	s.lastErrMu.Unlock()
	stats := SyslogStats{
		Delivered: s.delivered.Load(),
		Failed:    s.failed.Load(),
		Dropped:   s.dropped.Load(),
		Abandoned: s.abandoned.Load(),
		Degraded:  s.degraded.Load(),
		LastError: lastErr,
	}
	if s.queue != nil {
		stats.QueueLen = len(s.queue)
		stats.QueueCap = cap(s.queue)
	}
	return stats
}

func (s *SyslogSink) recordFailure(reason string, msg syslogMessage, err error) {
	s.failed.Add(1)
	s.degraded.Store(true)
	if err != nil {
		s.lastErrMu.Lock()
		s.lastErr = err.Error()
		s.lastErrMu.Unlock()
	}
	s.logDiagnostic("delivery_failed", reason, msg, err, 0)
}

func (s *SyslogSink) recordDropped(reason string, msg syslogMessage, err error) {
	s.dropped.Add(1)
	s.degraded.Store(true)
	lastErr := reason
	if err != nil {
		lastErr = err.Error()
	}
	s.lastErrMu.Lock()
	s.lastErr = lastErr
	s.lastErrMu.Unlock()
	s.logDiagnostic("event_dropped", reason, msg, err, 0)
}

func (s *SyslogSink) recordAbandoned(reason string, msg syslogMessage, count int) {
	if count < 1 {
		count = 1
	}
	s.abandoned.Add(uint64(count))
	s.degraded.Store(true)
	s.lastErrMu.Lock()
	s.lastErr = reason
	s.lastErrMu.Unlock()
	s.logDiagnostic("events_abandoned", reason, msg, nil, count)
}

func (s *SyslogSink) logDiagnostic(event, reason string, msg syslogMessage, err error, count int) {
	fields := map[string]any{
		"component":  "emit.syslog",
		"event":      event,
		"reason":     reason,
		"event_type": msg.eventType,
		"delivered":  s.delivered.Load(),
		"failed":     s.failed.Load(),
		"dropped":    s.dropped.Load(),
		"abandoned":  s.abandoned.Load(),
		"queue_len":  len(s.queue),
		"queue_cap":  cap(s.queue),
	}
	if err != nil {
		fields["error"] = err.Error()
	}
	if count > 0 {
		fields["count"] = count
	}
	encoded, marshalErr := json.Marshal(fields)
	if marshalErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "emit: syslog diagnostic marshal error: %v\n", marshalErr)
		return
	}
	_, _ = fmt.Fprintln(os.Stderr, string(encoded))
}
