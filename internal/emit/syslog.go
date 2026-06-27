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

const errSyslogClosed = "emit: syslog sink closed"

type syslogWriter interface {
	Crit(string) error
	Warning(string) error
	Info(string) error
	Close() error
}

// SyslogSink sends audit events to a syslog server.
// It maps emit.Severity to syslog priority levels.
type SyslogSink struct {
	writer    syslogWriter
	minSev    Severity
	queue     chan Event
	done      chan struct{}
	closed    bool // guarded by closeMu
	closeMu   sync.Mutex
	closeWG   sync.WaitGroup
	closeOnce sync.Once
}

// SyslogOption configures a SyslogSink.
type SyslogOption func(*syslogConfig)

type syslogConfig struct {
	facility syslog.Priority
	tag      string
	minSev   Severity
	queueLen int
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
	}
	for _, opt := range opts {
		opt(cfg)
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

func newSyslogSink(writer syslogWriter, cfg *syslogConfig) *SyslogSink {
	cfg.queueLen = normalizeSyslogQueueSize(cfg.queueLen)
	s := &SyslogSink{
		writer: writer,
		minSev: cfg.minSev,
		queue:  make(chan Event, cfg.queueLen),
		done:   make(chan struct{}),
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
func NewSyslogSinkFromConfig(address, facility, tag, minSeverity string) (*SyslogSink, error) {
	var opts []SyslogOption
	opts = append(opts, WithSyslogMinSeverity(ParseSeverity(minSeverity)))
	if facility != "" {
		opts = append(opts, WithSyslogFacility(parseFacility(facility)))
	}
	if tag != "" {
		opts = append(opts, WithSyslogTag(tag))
	}
	return NewSyslogSink(address, opts...)
}

// Emit enqueues an event for async delivery.
// Events below the minimum severity are silently dropped.
// Returns ErrSyslogQueueFull if the queue is at capacity, or an error if the sink is closed.
func (s *SyslogSink) Emit(_ context.Context, event Event) error {
	if s == nil || s.writer == nil || s.queue == nil {
		return errors.New("emit: syslog sink not initialized")
	}
	if event.Severity < s.minSev {
		return nil
	}
	event = cloneEvent(event)

	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return errors.New(errSyslogClosed)
	}
	select {
	case s.queue <- event:
		s.closeMu.Unlock()
		return nil
	default:
		s.closeMu.Unlock()
		return ErrSyslogQueueFull
	}
}

func (s *SyslogSink) run() {
	defer s.closeWG.Done()

	for {
		select {
		case event := <-s.queue:
			s.safeSend(event)
		case <-s.done:
			s.drain()
			return
		}
	}
}

func (s *SyslogSink) drain() {
	deadline := time.After(syslogDrainTimeout)
	for {
		select {
		case event := <-s.queue:
			s.safeSend(event)
		case <-deadline:
			return
		default:
			return
		}
	}
}

func (s *SyslogSink) safeSend(event Event) {
	defer func() {
		if r := recover(); r != nil {
			_, _ = fmt.Fprintf(os.Stderr, "emit: syslog send panic for event %s: %v\n", event.Type, r)
		}
	}()
	s.send(event)
}

func (s *SyslogSink) send(event Event) {
	payload := webhookPayload{
		Severity:  event.Severity.String(),
		Type:      event.Type,
		Timestamp: event.Timestamp.UTC().Format(time.RFC3339Nano),
		Instance:  event.InstanceID,
		Fields:    event.Fields,
	}

	msg, err := json.Marshal(payload)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "emit: syslog marshal error: %v\n", err)
		return
	}

	message := string(msg)
	var writeErr error

	switch event.Severity {
	case SeverityCritical:
		writeErr = s.writer.Crit(message)
	case SeverityWarn:
		writeErr = s.writer.Warning(message)
	default:
		writeErr = s.writer.Info(message)
	}
	if writeErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "emit: syslog send error: %v\n", writeErr)
	}
}

// Close closes the syslog writer. Safe to call on a nil or already-closed writer.
func (s *SyslogSink) Close() error {
	if s == nil || s.writer == nil {
		return nil
	}

	var closeErr error
	s.closeOnce.Do(func() {
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
				closeErr = ErrSyslogCloseTimeout
			}
		}
		if err := s.writer.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	})
	return closeErr
}

func cloneEvent(event Event) Event {
	if event.Fields == nil {
		return event
	}
	fields := make(map[string]any, len(event.Fields))
	for k, v := range event.Fields {
		fields[k] = v
	}
	event.Fields = fields
	return event
}
