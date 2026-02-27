//go:build !windows

package emit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/syslog"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// SyslogSink sends audit events to a syslog server.
// It maps emit.Severity to syslog priority levels.
type SyslogSink struct {
	writer *syslog.Writer
	minSev Severity
}

// SyslogOption configures a SyslogSink.
type SyslogOption func(*syslogConfig)

type syslogConfig struct {
	facility syslog.Priority
	tag      string
	minSev   Severity
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

// parseSyslogAddress parses "udp://host:port" or "tcp://host:port" into
// (network, address) suitable for syslog.Dial.
func parseSyslogAddress(addr string) (string, string, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return "", "", fmt.Errorf("emit: invalid syslog address %q: %w", addr, err)
	}
	network := strings.ToLower(u.Scheme)
	if network != "udp" && network != "tcp" {
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

	return &SyslogSink{
		writer: writer,
		minSev: cfg.minSev,
	}, nil
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

// Emit writes an event to syslog at the appropriate priority level.
// Events below the minimum severity are silently dropped.
func (s *SyslogSink) Emit(_ context.Context, event Event) error {
	if event.Severity < s.minSev {
		return nil
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
		return fmt.Errorf("emit: syslog marshal: %w", err)
	}

	message := string(msg)

	switch event.Severity {
	case SeverityCritical:
		return s.writer.Crit(message)
	case SeverityWarn:
		return s.writer.Warning(message)
	default:
		return s.writer.Info(message)
	}
}

// Close closes the syslog writer. Safe to call on a nil or already-closed writer.
func (s *SyslogSink) Close() error {
	if s == nil || s.writer == nil {
		return nil
	}
	return s.writer.Close()
}
