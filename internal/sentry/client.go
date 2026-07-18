// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package plsentry

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Client wraps the Sentry SDK with event minimization. When disabled (enabled=false),
// all methods are safe no-ops. Nil-safe: (*Client)(nil).CaptureError(err) is a no-op.
//
// Uses the global Sentry hub - only one Client should be active per process.
// This is fine for pipelock (single binary, one of run or mcp active at a time).
type Client struct {
	scrubber *Scrubber
	enabled  bool
}

// Init initializes a Sentry client from config. Returns a no-op client when
// Sentry is disabled or no DSN is available (config or SENTRY_DSN env).
func Init(cfg *config.Config, version string) (*Client, error) {
	return initClient(cfg, version, nil)
}

// initClient is the internal initializer. When transport is non-nil it is
// injected into the Sentry SDK options (used by tests to capture events).
func initClient(cfg *config.Config, version string, transport sentry.Transport) (*Client, error) {
	if !cfg.Sentry.IsEnabled() {
		disableGlobalClient()
		return &Client{enabled: false}, nil
	}
	if cfg.Sentry.SampleRate != nil && *cfg.Sentry.SampleRate == 0 {
		disableGlobalClient()
		return nil, fmt.Errorf("invalid sentry.sample_rate 0.0: it does not disable Sentry in sentry-go; use sentry.enabled: false or an empty DSN")
	}

	// SENTRY_DSN env overrides config so users can redirect crash reports
	// without editing checked-in configs.
	dsn := os.Getenv("SENTRY_DSN")
	if dsn == "" {
		dsn = cfg.Sentry.DSN
	}
	if dsn == "" {
		disableGlobalClient()
		return &Client{enabled: false}, nil
	}

	// Build scrubber from DLP patterns + safety-net + env secrets + file secrets.
	var literalSecrets []string
	if cfg.DLP.ScanEnv {
		for _, kv := range os.Environ() {
			for i := range len(kv) {
				if kv[i] == '=' {
					val := kv[i+1:]
					if len(val) >= 8 {
						literalSecrets = append(literalSecrets, val)
					}
					break
				}
			}
		}
	}

	// Load file-backed explicit secrets (same file the scanner uses).
	if cfg.DLP.SecretsFile != "" {
		fileSecrets, err := loadFileSecrets(cfg.DLP.SecretsFile)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "pipelock: warning: sentry scrubber could not load secrets_file: %v\n", err)
		} else {
			literalSecrets = append(literalSecrets, fileSecrets...)
		}
	}

	scrubber := NewScrubber(cfg.DLP.Patterns, literalSecrets)

	opts := sentry.ClientOptions{
		Dsn:              dsn,
		Release:          version,
		Environment:      cfg.Sentry.Environment,
		SampleRate:       cfg.Sentry.EffectiveSampleRate(),
		Debug:            cfg.Sentry.Debug,
		AttachStacktrace: false,
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			if isUnsafeEventType(event) {
				return nil
			}
			return scrubber.ScrubEvent(event, hint)
		},
		BeforeSendTransaction: func(_ *sentry.Event, _ *sentry.EventHint) *sentry.Event {
			return nil
		},
		BeforeSendLog: func(_ *sentry.Log) *sentry.Log {
			return nil
		},
		BeforeSendMetric: func(_ *sentry.Metric) *sentry.Metric {
			return nil
		},
	}
	if transport != nil {
		opts.Transport = dropUnsafeEventTransport{delegate: transport, scrubber: scrubber}
	} else {
		opts.Transport = dropUnsafeEventTransport{delegate: sentry.NewHTTPTransport(), scrubber: scrubber}
	}

	err := sentry.Init(opts)
	if err != nil {
		disableGlobalClient()
		return nil, err
	}

	_, _ = fmt.Fprintln(os.Stderr, "pipelock: Sentry crash reporting enabled; crash reports go to the configured Sentry DSN and payloads are minimized without request bodies, headers, user, hostname, breadcrumbs, or local variables.")

	return &Client{scrubber: scrubber, enabled: true}, nil
}

func disableGlobalClient() {
	sentry.CurrentHub().BindClient(nil)
}

// CaptureError sends an error event to Sentry (scrubbed by BeforeSend and the
// transport guard).
// context.Canceled is dropped because it signals normal shutdown propagation
// (SIGINT, parent exit, session end), not a failure worth paging on.
// Expected operational errors (e.g. a listener bind hitting EADDRINUSE on a
// restart race or double-start) are also dropped: they are misconfiguration or
// environment conditions surfaced to stderr and a non-zero exit, not code
// defects worth a Sentry alert.
func (c *Client) CaptureError(err error) {
	if c == nil || !c.enabled {
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	if isExpectedOperationalError(err) {
		return
	}
	sentry.CaptureException(err)
}

// isExpectedOperationalError reports whether err is an environment/operator
// condition that should not page Sentry. Listener bind conflicts (EADDRINUSE)
// are the canonical case: a port already in use is an operational state, not a
// pipelock bug. Kept narrow on purpose - only clearly-operational syscall
// conditions belong here, so genuine listen failures (and everything else)
// still report.
func isExpectedOperationalError(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}

// CaptureMessage sends a message event to Sentry (scrubbed by BeforeSend and
// the transport guard).
func (c *Client) CaptureMessage(msg string) {
	if c == nil || !c.enabled {
		return
	}
	sentry.CaptureMessage(msg)
}

// AddBreadcrumb records local context for later Sentry events.
func (c *Client) AddBreadcrumb(category, message, level string, data map[string]any) {
	if c == nil || !c.enabled {
		return
	}
	sentry.AddBreadcrumb(&sentry.Breadcrumb{
		Category: category,
		Message:  message,
		Level:    sentry.Level(level),
		Data:     data,
	})
}

// Flush waits for queued events to be sent.
func (c *Client) Flush(timeout time.Duration) bool {
	if c == nil || !c.enabled {
		return true
	}
	return sentry.Flush(timeout)
}

// Close flushes and cleans up the Sentry client.
func (c *Client) Close() {
	if c == nil || !c.enabled {
		return
	}
	sentry.Flush(2 * time.Second)
}

// dropUnsafeEventTransport blocks SDK event classes that do not flow through
// the allowlist sanitizer. Check-ins intentionally skip BeforeSend in
// sentry-go, so the transport is the last in-process choke point.
type dropUnsafeEventTransport struct {
	delegate sentry.Transport
	scrubber *Scrubber
}

func (t dropUnsafeEventTransport) Configure(options sentry.ClientOptions) {
	if t.delegate != nil {
		t.delegate.Configure(options)
	}
}

func (t dropUnsafeEventTransport) SendEvent(event *sentry.Event) {
	if event == nil || isUnsafeEventType(event) || t.delegate == nil {
		return
	}
	safe := t.scrubber.ScrubEvent(event, nil)
	if safe == nil || isUnsafeEventType(safe) {
		return
	}
	t.delegate.SendEvent(safe)
}

func (t dropUnsafeEventTransport) Flush(timeout time.Duration) bool {
	if t.delegate == nil {
		return true
	}
	return t.delegate.Flush(timeout)
}

func (t dropUnsafeEventTransport) FlushWithContext(ctx context.Context) bool {
	if t.delegate == nil {
		return true
	}
	return t.delegate.FlushWithContext(ctx)
}

func (t dropUnsafeEventTransport) Close() {
	if t.delegate != nil {
		t.delegate.Close()
	}
}

func isUnsafeEventType(event *sentry.Event) bool {
	return event.Type == "check_in" ||
		event.Type == "transaction" ||
		event.CheckIn != nil ||
		event.MonitorConfig != nil ||
		len(event.Logs) > 0 ||
		len(event.Metrics) > 0
}

// loadFileSecrets reads literal secret values from a file, one per line.
// Skips blank lines, comment lines (# prefix), and values shorter than 8 chars.
// The scanner has a more robust version with BOM stripping and caps; this
// simplified version is sufficient for the scrubber's redaction needs.
func loadFileSecrets(path string) ([]string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("opening secrets file: %w", err)
	}
	defer func() { _ = f.Close() }()

	const minLen = 8 // match the env secret minimum

	var secrets []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) < minLen {
			continue
		}
		secrets = append(secrets, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading secrets file: %w", err)
	}
	return secrets, nil
}
