package plsentry

import (
	"os"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Client wraps the Sentry SDK with secret scrubbing. When disabled (enabled=false),
// all methods are safe no-ops. Nil-safe: (*Client)(nil).CaptureError(err) is a no-op.
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
	if !cfg.Sentry.SentryEnabled() {
		return &Client{enabled: false}, nil
	}

	dsn := cfg.Sentry.DSN
	if dsn == "" {
		dsn = os.Getenv("SENTRY_DSN")
	}
	if dsn == "" {
		return &Client{enabled: false}, nil
	}

	// Build scrubber from DLP patterns + safety-net + env secrets.
	var envSecrets []string
	if cfg.DLP.ScanEnv {
		for _, kv := range os.Environ() {
			for i := range len(kv) {
				if kv[i] == '=' {
					val := kv[i+1:]
					if len(val) >= 8 {
						envSecrets = append(envSecrets, val)
					}
					break
				}
			}
		}
	}

	scrubber := NewScrubber(cfg.DLP.Patterns, envSecrets)

	opts := sentry.ClientOptions{
		Dsn:              dsn,
		Release:          version,
		Environment:      cfg.Sentry.Environment,
		SampleRate:       cfg.Sentry.SampleRate,
		Debug:            cfg.Sentry.Debug,
		AttachStacktrace: true,
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			return scrubber.ScrubEvent(event, hint)
		},
	}
	if transport != nil {
		opts.Transport = transport
	}

	err := sentry.Init(opts)
	if err != nil {
		return nil, err
	}

	return &Client{scrubber: scrubber, enabled: true}, nil
}

// CaptureError sends an error event to Sentry (scrubbed by BeforeSend).
func (c *Client) CaptureError(err error) {
	if c == nil || !c.enabled {
		return
	}
	sentry.CaptureException(err)
}

// CaptureMessage sends a message event to Sentry (scrubbed by BeforeSend).
func (c *Client) CaptureMessage(msg string) {
	if c == nil || !c.enabled {
		return
	}
	sentry.CaptureMessage(msg)
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
