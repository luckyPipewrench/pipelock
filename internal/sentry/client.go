package plsentry

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Client wraps the Sentry SDK with secret scrubbing. When disabled (enabled=false),
// all methods are safe no-ops. Nil-safe: (*Client)(nil).CaptureError(err) is a no-op.
//
// Uses the global Sentry hub — only one Client should be active per process.
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
		return &Client{enabled: false}, nil
	}

	// SENTRY_DSN env overrides config so users can redirect crash reports
	// away from the maintainer DSN shipped in preset configs.
	dsn := os.Getenv("SENTRY_DSN")
	if dsn == "" {
		dsn = cfg.Sentry.DSN
	}
	if dsn == "" {
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
