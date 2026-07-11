//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package siemforward provides durable, asynchronous HTTP forwarding for
// Pipelock audit events. Accepted events are first appended to a local spool;
// a content-bound cursor advances only after the remote endpoint acknowledges
// delivery, giving at-least-once replay across process restarts.
package siemforward

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	SchemaV1             = "pipelock.siem.event.v1"
	cursorVersion        = 1
	defaultQueueSize     = 256
	defaultTimeout       = 5 * time.Second
	defaultRetry         = time.Second
	defaultMaxSpoolBytes = int64(100) << 20 // 100 MiB
)

var (
	ErrQueueFull             = errors.New("siem forwarder queue full, event dropped")
	errClosed                = errors.New("siem forwarder closed")
	errDestinationUnresolved = errors.New("siem forwarder destination unresolved")
	// errPermanentEncode marks an event that can never be serialized (e.g. a
	// NaN/Inf or unsupported type in Fields). Retrying it forever would block
	// the worker, so it is dropped instead.
	errPermanentEncode = errors.New("siem forwarder event cannot be encoded")
	// errSpoolFull marks a refused append because the on-disk spool has reached
	// its configured ceiling. The new event is dropped so a stalled endpoint
	// cannot exhaust host disk.
	errSpoolFull = errors.New("siem forwarder spool at capacity")
)

type Config struct {
	URL               string
	AllowedHosts      []string
	SpoolFile         string
	CursorFile        string
	AuthToken         string
	QueueSize         int
	Timeout           time.Duration
	RetryInterval     time.Duration
	MinSeverity       emit.Severity
	MaxSpoolBytes     int64
	AllowInsecureHTTP bool
}

type Options struct {
	Resolver      scanner.Resolver
	DialContext   func(context.Context, string, string) (net.Conn, error)
	IsInternalIP  func(net.IP) bool
	Close         func()
	Observer      Observer
	DeferredStart bool
}

type Observer interface {
	SetQueued(float64)
	RecordDelivered()
	RecordFailed()
	RecordDropped()
	SetLastSuccess(time.Time)
	SetSpoolBytes(float64)
}

type Envelope struct {
	Schema string        `json:"schema"`
	Event  DeliveryEvent `json:"event"`
}

type DeliveryEvent struct {
	Severity   string         `json:"severity"`
	Type       string         `json:"type"`
	Timestamp  string         `json:"timestamp"`
	InstanceID string         `json:"pipelock_instance"`
	Fields     map[string]any `json:"fields,omitempty"`
}

type Health struct {
	Queued      int       `json:"queued"`
	Delivered   uint64    `json:"delivered"`
	Failed      uint64    `json:"failed"`
	Dropped     uint64    `json:"dropped"`
	LastError   string    `json:"last_error,omitempty"`
	LastSuccess time.Time `json:"last_success_time,omitempty"`
}

type cursor struct {
	Version     int    `json:"version"`
	SourceFile  string `json:"source_file"`
	Offset      int64  `json:"offset"`
	ContentHash string `json:"content_hash"`
}

type Forwarder struct {
	cfg                 Config
	target              *url.URL
	resolver            scanner.Resolver
	dial                func(context.Context, string, string) (net.Conn, error)
	client              *http.Client
	queue               chan emit.Event
	done                chan struct{}
	worker              sync.WaitGroup
	start               sync.Once
	lifecycleMu         sync.Mutex
	closed              bool
	resourceClose       sync.Once
	observer            Observer
	isInternalIP        func(net.IP) bool
	closeResources      func()
	allowPrivateLiteral bool
	appendEvent         func(emit.Event) error
	maxSpoolBytes       int64
	lockFile            *os.File

	// deliverCtx is cancelled by Close so an in-flight HTTP delivery aborts
	// promptly instead of blocking shutdown/reload for the whole backlog.
	deliverCtx    context.Context
	deliverCancel context.CancelFunc

	cursorMu sync.Mutex
	cursor   cursor

	delivered atomic.Uint64
	failed    atomic.Uint64
	dropped   atomic.Uint64
	healthMu  sync.RWMutex
	lastError string
	lastOK    time.Time
}

func New(cfg Config, opts Options) (*Forwarder, error) {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = defaultRetry
	}
	if cfg.MaxSpoolBytes <= 0 {
		cfg.MaxSpoolBytes = defaultMaxSpoolBytes
	}
	if cfg.SpoolFile == "" || cfg.CursorFile == "" {
		return nil, errors.New("siem forwarder spool_file and cursor_file are required")
	}
	target, err := validateTarget(cfg.URL, cfg.AllowedHosts, cfg.AuthToken, cfg.AllowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	resolver := opts.Resolver
	internalIP := opts.IsInternalIP
	closeResources := opts.Close
	if resolver == nil || internalIP == nil {
		ssrfScanner := scanner.New(config.Defaults())
		if resolver == nil {
			resolver = ssrfScanner.HostResolver()
		}
		if internalIP == nil {
			internalIP = ssrfScanner.IsInternalIP
		}
		priorClose := closeResources
		closeResources = func() {
			ssrfScanner.Close()
			if priorClose != nil {
				priorClose()
			}
		}
	}
	allowPrivateLiteral := net.ParseIP(target.Hostname()) != nil
	validationCtx, validationCancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer validationCancel()
	var startupResolutionErr error
	if err := validateResolvedHost(validationCtx, resolver, target.Hostname(), internalIP, allowPrivateLiteral); err != nil {
		if errors.Is(err, errDestinationUnresolved) {
			startupResolutionErr = err
		} else {
			if closeResources != nil {
				closeResources()
			}
			return nil, fmt.Errorf("siem forwarder destination validation: %w", err)
		}
	}
	if err := prepareStateFiles(cfg.SpoolFile, cfg.CursorFile); err != nil {
		if closeResources != nil {
			closeResources()
		}
		return nil, err
	}
	c, err := loadCursor(cfg.SpoolFile, cfg.CursorFile)
	if err != nil {
		if closeResources != nil {
			closeResources()
		}
		return nil, err
	}
	dial := opts.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: cfg.Timeout}).DialContext
	}
	deliverCtx, deliverCancel := context.WithCancel(context.Background())
	f := &Forwarder{
		cfg:                 cfg,
		target:              target,
		resolver:            resolver,
		dial:                dial,
		queue:               make(chan emit.Event, cfg.QueueSize),
		done:                make(chan struct{}),
		observer:            opts.Observer,
		isInternalIP:        internalIP,
		closeResources:      closeResources,
		allowPrivateLiteral: allowPrivateLiteral,
		maxSpoolBytes:       cfg.MaxSpoolBytes,
		deliverCtx:          deliverCtx,
		deliverCancel:       deliverCancel,
		cursor:              c,
	}
	f.appendEvent = f.append
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           f.safeDialContext,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
	}
	f.client = &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("siem forwarder redirects are disabled")
		},
	}
	if startupResolutionErr != nil {
		f.recordFailure(startupResolutionErr)
	}
	if !opts.DeferredStart {
		f.Start()
	}
	return f, nil
}

// Start activates replay and delivery. Runtime reloads build a dormant
// replacement, close the old sink, then start the replacement so two workers
// never race the same spool and cursor.
func (f *Forwarder) Start() {
	f.start.Do(func() {
		f.lifecycleMu.Lock()
		defer f.lifecycleMu.Unlock()
		if f.closed {
			return
		}
		// Acquire the exclusive state lock at delivery time, not in New: a
		// reload builds the replacement while the outgoing forwarder still
		// holds the lock, and only releases it on Close before this Start
		// runs. Locking here still blocks a second OS process pointed at the
		// same spool/cursor. A failed lock fails safe: no worker runs, so
		// events queue and overflow rather than racing another writer.
		lock, err := acquireStateLock(f.cfg.SpoolFile)
		if err != nil {
			f.recordFailure(err)
			return
		}
		f.lockFile = lock
		f.worker.Add(1)
		go f.run()
	})
}

func validateTarget(rawURL string, allowedHosts []string, authToken string, allowInsecureHTTP bool) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid siem forwarder url %q: must be http:// or https:// with a host", rawURL)
	}
	if u.User != nil || u.Fragment != "" {
		return nil, errors.New("siem forwarder url must not contain userinfo or a fragment")
	}
	allowed := make(map[string]struct{}, len(allowedHosts))
	for _, entry := range allowedHosts {
		host := normalizeHost(entry)
		if host == "" || (net.ParseIP(host) == nil && strings.ContainsAny(host, "*/:@[]")) {
			return nil, fmt.Errorf("invalid siem forwarder allowed host %q: use an exact hostname only", entry)
		}
		allowed[host] = struct{}{}
	}
	host := normalizeHost(u.Hostname())
	if len(allowed) == 0 {
		return nil, errors.New("siem forwarder requires a non-empty destination allowlist")
	}
	if _, ok := allowed[host]; !ok {
		return nil, fmt.Errorf("siem forwarder destination host %q is not exactly allowlisted", host)
	}
	if u.Scheme == "http" && !hostIsLoopback(host) {
		if authToken != "" {
			return nil, errors.New("siem forwarder auth_token requires an https:// url: plaintext http would expose the bearer token (loopback destinations are exempt)")
		}
		if !allowInsecureHTTP {
			return nil, fmt.Errorf("siem forwarder url uses plaintext http:// to non-loopback host %q: use https:// or set allow_insecure_http", host)
		}
	}
	return u, nil
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// hostIsLoopback reports whether an already-normalized host refers to the local
// machine, where plaintext http forwarding is acceptable.
func hostIsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func validateResolvedHost(ctx context.Context, resolver scanner.Resolver, host string, internal func(net.IP) bool, allowPrivateLiteral bool) error {
	if ip := net.ParseIP(host); ip != nil {
		if internal(ip) && !allowPrivateLiteral {
			return fmt.Errorf("SSRF blocked: destination is internal IP %s", host)
		}
		return nil
	}
	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return fmt.Errorf("%w: resolve %q: %w", errDestinationUnresolved, host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%w: DNS returned no addresses for %s", errDestinationUnresolved, host)
	}
	return assertResolvedIPsSafe(host, ips, internal, allowPrivateLiteral)
}

// assertResolvedIPsSafe rejects a resolved address set that contains an
// unparseable entry or an internal IP (unless allowPrivate). Startup validation
// and connection-time pinning both call it so the resolved-IP SSRF rule stays
// in lock-step and cannot drift between the two paths.
func assertResolvedIPsSafe(host string, ips []string, internal func(net.IP) bool, allowPrivate bool) error {
	for _, rawIP := range ips {
		ip := net.ParseIP(stripZone(rawIP))
		if ip == nil {
			return fmt.Errorf("SSRF blocked: unparseable DNS address %q for %s", rawIP, host)
		}
		if internal(ip) && !allowPrivate {
			return fmt.Errorf("SSRF blocked: %s resolves to internal IP %s", host, rawIP)
		}
	}
	return nil
}

func stripZone(ip string) string {
	if idx := strings.IndexByte(ip, '%'); idx >= 0 {
		return ip[:idx]
	}
	return ip
}

func prepareStateFiles(spoolPath, cursorPath string) error {
	for _, path := range []string{spoolPath, cursorPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return fmt.Errorf("create siem forwarder state directory: %w", err)
		}
		info, err := os.Lstat(path)
		if err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
			return fmt.Errorf("siem forwarder state path %q is not a regular file", path)
		}
		if err == nil {
			file, openErr := openRegularFile(path, os.O_RDWR, 0)
			if openErr != nil {
				return fmt.Errorf("open siem forwarder state path %q: %w", path, openErr)
			}
			if chmodErr := file.Chmod(0o600); chmodErr != nil {
				_ = file.Close()
				return fmt.Errorf("secure siem forwarder state path %q: %w", path, chmodErr)
			}
			if closeErr := file.Close(); closeErr != nil {
				return fmt.Errorf("close siem forwarder state path %q: %w", path, closeErr)
			}
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect siem forwarder state path %q: %w", path, err)
		}
	}
	file, err := openRegularFile(spoolPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open siem forwarder spool: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure siem forwarder spool: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close siem forwarder spool: %w", err)
	}
	return nil
}

func loadCursor(spoolPath, cursorPath string) (cursor, error) {
	wantSource, err := filepath.Abs(spoolPath)
	if err != nil {
		return cursor{}, fmt.Errorf("resolve spool path: %w", err)
	}
	c := cursor{Version: cursorVersion, SourceFile: wantSource}
	file, err := openRegularFile(cursorPath, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return cursor{}, fmt.Errorf("read siem forwarder cursor: %w", err)
	}
	b, err := io.ReadAll(file)
	closeErr := file.Close()
	if err != nil {
		return cursor{}, fmt.Errorf("read siem forwarder cursor: %w", err)
	}
	if closeErr != nil {
		return cursor{}, fmt.Errorf("close siem forwarder cursor: %w", closeErr)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return cursor{}, fmt.Errorf("parse siem forwarder cursor: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return cursor{}, fmt.Errorf("parse siem forwarder cursor: %w", err)
	}
	if c.Version != cursorVersion || c.SourceFile != wantSource || c.Offset < 0 {
		return cursor{}, errors.New("siem forwarder cursor metadata is invalid")
	}
	if err := verifyCursor(spoolPath, c); err != nil {
		return cursor{}, err
	}
	return c, nil
}

func verifyCursor(spoolPath string, c cursor) error {
	if c.Offset == 0 {
		if c.ContentHash != "" {
			return errors.New("siem forwarder zero cursor has a content hash")
		}
		return nil
	}
	file, err := openRegularFile(spoolPath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open siem forwarder spool for cursor verification: %w", err)
	}
	defer func() { _ = file.Close() }()
	reader := bufio.NewReader(file)
	var offset int64
	var last []byte
	for offset < c.Offset {
		line, readErr := reader.ReadBytes('\n')
		if readErr != nil {
			return fmt.Errorf("siem forwarder cursor is not on a complete record boundary: %w", readErr)
		}
		offset += int64(len(line))
		last = bytes.TrimSuffix(line, []byte{'\n'})
	}
	if offset != c.Offset || hashRecord(last) != c.ContentHash {
		return errors.New("siem forwarder cursor content hash mismatch")
	}
	return nil
}

func (f *Forwarder) Emit(_ context.Context, event emit.Event) error {
	if event.Severity < f.cfg.MinSeverity {
		return nil
	}
	f.lifecycleMu.Lock()
	defer f.lifecycleMu.Unlock()
	if f.closed {
		return errClosed
	}
	select {
	case f.queue <- event:
		f.setQueued()
		return nil
	default:
		f.dropped.Add(1)
		if f.observer != nil {
			f.observer.RecordDropped()
		}
		return ErrQueueFull
	}
}

func (f *Forwarder) Close() error {
	f.lifecycleMu.Lock()
	if !f.closed {
		f.closed = true
		close(f.done)
	}
	f.lifecycleMu.Unlock()
	// Abort any in-flight HTTP delivery so Close returns promptly. The worker
	// still persists already-queued events to the spool within the bounded
	// shutdown deadline; undelivered spool records replay after restart.
	f.deliverCancel()
	f.worker.Wait()
	f.resourceClose.Do(func() {
		releaseStateLock(f.lockFile)
		if f.closeResources != nil {
			f.closeResources()
		}
	})
	return nil
}

func (f *Forwarder) Health() Health {
	f.healthMu.RLock()
	defer f.healthMu.RUnlock()
	return Health{
		Queued:      len(f.queue),
		Delivered:   f.delivered.Load(),
		Failed:      f.failed.Load(),
		Dropped:     f.dropped.Load(),
		LastError:   f.lastError,
		LastSuccess: f.lastOK,
	}
}

func (f *Forwarder) run() {
	defer f.worker.Done()
	retry := time.NewTicker(f.cfg.RetryInterval)
	defer retry.Stop()
	f.deliverPending()
	for {
		select {
		case event := <-f.queue:
			f.setQueued()
			persisted, shutdownDeadline := f.persistAccepted(event)
			if !shutdownDeadline.IsZero() {
				f.drainQueue(shutdownDeadline)
				return
			}
			if persisted {
				f.deliverPending()
			}
		case <-retry.C:
			f.deliverPending()
		case <-f.done:
			f.drainQueue(time.Now().Add(f.cfg.Timeout))
			return
		}
	}
}

// persistAccepted keeps an accepted event at the head of the worker until it
// reaches durable storage. It does not consume another queued event while the
// spool is unavailable. Close switches the retry loop to the same bounded
// shutdown deadline used to drain the rest of the queue.
func (f *Forwarder) persistAccepted(event emit.Event) (bool, time.Time) {
	for {
		err := f.appendEvent(event)
		if err == nil {
			return true, time.Time{}
		}
		if isPermanentAppendErr(err) {
			f.recordDroppedEvent(event, err)
			return false, time.Time{}
		}
		f.recordFailure(err)

		timer := time.NewTimer(f.cfg.RetryInterval)
		select {
		case <-timer.C:
		case <-f.done:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			deadline := time.Now().Add(f.cfg.Timeout)
			return f.persistUntil(event, deadline), deadline
		}
	}
}

// persistUntil retries one accepted event until it is durable or the shared
// shutdown deadline expires.
func (f *Forwarder) persistUntil(event emit.Event, deadline time.Time) bool {
	for {
		err := f.appendEvent(event)
		if err == nil {
			return true
		}
		if isPermanentAppendErr(err) {
			f.recordDroppedEvent(event, err)
			return false
		}
		f.recordFailure(err)
		remaining := time.Until(deadline)
		if remaining <= 0 {
			f.recordDropped()
			return false
		}
		wait := min(f.cfg.RetryInterval, remaining)
		timer := time.NewTimer(wait)
		<-timer.C
	}
}

// drainQueue persists queued events in order without extending Close's single
// shutdown deadline for each event.
func (f *Forwarder) drainQueue(deadline time.Time) {
	for {
		select {
		case event := <-f.queue:
			_ = f.persistUntil(event, deadline)
		default:
			f.setQueued()
			return
		}
	}
}

// recordDropped exposes the otherwise unavoidable loss when storage stays
// unavailable through the bounded shutdown window.
func (f *Forwarder) recordDropped() {
	f.dropped.Add(1)
	if f.observer != nil {
		f.observer.RecordDropped()
	}
}

// recordDroppedEvent drops an event that can never be persisted (permanent
// encode failure or a full spool) and emits a sanitized diagnostic. Only the
// event type and the sentinel reason are logged; the untrusted Fields are never
// written out.
func (f *Forwarder) recordDroppedEvent(event emit.Event, err error) {
	f.dropped.Add(1)
	if f.observer != nil {
		f.observer.RecordDropped()
	}
	f.healthMu.Lock()
	f.lastError = err.Error()
	f.healthMu.Unlock()
	_, _ = fmt.Fprintf(os.Stderr, "siem forwarder dropped event type=%q: %v\n", event.Type, err)
}

// isPermanentAppendErr reports whether an append failure should not be retried:
// the event is unencodable or the spool is at capacity.
func isPermanentAppendErr(err error) bool {
	return errors.Is(err, errPermanentEncode) || errors.Is(err, errSpoolFull)
}

func (f *Forwarder) append(event emit.Event) error {
	envelope := Envelope{Schema: SchemaV1, Event: DeliveryEvent{
		Severity: event.Severity.String(), Type: event.Type,
		Timestamp:  event.Timestamp.UTC().Format(time.RFC3339Nano),
		InstanceID: event.InstanceID, Fields: event.Fields,
	}}
	b, err := json.Marshal(envelope)
	if err != nil {
		// A serialization failure (NaN/Inf, unsupported type) is permanent:
		// retrying the same event never succeeds. Wrap it so the caller drops
		// it instead of head-of-line blocking every later audit event.
		return fmt.Errorf("%w: %w", errPermanentEncode, err)
	}
	b = append(b, '\n')
	if info, statErr := os.Stat(f.cfg.SpoolFile); statErr == nil && info.Size()+int64(len(b)) > f.maxSpoolBytes {
		return fmt.Errorf("%w: spool at %d of %d bytes", errSpoolFull, info.Size(), f.maxSpoolBytes)
	}
	file, err := openRegularFile(f.cfg.SpoolFile, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open siem forwarder spool: %w", err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(b); err != nil {
		return fmt.Errorf("append siem forwarder spool: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync siem forwarder spool: %w", err)
	}
	f.setSpoolBytes()
	return nil
}

func (f *Forwarder) deliverPending() {
	f.cursorMu.Lock()
	defer f.cursorMu.Unlock()
	file, err := openRegularFile(f.cfg.SpoolFile, os.O_RDONLY, 0)
	if err != nil {
		f.recordFailure(fmt.Errorf("open siem forwarder spool: %w", err))
		return
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Seek(f.cursor.Offset, io.SeekStart); err != nil {
		f.recordFailure(fmt.Errorf("seek siem forwarder spool: %w", err))
		return
	}
	reader := bufio.NewReader(file)
	for {
		// Stop promptly on shutdown/reload instead of walking the whole
		// backlog: any undelivered record stays spooled for replay.
		if f.deliverCtx.Err() != nil {
			return
		}
		line, readErr := reader.ReadBytes('\n')
		if errors.Is(readErr, io.EOF) && len(line) == 0 {
			break
		}
		if readErr != nil {
			f.recordFailure(fmt.Errorf("read siem forwarder spool: %w", readErr))
			return
		}
		record := bytes.TrimSuffix(line, []byte{'\n'})
		if err := f.deliver(record); err != nil {
			f.recordFailure(err)
			return
		}
		f.cursor.Offset += int64(len(line))
		f.cursor.ContentHash = hashRecord(record)
		if err := persistCursor(f.cfg.CursorFile, f.cursor); err != nil {
			f.recordFailure(err)
			return
		}
		f.delivered.Add(1)
		now := time.Now().UTC()
		if f.observer != nil {
			f.observer.RecordDelivered()
			f.observer.SetLastSuccess(now)
		}
		f.healthMu.Lock()
		f.lastError = ""
		f.lastOK = now
		f.healthMu.Unlock()
	}
	f.compactIfDrained(file)
}

// compactIfDrained truncates the spool once every record has been delivered so
// healthy operation stays bounded and the max_spool_bytes cap only trips under
// a genuine delivery backlog. The cursor is reset to zero on disk before the
// truncate, so a crash in the window replays the (already-delivered) tail —
// at-least-once, never a gap. Runs on the worker goroutine, so it never races
// append.
func (f *Forwarder) compactIfDrained(spool *os.File) {
	info, err := spool.Stat()
	if err != nil || f.cursor.Offset == 0 || f.cursor.Offset != info.Size() {
		return
	}
	reset := cursor{Version: cursorVersion, SourceFile: f.cursor.SourceFile}
	if err := persistCursor(f.cfg.CursorFile, reset); err != nil {
		f.recordFailure(fmt.Errorf("reset siem forwarder cursor for compaction: %w", err))
		return
	}
	wf, err := openRegularFile(f.cfg.SpoolFile, os.O_WRONLY, 0)
	if err != nil {
		f.recordFailure(fmt.Errorf("open siem forwarder spool for compaction: %w", err))
		return
	}
	defer func() { _ = wf.Close() }()
	if err := wf.Truncate(0); err != nil {
		f.recordFailure(fmt.Errorf("truncate siem forwarder spool: %w", err))
		return
	}
	if err := wf.Sync(); err != nil {
		f.recordFailure(fmt.Errorf("sync siem forwarder spool after compaction: %w", err))
		return
	}
	f.cursor = reset
	f.setSpoolBytes()
}

func (f *Forwarder) deliver(record []byte) error {
	var envelope Envelope
	if err := decodeEnvelope(bytes.NewReader(record), &envelope); err != nil {
		return fmt.Errorf("decode siem forwarder spool record: %w", err)
	}
	if envelope.Schema != SchemaV1 {
		return fmt.Errorf("unsupported siem forwarder schema %q", envelope.Schema)
	}
	req, err := http.NewRequestWithContext(f.deliverCtx, http.MethodPost, f.target.String(), bytes.NewReader(record))
	if err != nil {
		return fmt.Errorf("create siem forwarder request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pipelock-siem-forwarder/1")
	if f.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+f.cfg.AuthToken)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fmt.Errorf("deliver siem forwarder event: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("siem forwarder endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func openRegularFile(path string, flags int, perm os.FileMode) (*os.File, error) {
	cleanPath := filepath.Clean(path)
	file, err := os.OpenFile(cleanPath, flags|noFollowFlag, perm)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat state file %q: %w", cleanPath, err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("state path %q is not a regular file", cleanPath)
	}
	return file, nil
}

func decodeEnvelope(r io.Reader, dst *Envelope) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := requireJSONEOF(dec); err != nil {
		return err
	}
	if dst.Schema == "" || dst.Event.Type == "" || dst.Event.Timestamp == "" {
		return errors.New("incomplete siem forwarder envelope")
	}
	return nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func (f *Forwarder) safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("siem forwarder split destination %q: %w", addr, err)
	}
	if normalizeHost(host) != normalizeHost(f.target.Hostname()) {
		return nil, fmt.Errorf("siem forwarder refused unexpected destination host %q", host)
	}
	if literalIP := net.ParseIP(host); literalIP != nil {
		if f.isInternalIP(literalIP) && !f.allowPrivateLiteral {
			return nil, fmt.Errorf("SSRF blocked: destination is internal IP %s", host)
		}
		return f.dial(ctx, network, net.JoinHostPort(literalIP.String(), port))
	}
	ips, err := f.resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("siem forwarder resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("SSRF blocked: DNS returned no addresses for %s", host)
	}
	if err := assertResolvedIPsSafe(host, ips, f.isInternalIP, f.allowPrivateLiteral); err != nil {
		return nil, err
	}
	return f.dial(ctx, network, net.JoinHostPort(stripZone(ips[0]), port))
}

func persistCursor(path string, c cursor) error {
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal siem forwarder cursor: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".siem-cursor-*")
	if err != nil {
		return fmt.Errorf("create siem forwarder cursor temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure siem forwarder cursor: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write siem forwarder cursor: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync siem forwarder cursor: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close siem forwarder cursor: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Clean(path)); err != nil {
		return fmt.Errorf("replace siem forwarder cursor: %w", err)
	}
	return nil
}

func hashRecord(record []byte) string {
	sum := sha256.Sum256(record)
	return hex.EncodeToString(sum[:])
}

func (f *Forwarder) recordFailure(err error) {
	f.failed.Add(1)
	if f.observer != nil {
		f.observer.RecordFailed()
	}
	f.healthMu.Lock()
	changed := f.lastError != err.Error()
	f.lastError = err.Error()
	f.healthMu.Unlock()
	if changed {
		_, _ = fmt.Fprintf(os.Stderr, "siem forwarder delivery error: %v\n", err)
	}
}

func (f *Forwarder) setQueued() {
	if f.observer != nil {
		f.observer.SetQueued(float64(len(f.queue)))
	}
}

// setSpoolBytes publishes the current on-disk spool size so operators can see
// backlog growth toward the max_spool_bytes ceiling.
func (f *Forwarder) setSpoolBytes() {
	if f.observer == nil {
		return
	}
	if info, err := os.Stat(f.cfg.SpoolFile); err == nil {
		f.observer.SetSpoolBytes(float64(info.Size()))
	}
}
