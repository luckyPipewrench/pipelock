// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package filesentry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// debounceDelay is the quiet period after the last write event before scanning.
// fsnotify fires Write on each write syscall, not on close. 50ms avoids
// scanning partial writes while keeping detection latency low.
const debounceDelay = 50 * time.Millisecond

// findingsChanSize is the buffer size for the findings channel.
// Large enough to avoid blocking the watcher goroutine under burst writes.
const findingsChanSize = 64

// maxArmDiagnosticSamples bounds the error paths retained and logged during a
// single Arm call. A kernel watch limit can otherwise make a broad tree retain
// and emit one error for every remaining directory after the limit is reached.
const maxArmDiagnosticSamples = 64

// maxFileSize is the default maximum file size to scan when file_sentry
// max_file_bytes is unset. Files larger than the effective cap are skipped to
// avoid unbounded memory use from scanning large binaries; the skip is
// surfaced via the watcher's error callback so it is visible, not silent.
const maxFileSize = 10 * 1024 * 1024 // 10MB

// ErrNoWatchPaths marks an Arm failure where no directory remains watched.
// Runtimes must not interpret best-effort as permission to start with this
// condition, because file sentry would provide no coverage at all.
var ErrNoWatchPaths = errors.New("filesentry: no watch paths armed")

// ErrRequiredWatchPath marks an Arm failure for a required watch root or one
// of its descendants. Runtimes can use errors.Is to keep required coverage
// fail-closed even when other file sentry paths use best-effort behavior.
var ErrRequiredWatchPath = errors.New("filesentry: required watch coverage unavailable")

// fsWatcher implements Watcher using fsnotify for cross-platform file watching.
type fsWatcher struct {
	cfg      *config.FileSentry
	scanner  DLPScanner
	lineage  Lineage
	watcher  *fsnotify.Watcher
	findings chan Finding
	// overflow is a one-entry priority lane used when findings is saturated.
	// Agent-attributed findings replace a queued non-agent overflow so block
	// mode cannot be bypassed by filling the normal delivery channel first.
	overflow chan Finding
	onError  func(error) // optional callback for non-fatal errors (e.g. runtime watch failures)
	mu       sync.Mutex
	scanWG   sync.WaitGroup         // debounce scans that began before Close
	timers   map[string]*time.Timer // per-path debounce timers
	pidSnap  map[string]bool        // per-path agent attribution snapshot at event time
	closed   bool
	// watchedPaths prevents duplicate fsnotify registrations when configured
	// roots overlap or Arm is called more than once.
	watchedPaths map[string]struct{}
	// degradedPaths records every configured root or descendant subtree that
	// Arm could not monitor. Populated by Arm() and exposed via DegradedPaths()
	// so health endpoints can surface "armed but degraded" without lying about
	// coverage.
	degradedPaths []DegradedPath
	// degradedPathCount includes omitted diagnostic samples. It is kept
	// separately so health output can say how much coverage is missing without
	// retaining every failed path in memory.
	degradedPathCount int
	// addWatch is the fsnotify registration seam. It is only replaced by tests
	// to deterministically exercise per-subtree watch-install failures.
	addWatch func(string) error
}

// DegradedPath records a configured watch_paths entry whose install failed
// during Arm() but was not marked required:true. Operators see these via
// the watcher's DegradedPaths() / health surface so degraded coverage is
// visible, not silent.
type DegradedPath struct {
	Path  string
	Error string
}

type skippedSubtree struct {
	path  string
	cause error
}

func (s skippedSubtree) err() error {
	return fmt.Errorf("cannot monitor subtree %q: %w", s.path, s.cause)
}

type recursiveAddResult struct {
	added        int
	skipped      []skippedSubtree
	skippedCount int
}

func (r recursiveAddResult) err() error {
	if len(r.skipped) == 0 {
		return nil
	}
	errs := make([]error, 0, len(r.skipped))
	for _, skipped := range r.skipped {
		errs = append(errs, skipped.err())
	}
	return errors.Join(errs...)
}

// NewWatcher creates a file watcher that monitors configured directories for
// writes and scans file content for DLP pattern matches. Lineage may be nil
// (PID attribution will be unavailable). onError is called for non-fatal
// runtime errors (e.g. failing to watch a newly created directory); it may
// be nil.
func NewWatcher(cfg *config.FileSentry, sc DLPScanner, lin Lineage, onError func(error)) (Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("filesentry: create watcher: %w", err)
	}
	return &fsWatcher{
		cfg:          cfg,
		scanner:      sc,
		lineage:      lin,
		watcher:      w,
		findings:     make(chan Finding, findingsChanSize),
		overflow:     make(chan Finding, 1),
		timers:       make(map[string]*time.Timer),
		pidSnap:      make(map[string]bool),
		watchedPaths: make(map[string]struct{}),
		onError:      onError,
		addWatch:     w.Add,
	}, nil
}

// logError invokes the error handler if one is registered.
func (w *fsWatcher) logError(err error) {
	if w.onError != nil {
		w.onError(err)
	}
}

// effectiveMaxFileSize returns the configured file_sentry max_file_bytes when
// set to a positive value, otherwise the built-in default. Validation rejects
// negative values, so a non-positive cfg value here means "unset".
func (w *fsWatcher) effectiveMaxFileSize() int64 {
	if w.cfg != nil && w.cfg.MaxFileBytes > 0 {
		return w.cfg.MaxFileBytes
	}
	return maxFileSize
}

// Arm installs watches on all configured directories synchronously.
// Call this before launching the child process to ensure no writes
// are missed during the startup window.
//
// Any skipped root or descendant is reported individually through
// DegradedPaths and the optional error callback. In best_effort mode, Arm
// keeps every accessible sibling armed. Strict mode (the default) returns an
// error after completing the walk, so a partial watch set cannot be mistaken
// for complete coverage. required:true remains a per-root override that
// rejects degradation even when best_effort is selected.
func (w *fsWatcher) Arm() error {
	w.mu.Lock()
	w.degradedPaths = w.degradedPaths[:0]
	w.degradedPathCount = 0
	w.mu.Unlock()
	var armErrs []error
	requiredFailed := false
	// Normalize before walking so a later required declaration cannot be
	// suppressed by an equivalent optional root (for example /a and /a/).
	roots := make(map[string]config.WatchPath, len(w.cfg.WatchPaths))
	rootOrder := make([]string, 0, len(w.cfg.WatchPaths))
	for _, wp := range w.cfg.WatchPaths {
		abs, err := filepath.Abs(wp.Path)
		if err != nil {
			w.recordDegraded(wp.Path, err)
			armErr := fmt.Errorf("resolve watch root %q: %w", wp.Path, err)
			if wp.Required {
				requiredFailed = true
			}
			armErrs = appendDiagnosticError(armErrs, armErr)
			continue
		}
		if prior, duplicate := roots[abs]; duplicate {
			prior.Required = prior.Required || wp.Required
			roots[abs] = prior
		} else {
			roots[abs] = config.WatchPath{Path: abs, Required: wp.Required}
			rootOrder = append(rootOrder, abs)
		}
	}

	for _, abs := range rootOrder {
		wp := roots[abs]
		result := w.addRecursiveDetailed(abs)
		for _, skipped := range result.skipped {
			w.recordDegraded(skipped.path, skipped.cause)
			armErr := skipped.err()
			armErrs = appendDiagnosticError(armErrs, armErr)
		}
		w.recordOmittedDegraded(result.skippedCount - len(result.skipped))
		if wp.Required && result.skippedCount > 0 {
			// required:true overrides the global best-effort setting.
			requiredFailed = true
		}
	}
	w.appendTruncatedDiagnostic(&armErrs)

	w.mu.Lock()
	armed := len(w.watchedPaths)
	w.mu.Unlock()
	cause := errors.Join(armErrs...)
	if requiredFailed {
		cause = errors.Join(ErrRequiredWatchPath, cause)
	}
	if armed == 0 {
		if len(armErrs) == 0 {
			return ErrNoWatchPaths
		}
		return fmt.Errorf("%w: %w", ErrNoWatchPaths, cause)
	}
	if len(armErrs) > 0 && (!w.cfg.BestEffort || requiredFailed) {
		return fmt.Errorf("filesentry: incomplete watch coverage: %w", cause)
	}
	return nil
}

func appendDiagnosticError(errs []error, err error) []error {
	if len(errs) < maxArmDiagnosticSamples {
		return append(errs, err)
	}
	return errs
}

func (w *fsWatcher) appendTruncatedDiagnostic(errs *[]error) {
	w.mu.Lock()
	truncated := w.degradedPathCount - len(w.degradedPaths)
	w.mu.Unlock()
	if truncated == 0 {
		return
	}
	*errs = append(*errs, fmt.Errorf("%d additional watch subtree failure(s) omitted from diagnostics", truncated))
	w.logError(fmt.Errorf("filesentry: %d additional watch subtree failure(s) omitted from diagnostics", truncated))
}

// recordDegraded captures an Arm-time subtree failure for later visibility
// through DegradedPaths() and the optional onError callback.
func (w *fsWatcher) recordDegraded(path string, cause error) {
	w.mu.Lock()
	w.degradedPathCount++
	if len(w.degradedPaths) >= maxArmDiagnosticSamples {
		w.mu.Unlock()
		return
	}
	w.degradedPaths = append(w.degradedPaths, DegradedPath{Path: path, Error: cause.Error()})
	w.mu.Unlock()
	w.logError(fmt.Errorf("filesentry: watch subtree %q failed (coverage degraded): %w", path, cause))
}

func (w *fsWatcher) recordOmittedDegraded(count int) {
	if count <= 0 {
		return
	}
	w.mu.Lock()
	w.degradedPathCount += count
	w.mu.Unlock()
}

// DegradedPaths returns root or descendant subtrees that Arm() could not
// monitor. Returned slice is a copy safe for concurrent health inspection.
func (w *fsWatcher) DegradedPaths() []DegradedPath {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]DegradedPath, len(w.degradedPaths))
	copy(out, w.degradedPaths)
	return out
}

// DegradedPathCount returns the total number of failed root or subtree watch
// registrations from the most recent Arm call, including diagnostic samples
// omitted to keep startup memory and log volume bounded.
func (w *fsWatcher) DegradedPathCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.degradedPathCount
}

// Start processes filesystem events until ctx is cancelled. Blocks until done.
// Call Arm() first to install watches before starting the child process.
func (w *fsWatcher) Start(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.watcher.Events:
			if !ok {
				return nil
			}
			w.handleEvent(ctx, ev)
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return nil
			}
			// Backend error from fsnotify (e.g. inotify queue overflow).
			// Fail closed: return the error so the caller can handle it
			// (log, cancel context, restart). Silently continuing would
			// leave the watcher partially broken with no signal to the operator.
			return fmt.Errorf("fsnotify backend error: %w", err)
		}
	}
}

// Findings returns the channel that receives DLP findings.
func (w *fsWatcher) Findings() <-chan Finding {
	return w.findings
}

// OverflowFindings returns the priority lane for findings detected while the
// normal delivery buffer is saturated.
func (w *fsWatcher) OverflowFindings() <-chan Finding {
	return w.overflow
}

// Close stops the watcher, flushes pending debounced scans, and closes the
// findings channel so consumer goroutines exit their range loops.
// Pending timers are stopped and their scans run synchronously so that
// secrets written in the final debounce window before subprocess exit
// are not silently dropped.
func (w *fsWatcher) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.mu.Unlock()

	// Stop the fsnotify watcher first. This closes the Events/Errors
	// channels, which causes Start() to return. The event loop must be
	// stopped BEFORE we touch timers/pidSnap to avoid a race where a
	// queued event writes to the maps after we nil them.
	err := w.watcher.Close()

	// Now safe to collect and clear pending state - event loop is done.
	w.mu.Lock()
	pendingPaths := make([]string, 0, len(w.timers))
	pendingAgent := make([]bool, 0, len(w.timers))
	for path, t := range w.timers {
		t.Stop()
		pendingPaths = append(pendingPaths, path)
		pendingAgent = append(pendingAgent, w.pidSnap[path])
	}
	w.timers = nil
	w.pidSnap = nil
	w.mu.Unlock()

	// Flush pending scans synchronously.
	for i, path := range pendingPaths {
		w.flushScan(path, pendingAgent[i])
	}

	// A timer may have removed itself from timers and started scanning just
	// before Close set closed=true. Wait for those registered scans before
	// closing their delivery channels.
	w.scanWG.Wait()

	close(w.findings)
	close(w.overflow)
	return err
}

// addRecursive walks a directory tree and adds an fsnotify watch on every
// subdirectory. Files themselves don't need watches - directory watches
// catch all file events within them.
func (w *fsWatcher) addRecursive(root string) error {
	return w.addRecursiveDetailed(root).err()
}

// addRecursiveDetailed adds every accessible directory beneath root and
// records every inaccessible subtree instead of abandoning the first sibling
// failure. Symlinks are never followed: a child symlink could leave the
// configured tree, while a root symlink has no trustworthy direct watch root.
func (w *fsWatcher) addRecursiveDetailed(root string) recursiveAddResult {
	result := recursiveAddResult{}
	info, err := os.Lstat(root)
	if err != nil {
		result.addSkipped(root, fmt.Errorf("watch root: %w", err))
		return result
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		result.addSkipped(root, errors.New("watch root must not be a symlink"))
		return result
	}
	if !info.IsDir() {
		result.addSkipped(root, fmt.Errorf("watch root %q is a file, not a directory", root))
		return result
	}

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			result.addSkipped(path, fmt.Errorf("inaccessible path: %w", walkErr))
			return filepath.SkipDir
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if w.isIgnored(path) {
			return filepath.SkipDir
		}
		if added, addErr := w.addDirectory(path); addErr != nil {
			result.addSkipped(path, addErr)
			return filepath.SkipDir
		} else if added {
			result.added++
		}
		return nil
	})
	if walkErr != nil {
		result.addSkipped(root, fmt.Errorf("walk root: %w", walkErr))
	}
	return result
}

func (r *recursiveAddResult) addSkipped(path string, cause error) {
	r.skippedCount++
	if len(r.skipped) < maxArmDiagnosticSamples {
		r.skipped = append(r.skipped, skippedSubtree{path: path, cause: cause})
	}
}

// addDirectory installs one watch once. The mutex protects the duplicate set
// against Arm and runtime directory-creation handling overlapping.
func (w *fsWatcher) addDirectory(path string) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.watchedPaths[path]; ok {
		return false, nil
	}
	if err := w.addWatch(path); err != nil {
		return false, err
	}
	w.watchedPaths[path] = struct{}{}
	return true, nil
}

// handleEvent processes a single fsnotify event.
func (w *fsWatcher) handleEvent(ctx context.Context, ev fsnotify.Event) {
	if ev.Has(fsnotify.Remove) || ev.Has(fsnotify.Rename) {
		w.forgetWatchPath(ev.Name)
	}
	// New directory created - add a recursive watch so we catch writes inside it.
	// Errors here are non-fatal: the initial Arm() call fail-closes on watch
	// failures, but runtime directory creation is best-effort. We log failures
	// so the operator can see the gap.
	if ev.Has(fsnotify.Create) {
		if info, err := os.Stat(ev.Name); err == nil && info.IsDir() {
			if !w.isIgnored(ev.Name) {
				if addErr := w.addRecursive(ev.Name); addErr != nil {
					w.logError(fmt.Errorf("failed to watch new directory %q: %w", ev.Name, addErr))
				}
			}
		}
	}

	// Scan on Write, Create, and Rename events. A secret written to a temp
	// file outside the watch tree and rename(2)d in produces Create/Rename
	// at the destination, not Write. Scanning only Write is a bypass vector.
	isWriteEvent := ev.Has(fsnotify.Write) || ev.Has(fsnotify.Create) || ev.Has(fsnotify.Rename)
	if !isWriteEvent {
		return
	}

	// Skip directories - we only scan file content.
	if info, err := os.Stat(ev.Name); err != nil || info.IsDir() {
		return
	}

	if w.isIgnored(ev.Name) {
		return
	}

	// Snapshot PID attribution at event time, not after the debounce delay.
	// Short-lived writers may close their FD within the 50ms debounce window.
	// Checking /proc at event time catches more writers than checking after
	// the quiet period. The snapshot is consumed by scanFile after debounce.
	if w.lineage != nil {
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			return
		}
		w.pidSnap[ev.Name] = w.lineage.HasFileOpen(ev.Name)
		w.mu.Unlock()
	}

	// Debounce: reset the timer for this path. The scan fires only after
	// debounceDelay of quiet (no more writes to this path).
	//
	// Timer identity check: capture the timer pointer in the closure.
	// If a second write replaces this timer before the callback fires,
	// the old callback sees its pointer differs from the map entry and
	// does nothing. Without this, the old callback would delete the new
	// timer's map entry, causing the new callback to scan without cleanup.
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	if existing, ok := w.timers[ev.Name]; ok {
		existing.Stop()
	}
	path := ev.Name
	// Declare timer before AfterFunc so the closure can capture it.
	// The closure uses timer identity to detect stale callbacks.
	var timer *time.Timer
	timer = time.AfterFunc(debounceDelay, func() {
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			return
		}
		// Only proceed if this timer is still the active one for this path.
		if current, ok := w.timers[path]; !ok || current != timer {
			w.mu.Unlock()
			return
		}
		delete(w.timers, path)
		// Consume the PID snapshot (take the cached value, then clean up).
		isAgent := w.pidSnap[path]
		delete(w.pidSnap, path)
		w.scanWG.Add(1)
		w.mu.Unlock()
		defer w.scanWG.Done()
		w.doScan(ctx, path, isAgent, true)
	})
	w.timers[path] = timer
	w.mu.Unlock()
}

// forgetWatchPath drops cached registrations which fsnotify has removed after
// a directory is deleted or renamed. A later Arm must attempt a fresh backend
// registration rather than treating this cache as proof coverage still exists.
func (w *fsWatcher) forgetWatchPath(path string) {
	cleanPath := filepath.Clean(path)
	prefix := cleanPath + string(filepath.Separator)
	w.mu.Lock()
	defer w.mu.Unlock()
	for watched := range w.watchedPaths {
		if watched == cleanPath || strings.HasPrefix(watched, prefix) {
			delete(w.watchedPaths, watched)
		}
	}
}

// flushScan runs a DLP scan synchronously during Close. Close keeps both
// delivery channels open until every pending and registered scan finishes, so
// the flush can use the same agent-priority overflow lane as live scans.
func (w *fsWatcher) flushScan(path string, isAgent bool) {
	w.doScan(context.Background(), path, isAgent, true)
}

// scanFile reads a file and runs DLP scanning on its content.
// isAgent is the PID attribution result snapshotted at event time.
func (w *fsWatcher) scanFile(ctx context.Context, path string, isAgent bool) {
	w.doScan(ctx, path, isAgent, false)
}

// doScan is the shared scan implementation. A registered debounce scan may
// finish after Close begins because Close waits for scanWG before closing the
// delivery channels. Direct callers do not have that lifetime guarantee.
func (w *fsWatcher) doScan(ctx context.Context, path string, isAgent, registered bool) {
	if w.cfg.ScanContent != nil && !*w.cfg.ScanContent {
		return
	}

	// Open once and use the fd for both size check and read. This avoids
	// a TOCTOU window between Stat and ReadFile where a rename/symlink
	// swap could change what we read.
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		w.logError(fmt.Errorf("filesentry: open failed, file left unscanned: %s: %w", path, err))
		return
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		w.logError(fmt.Errorf("filesentry: stat failed, file left unscanned: %s: %w", path, err))
		return
	}
	if info.IsDir() || info.Size() == 0 {
		return
	}
	sizeCap := w.effectiveMaxFileSize()
	if info.Size() > sizeCap {
		w.logError(fmt.Errorf("filesentry: skipped oversized file, left unscanned (%d bytes > cap %d): %s", info.Size(), sizeCap, path))
		return
	}

	data, err := io.ReadAll(io.LimitReader(f, sizeCap+1))
	if err != nil {
		w.logError(fmt.Errorf("filesentry: read failed, file left unscanned: %s: %w", path, err))
		return
	}
	if len(data) == 0 {
		return
	}
	if int64(len(data)) > sizeCap {
		w.logError(fmt.Errorf("filesentry: skipped oversized file, left unscanned (grew beyond cap %d while reading): %s", sizeCap, path))
		return
	}

	result := w.scanner.ScanTextForDLP(ctx, string(data))
	if result.Clean {
		return
	}

	for _, m := range result.Matches {
		f := Finding{
			Path:        path,
			PatternName: m.PatternName,
			Severity:    m.Severity,
			Encoded:     m.Encoded,
			IsAgent:     isAgent,
		}
		// Hold the lock across the closed check and delivery. This prevents
		// Close from closing either channel during a send and serializes every
		// overflow writer; Close closes channels only after scanWG.Wait.
		w.mu.Lock()
		if w.closed && !registered {
			w.mu.Unlock()
			return
		}
		var overflowErr error
		select {
		case w.findings <- f:
		default:
			overflowErr = w.enqueueOverflow(f)
		}
		w.mu.Unlock()
		if overflowErr != nil {
			w.logError(overflowErr)
		}
	}
}

// enqueueOverflow preserves visibility and block-mode enforcement without
// blocking timer goroutines or growing an unbounded queue. The caller holds
// w.mu, which also prevents Close from closing overflow during this send.
func (w *fsWatcher) enqueueOverflow(f Finding) error {
	select {
	case w.overflow <- f:
		return nil
	default:
	}

	if !f.IsAgent {
		return overflowError(f, "priority lane already occupied")
	}

	// An agent finding is enforcement-relevant. Replace a pending non-agent
	// sample so ConsumeFindings is guaranteed to observe an agent overflow and
	// cancel in block mode. If the consumer raced us and drained the lane, the
	// direct retry below succeeds.
	select {
	case pending := <-w.overflow:
		if pending.IsAgent {
			return errors.Join(
				w.tryOverflowSendError(pending, "priority lane refilled concurrently"),
				overflowError(f, "agent overflow already pending"),
			)
		}
		displacedErr := overflowError(pending, "replaced by agent-attributed overflow")
		return errors.Join(displacedErr, w.tryOverflowSendError(f, "priority lane refilled concurrently"))
	default:
	}

	return w.tryOverflowSendError(f, "priority lane refilled concurrently")
}

// tryOverflowSend degrades a lost single-writer invariant to a reported drop
// instead of blocking while holding w.mu and preventing Close from completing.
func (w *fsWatcher) tryOverflowSend(f Finding) bool {
	select {
	case w.overflow <- f:
		return true
	default:
		return false
	}
}

func (w *fsWatcher) tryOverflowSendError(f Finding, reason string) error {
	if w.tryOverflowSend(f) {
		return nil
	}
	return overflowError(f, reason)
}

func overflowError(f Finding, reason string) error {
	return fmt.Errorf(
		"filesentry: finding delivery overflow (%s): path=%s pattern=%s severity=%s agent=%t",
		reason,
		f.Path,
		f.PatternName,
		f.Severity,
		f.IsAgent,
	)
}

// isIgnored checks if a path matches any configured ignore pattern.
func (w *fsWatcher) isIgnored(path string) bool {
	for _, pattern := range w.cfg.IgnorePatterns {
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
		// Also try matching against the relative path for patterns like "node_modules/**".
		// filepath.Match doesn't support **, so check if the base directory name matches
		// the first segment of the pattern.
		if dir := firstSegment(pattern); dir != "" {
			if filepath.Base(path) == dir {
				return true
			}
		}
	}
	return false
}

// firstSegment returns the first path segment of a glob pattern, or "" if
// the pattern has no separators.
func firstSegment(pattern string) string {
	for i, c := range pattern {
		if c == '/' || c == filepath.Separator {
			return pattern[:i]
		}
	}
	return ""
}
