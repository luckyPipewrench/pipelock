// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/nacl/box"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// dropSentinelInterval controls how many drops occur between sentinel entries
// written to the capture-meta recorder. A sentinel every 100 drops keeps the
// evidence chain aware of loss without flooding it.
const dropSentinelInterval = 100

// maxScannerSample is the maximum number of bytes stored in ScannerSample and
// WirePayloadSample fields. Keeps CaptureSummary compact while preserving
// enough context for human inspection and replay debugging.
const maxScannerSample = 256

// redactedPlaceholder replaces sensitive inline content when redaction is on.
// Exact payloads still reach the encrypted sidecar files.
const redactedPlaceholder = "[REDACTED]"

// metaSessionID is the fixed session identifier used for the capture-meta
// recorder that stores drop sentinel entries.
const metaSessionID = "capture-meta"

// dropReason is the reason string used in drop sentinel entries.
const dropReason = "backpressure"

// WriterConfig configures a capture Writer.
type WriterConfig struct {
	// RecorderConfig is the base config for per-session recorders.
	RecorderConfig recorder.Config
	// RedactFn is the DLP redaction function passed to per-session recorders.
	RedactFn recorder.RedactFunc
	// PrivKey is the Ed25519 key for signing checkpoints.
	PrivKey ed25519.PrivateKey
	// EscrowPublicKey is the X25519 public key for encrypting payload sidecars.
	// When nil, no sidecars are written.
	EscrowPublicKey *[32]byte
	// DropSink receives notifications when captures are dropped.
	DropSink DropSink
	// QueueSize is the bounded channel capacity. Zero uses a default of 4096.
	QueueSize int
	// BuildVersion is the pipelock version string baked into every summary.
	BuildVersion string
	// BuildSHA is the git commit SHA baked into every summary.
	BuildSHA string
}

// defaultQueueSize is used when WriterConfig.QueueSize is zero or negative.
const defaultQueueSize = 4096

// Writer implements CaptureObserver by buffering capture entries in a bounded
// async queue and persisting them via per-session recorder instances.
type Writer struct {
	baseCfg      recorder.Config
	redactFn     recorder.RedactFunc
	privKey      ed25519.PrivateKey
	escrowPub    *[32]byte
	dropSink     DropSink
	recorders    map[string]*recorder.Recorder
	payloadSeq   map[string]uint64
	metaRec      *recorder.Recorder
	ch           chan captureEntry
	buildVersion string
	buildSHA     string
	dropped      atomic.Int64
	closed       atomic.Bool
	closeOnce    sync.Once
	done         chan struct{}
}

// captureEntry is the internal message passed through the async channel from
// observer methods to the worker goroutine.
type captureEntry struct {
	entry        recorder.Entry
	summary      CaptureSummary
	scannerInput string
	wirePayload  string
}

// NewWriter creates a Writer and starts its background worker goroutine.
// The meta recorder is created immediately for drop sentinel entries.
func NewWriter(cfg WriterConfig) (*Writer, error) {
	queueSize := cfg.QueueSize
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}

	// Create the meta recorder for drop sentinels. It lives in a
	// "capture-meta" subdirectory under the base evidence dir.
	metaCfg := cfg.RecorderConfig
	metaCfg.Dir = filepath.Join(cfg.RecorderConfig.Dir, metaSessionID)

	metaRec, err := recorder.New(metaCfg, cfg.RedactFn, cfg.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("creating capture-meta recorder: %w", err)
	}

	w := &Writer{
		baseCfg:      cfg.RecorderConfig,
		redactFn:     cfg.RedactFn,
		privKey:      cfg.PrivKey,
		escrowPub:    cfg.EscrowPublicKey,
		dropSink:     cfg.DropSink,
		recorders:    make(map[string]*recorder.Recorder),
		payloadSeq:   make(map[string]uint64),
		metaRec:      metaRec,
		ch:           make(chan captureEntry, queueSize),
		buildVersion: cfg.BuildVersion,
		buildSHA:     cfg.BuildSHA,
		done:         make(chan struct{}),
	}

	go w.worker()

	return w, nil
}

// sanitizeSessionID validates that a session ID is safe to use as a directory
// name. It rejects empty strings, path separators, and traversal sequences.
func sanitizeSessionID(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("empty session ID")
	}
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return "", fmt.Errorf("invalid session ID %q: contains path separator or traversal", id)
	}
	// Use filepath.Base as defense in depth.
	return filepath.Base(id), nil
}

// getRecorder returns the recorder for a session, creating one if needed.
// Called only from the worker goroutine (no mutex needed).
func (w *Writer) getRecorder(sessionID string) (*recorder.Recorder, error) {
	if rec, ok := w.recorders[sessionID]; ok {
		return rec, nil
	}

	safe, err := sanitizeSessionID(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session ID sanitization: %w", err)
	}

	cfg := w.baseCfg
	cfg.Dir = filepath.Join(w.baseCfg.Dir, safe)

	rec, err := recorder.New(cfg, w.redactFn, w.privKey)
	if err != nil {
		return nil, fmt.Errorf("creating session recorder %q: %w", safe, err)
	}

	w.recorders[sessionID] = rec
	return rec, nil
}

// writePayloadSidecar encrypts scannerInput to a sidecar file and returns
// the filename. seq is the per-session sidecar ordinal, not recorder seq.
// Returns ("", nil) if no escrow key is configured or payload is empty.
func (w *Writer) writePayloadSidecar(sessionDir string, seq uint64, payload string) (string, error) {
	if w.escrowPub == nil || payload == "" {
		return "", nil
	}

	filename := fmt.Sprintf("%06d.payload.enc", seq)
	path := filepath.Join(filepath.Clean(sessionDir), filename)

	encrypted, err := box.SealAnonymous(nil, []byte(payload), w.escrowPub, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("encrypt payload: %w", err)
	}

	if err := os.WriteFile(path, encrypted, 0o600); err != nil {
		return "", fmt.Errorf("write payload sidecar: %w", err)
	}

	return filename, nil
}

// worker reads entries from the channel and persists them. It runs in a
// dedicated goroutine and is the only code that touches recorders or
// payloadSeq maps (no concurrent access).
func (w *Writer) worker() {
	defer close(w.done)

	for ce := range w.ch {
		rec, err := w.getRecorder(ce.entry.SessionID)
		if err != nil {
			w.recordDrop()
			continue
		}

		// Write payload sidecar if escrow is configured. Prefer scannerInput
		// (exact scanner input for deterministic replay). Fall back to
		// wirePayload (raw content before transformation) when scannerInput
		// is empty — ObserveResponseVerdict stores raw response bytes only
		// in wirePayload.
		sidecarPayload := ce.scannerInput
		if sidecarPayload == "" {
			sidecarPayload = ce.wirePayload
		}

		sessionDir := filepath.Join(w.baseCfg.Dir, ce.entry.SessionID)
		payloadSeq := w.payloadSeq[ce.entry.SessionID]
		w.payloadSeq[ce.entry.SessionID] = payloadSeq + 1

		payloadRef, sidecarErr := w.writePayloadSidecar(sessionDir, payloadSeq, sidecarPayload)
		if sidecarErr != nil {
			// Sidecar failed -- keep the summary with PayloadComplete: false.
			ce.summary.PayloadComplete = false
			ce.summary.PayloadRef = ""
		} else if payloadRef != "" {
			ce.summary.PayloadRef = payloadRef
			ce.summary.PayloadComplete = true
			ce.summary.PayloadBytes = len(sidecarPayload)
			h := sha256.Sum256([]byte(sidecarPayload))
			ce.summary.PayloadSHA256 = "sha256:" + hex.EncodeToString(h[:])
		}

		ce.entry.Detail = ce.summary
		if err := rec.Record(ce.entry); err != nil {
			w.recordDrop()
		}
	}

	// Flush any remaining drop sentinel on close.
	if d := w.dropped.Load(); d > 0 && d%dropSentinelInterval != 0 {
		w.writeDropSentinel(d)
	}
}

// send performs a non-blocking send to the channel. If the writer has been
// closed or the channel is full, the entry is dropped and recorded.
func (w *Writer) send(ce captureEntry) {
	if w.closed.Load() {
		w.recordDrop()
		return
	}
	select {
	case w.ch <- ce:
	default:
		w.recordDrop()
	}
}

// recordDrop increments the atomic drop counter, notifies the DropSink, and
// periodically writes a sentinel entry to the meta recorder. A sentinel is
// emitted on the first drop and every dropSentinelInterval drops thereafter.
func (w *Writer) recordDrop() {
	n := w.dropped.Add(1)
	if w.dropSink != nil {
		w.dropSink.RecordCaptureDrop()
	}
	if n == 1 || n%dropSentinelInterval == 0 {
		w.writeDropSentinel(n)
	}
}

// writeDropSentinel writes a capture_drop entry to the meta recorder.
func (w *Writer) writeDropSentinel(count int64) {
	_ = w.metaRec.Record(recorder.Entry{
		SessionID: metaSessionID,
		Type:      EntryTypeCaptureDrop,
		EventKind: EntryTypeCaptureDrop,
		Summary:   "capture queue overflow",
		Detail: CaptureDropDetail{
			Count:  int(count),
			Reason: dropReason,
		},
	})
}

// captureEventKind returns the event_kind string to stamp on a capture
// recorder.Entry. The current PR uses the surface name (url, response, dlp,
// cee, tool_policy, tool_scan) unconditionally — proxy and MCP call sites do
// not yet populate Verdict.ActionClass, so switching on the zero value would
// silently mark every observation as "read" and mask the unclassified state.
//
// The follow-up task that wires ActionClass through the proxy/mcp layers will
// swap this helper to prefer the classified verb when set, falling back to
// the surface only for pre-classification callers. Until then, surface names
// preserve attributability without inventing a classification.
func captureEventKind(surface string) string {
	return surface
}

// buildSummary constructs a CaptureSummary, truncating scanner and wire
// payload samples to maxScannerSample bytes. actionClass is the session-level
// action verb classification supplied by the call site; the zero value
// (ActionClassRead) is rendered as the literal wire label "read" — callers
// that have not classified should still pass the zero value, and downstream
// consumers must not interpret a populated ActionClass field as proof of
// explicit classification.
func (w *Writer) buildSummary(
	surface, subsurface, configHash, agent, profile string,
	actionClass session.ActionClass,
	scannerInput string,
	payloadComplete bool,
	transformKind, wirePayload string,
	batchIndex *int,
	req CaptureRequest,
	rawFindings, effectiveFindings []Finding,
	effectiveAction, outcome, skipReason string,
) CaptureSummary {
	s := CaptureSummary{
		CaptureSchemaVersion: CaptureSchemaV1,
		Surface:              surface,
		Subsurface:           subsurface,
		BatchIndex:           batchIndex,
		ConfigHash:           configHash,
		BuildVersion:         w.buildVersion,
		BuildSHA:             w.buildSHA,
		Agent:                agent,
		Profile:              profile,
		ActionClass:          actionClass.String(),
		PayloadComplete:      payloadComplete,
		TransformKind:        transformKind,
		Request:              req,
		RawFindings:          rawFindings,
		EffectiveFindings:    effectiveFindings,
		EffectiveAction:      effectiveAction,
		Outcome:              outcome,
		SkipReason:           skipReason,
	}

	if scannerInput != "" {
		s.ScannerBytes = len(scannerInput)
		if len(scannerInput) > maxScannerSample {
			s.ScannerSample = scannerInput[:maxScannerSample]
		} else {
			s.ScannerSample = scannerInput
		}
	}

	if wirePayload != "" && wirePayload != scannerInput {
		s.WirePayloadBytes = len(wirePayload)
		if len(wirePayload) > maxScannerSample {
			s.WirePayloadSample = wirePayload[:maxScannerSample]
		} else {
			s.WirePayloadSample = wirePayload
		}
	}

	// When redaction is configured, strip sensitive inline content from the
	// summary. Metadata (sizes, hashes, surface, action) is preserved; exact
	// content reaches only the encrypted payload sidecars.
	if w.redactFn != nil {
		s.ScannerSample = redactedPlaceholder
		s.WirePayloadSample = redactedPlaceholder
		s.Request.Headers = nil
		if s.Request.BodySample != "" {
			s.Request.BodySample = redactedPlaceholder
		}
		if s.Request.ToolArgsJSON != "" {
			s.Request.ToolArgsJSON = redactedPlaceholder
		}
		for i := range s.RawFindings {
			s.RawFindings[i].MatchText = ""
		}
		for i := range s.EffectiveFindings {
			s.EffectiveFindings[i].MatchText = ""
		}
	}

	return s
}

// ObserveURLVerdict implements CaptureObserver for URL pipeline verdicts.
func (w *Writer) ObserveURLVerdict(_ context.Context, rec *URLVerdictRecord) {
	// URL verdicts have no separate scanner input; the URL is the input.
	scannerInput := rec.Request.URL
	w.send(captureEntry{
		entry: recorder.Entry{
			SessionID: rec.SessionID,
			TraceID:   rec.RequestID,
			Type:      EntryTypeCapture,
			EventKind: captureEventKind(SurfaceURL),
			Transport: rec.Transport,
			Summary:   rec.Subsurface + ":" + rec.EffectiveAction,
		},
		summary: w.buildSummary(
			SurfaceURL, rec.Subsurface, rec.ConfigHash, rec.Agent, rec.Profile,
			rec.ActionClass,
			scannerInput, true, TransformRaw, "", nil,
			rec.Request, rec.RawFindings, rec.EffectiveFindings,
			rec.EffectiveAction, rec.Outcome, rec.SkipReason,
		),
		scannerInput: scannerInput,
	})
}

// ObserveResponseVerdict implements CaptureObserver for response injection verdicts.
func (w *Writer) ObserveResponseVerdict(_ context.Context, rec *ResponseVerdictRecord) {
	wire := string(rec.WirePayload)
	w.send(captureEntry{
		entry: recorder.Entry{
			SessionID: rec.SessionID,
			TraceID:   rec.RequestID,
			Type:      EntryTypeCapture,
			EventKind: captureEventKind(SurfaceResponse),
			Transport: rec.Transport,
			Summary:   rec.Subsurface + ":" + rec.EffectiveAction,
		},
		summary: w.buildSummary(
			SurfaceResponse, rec.Subsurface, rec.ConfigHash, rec.Agent, rec.Profile,
			rec.ActionClass,
			"", false, rec.TransformKind, wire, nil,
			rec.Request, rec.RawFindings, rec.EffectiveFindings,
			rec.EffectiveAction, rec.Outcome, rec.SkipReason,
		),
		wirePayload: wire,
	})
}

// ObserveDLPVerdict implements CaptureObserver for DLP body-scan verdicts.
func (w *Writer) ObserveDLPVerdict(_ context.Context, rec *DLPVerdictRecord) {
	w.send(captureEntry{
		entry: recorder.Entry{
			SessionID: rec.SessionID,
			TraceID:   rec.RequestID,
			Type:      EntryTypeCapture,
			EventKind: captureEventKind(SurfaceDLP),
			Transport: rec.Transport,
			Summary:   rec.Subsurface + ":" + rec.EffectiveAction,
		},
		summary: w.buildSummary(
			SurfaceDLP, rec.Subsurface, rec.ConfigHash, rec.Agent, rec.Profile,
			rec.ActionClass,
			rec.ScannerInput, false, rec.TransformKind, "", nil,
			rec.Request, rec.RawFindings, rec.EffectiveFindings,
			rec.EffectiveAction, rec.Outcome, rec.SkipReason,
		),
		scannerInput: rec.ScannerInput,
	})
}

// ObserveCEEVerdict implements CaptureObserver for cross-entry entropy verdicts.
func (w *Writer) ObserveCEEVerdict(_ context.Context, rec *CEERecord) {
	w.send(captureEntry{
		entry: recorder.Entry{
			SessionID: rec.SessionID,
			TraceID:   rec.RequestID,
			Type:      EntryTypeCapture,
			EventKind: captureEventKind(SurfaceCEE),
			Transport: rec.Transport,
			Summary:   rec.Subsurface + ":" + rec.EffectiveAction,
		},
		summary: w.buildSummary(
			SurfaceCEE, rec.Subsurface, rec.ConfigHash, rec.Agent, rec.Profile,
			rec.ActionClass,
			rec.ScannerInput, false, rec.TransformKind, "", nil,
			rec.Request, rec.RawFindings, rec.EffectiveFindings,
			rec.EffectiveAction, rec.Outcome, rec.SkipReason,
		),
		scannerInput: rec.ScannerInput,
	})
}

// ObserveToolPolicyVerdict implements CaptureObserver for tool policy verdicts.
func (w *Writer) ObserveToolPolicyVerdict(_ context.Context, rec *ToolPolicyRecord) {
	w.send(captureEntry{
		entry: recorder.Entry{
			SessionID: rec.SessionID,
			TraceID:   rec.RequestID,
			Type:      EntryTypeCapture,
			EventKind: captureEventKind(SurfaceToolPolicy),
			Transport: rec.Transport,
			Summary:   rec.Subsurface + ":" + rec.EffectiveAction,
		},
		summary: w.buildSummary(
			SurfaceToolPolicy, rec.Subsurface, rec.ConfigHash, rec.Agent, rec.Profile,
			rec.ActionClass,
			"", rec.Request.ToolArgsJSON != "", TransformRaw, "", rec.BatchIndex,
			rec.Request, rec.RawFindings, rec.EffectiveFindings,
			rec.EffectiveAction, rec.Outcome, rec.SkipReason,
		),
	})
}

// ObserveToolScanVerdict implements CaptureObserver for tool scan verdicts.
func (w *Writer) ObserveToolScanVerdict(_ context.Context, rec *ToolScanRecord) {
	w.send(captureEntry{
		entry: recorder.Entry{
			SessionID: rec.SessionID,
			TraceID:   rec.RequestID,
			Type:      EntryTypeCapture,
			EventKind: captureEventKind(SurfaceToolScan),
			Transport: rec.Transport,
			Summary:   rec.Subsurface + ":" + rec.EffectiveAction,
		},
		summary: w.buildSummary(
			SurfaceToolScan, rec.Subsurface, rec.ConfigHash, rec.Agent, rec.Profile,
			rec.ActionClass,
			rec.ScannerInput, false, rec.TransformKind, "", rec.BatchIndex,
			rec.Request, rec.RawFindings, rec.EffectiveFindings,
			rec.EffectiveAction, rec.Outcome, rec.SkipReason,
		),
		scannerInput: rec.ScannerInput,
	})
}

// Close drains the queue and closes all per-session recorders plus the meta
// recorder. Safe to call multiple times.
func (w *Writer) Close() error {
	var firstErr error
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		close(w.ch)
		<-w.done

		for _, rec := range w.recorders {
			if err := rec.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}

		if err := w.metaRec.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	})

	return firstErr
}
