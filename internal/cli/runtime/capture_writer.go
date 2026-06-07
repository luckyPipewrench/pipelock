// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	// captureMaxEntriesPerFile bounds evidence-*.jsonl files before rotation.
	captureMaxEntriesPerFile = 10000
	// captureQueueSize is the bounded async channel capacity for the capture
	// writer. Matches capture.defaultQueueSize; overflow drops + counts.
	captureQueueSize = 4096
	// escrowPublicKeyBytes is the X25519 public-key length for payload-sidecar
	// encryption (64 hex chars).
	escrowPublicKeyBytes = 32
)

// parseCaptureEscrowKey decodes the --capture-escrow-public-key hex string into
// an X25519 public key. Empty input yields (nil, nil): no escrow, no error.
func parseCaptureEscrowKey(escrowHex string) (*[escrowPublicKeyBytes]byte, error) {
	if escrowHex == "" {
		return nil, nil
	}
	keyBytes, err := hex.DecodeString(escrowHex)
	if err != nil || len(keyBytes) != escrowPublicKeyBytes {
		return nil, fmt.Errorf("invalid --capture-escrow-public-key: must be 64 hex chars (32 bytes)")
	}
	return (*[escrowPublicKeyBytes]byte)(keyBytes), nil
}

// buildCaptureWriter constructs a key-free evidence capture.Writer for the
// --capture-output flag. Shared by `pipelock run` and `pipelock mcp proxy` so
// both surfaces capture identically. redactFn is the DLP scrubber applied to
// captured payloads before they reach disk; callers gate it on
// flight_recorder.redact (default true). A nil metrics value disables the drop
// and capture-observability counters without tripping the typed-nil interface
// trap (the sinks stay nil interfaces, not interfaces wrapping a nil pointer).
func buildCaptureWriter(dir, escrowHex string, fileMode os.FileMode, redactFn recorder.RedactFunc, m *metrics.Metrics) (*capture.Writer, error) {
	escrowPub, err := parseCaptureEscrowKey(escrowHex)
	if err != nil {
		return nil, err
	}

	var dropSink capture.DropSink
	var metricsSink capture.MetricsSink
	if m != nil {
		dropSink = m
		metricsSink = m
	}

	return capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:           true,
			Dir:               dir,
			MaxEntriesPerFile: captureMaxEntriesPerFile,
			FileMode:          fileMode,
			// Redact gates the per-session recorder's DLP scrub. RedactFn
			// alone is inert without it (recorder applies redaction only when
			// cfg.Redact && redactFn != nil), so couple the two: callers that
			// pass a redactor get redaction, callers that pass nil do not.
			Redact: redactFn != nil,
		},
		RedactFn:        redactFn,
		EscrowPublicKey: escrowPub,
		DropSink:        dropSink,
		MetricsSink:     metricsSink,
		QueueSize:       captureQueueSize,
		BuildVersion:    cliutil.Version,
		BuildSHA:        cliutil.GitCommit,
	})
}
