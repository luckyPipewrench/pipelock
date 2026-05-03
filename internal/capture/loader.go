// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// ErrSidecarDecrypt is returned when replay was asked to use encrypted
// sidecars but a sidecar cannot be safely read, decrypted, or verified.
var ErrSidecarDecrypt = errors.New("capture replay: sidecar decrypt failed")

// ReplayOptions controls optional full-fidelity replay behavior.
type ReplayOptions struct {
	// EscrowPrivateKey is the X25519 private key used to decrypt payload
	// sidecars written by Writer when capture escrow is enabled.
	EscrowPrivateKey []byte
	// Contract enables contract-aware replay for supported surfaces.
	Contract *contract.Contract
	// SessionFilter optionally limits replay to matching session directories.
	// The filter receives the session directory's base name and absolute path
	// so callers can perform content-level validation (e.g. verifying the
	// embedded agent matches the requested agent) rather than trusting the
	// directory name alone.
	SessionFilter func(name, sessionDir string) bool
}

type replayEscrowKey struct {
	pub  [32]byte
	priv [32]byte
}

// LoadAndReplay reads all capture sessions from sessionsDir, replays each
// entry against the candidate config, and returns the replayed records, total
// drop count, skipped entry count, original config hash, and any error.
//
// A fresh scanner is created per session so rate-limiter and data-budget state
// does not bleed across sessions.
//
// Sessions are enumerated as direct subdirectories of sessionsDir. The reserved
// "capture-meta" subdirectory is skipped (it stores drop sentinels, not capture
// entries). Within each session directory, all evidence-*.jsonl files are read
// in sequence order. Only entries of type EntryTypeCapture with a valid
// CaptureSummary are replayed; checkpoint, drop, and other entry types are
// skipped. Entries that fail to unmarshal are counted as skipped.
//
// The original config hash is taken from the first CaptureSummary with a
// non-empty ConfigHash. The drop count is the maximum Count seen across all
// EntryTypeCaptureDrop entries in the capture-meta subdirectory.
func LoadAndReplay(cfg *config.Config, sessionsDir string) ([]ReplayedRecord, int, int, string, error) {
	return LoadAndReplayWithOptions(cfg, sessionsDir, ReplayOptions{})
}

// LoadAndReplayWithOptions is LoadAndReplay with optional encrypted sidecar
// decryption enabled.
func LoadAndReplayWithOptions(cfg *config.Config, sessionsDir string, opts ReplayOptions) ([]ReplayedRecord, int, int, string, error) {
	sessionsDir = filepath.Clean(sessionsDir)
	escrowPriv, err := decodeReplayEscrowPrivateKey(opts.EscrowPrivateKey)
	if err != nil {
		return nil, 0, 0, "", err
	}

	dirEntries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return nil, 0, 0, "", fmt.Errorf("reading sessions directory: %w", err)
	}

	// Read drop count from capture-meta subdirectory. The meta recorder writes
	// cumulative counts in each sentinel, so the maximum value is the total.
	totalDropped := 0
	metaDir := filepath.Join(sessionsDir, metaSessionID)
	if metaResult, metaErr := recorder.QuerySession(metaDir, metaSessionID, &recorder.QueryFilter{Type: EntryTypeCaptureDrop}); metaErr == nil {
		for _, entry := range metaResult.Entries {
			detailJSON, marshalErr := json.Marshal(entry.Detail)
			if marshalErr != nil {
				continue
			}
			var drop CaptureDropDetail
			if unmarshalErr := json.Unmarshal(detailJSON, &drop); unmarshalErr != nil {
				continue
			}
			if drop.Count > totalDropped {
				totalDropped = drop.Count
			}
		}
	}

	// os.ReadDir returns entries sorted by name. For deterministic replay,
	// sessions are processed in alphabetical order by session ID.
	var sessionNames []string
	for _, de := range dirEntries {
		if !de.IsDir() || de.Name() == metaSessionID {
			continue
		}
		if opts.SessionFilter != nil && !opts.SessionFilter(de.Name(), filepath.Join(sessionsDir, de.Name())) {
			continue
		}
		sessionNames = append(sessionNames, de.Name())
	}
	sort.Strings(sessionNames)

	var (
		allRecords   []ReplayedRecord
		totalSkipped int
		originalHash string
	)

	for _, sessionName := range sessionNames {
		sessionDir := filepath.Join(sessionsDir, sessionName)

		sessions, listErr := recorder.ListSessions(sessionDir)
		if listErr != nil {
			return nil, 0, 0, "", fmt.Errorf("listing sessions in %s: %w", sessionName, listErr)
		}

		// Fresh scanner per session to avoid rate-limiter / data-budget bleed.
		sc := scanner.New(cfg)
		re := NewReplayEngine(cfg, sc)
		if opts.Contract != nil {
			re = NewContractReplayEngine(cfg, sc, *opts.Contract)
		}

		for _, sessionID := range sessions {
			result, queryErr := recorder.QuerySession(sessionDir, sessionID, &recorder.QueryFilter{
				Type: EntryTypeCapture,
			})
			if queryErr != nil {
				sc.Close()
				return nil, 0, 0, "", fmt.Errorf("querying session %s/%s: %w", sessionName, sessionID, queryErr)
			}

			for _, entry := range result.Entries {
				summary, scannerInput, sidecarDecrypted, err := extractCaptureSummaryWithOptions(entry, sessionDir, escrowPriv)
				if err != nil {
					if errors.Is(err, ErrSidecarDecrypt) {
						sc.Close()
						return nil, 0, 0, "", err
					}
					totalSkipped++
					continue
				}

				// Extract the original config hash from the first valid record.
				if originalHash == "" && summary.ConfigHash != "" {
					originalHash = summary.ConfigHash
				}

				replayed := re.ReplayRecord(summary, scannerInput)
				replayed.SidecarDecrypted = sidecarDecrypted
				allRecords = append(allRecords, ReplayedRecord{
					Summary:   summary,
					Result:    replayed,
					Timestamp: entry.Timestamp,
				})
			}
		}

		sc.Close()
	}

	return allRecords, totalDropped, totalSkipped, originalHash, nil
}

// extractCaptureSummary extracts a CaptureSummary and scanner input from a
// recorder.Entry. Returns an error if the entry cannot be parsed or has an
// unsupported schema version.
//
// For URL surfaces the scanner input is the request URL (always available in
// the summary). Tool policy surfaces need no scanner input (they replay via
// ToolName + ToolArgsJSON). All other surfaces (response, DLP, tool_scan,
// CEE) return empty scanner input, producing summary-only replay results.
// This avoids false diffs from truncated ScannerSample (256 bytes). Full
// payload replay requires sidecar decryption through ReplayOptions.
func extractCaptureSummaryWithOptions(entry recorder.Entry, sessionDir string, escrowKey *replayEscrowKey) (CaptureSummary, string, bool, error) {
	if entry.Type != EntryTypeCapture {
		return CaptureSummary{}, "", false, fmt.Errorf("skipping entry type %q", entry.Type)
	}

	detailJSON, err := json.Marshal(entry.Detail)
	if err != nil {
		return CaptureSummary{}, "", false, fmt.Errorf("marshaling entry detail: %w", err)
	}

	var summary CaptureSummary
	if err := json.Unmarshal(detailJSON, &summary); err != nil {
		return CaptureSummary{}, "", false, fmt.Errorf("parsing capture summary: %w", err)
	}

	if summary.CaptureSchemaVersion != CaptureSchemaV1 {
		return CaptureSummary{}, "", false,
			fmt.Errorf("unsupported capture schema version %d (expected %d)",
				summary.CaptureSchemaVersion, CaptureSchemaV1)
	}

	// Determine scanner input based on surface type. Only URL has a
	// full-fidelity input always available (the request URL). Tool policy
	// uses ToolName + ToolArgsJSON from the request, not scanner input.
	// All other surfaces (response, DLP, address, tool_scan, CEE) require
	// exact payload from sidecar decryption. Without escrow, these are
	// summary-only -- using the truncated ScannerSample (256 bytes) would
	// produce false diffs for longer payloads.
	var scannerInput string
	switch summary.Surface {
	case SurfaceURL:
		scannerInput = summary.Request.URL
	case SurfaceToolPolicy:
		// Tool policy replays via ToolName + ToolArgsJSON, no scanner input.
		scannerInput = ""
	default:
		if escrowKey != nil && summary.PayloadRef != "" {
			input, err := decryptPayloadSidecar(sessionDir, summary, escrowKey)
			if err != nil {
				return CaptureSummary{}, "", false, err
			}
			return summary, input, true, nil
		}
		// Response, DLP, address, tool_scan, CEE: require exact scanner input
		// from sidecar. Without escrow decryption, leave scannerInput empty so
		// the replay result stays summary/evidence-only.
		scannerInput = ""
	}

	return summary, scannerInput, false, nil
}

func decodeReplayEscrowPrivateKey(key []byte) (*replayEscrowKey, error) {
	if len(key) == 0 {
		return nil, nil
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: escrow private key must be 32 bytes", ErrSidecarDecrypt)
	}
	pub, err := curve25519.X25519(key, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("%w: derive public key: %w", ErrSidecarDecrypt, err)
	}
	var out replayEscrowKey
	copy(out.priv[:], key)
	copy(out.pub[:], pub)
	return &out, nil
}

func decryptPayloadSidecar(sessionDir string, summary CaptureSummary, escrowKey *replayEscrowKey) (string, error) {
	if sessionDir == "" {
		return "", fmt.Errorf("%w: session directory is required", ErrSidecarDecrypt)
	}
	if !safePayloadRef(summary.PayloadRef) {
		return "", fmt.Errorf("%w: unsafe payload_ref %q", ErrSidecarDecrypt, summary.PayloadRef)
	}
	ciphertext, err := os.ReadFile(filepath.Join(filepath.Clean(sessionDir), summary.PayloadRef))
	if err != nil {
		return "", fmt.Errorf("%w: read %s: %w", ErrSidecarDecrypt, summary.PayloadRef, err)
	}
	plaintext, ok := box.OpenAnonymous(nil, ciphertext, &escrowKey.pub, &escrowKey.priv)
	if !ok {
		return "", fmt.Errorf("%w: decrypt %s", ErrSidecarDecrypt, summary.PayloadRef)
	}
	if summary.PayloadSHA256 == "" {
		return "", fmt.Errorf("%w: missing payload_sha256 for %s", ErrSidecarDecrypt, summary.PayloadRef)
	}
	sum := sha256.Sum256(plaintext)
	got := "sha256:" + fmt.Sprintf("%x", sum[:])
	if got != summary.PayloadSHA256 {
		return "", fmt.Errorf("%w: payload sha256 %s != %s", ErrSidecarDecrypt, got, summary.PayloadSHA256)
	}
	return string(plaintext), nil
}

func safePayloadRef(ref string) bool {
	if ref == "" || filepath.IsAbs(ref) {
		return false
	}
	clean := filepath.Clean(ref)
	return clean == ref && filepath.Base(clean) == clean && !strings.Contains(clean, "..")
}
