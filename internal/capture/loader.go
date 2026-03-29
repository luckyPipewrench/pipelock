// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// LoadAndReplay reads all capture sessions from sessionsDir, replays each
// entry against the candidate config, and returns the replayed records, total
// drop count, original config hash, and any error.
//
// A fresh scanner is created per session so rate-limiter and data-budget state
// does not bleed across sessions.
//
// Sessions are enumerated as direct subdirectories of sessionsDir. The reserved
// "capture-meta" subdirectory is skipped (it stores drop sentinels, not capture
// entries). Within each session directory, all evidence-*.jsonl files are read
// in sequence order. Only entries of type EntryTypeCapture with a valid
// CaptureSummary are replayed; checkpoint, drop, and other entry types are
// skipped.
//
// The original config hash is taken from the first CaptureSummary with a
// non-empty ConfigHash. The drop count is the maximum Count seen across all
// EntryTypeCaptureDrop entries in the capture-meta subdirectory.
func LoadAndReplay(cfg *config.Config, sessionsDir string) ([]ReplayedRecord, int, string, error) {
	sessionsDir = filepath.Clean(sessionsDir)

	dirEntries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return nil, 0, "", fmt.Errorf("reading sessions directory: %w", err)
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

	// Sort session directories for deterministic replay order.
	var sessionNames []string
	for _, de := range dirEntries {
		if de.IsDir() && de.Name() != metaSessionID {
			sessionNames = append(sessionNames, de.Name())
		}
	}
	sort.Strings(sessionNames)

	var allRecords []ReplayedRecord
	originalHash := ""

	for _, sessionName := range sessionNames {
		sessionDir := filepath.Join(sessionsDir, sessionName)

		sessions, listErr := recorder.ListSessions(sessionDir)
		if listErr != nil {
			return nil, 0, "", fmt.Errorf("listing sessions in %s: %w", sessionName, listErr)
		}

		// Fresh scanner per session to avoid rate-limiter / data-budget bleed.
		sc := scanner.New(cfg)
		re := NewReplayEngine(cfg, sc)

		for _, sessionID := range sessions {
			result, queryErr := recorder.QuerySession(sessionDir, sessionID, &recorder.QueryFilter{
				Type: EntryTypeCapture,
			})
			if queryErr != nil {
				sc.Close()
				return nil, 0, "", fmt.Errorf("querying session %s/%s: %w", sessionName, sessionID, queryErr)
			}

			for _, entry := range result.Entries {
				summary, scannerInput, err := extractCaptureSummary(entry)
				if err != nil {
					// Skip unparseable entries.
					continue
				}

				// Extract the original config hash from the first valid record.
				if originalHash == "" && summary.ConfigHash != "" {
					originalHash = summary.ConfigHash
				}

				replayed := re.ReplayRecord(summary, scannerInput)
				allRecords = append(allRecords, ReplayedRecord{
					Summary: summary,
					Result:  replayed,
				})
			}
		}

		sc.Close()
	}

	return allRecords, totalDropped, originalHash, nil
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
// payload replay requires sidecar decryption (--escrow-private-key, not yet
// wired).
func extractCaptureSummary(entry recorder.Entry) (CaptureSummary, string, error) {
	if entry.Type != EntryTypeCapture {
		return CaptureSummary{}, "", fmt.Errorf("skipping entry type %q", entry.Type)
	}

	detailJSON, err := json.Marshal(entry.Detail)
	if err != nil {
		return CaptureSummary{}, "", fmt.Errorf("marshaling entry detail: %w", err)
	}

	var summary CaptureSummary
	if err := json.Unmarshal(detailJSON, &summary); err != nil {
		return CaptureSummary{}, "", fmt.Errorf("parsing capture summary: %w", err)
	}

	if summary.CaptureSchemaVersion != CaptureSchemaV1 {
		return CaptureSummary{}, "",
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
		// Response, DLP, address, tool_scan, CEE: require exact scanner
		// input from sidecar. Without escrow decryption, mark as
		// summary-only by leaving scannerInput empty.
		scannerInput = ""
	}

	return summary, scannerInput, nil
}
