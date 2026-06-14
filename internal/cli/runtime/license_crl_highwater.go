// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
)

// crlHighWaterSuffix is appended to the configured CRL file path to locate the
// sidecar high-water file. The high-water lives next to the CRL it guards so it
// shares the CRL's directory and operator-controlled location, and so a restart
// reads back the same on-disk state instead of resetting to 0.
const crlHighWaterSuffix = ".highwater"

// crlHighWaterMaxSize caps the high-water file read. The payload is a tiny JSON
// object; anything larger is corrupt or hostile and is rejected (fail closed).
const crlHighWaterMaxSize = 4 * 1024

// crlHighWaterState is the on-disk high-water payload. Generation is the highest
// CRL generation this consumer has accepted; it only ever advances.
type crlHighWaterState struct {
	Generation uint64 `json:"generation"`
}

// crlHighWaterPath returns the sidecar high-water path for a configured CRL file.
func crlHighWaterPath(crlFile string) string {
	return filepath.Clean(crlFile) + crlHighWaterSuffix
}

// readCRLHighWater returns the persisted high-water generation.
//
// Fail-closed semantics, per the rollback-defense design:
//   - File absent  -> (0, false, nil): first run, lowest generation. Not an error.
//   - File present but unreadable / oversized / corrupt -> (0, false, err): the
//     state EXISTS but cannot be trusted, so the caller must fail closed rather
//     than silently treat it as generation 0 (which would re-open the rollback
//     window). The bool reports whether a valid prior high-water was found.
//
// KNOWN RESIDUAL (documented, tested): an attacker who can DELETE the sidecar
// makes "absent" indistinguishable from a genuine first run, so a subsequent
// lower-generation CRL is accepted. This control defends against the stated
// threat — swapping the CRL file for an older signed one — not against deletion
// of the high-water file. The sidecar and the CRL share the same write-trust
// boundary, so distinguishing "first run" from "attacker deleted it" is not
// possible from on-disk state alone. Hardening this further (e.g. anchoring the
// high-water in a write-protected location separate from the CRL directory) is
// out of scope for this control; see TestCRLRollbackSidecarDeletionResidual.
func readCRLHighWater(crlFile string) (generation uint64, found bool, err error) {
	path := crlHighWaterPath(crlFile)
	info, statErr := os.Stat(path)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("stat license CRL high-water: %w", statErr)
	}
	if !info.Mode().IsRegular() {
		return 0, false, errors.New("license CRL high-water must be a regular file")
	}
	if info.Size() > crlHighWaterMaxSize {
		return 0, false, errors.New("license CRL high-water exceeds maximum size")
	}
	data, readErr := os.ReadFile(path) // #nosec G304 -- path derived from operator-configured CRL file, cleaned, size-capped
	if readErr != nil {
		return 0, false, fmt.Errorf("read license CRL high-water: %w", readErr)
	}
	var state crlHighWaterState
	if jsonErr := json.Unmarshal(data, &state); jsonErr != nil {
		return 0, false, fmt.Errorf("parse license CRL high-water: %w", jsonErr)
	}
	return state.Generation, true, nil
}

// writeCRLHighWater atomically persists the high-water generation (temp + rename,
// file mode 0o600). The directory is the CRL file's directory, which already
// exists; it is created with 0o750 if somehow absent. A write failure is an
// error the caller must surface as fail-closed, because an accepted-but-unpersisted
// generation would re-open the rollback window on the next restart.
func writeCRLHighWater(crlFile string, generation uint64) error {
	path := crlHighWaterPath(crlFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create license CRL high-water dir: %w", err)
	}
	data, err := json.Marshal(crlHighWaterState{Generation: generation})
	if err != nil {
		return fmt.Errorf("marshal license CRL high-water: %w", err)
	}
	if err := atomicfile.Write(path, data, 0o600); err != nil {
		return fmt.Errorf("write license CRL high-water: %w", err)
	}
	return nil
}
