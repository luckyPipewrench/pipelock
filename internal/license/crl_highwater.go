// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
)

const (
	// CRLHighWaterSuffix is appended to the configured CRL file path to locate
	// the sidecar high-water file. The high-water lives next to the CRL it
	// guards so a restart reads back the same on-disk state instead of resetting
	// to generation 0.
	CRLHighWaterSuffix = ".highwater"

	// crlHighWaterMaxSize caps the high-water file read. The payload is a tiny
	// JSON object; anything larger is corrupt or hostile and is rejected.
	crlHighWaterMaxSize = 4 * 1024
)

var crlHighWaterMu sync.Mutex

type crlHighWaterState struct {
	Generation uint64 `json:"generation"`
}

// CRLHighWaterPath returns the sidecar high-water path for a configured CRL
// file.
func CRLHighWaterPath(crlFile string) string {
	return filepath.Clean(crlFile) + CRLHighWaterSuffix
}

// LoadAndVerifyCRLMonotonic verifies the signed CRL and advances the consumer's
// durable high-water mark. A signature-valid, unexpired CRL is necessary but not
// sufficient: any CRL below the accepted high-water is rejected fail-closed.
func LoadAndVerifyCRLMonotonic(path string, publicKey ed25519.PublicKey, now time.Time) (CRL, error) {
	crl, err := LoadAndVerifyCRL(path, publicKey, now)
	if err != nil {
		return CRL{}, err
	}
	if _, err := AdvanceCRLHighWater(path, crl.Payload.Generation); err != nil {
		return CRL{}, err
	}
	return crl, nil
}

// ReadCRLHighWater returns the persisted high-water generation.
//
// Fail-closed semantics:
//   - File absent -> (0, false, nil): first run, lowest generation.
//   - File present but unreadable / oversized / corrupt -> error: the caller
//     must not silently treat existing-but-untrusted state as generation 0.
//
// Known residual: deleting the sidecar makes "absent" indistinguishable from a
// genuine first run. This control defends against swapping the CRL file for an
// older signed CRL, not deletion of the high-water state itself.
func ReadCRLHighWater(crlFile string) (generation uint64, found bool, err error) {
	path := CRLHighWaterPath(crlFile)
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
	data, readErr := os.ReadFile(path) // #nosec G304 -- path derives from operator-configured CRL file, cleaned and size-capped
	if readErr != nil {
		return 0, false, fmt.Errorf("read license CRL high-water: %w", readErr)
	}
	var state crlHighWaterState
	if jsonErr := json.Unmarshal(data, &state); jsonErr != nil {
		return 0, false, fmt.Errorf("parse license CRL high-water: %w", jsonErr)
	}
	return state.Generation, true, nil
}

// AdvanceCRLHighWater atomically persists generation if it is not below the
// accepted high-water. The read/compare/write is serialized in-process and
// guarded with a sidecar lock file across local processes so two verifiers
// cannot race and rewrite the high-water backwards.
func AdvanceCRLHighWater(crlFile string, generation uint64) (uint64, error) {
	crlHighWaterMu.Lock()
	defer crlHighWaterMu.Unlock()

	unlock, err := acquireCRLHighWaterLock(crlFile)
	if err != nil {
		return 0, err
	}
	defer unlock()

	highWater, found, err := ReadCRLHighWater(crlFile)
	if err != nil {
		return 0, fmt.Errorf("license CRL high-water unreadable, cannot verify rollback: %w", err)
	}
	if found && generation < highWater {
		return highWater, fmt.Errorf("license CRL rollback rejected: generation %d below accepted %d", generation, highWater)
	}
	if !found || generation > highWater {
		if err := writeCRLHighWater(crlFile, generation); err != nil {
			return 0, fmt.Errorf("persist license CRL high-water: %w", err)
		}
		return generation, nil
	}
	return highWater, nil
}

func writeCRLHighWater(crlFile string, generation uint64) error {
	path := CRLHighWaterPath(crlFile)
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
