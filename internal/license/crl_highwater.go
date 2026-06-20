// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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
	CRLHighWaterSuffix       = ".highwater"
	CRLHighWaterAnchorSuffix = ".anchor"
	crlHighWaterContextFile  = "context.json"

	// crlHighWaterMaxSize caps the high-water file read. The payload is a tiny
	// JSON object; anything larger is corrupt or hostile and is rejected.
	crlHighWaterMaxSize = 4 * 1024
)

var crlHighWaterMu sync.Mutex

type crlHighWaterState struct {
	Generation uint64 `json:"generation"`
	Context    string `json:"context,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

type crlHighWaterContext struct {
	Context string `json:"context"`
}

// CRLHighWaterPath returns the sidecar high-water path for a configured CRL
// file.
func CRLHighWaterPath(crlFile string) string {
	return filepath.Clean(crlFile) + CRLHighWaterSuffix
}

// CRLHighWaterAnchorPath returns the secondary durable anchor for the CRL
// generation high-water. It protects against accidental or hostile deletion of
// only the primary sidecar.
func CRLHighWaterAnchorPath(crlFile string) string {
	return filepath.Join(crlHighWaterProtectedDir(crlFile), "secondary.json")
}

func crlHighWaterContextPath(crlFile string) string {
	return filepath.Join(crlHighWaterProtectedDir(crlFile), crlHighWaterContextFile)
}

func crlHighWaterProtectedDir(crlFile string) string {
	clean := filepath.Clean(crlFile)
	sum := sha256.Sum256([]byte(clean))
	return filepath.Join(filepath.Dir(clean), ".pipelock-state", "license-crl-highwater", hex.EncodeToString(sum[:16]))
}

func crlHighWaterContextID(crlFile string) string {
	clean := filepath.Clean(crlFile)
	sum := sha256.Sum256([]byte("license-crl-highwater-v1\n" + clean))
	return hex.EncodeToString(sum[:])
}

func crlHighWaterDigest(crlFile string, generation uint64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("license-crl-highwater-v1\n%s\n%d", crlHighWaterContextID(crlFile), generation)))
	return hex.EncodeToString(sum[:])
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

// LoadAndVerifyCRLMonotonicFresh extends LoadAndVerifyCRLMonotonic with an
// IssuedAt-age freshness gate. It is the function the require-intermediate
// resolver uses: under require mode an unexpired-but-stale CRL is a
// rollback/compromise-response gap and must fail closed. maxAge is the operator-
// configured freshness window (license_crl_max_age); a zero/negative value is
// clamped to DefaultCRLMaxAge so a misconfiguration can never DISABLE the check.
// The legacy (non-require) paths keep calling LoadAndVerifyCRLMonotonic so
// behaviour is unchanged when require mode is off.
func LoadAndVerifyCRLMonotonicFresh(path string, publicKey ed25519.PublicKey, now time.Time, maxAge time.Duration) (CRL, error) {
	crl, err := LoadAndVerifyCRL(path, publicKey, now)
	if err != nil {
		return CRL{}, err
	}
	if maxAge <= 0 {
		maxAge = DefaultCRLMaxAge
	}
	if err := crl.CheckFreshness(now, maxAge); err != nil {
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
// The primary sidecar is paired with a secondary anchor. If one is missing, the
// remaining record is still treated as the rollback floor; if both are missing,
// the verifier treats it as a genuine first run and seeds from the signed CRL.
func ReadCRLHighWater(crlFile string) (generation uint64, found bool, err error) {
	return readCRLHighWaterFileForContext(CRLHighWaterPath(crlFile), "license CRL high-water", crlFile)
}

func readCRLHighWaterFile(path, label string) (generation uint64, found bool, err error) {
	return readCRLHighWaterFileForContext(path, label, "")
}

func readCRLHighWaterFileForContext(path, label, crlFile string) (generation uint64, found bool, err error) {
	info, statErr := os.Stat(path)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("stat %s: %w", label, statErr)
	}
	if !info.Mode().IsRegular() {
		return 0, false, fmt.Errorf("%s must be a regular file", label)
	}
	if info.Size() > crlHighWaterMaxSize {
		return 0, false, fmt.Errorf("%s exceeds maximum size", label)
	}
	data, readErr := os.ReadFile(path) // #nosec G304 -- path derives from operator-configured CRL file, cleaned and size-capped
	if readErr != nil {
		return 0, false, fmt.Errorf("read %s: %w", label, readErr)
	}
	var state crlHighWaterState
	if jsonErr := json.Unmarshal(data, &state); jsonErr != nil {
		return 0, false, fmt.Errorf("parse %s: %w", label, jsonErr)
	}
	if crlFile != "" {
		if state.Context != "" && state.Context != crlHighWaterContextID(crlFile) {
			return 0, false, fmt.Errorf("%s context mismatch", label)
		}
		if state.Digest != "" && state.Digest != crlHighWaterDigest(crlFile, state.Generation) {
			return 0, false, fmt.Errorf("%s digest mismatch", label)
		}
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

	highWater, found, err := readDurableCRLHighWater(crlFile)
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

func readDurableCRLHighWater(crlFile string) (uint64, bool, error) {
	primary, primaryFound, err := ReadCRLHighWater(crlFile)
	if err != nil {
		return 0, false, err
	}
	anchor, anchorFound, err := readCRLHighWaterFileForContext(CRLHighWaterAnchorPath(crlFile), "license CRL high-water secondary", crlFile)
	if err != nil {
		return 0, false, err
	}
	switch {
	case primaryFound && anchorFound:
		if primary != anchor {
			return 0, false, fmt.Errorf("license CRL high-water mismatch: primary=%d anchor=%d", primary, anchor)
		}
		return primary, true, nil
	case primaryFound:
		if err := writeCRLHighWaterFileForCRL(CRLHighWaterAnchorPath(crlFile), crlFile, primary); err != nil {
			return 0, false, fmt.Errorf("backfill license CRL high-water anchor: %w", err)
		}
		if err := writeCRLHighWaterContext(crlFile); err != nil {
			return 0, false, fmt.Errorf("backfill license CRL high-water context: %w", err)
		}
		return primary, true, nil
	case anchorFound:
		if err := writeCRLHighWaterFileForCRL(CRLHighWaterPath(crlFile), crlFile, anchor); err != nil {
			return 0, false, fmt.Errorf("restore license CRL high-water primary: %w", err)
		}
		if err := writeCRLHighWaterContext(crlFile); err != nil {
			return 0, false, fmt.Errorf("backfill license CRL high-water context: %w", err)
		}
		return anchor, true, nil
	default:
		contextFound, contextErr := readCRLHighWaterContext(crlFile)
		if contextErr != nil {
			return 0, false, contextErr
		}
		if contextFound {
			return 0, false, fmt.Errorf("license CRL high-water missing while CRL context is present; run an explicit high-water reset after fetching the latest CRL")
		}
		return 0, false, nil
	}
}

func writeCRLHighWater(crlFile string, generation uint64) error {
	if err := writeCRLHighWaterFileForCRL(CRLHighWaterPath(crlFile), crlFile, generation); err != nil {
		return err
	}
	if err := writeCRLHighWaterFileForCRL(CRLHighWaterAnchorPath(crlFile), crlFile, generation); err != nil {
		return err
	}
	if err := writeCRLHighWaterContext(crlFile); err != nil {
		return err
	}
	return nil
}

func readCRLHighWaterContext(crlFile string) (bool, error) {
	path := crlHighWaterContextPath(crlFile)
	info, statErr := os.Stat(path)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat license CRL high-water context: %w", statErr)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("license CRL high-water context must be a regular file")
	}
	if info.Size() > crlHighWaterMaxSize {
		return false, fmt.Errorf("license CRL high-water context exceeds maximum size")
	}
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- path derives from operator-configured CRL file and protected state root
	if err != nil {
		return false, fmt.Errorf("read license CRL high-water context: %w", err)
	}
	var ctx crlHighWaterContext
	if err := json.Unmarshal(data, &ctx); err != nil {
		return false, fmt.Errorf("parse license CRL high-water context: %w", err)
	}
	if ctx.Context != crlHighWaterContextID(crlFile) {
		return false, fmt.Errorf("license CRL high-water context mismatch")
	}
	return true, nil
}

func writeCRLHighWaterContext(crlFile string) error {
	path := crlHighWaterContextPath(crlFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create license CRL high-water context dir: %w", err)
	}
	data, err := json.Marshal(crlHighWaterContext{Context: crlHighWaterContextID(crlFile)})
	if err != nil {
		return fmt.Errorf("marshal license CRL high-water context: %w", err)
	}
	if err := atomicfile.Write(path, data, 0o600); err != nil {
		return fmt.Errorf("write license CRL high-water context: %w", err)
	}
	return nil
}

func writeCRLHighWaterFileForCRL(path, crlFile string, generation uint64) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create license CRL high-water dir: %w", err)
	}
	data, err := json.Marshal(crlHighWaterState{
		Generation: generation,
		Context:    crlHighWaterContextID(crlFile),
		Digest:     crlHighWaterDigest(crlFile, generation),
	})
	if err != nil {
		return fmt.Errorf("marshal license CRL high-water: %w", err)
	}
	if err := atomicfile.Write(path, data, 0o600); err != nil {
		return fmt.Errorf("write license CRL high-water: %w", err)
	}
	return nil
}

// ResetCRLHighWater explicitly seeds the durable CRL rollback floor for an
// operator migration or recovery. Callers should log the operator reason before
// invoking this; there is intentionally no implicit reset path.
func ResetCRLHighWater(crlFile string, generation uint64) error {
	crlHighWaterMu.Lock()
	defer crlHighWaterMu.Unlock()

	unlock, err := acquireCRLHighWaterLock(crlFile)
	if err != nil {
		return err
	}
	defer unlock()
	return writeCRLHighWater(crlFile, generation)
}
