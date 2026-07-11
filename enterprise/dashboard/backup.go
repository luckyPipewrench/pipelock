//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

const (
	ExemptionStateFile     = "exemptions.json"
	DeliveryInboxStateFile = "delivery-inbox.json"
	backupManifestName     = "manifest.json"
	backupFormatVersion    = 1
	maxBackupFileSize      = 64 << 20
	maxBackupArchiveSize   = 3*maxBackupFileSize + 1<<20
)

var durableStateFiles = map[string]struct{}{
	ExemptionStateFile:     {},
	DeliveryInboxStateFile: {},
}

type backupManifest struct {
	Version int                  `json:"version"`
	Files   []backupManifestFile `json:"files"`
}

type backupManifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

var stateDirLocks sync.Map

func stateDirLock(path string) *sync.Mutex {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err == nil {
		path = abs
	}
	mu, _ := stateDirLocks.LoadOrStore(path, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// BackupState writes a deterministic tar archive containing only recognized,
// non-reconstructible dashboard state. Recorder evidence and read-model
// indexes are intentionally excluded.
func BackupState(stateDir, archivePath string) error {
	stateDir = filepath.Clean(stateDir)
	archivePath = filepath.Clean(archivePath)
	if err := rejectProtectedArchivePath(stateDir, archivePath); err != nil {
		return err
	}
	mu := stateDirLock(stateDir)
	mu.Lock()
	defer mu.Unlock()
	releaseFiles, err := lockDurableStateFiles(stateDir)
	if err != nil {
		return err
	}
	defer releaseFiles()

	names := make([]string, 0, len(durableStateFiles))
	for name := range durableStateFiles {
		names = append(names, name)
	}
	sort.Strings(names)
	files := make(map[string][]byte, len(names))
	manifest := backupManifest{Version: backupFormatVersion}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Clean(filepath.Join(stateDir, name)))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("backup dashboard state %s: %w", name, err)
		}
		if len(data) > maxBackupFileSize {
			return fmt.Errorf("backup dashboard state %s: exceeds %d-byte limit", name, maxBackupFileSize)
		}
		if err := validateStateFile(name, data); err != nil {
			return fmt.Errorf("backup dashboard state %s: %w", name, err)
		}
		sum := sha256.Sum256(data)
		files[name] = data
		manifest.Files = append(manifest.Files, backupManifestFile{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))})
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("backup dashboard state manifest: %w", err)
	}

	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := writeTarFile(tw, backupManifestName, manifestData); err != nil {
		return err
	}
	for _, entry := range manifest.Files {
		if err := writeTarFile(tw, entry.Name, files[entry.Name]); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close dashboard backup archive: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o750); err != nil {
		return fmt.Errorf("create dashboard backup directory: %w", err)
	}
	if err := atomicfile.Write(archivePath, archive.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write dashboard backup: %w", err)
	}
	return nil
}

func rejectProtectedArchivePath(stateDir, archivePath string) error {
	canonicalDir, err := canonicalPath(stateDir)
	if err != nil {
		return fmt.Errorf("resolve dashboard state directory: %w", err)
	}
	canonicalArchive, err := canonicalPath(archivePath)
	if err != nil {
		return fmt.Errorf("resolve dashboard backup path: %w", err)
	}
	for name := range durableStateFiles {
		for _, protected := range []string{name, name + ".lock"} {
			if canonicalArchive == filepath.Join(canonicalDir, protected) {
				return fmt.Errorf("dashboard backup path must not overwrite protected state file %s", protected)
			}
		}
	}
	return nil
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	current := abs
	var missing []string
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return resolved, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor for %s", abs)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func writeTarFile(tw *tar.Writer, name string, data []byte) error {
	header := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("write dashboard backup header %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("write dashboard backup file %s: %w", name, err)
	}
	return nil
}

// RestoreState validates the complete archive before replacing any file. If
// validation fails, existing state is untouched. Commit-time errors trigger a
// rollback from in-memory originals before an error is returned.
func RestoreState(stateDir, archivePath string) error {
	data, err := readBackupArchive(archivePath)
	if err != nil {
		return fmt.Errorf("read dashboard backup: %w", err)
	}
	restored, err := decodeBackup(data)
	if err != nil {
		return err
	}
	stateDir = filepath.Clean(stateDir)
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return fmt.Errorf("create dashboard state directory: %w", err)
	}
	mu := stateDirLock(stateDir)
	mu.Lock()
	defer mu.Unlock()
	releaseFiles, err := lockDurableStateFiles(stateDir)
	if err != nil {
		return err
	}
	defer releaseFiles()

	originals := make(map[string][]byte, len(durableStateFiles))
	missing := make(map[string]bool, len(durableStateFiles))
	for name := range durableStateFiles {
		prior, readErr := os.ReadFile(filepath.Clean(filepath.Join(stateDir, name)))
		if errors.Is(readErr, os.ErrNotExist) {
			missing[name] = true
			continue
		}
		if readErr != nil {
			return fmt.Errorf("snapshot existing dashboard state %s: %w", name, readErr)
		}
		originals[name] = prior
	}

	names := make([]string, 0, len(durableStateFiles))
	for name := range durableStateFiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(stateDir, name)
		file, exists := restored[name]
		if exists {
			err = atomicfile.Write(path, file, 0o600)
		} else {
			err = os.Remove(path)
			if errors.Is(err, os.ErrNotExist) {
				err = nil
			}
		}
		if err == nil {
			continue
		}
		rollbackErr := rollbackState(stateDir, names, originals, missing)
		return fmt.Errorf("restore dashboard state %s: %w", name, errors.Join(err, rollbackErr))
	}
	return nil
}

func readBackupArchive(path string) ([]byte, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxBackupArchiveSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBackupArchiveSize {
		return nil, fmt.Errorf("archive exceeds %d-byte limit", maxBackupArchiveSize)
	}
	return data, nil
}

func lockDurableStateFiles(stateDir string) (func(), error) {
	names := make([]string, 0, len(durableStateFiles))
	for name := range durableStateFiles {
		names = append(names, name)
	}
	sort.Strings(names)
	type heldLock struct {
		pathMu *sync.Mutex
		file   *exemptionStoreFileLock
	}
	held := make([]heldLock, 0, len(names))
	release := func() {
		for index := len(held) - 1; index >= 0; index-- {
			_ = held[index].file.Close()
			held[index].pathMu.Unlock()
		}
	}
	for _, name := range names {
		path := filepath.Join(stateDir, name)
		pathMu := exemptionStorePathLock(path)
		pathMu.Lock()
		fileLock, err := acquireExemptionStoreFileLock(path + ".lock")
		if err != nil {
			pathMu.Unlock()
			release()
			return nil, fmt.Errorf("lock dashboard state %s: %w", name, err)
		}
		held = append(held, heldLock{pathMu: pathMu, file: fileLock})
	}
	return release, nil
}

func rollbackState(stateDir string, names []string, originals map[string][]byte, missing map[string]bool) error {
	var errs []error
	for _, name := range names {
		path := filepath.Join(stateDir, name)
		if missing[name] {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove %s: %w", name, err))
			}
			continue
		}
		if err := atomicfile.Write(path, originals[name], 0o600); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func decodeBackup(data []byte) (map[string][]byte, error) {
	reader := bytes.NewReader(data)
	tr := tar.NewReader(reader)
	entries := make(map[string][]byte)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("validate dashboard backup archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || filepath.Base(header.Name) != header.Name || header.Name == "." || header.Name == ".." {
			return nil, fmt.Errorf("validate dashboard backup archive: unsafe entry %q", header.Name)
		}
		if header.Size < 0 || header.Size > maxBackupFileSize {
			return nil, fmt.Errorf("validate dashboard backup archive: invalid size for %q", header.Name)
		}
		if _, exists := entries[header.Name]; exists {
			return nil, fmt.Errorf("validate dashboard backup archive: duplicate entry %q", header.Name)
		}
		if header.Name != backupManifestName {
			if _, ok := durableStateFiles[header.Name]; !ok {
				return nil, fmt.Errorf("validate dashboard backup archive: unknown state file %q", header.Name)
			}
		}
		entry, err := io.ReadAll(io.LimitReader(tr, maxBackupFileSize+1))
		if err != nil || int64(len(entry)) != header.Size {
			return nil, fmt.Errorf("validate dashboard backup archive: incomplete entry %q", header.Name)
		}
		entries[header.Name] = entry
	}
	trailing, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("validate dashboard backup archive trailer: %w", err)
	}
	for _, value := range trailing {
		if value != 0 {
			return nil, errors.New("validate dashboard backup archive: non-zero data after tar terminator")
		}
	}
	manifestData, ok := entries[backupManifestName]
	if !ok {
		return nil, errors.New("validate dashboard backup archive: manifest missing")
	}
	delete(entries, backupManifestName)
	var manifest backupManifest
	if err := decodeStrictJSON(manifestData, &manifest); err != nil || manifest.Version != backupFormatVersion {
		return nil, errors.New("validate dashboard backup archive: invalid manifest")
	}
	if len(manifest.Files) != len(entries) {
		return nil, errors.New("validate dashboard backup archive: manifest file set mismatch")
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	for _, file := range manifest.Files {
		entry, exists := entries[file.Name]
		if _, duplicate := seen[file.Name]; duplicate || !exists || int64(len(entry)) != file.Size {
			return nil, fmt.Errorf("validate dashboard backup archive: manifest mismatch for %q", file.Name)
		}
		seen[file.Name] = struct{}{}
		sum := sha256.Sum256(entry)
		if hex.EncodeToString(sum[:]) != file.SHA256 {
			return nil, fmt.Errorf("validate dashboard backup archive: checksum mismatch for %q", file.Name)
		}
		if err := validateStateFile(file.Name, entry); err != nil {
			return nil, fmt.Errorf("validate dashboard backup archive: %s: %w", file.Name, err)
		}
	}
	return entries, nil
}

func validateStateFile(name string, data []byte) error {
	if name == DeliveryInboxStateFile {
		var state deliveryInboxState
		if err := decodeStrictJSON(data, &state); err != nil || validateDeliveryState(state) != nil {
			return errors.New("invalid delivery inbox schema")
		}
	}
	if name == ExemptionStateFile {
		var records []ExemptionRecord
		if err := decodeStrictJSON(data, &records); err != nil || records == nil {
			return errors.New("invalid exemption store schema")
		}
		seen := make(map[string]struct{}, len(records))
		for _, record := range records {
			if err := validateExemptionRecordForAdd(record); err != nil {
				return errors.New("invalid exemption store schema")
			}
			if _, duplicate := seen[record.ID]; duplicate {
				return errors.New("invalid exemption store schema")
			}
			seen[record.ID] = struct{}{}
		}
	}
	return nil
}

func decodeStrictJSON(data []byte, dst any) error {
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
