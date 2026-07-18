//go:build enterprise

// Copyright 2026 Pipelock contributors
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
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

const (
	ExemptionStateFile     = "exemptions.json"
	DeliveryInboxStateFile = "delivery-inbox.json"
	LegalHoldStateFile     = "legal-holds.json"
	backupManifestName     = "manifest.json"
	backupFormatVersion    = 1
	maxBackupFileSize      = 64 << 20
	maxBackupArchiveSize   = 3*maxBackupFileSize + 1<<20
)

var durableStateFiles = map[string]struct{}{
	ExemptionStateFile:     {},
	DeliveryInboxStateFile: {},
	LegalHoldStateFile:     {},
}

const (
	backupStoreExemptions = "exemptions"
	backupStoreDelivery   = "delivery-inbox"
	backupStoreLegalHolds = "legal-holds"
)

type backupManifest struct {
	Version int                  `json:"version"`
	Files   []backupManifestFile `json:"files"`
}

type backupManifestFile struct {
	Store  string `json:"store,omitempty"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// BackupOptions selects the operator-configured dashboard state stores to
// archive. Empty exemption and delivery paths default under StateDir; an empty
// legal-hold path means no legal-hold store is configured for this backup.
type BackupOptions struct {
	StateDir           string
	ArchivePath        string
	ExemptionStorePath string
	DeliveryInboxPath  string
	LegalHoldStorePath string
}

// RestoreOptions selects the operator-configured dashboard state store targets.
// Empty exemption and delivery paths default under StateDir. A backup containing
// legal holds requires LegalHoldStorePath so restore cannot silently drop them.
type RestoreOptions struct {
	StateDir           string
	ArchivePath        string
	ExemptionStorePath string
	DeliveryInboxPath  string
	LegalHoldStorePath string
}

type BackupResult struct {
	CapturedStores []string
	MissingStores  []string
}

type RestoreResult struct {
	RestoredStores []string
	RemovedStores  []string
}

type durableStateStore struct {
	store       string
	archiveName string
	path        string
	label       string
	pathLock    func(string) *sync.Mutex
}

var (
	stateDirLocks           sync.Map
	writeDashboardStateFile = atomicfile.Write
)

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
	_, err := BackupStateWithOptions(BackupOptions{StateDir: stateDir, ArchivePath: archivePath})
	return err
}

// BackupStateWithOptions writes a deterministic tar archive containing the
// configured non-reconstructible dashboard state stores.
func BackupStateWithOptions(opts BackupOptions) (BackupResult, error) {
	stateDir := filepath.Clean(opts.StateDir)
	archivePath := filepath.Clean(opts.ArchivePath)
	stores := backupStoresFromOptions(stateDir, opts.ExemptionStorePath, opts.DeliveryInboxPath, opts.LegalHoldStorePath)
	if err := rejectDuplicateStorePaths(stores); err != nil {
		return BackupResult{}, err
	}
	if err := rejectProtectedArchivePath(stateDir, archivePath, stores); err != nil {
		return BackupResult{}, err
	}
	mu := stateDirLock(stateDir)
	mu.Lock()
	defer mu.Unlock()
	releaseFiles, err := lockDurableStateStores(stores)
	if err != nil {
		return BackupResult{}, err
	}
	defer releaseFiles()

	files := make(map[string][]byte, len(stores))
	manifest := backupManifest{Version: backupFormatVersion}
	result := BackupResult{}
	for _, store := range stores {
		data, exists, err := readDurableStateStore(store)
		if err != nil {
			return BackupResult{}, fmt.Errorf("backup dashboard state %s: %w", store.archiveName, err)
		}
		if !exists {
			result.MissingStores = append(result.MissingStores, store.store)
			continue
		}
		if len(data) > maxBackupFileSize {
			return BackupResult{}, fmt.Errorf("backup dashboard state %s: exceeds %d-byte limit", store.archiveName, maxBackupFileSize)
		}
		if err := validateStateFile(store.archiveName, data); err != nil {
			return BackupResult{}, fmt.Errorf("backup dashboard state %s: %w", store.archiveName, err)
		}
		sum := sha256.Sum256(data)
		files[store.archiveName] = data
		result.CapturedStores = append(result.CapturedStores, store.store)
		manifest.Files = append(manifest.Files, backupManifestFile{
			Store:  store.store,
			Name:   store.archiveName,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(data)),
		})
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return BackupResult{}, fmt.Errorf("backup dashboard state manifest: %w", err)
	}

	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := writeTarFile(tw, backupManifestName, manifestData); err != nil {
		return BackupResult{}, err
	}
	for _, entry := range manifest.Files {
		if err := writeTarFile(tw, entry.Name, files[entry.Name]); err != nil {
			return BackupResult{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return BackupResult{}, fmt.Errorf("close dashboard backup archive: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o750); err != nil {
		return BackupResult{}, fmt.Errorf("create dashboard backup directory: %w", err)
	}
	if err := atomicfile.Write(archivePath, archive.Bytes(), 0o600); err != nil {
		return BackupResult{}, fmt.Errorf("write dashboard backup: %w", err)
	}
	return result, nil
}

func backupStoresFromOptions(stateDir, exemptionStorePath, deliveryInboxPath, legalHoldStorePath string) []durableStateStore {
	stores := []durableStateStore{
		{
			store:       backupStoreExemptions,
			archiveName: ExemptionStateFile,
			path:        defaultOrConfiguredPath(stateDir, ExemptionStateFile, exemptionStorePath),
			label:       "exemption store",
			pathLock:    exemptionStorePathLock,
		},
		{
			store:       backupStoreDelivery,
			archiveName: DeliveryInboxStateFile,
			path:        defaultOrConfiguredPath(stateDir, DeliveryInboxStateFile, deliveryInboxPath),
			label:       "delivery inbox",
			pathLock:    exemptionStorePathLock,
		},
	}
	if strings.TrimSpace(legalHoldStorePath) != "" {
		stores = append(stores, durableStateStore{
			store:       backupStoreLegalHolds,
			archiveName: LegalHoldStateFile,
			path:        filepath.Clean(legalHoldStorePath),
			label:       "legal hold store",
			pathLock:    legalHoldStorePathLock,
		})
	}
	return stores
}

func restoreStoresFromOptions(stateDir, exemptionStorePath, deliveryInboxPath, legalHoldStorePath string) []durableStateStore {
	return backupStoresFromOptions(stateDir, exemptionStorePath, deliveryInboxPath, legalHoldStorePath)
}

func defaultOrConfiguredPath(stateDir, name, configured string) string {
	if strings.TrimSpace(configured) != "" {
		return filepath.Clean(configured)
	}
	return filepath.Join(stateDir, name)
}

func rejectDuplicateStorePaths(stores []durableStateStore) error {
	seen := make(map[string]string, len(stores))
	for _, store := range stores {
		key, err := canonicalPath(store.path)
		if errors.Is(err, os.ErrNotExist) {
			key, err = filepath.Abs(filepath.Clean(store.path))
		}
		if err != nil {
			return fmt.Errorf("resolve dashboard state path %s: %w", store.archiveName, err)
		}
		if prior, duplicate := seen[key]; duplicate {
			return fmt.Errorf("dashboard state stores %s and %s resolve to the same path", prior, store.archiveName)
		}
		seen[key] = store.archiveName
	}
	return nil
}

func readDurableStateStore(store durableStateStore) ([]byte, bool, error) {
	data, err := readBackupStateStoreFile(store)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func readBackupStateStoreFile(store durableStateStore) ([]byte, error) {
	file, info, err := openRegularDashboardFile(store.path, store.label)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	switch store.archiveName {
	case ExemptionStateFile, LegalHoldStateFile:
		if err := requireOwnerOnlyDashboardFile(file, info, store.label); err != nil {
			return nil, err
		}
	case DeliveryInboxStateFile:
	default:
		return nil, fmt.Errorf("unknown dashboard state store %q", store.archiveName)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBackupFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBackupFileSize {
		return nil, fmt.Errorf("exceeds %d-byte limit", maxBackupFileSize)
	}
	return data, nil
}

func rejectProtectedArchivePath(stateDir, archivePath string, stores []durableStateStore) error {
	if _, err := canonicalPath(stateDir); err != nil {
		return fmt.Errorf("resolve dashboard state directory: %w", err)
	}
	canonicalArchive, err := canonicalPath(archivePath)
	if err != nil {
		return fmt.Errorf("resolve dashboard backup path: %w", err)
	}
	for _, store := range stores {
		protectedPath := store.path
		for _, protected := range []string{protectedPath, protectedPath + ".lock"} {
			canonicalProtected, protectedErr := canonicalPath(protected)
			if protectedErr != nil {
				continue
			}
			if canonicalArchive == canonicalProtected {
				return fmt.Errorf("dashboard backup path must not overwrite protected state file %s", filepath.Base(protected))
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
	_, err := RestoreStateWithOptions(RestoreOptions{StateDir: stateDir, ArchivePath: archivePath})
	return err
}

// RestoreStateWithOptions validates the complete archive before replacing any
// configured state store. Commit-time errors trigger rollback from in-memory
// originals before an error is returned.
func RestoreStateWithOptions(opts RestoreOptions) (RestoreResult, error) {
	data, err := readBackupArchive(opts.ArchivePath)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("read dashboard backup: %w", err)
	}
	restored, err := decodeBackup(data)
	if err != nil {
		return RestoreResult{}, err
	}
	stateDir := filepath.Clean(opts.StateDir)
	stores := restoreStoresFromOptions(stateDir, opts.ExemptionStorePath, opts.DeliveryInboxPath, opts.LegalHoldStorePath)
	if err := rejectDuplicateStorePaths(stores); err != nil {
		return RestoreResult{}, err
	}
	storesByArchive := make(map[string]durableStateStore, len(stores))
	for _, store := range stores {
		storesByArchive[store.archiveName] = store
	}
	for name := range restored {
		if _, configured := storesByArchive[name]; !configured {
			return RestoreResult{}, fmt.Errorf("restore dashboard state %s: target store path is not configured", name)
		}
	}
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return RestoreResult{}, fmt.Errorf("create dashboard state directory: %w", err)
	}
	for _, store := range stores {
		if err := os.MkdirAll(filepath.Dir(store.path), 0o750); err != nil {
			return RestoreResult{}, fmt.Errorf("create dashboard state directory for %s: %w", store.archiveName, err)
		}
	}
	mu := stateDirLock(stateDir)
	mu.Lock()
	defer mu.Unlock()
	releaseFiles, err := lockDurableStateStores(stores)
	if err != nil {
		return RestoreResult{}, err
	}
	defer releaseFiles()

	originals := make(map[string][]byte, len(stores))
	missing := make(map[string]bool, len(stores))
	for _, store := range stores {
		prior, readErr := os.ReadFile(filepath.Clean(store.path))
		if errors.Is(readErr, os.ErrNotExist) {
			missing[store.archiveName] = true
			continue
		}
		if readErr != nil {
			return RestoreResult{}, fmt.Errorf("snapshot existing dashboard state %s: %w", store.archiveName, readErr)
		}
		originals[store.archiveName] = prior
	}

	stores = sortedDurableStateStores(stores)
	result := RestoreResult{}
	for _, store := range stores {
		file, exists := restored[store.archiveName]
		if exists {
			if err := os.MkdirAll(filepath.Dir(store.path), 0o750); err != nil {
				return RestoreResult{}, fmt.Errorf("create dashboard state directory for %s: %w", store.archiveName, err)
			}
			err = writeDashboardStateFile(store.path, file, 0o600)
			if err == nil {
				result.RestoredStores = append(result.RestoredStores, store.store)
			}
		} else {
			err = os.Remove(store.path)
			if errors.Is(err, os.ErrNotExist) {
				err = nil
			}
			if err == nil {
				result.RemovedStores = append(result.RemovedStores, store.store)
			}
		}
		if err == nil {
			continue
		}
		rollbackErr := rollbackState(stores, originals, missing)
		return RestoreResult{}, fmt.Errorf("restore dashboard state %s: %w", store.archiveName, errors.Join(err, rollbackErr))
	}
	return result, nil
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

func lockDurableStateStores(stores []durableStateStore) (func(), error) {
	stores = sortedDurableStateStores(stores)
	type heldLock struct {
		pathMu *sync.Mutex
		file   *exemptionStoreFileLock
	}
	held := make([]heldLock, 0, len(stores))
	release := func() {
		for index := len(held) - 1; index >= 0; index-- {
			_ = held[index].file.Close()
			held[index].pathMu.Unlock()
		}
	}
	for _, store := range stores {
		pathMu := store.pathLock(store.path)
		pathMu.Lock()
		fileLock, err := acquireExemptionStoreFileLock(store.path + ".lock")
		if err != nil {
			pathMu.Unlock()
			release()
			return nil, fmt.Errorf("lock dashboard state %s: %w", store.archiveName, err)
		}
		held = append(held, heldLock{pathMu: pathMu, file: fileLock})
	}
	return release, nil
}

func sortedDurableStateStores(stores []durableStateStore) []durableStateStore {
	out := append([]durableStateStore(nil), stores...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].path == out[j].path {
			return out[i].archiveName < out[j].archiveName
		}
		return out[i].path < out[j].path
	})
	return out
}

func rollbackState(stores []durableStateStore, originals map[string][]byte, missing map[string]bool) error {
	var errs []error
	for _, store := range sortedDurableStateStores(stores) {
		if missing[store.archiveName] {
			if err := os.Remove(store.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove %s: %w", store.archiveName, err))
			}
			continue
		}
		if err := writeDashboardStateFile(store.path, originals[store.archiveName], 0o600); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", store.archiveName, err))
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
		if err := validateManifestFileIdentity(file); err != nil {
			return nil, err
		}
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

func validateManifestFileIdentity(file backupManifestFile) error {
	store := file.Store
	if store == "" {
		store = storeForArchiveName(file.Name)
	}
	if store == "" || storeForArchiveName(file.Name) != store {
		return fmt.Errorf("validate dashboard backup archive: manifest mismatch for %q", file.Name)
	}
	return nil
}

func storeForArchiveName(name string) string {
	switch name {
	case ExemptionStateFile:
		return backupStoreExemptions
	case DeliveryInboxStateFile:
		return backupStoreDelivery
	case LegalHoldStateFile:
		return backupStoreLegalHolds
	default:
		return ""
	}
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
	if name == LegalHoldStateFile {
		if err := validateLegalHoldState(data); err != nil {
			return errors.New("invalid legal hold store schema")
		}
	}
	return nil
}

func validateLegalHoldState(data []byte) error {
	if len(data) == 0 {
		return errors.New("legal hold store: empty file is invalid")
	}
	var records []LegalHold
	if err := decodeStrictJSON(data, &records); err != nil {
		return err
	}
	if records == nil {
		return errors.New("legal hold store: root must be a JSON array")
	}
	if len(records) > legalHoldMaxRecords {
		return fmt.Errorf("legal hold store: record count exceeds %d", legalHoldMaxRecords)
	}
	seen := make(map[string]struct{}, len(records))
	for _, hold := range records {
		if err := validateLegalHold(hold, true); err != nil {
			return err
		}
		if _, duplicate := seen[hold.ID]; duplicate {
			return fmt.Errorf("legal hold store: duplicate id %q", hold.ID)
		}
		seen[hold.ID] = struct{}{}
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
