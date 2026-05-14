// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	domenvelope "github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

type trustRecord struct {
	TrustDomain string    `json:"trust_domain"`
	SPIFFEID    string    `json:"spiffe_id,omitempty"`
	KeyHex      string    `json:"key_hex"`
	KeySource   string    `json:"key_source,omitempty"`
	AddedAt     time.Time `json:"added_at"`
}

type trustStore struct {
	path string
	root string
}

func newTrustStore(path string) (*trustStore, error) {
	var root string
	if path == "" {
		var err error
		root, path, err = defaultTrustStorePath()
		if err != nil {
			return nil, err
		}
	}
	if root != "" {
		root = filepath.Clean(root)
	}
	return &trustStore{path: filepath.Clean(path), root: root}, nil
}

func defaultTrustStorePath() (string, string, error) {
	stateHome := strings.TrimSpace(os.Getenv("XDG_STATE_HOME"))
	if stateHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", fmt.Errorf("determining home directory: %w", err)
		}
		stateHome = filepath.Join(home, ".local", "state")
	}
	root := filepath.Clean(stateHome)
	return root, filepath.Join(root, "pipelock", "envelope", "trust.json"), nil
}

func (s *trustStore) load() ([]trustRecord, error) {
	path, err := s.readPath()
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-selected state store path after validation.
	if err != nil {
		return nil, fmt.Errorf("reading trust store: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var records []trustRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parsing trust store: %w", err)
	}
	for i := range records {
		records[i].TrustDomain = strings.ToLower(strings.TrimSpace(records[i].TrustDomain))
		records[i].SPIFFEID = strings.TrimSpace(records[i].SPIFFEID)
		records[i].KeyHex = strings.ToLower(strings.TrimSpace(records[i].KeyHex))
		records[i].KeySource = strings.TrimSpace(records[i].KeySource)
		if err := validateTrustRecord(records[i]); err != nil {
			return nil, fmt.Errorf("trust store record %d: %w", i, err)
		}
	}
	return records, nil
}

func (s *trustStore) save(records []trustRecord) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("creating trust store directory: %w", err)
	}
	if err := s.validateWritePath(); err != nil {
		return err
	}
	for i, rec := range records {
		if err := validateTrustRecord(rec); err != nil {
			return fmt.Errorf("trust store record %d: %w", i, err)
		}
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding trust store: %w", err)
	}
	data = append(data, '\n')
	if err := atomicfile.Write(s.path, data, 0o600); err != nil {
		return fmt.Errorf("writing trust store: %w", err)
	}
	return nil
}

func (s *trustStore) readPath() (string, error) {
	cleanPath := filepath.Clean(s.path)
	info, err := os.Lstat(cleanPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("checking trust store path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("trust store path must not be a symlink")
	}
	if err := validateTrustStoreParent(cleanPath); err != nil {
		return "", err
	}
	if s.root == "" {
		return cleanPath, nil
	}
	resolvedPath, err := filepath.EvalSymlinks(cleanPath)
	if err != nil {
		return "", fmt.Errorf("resolving trust store path: %w", err)
	}
	if err := s.validateContained(resolvedPath); err != nil {
		return "", err
	}
	return resolvedPath, nil
}

func (s *trustStore) validateWritePath() error {
	cleanPath := filepath.Clean(s.path)
	info, err := os.Lstat(cleanPath)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("trust store path must not be a symlink")
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("checking trust store path: %w", err)
	}
	if err := validateTrustStoreParent(cleanPath); err != nil {
		return err
	}
	if s.root == "" {
		return nil
	}
	return s.validateContained(filepath.Dir(cleanPath))
}

func validateTrustStoreParent(cleanPath string) error {
	parent := filepath.Dir(cleanPath)
	absParent, err := filepath.Abs(parent)
	if err != nil {
		return fmt.Errorf("resolving trust store directory: %w", err)
	}
	resolvedParent, err := filepath.EvalSymlinks(absParent)
	if err != nil {
		return fmt.Errorf("resolving trust store directory: %w", err)
	}
	if filepath.Clean(resolvedParent) != filepath.Clean(absParent) {
		return fmt.Errorf("trust store path must not be a symlink")
	}
	return nil
}

func (s *trustStore) validateContained(path string) error {
	root, err := filepath.EvalSymlinks(s.root)
	if err != nil {
		return fmt.Errorf("resolving trust store root: %w", err)
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolving trust store path: %w", err)
	}
	rel, err := filepath.Rel(root, resolvedPath)
	if err != nil {
		return fmt.Errorf("checking trust store containment: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("trust store directory escapes XDG state home")
	}
	return nil
}

func validateTrustRecord(rec trustRecord) error {
	if !domenvelope.IsValidTrustDomain(rec.TrustDomain) {
		return fmt.Errorf("trust_domain %q must be a DNS-shaped SPIFFE trust domain", rec.TrustDomain)
	}
	if rec.SPIFFEID != "" {
		parsed, err := domenvelope.ParseActorStrict(rec.SPIFFEID)
		if err != nil {
			return fmt.Errorf("spiffe_id: %w", err)
		}
		if parsed.TrustDomain != rec.TrustDomain {
			return fmt.Errorf("spiffe_id trust domain %q does not match trust_domain %q", parsed.TrustDomain, rec.TrustDomain)
		}
	}
	pub, err := signing.ParsePublicKey(rec.KeyHex)
	if err != nil {
		return fmt.Errorf("key_hex: %w", err)
	}
	if rec.KeyHex != hex.EncodeToString(pub) {
		return fmt.Errorf("key_hex must be raw lowercase Ed25519 public-key hex")
	}
	if rec.KeySource != "" {
		u, err := url.Parse(rec.KeySource)
		if err != nil {
			return fmt.Errorf("key_source: %w", err)
		}
		if !isAllowedDirectoryURL(u) {
			return fmt.Errorf("key_source must be https or loopback http")
		}
	}
	if rec.AddedAt.IsZero() {
		return fmt.Errorf("added_at must be set")
	}
	return nil
}

func parseTrustTarget(raw string) (trustDomain, spiffeID string, err error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return "", "", fmt.Errorf("trust target must not be empty")
	}
	if strings.HasPrefix(strings.ToLower(target), "spiffe://") {
		parsed, err := domenvelope.ParseActorStrict(target)
		if err != nil {
			return "", "", err
		}
		return parsed.TrustDomain, parsed.Raw, nil
	}
	domain := strings.ToLower(target)
	if !domenvelope.IsValidTrustDomain(domain) {
		return "", "", fmt.Errorf("trust target %q must be a SPIFFE ID or DNS-shaped trust domain", raw)
	}
	return domain, "", nil
}

func normalizeKeyHex(raw string) (string, error) {
	pub, err := signing.ParsePublicKey(raw)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub), nil
}

func findTrustRecord(records []trustRecord, trustDomain, spiffeID string) int {
	for i, rec := range records {
		if rec.TrustDomain == trustDomain && rec.SPIFFEID == spiffeID {
			return i
		}
	}
	return -1
}

func isLocalHTTPSource(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func isAllowedDirectoryURL(u *url.URL) bool {
	return u.Scheme == "https" || isLocalHTTPSource(u)
}
