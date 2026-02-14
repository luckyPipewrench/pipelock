package signing

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// DefaultPipelockDir is the directory name for pipelock key storage.
const DefaultPipelockDir = ".pipelock"

const (
	agentsSubdir     = "agents"
	trustedSubdir    = "trusted_keys"
	privateKeyFile   = "id_ed25519"
	publicKeyFile    = "id_ed25519.pub"
	maxAgentNameLen  = 64
	dirPermission    = 0o700
	trustedPubSuffix = ".pub"
)

// agentNameRe matches characters NOT allowed in agent names.
// Same rule as internal/proxy/agent.go for consistency.
var agentNameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// Keystore manages Ed25519 keys on disk under a base directory.
type Keystore struct {
	baseDir string
}

// NewKeystore creates a Keystore rooted at baseDir.
func NewKeystore(baseDir string) *Keystore {
	return &Keystore{baseDir: baseDir}
}

// DefaultKeystorePath returns ~/.pipelock, resolving the home directory.
func DefaultKeystorePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, DefaultPipelockDir), nil
}

// SanitizeAgentName cleans an agent name to safe characters.
func SanitizeAgentName(name string) string {
	name = agentNameRe.ReplaceAllString(name, "_")
	if len(name) > maxAgentNameLen {
		name = name[:maxAgentNameLen]
	}
	return name
}

// ValidateAgentName checks that a name is non-empty, already clean, and not
// a path traversal attempt. Rejects names containing ".." (consecutive dots),
// which could resolve to parent directories via filepath.Join.
func ValidateAgentName(name string) error {
	if name == "" {
		return fmt.Errorf("agent name cannot be empty")
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("agent name %q contains path traversal sequence", name)
	}
	if name == "." {
		return fmt.Errorf("agent name %q is a path traversal sequence", name)
	}
	if sanitized := SanitizeAgentName(name); sanitized != name {
		return fmt.Errorf("agent name %q contains invalid characters (use %q)", name, sanitized)
	}
	return nil
}

// GenerateAgent creates a new Ed25519 key pair for an agent.
// Returns an error if keys already exist unless force is true.
func (k *Keystore) GenerateAgent(name string) (ed25519.PublicKey, error) {
	if k.AgentExists(name) {
		return nil, fmt.Errorf("keys already exist for agent %q (use --force to overwrite)", name)
	}
	return k.generateAgent(name)
}

// ForceGenerateAgent creates a new key pair, overwriting any existing keys.
func (k *Keystore) ForceGenerateAgent(name string) (ed25519.PublicKey, error) {
	return k.generateAgent(name)
}

func (k *Keystore) generateAgent(name string) (ed25519.PublicKey, error) {
	if err := ValidateAgentName(name); err != nil {
		return nil, err
	}

	dir := k.agentDir(name)
	if err := os.MkdirAll(dir, dirPermission); err != nil {
		return nil, fmt.Errorf("creating agent directory: %w", err)
	}

	pub, priv, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	privPath := filepath.Join(dir, privateKeyFile)
	pubPath := filepath.Join(dir, publicKeyFile)

	if err := SavePrivateKey(priv, privPath); err != nil {
		return nil, fmt.Errorf("saving private key: %w", err)
	}
	if err := SavePublicKey(pub, pubPath); err != nil {
		return nil, fmt.Errorf("saving public key: %w", err)
	}

	return pub, nil
}

// LoadPrivateKey loads an agent's private key from the keystore.
func (k *Keystore) LoadPrivateKey(name string) (ed25519.PrivateKey, error) {
	if err := ValidateAgentName(name); err != nil {
		return nil, err
	}
	path := filepath.Join(k.agentDir(name), privateKeyFile)
	return LoadPrivateKeyFile(path)
}

// LoadPublicKey loads an agent's own public key from the keystore.
func (k *Keystore) LoadPublicKey(name string) (ed25519.PublicKey, error) {
	if err := ValidateAgentName(name); err != nil {
		return nil, err
	}
	path := filepath.Join(k.agentDir(name), publicKeyFile)
	return LoadPublicKeyFile(path)
}

// TrustKey copies a public key file into trusted_keys/<name>.pub.
// Reads the file once, validates the key from memory, then writes.
func (k *Keystore) TrustKey(name, pubKeyPath string) error {
	if err := ValidateAgentName(name); err != nil {
		return err
	}

	data, err := os.ReadFile(pubKeyPath) //nolint:gosec // G304: caller controls path
	if err != nil {
		return fmt.Errorf("reading public key: %w", err)
	}

	// Validate the key from the data we already read.
	if _, err := DecodePublicKey(string(data)); err != nil {
		return fmt.Errorf("invalid public key file: %w", err)
	}

	dir := filepath.Join(k.baseDir, trustedSubdir)
	if err := os.MkdirAll(dir, dirPermission); err != nil {
		return fmt.Errorf("creating trusted keys directory: %w", err)
	}

	dest := k.trustedKeyPath(name)
	return atomicWrite(dest, data, 0o644)
}

// LoadTrustedKey loads a trusted agent's public key.
func (k *Keystore) LoadTrustedKey(name string) (ed25519.PublicKey, error) {
	if err := ValidateAgentName(name); err != nil {
		return nil, err
	}
	return LoadPublicKeyFile(k.trustedKeyPath(name))
}

// ResolvePublicKey looks up a public key by agent name, checking the agent's
// own keys first, then trusted keys. Only falls through to trusted keys when
// the agent's own key file is not found.
func (k *Keystore) ResolvePublicKey(name string) (ed25519.PublicKey, error) {
	if err := ValidateAgentName(name); err != nil {
		return nil, err
	}
	pub, err := k.LoadPublicKey(name)
	if err == nil {
		return pub, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("loading public key for agent %q: %w", name, err)
	}
	return k.LoadTrustedKey(name)
}

// AgentExists returns whether a private key exists for the given agent.
func (k *Keystore) AgentExists(name string) bool {
	if ValidateAgentName(name) != nil {
		return false
	}
	privPath := filepath.Join(k.agentDir(name), privateKeyFile)
	_, err := os.Stat(privPath)
	return err == nil
}

// ListAgents returns all agent names with generated keys.
func (k *Keystore) ListAgents() ([]string, error) {
	dir := filepath.Join(k.baseDir, agentsSubdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing agents: %w", err)
	}

	var agents []string
	for _, e := range entries {
		if e.IsDir() {
			agents = append(agents, e.Name())
		}
	}
	sort.Strings(agents)
	return agents, nil
}

// ListTrusted returns all trusted agent names.
func (k *Keystore) ListTrusted() ([]string, error) {
	dir := filepath.Join(k.baseDir, trustedSubdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing trusted keys: %w", err)
	}

	var trusted []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && filepath.Ext(name) == trustedPubSuffix {
			trusted = append(trusted, name[:len(name)-len(trustedPubSuffix)])
		}
	}
	sort.Strings(trusted)
	return trusted, nil
}

func (k *Keystore) agentDir(name string) string {
	return filepath.Join(k.baseDir, agentsSubdir, name)
}

func (k *Keystore) trustedKeyPath(name string) string {
	return filepath.Join(k.baseDir, trustedSubdir, name+trustedPubSuffix)
}

// PublicKeyPath returns the path to an agent's public key file.
func (k *Keystore) PublicKeyPath(name string) string {
	return filepath.Join(k.agentDir(name), publicKeyFile)
}
