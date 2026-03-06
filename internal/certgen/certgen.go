package certgen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// serialBits is the number of random bits used for certificate serial numbers.
const serialBits = 128

// GenerateCA creates a self-signed ECDSA P-256 CA certificate.
func GenerateCA(org string, validity time.Duration) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	serial.Add(serial, big.NewInt(1)) // X.509 serials must be positive

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   "Pipelock CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour), // backdate 1h for clock skew tolerance
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,    // CA can only sign leaf certs, not intermediates
		MaxPathLenZero:        true, // explicitly encode MaxPathLen=0 in the certificate
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return cert, key, pemBytes, nil
}

// GenerateLeaf creates a leaf certificate for a hostname or IP, signed by the CA.
func GenerateLeaf(ca *x509.Certificate, caKey crypto.PrivateKey, host string, ttl time.Duration) (*tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	serial.Add(serial, big.NewInt(1)) // X.509 serials must be positive

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Hour), // backdate 1h for clock skew tolerance
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature, // ECDSA: DigitalSignature only (RFC 5480 Section 3)
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  leafKey,
	}, nil
}

// SaveCA writes the CA cert and key to PEM files. Returns error if files exist.
func SaveCA(certPath, keyPath string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	certPath = filepath.Clean(certPath)
	keyPath = filepath.Clean(keyPath)

	if _, err := os.Stat(certPath); err == nil {
		return fmt.Errorf("CA cert already exists at %s (use --force to overwrite)", certPath)
	}
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("CA key already exists at %s (use --force to overwrite)", keyPath)
	}
	return writeCAFiles(certPath, keyPath, cert, key)
}

// SaveCAForce writes the CA cert and key, overwriting existing files.
func SaveCAForce(certPath, keyPath string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	return writeCAFiles(filepath.Clean(certPath), filepath.Clean(keyPath), cert, key)
}

func writeCAFiles(certPath, keyPath string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o750); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		_ = os.Remove(certPath) // clean up cert if key write fails
		return fmt.Errorf("write CA key: %w", err)
	}

	return nil
}

// LoadCA reads a CA certificate and private key from PEM files.
func LoadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, errors.New("no PEM block in CA cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("no PEM block in CA key file")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}

	if !cert.IsCA {
		return nil, nil, errors.New("certificate is not a CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, errors.New("CA certificate missing KeyUsageCertSign")
	}
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("CA certificate public key is not ECDSA")
	}
	if !certPub.Equal(key.Public()) {
		return nil, nil, errors.New("CA key does not match certificate")
	}

	return cert, key, nil
}

// InstallCA prints platform-specific instructions for installing the CA cert.
func InstallCA(w io.Writer, certPath string) error {
	switch runtime.GOOS {
	case "linux":
		_, _ = fmt.Fprintf(w, "Installing CA certificate on Linux...\n\n")
		_, _ = fmt.Fprintf(w, "Run one of the following (requires root):\n\n")
		_, _ = fmt.Fprintf(w, "  # Debian/Ubuntu:\n")
		_, _ = fmt.Fprintf(w, "  sudo cp %s /usr/local/share/ca-certificates/pipelock-ca.crt\n", certPath)
		_, _ = fmt.Fprintf(w, "  sudo update-ca-certificates\n\n")
		_, _ = fmt.Fprintf(w, "  # RHEL/Fedora:\n")
		_, _ = fmt.Fprintf(w, "  sudo cp %s /etc/pki/ca-trust/source/anchors/pipelock-ca.crt\n", certPath)
		_, _ = fmt.Fprintf(w, "  sudo update-ca-trust extract\n")
	case "darwin":
		_, _ = fmt.Fprintf(w, "Installing CA certificate on macOS...\n\n")
		_, _ = fmt.Fprintf(w, "Run (requires admin password):\n\n")
		_, _ = fmt.Fprintf(w, "  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n", certPath)
	case "windows":
		_, _ = fmt.Fprintf(w, "Installing CA certificate on Windows...\n\n")
		_, _ = fmt.Fprintf(w, "Run in elevated Command Prompt:\n\n")
		_, _ = fmt.Fprintf(w, "  certutil -addstore -f \"ROOT\" %s\n", certPath)
	default:
		_, _ = fmt.Fprintf(w, "Unsupported OS: %s\n", runtime.GOOS)
		_, _ = fmt.Fprintf(w, "Manually add %s to your system trust store.\n", certPath)
	}
	return nil
}

type cachedCert struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

// CertCache is a bounded, TTL-based certificate cache.
type CertCache struct {
	mu      sync.RWMutex
	certs   map[string]*cachedCert
	maxSize int
	ca      *x509.Certificate
	caKey   crypto.PrivateKey
	ttl     time.Duration
}

// NewCertCache creates a certificate cache that generates leaf certs on demand.
// Panics if ca or caKey is nil, or maxSize <= 0 (programming errors after config validation).
func NewCertCache(ca *x509.Certificate, caKey crypto.PrivateKey, ttl time.Duration, maxSize int) *CertCache {
	if ca == nil || caKey == nil {
		panic("certgen: NewCertCache called with nil CA certificate or key")
	}
	if maxSize <= 0 {
		panic("certgen: NewCertCache called with non-positive maxSize")
	}
	return &CertCache{
		certs:   make(map[string]*cachedCert),
		maxSize: maxSize,
		ca:      ca,
		caKey:   caKey,
		ttl:     ttl,
	}
}

// Get returns a cached cert or generates a new one.
func (c *CertCache) Get(host string) (*tls.Certificate, error) {
	c.mu.RLock()
	if entry, ok := c.certs[host]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.RUnlock()
		return entry.cert, nil
	}
	c.mu.RUnlock()

	leaf, err := GenerateLeaf(c.ca, c.caKey, host, c.ttl)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock.
	if entry, ok := c.certs[host]; ok && time.Now().Before(entry.expiresAt) {
		return entry.cert, nil
	}

	c.certs[host] = &cachedCert{
		cert:      leaf,
		expiresAt: time.Now().Add(c.ttl),
	}

	if len(c.certs) > c.maxSize {
		c.evictLocked()
	}

	return leaf, nil
}

// Size returns the number of cached certificates.
func (c *CertCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.certs)
}

// evictLocked removes expired entries, then evicts oldest if still over cap.
// Must be called with c.mu held for writing.
func (c *CertCache) evictLocked() {
	now := time.Now()
	for host, entry := range c.certs {
		if now.After(entry.expiresAt) {
			delete(c.certs, host)
		}
	}
	// If still over cap, evict earliest-expiring entries.
	for len(c.certs) > c.maxSize {
		var oldestHost string
		var oldestTime time.Time
		for host, entry := range c.certs {
			if oldestHost == "" || entry.expiresAt.Before(oldestTime) {
				oldestHost = host
				oldestTime = entry.expiresAt
			}
		}
		delete(c.certs, oldestHost)
	}
}
