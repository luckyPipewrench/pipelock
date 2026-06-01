//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package bootstrap

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	rosterRootKeyID = "fleet-roster-root"
	remoteKillKeyID = "conductor-remote-kill-1"
	rollbackKeyID   = "conductor-rollback-1"

	certPEMType   = "CERTIFICATE"
	ecKeyPEMType  = "EC PRIVATE KEY"
	tokenRandSize = 32

	ed25519SigPrefix = "ed25519:"

	licenseEmail = "fleet-bootstrap@pipelock.local"
	licenseTier  = "enterprise"
)

// generateMaterial mints a fresh dev-fleet material set and writes every
// artifact to disk with locked-down permissions. It never logs private-key
// bytes. The returned materialSet carries the in-memory artifacts the live
// proof consumes so the proof path is identical for fresh and reused material.
func generateMaterial(layout Layout, opts Options, identity controlplane.FollowerIdentity) (*materialSet, error) {
	for _, dir := range []string{
		filepath.Dir(layout.CACertPath),
		filepath.Dir(layout.ConductorServerCertPath),
		layout.ConductorStorageDir,
		filepath.Dir(layout.FollowerClientCertPath),
		layout.FollowerBundleCacheDir,
		layout.FollowerAuditQueueDir,
		layout.FollowerRecorderDir,
		filepath.Dir(layout.TrustRosterPath),
		filepath.Dir(layout.LicenseKeyPath),
	} {
		if err := os.MkdirAll(dir, dirPerm); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}

	// 1. Local CA.
	caCert, caKey, _, err := certgen.GenerateCA("Pipelock Dev Fleet "+identity.FleetID, opts.Validity)
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}
	if err := certgen.SaveCAForce(layout.CACertPath, layout.CAKeyPath, caCert, caKey); err != nil {
		return nil, fmt.Errorf("write CA: %w", err)
	}

	// 2. Conductor TLS server cert (server-auth, loopback SANs).
	serverCert, err := certgen.GenerateLeafCert(caCert, caKey, certgen.LeafOptions{
		CommonName:  opts.ConductorID,
		DNSNames:    []string{"localhost"},
		IPAddresses: listenIPs(opts.ListenHost),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		TTL:         opts.Validity,
	})
	if err != nil {
		return nil, fmt.Errorf("generate conductor server cert: %w", err)
	}
	if err := writeCertKeyPEM(layout.ConductorServerCertPath, layout.ConductorServerKeyPath, serverCert); err != nil {
		return nil, err
	}

	// 3. Follower mTLS client cert (client-auth, SPIFFE URI SAN identity).
	spiffeURI, err := followerSPIFFEID(opts.TrustDomain, identity)
	if err != nil {
		return nil, err
	}
	clientCert, err := certgen.GenerateLeafCert(caCert, caKey, certgen.LeafOptions{
		CommonName:  identity.InstanceID,
		URIs:        []*url.URL{spiffeURI},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		TTL:         opts.Validity,
	})
	if err != nil {
		return nil, fmt.Errorf("generate follower client cert: %w", err)
	}
	if err := writeCertKeyPEM(layout.FollowerClientCertPath, layout.FollowerClientKeyPath, clientCert); err != nil {
		return nil, err
	}

	// 4. Follower audit/recorder signing key (one Ed25519 key serves both, as
	//    the follower runtime does — the schemes sign disjoint byte sets).
	auditPub, auditKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate follower audit key: %w", err)
	}
	if err := writePrivateKey(layout.FollowerAuditKeyPath, auditKey); err != nil {
		return nil, err
	}
	if err := writePublicKey(layout.FollowerAuditPubPath, auditPub); err != nil {
		return nil, err
	}

	// 5. Conductor control keys + roster-root, then a signed trust roster.
	rootFingerprint, err := generateTrust(layout, opts)
	if err != nil {
		return nil, err
	}

	// 6. Dev license keypair + fleet-flagged token for the spawned fleet.
	licensePubHex, err := generateLicense(layout, opts, identity)
	if err != nil {
		return nil, err
	}

	// 7. Operator bearer tokens (publisher / auditor / admin).
	tokens, err := generateOperatorTokens(layout)
	if err != nil {
		return nil, err
	}

	// 8. Follower config — written then validated through config.Load so the
	//    emitted YAML is provably loadable before we hand it to the operator.
	if err := generateFollowerConfig(layout, opts, identity, rootFingerprint); err != nil {
		return nil, err
	}

	return &materialSet{
		caCert:          caCert,
		caKey:           caKey,
		serverCert:      *serverCert,
		clientCert:      *clientCert,
		auditKey:        auditKey,
		rootFingerprint: rootFingerprint,
		licensePubHex:   licensePubHex,
		publisherToken:  tokens.publisher,
		auditorToken:    tokens.auditor,
		adminToken:      tokens.admin,
	}, nil
}

// loadMaterial reloads a previously-generated material set for the idempotent
// reuse path. It reads exactly the files generateMaterial wrote so a re-run can
// re-prove the round-trip without minting new keys (no double-issue).
func loadMaterial(layout Layout) (*materialSet, error) {
	caCert, caKey, err := certgen.LoadCA(layout.CACertPath, layout.CAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	serverCert, err := tls.LoadX509KeyPair(layout.ConductorServerCertPath, layout.ConductorServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load conductor server cert: %w", err)
	}
	clientCert, err := tls.LoadX509KeyPair(layout.FollowerClientCertPath, layout.FollowerClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load follower client cert: %w", err)
	}
	auditKey, err := signing.LoadPrivateKeyFile(layout.FollowerAuditKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load follower audit key: %w", err)
	}
	rootPub, err := signing.LoadPublicKeyFile(layout.RosterRootPubPath)
	if err != nil {
		return nil, fmt.Errorf("load roster root public key: %w", err)
	}
	rootFingerprint, err := signing.Fingerprint(rootPub)
	if err != nil {
		return nil, fmt.Errorf("compute roster root fingerprint: %w", err)
	}
	licensePub, err := signing.LoadPublicKeyFile(layout.LicensePubPath)
	if err != nil {
		return nil, fmt.Errorf("load license public key: %w", err)
	}
	publisher, err := readToken(layout.PublisherTokenPath)
	if err != nil {
		return nil, err
	}
	auditor, err := readToken(layout.AuditorTokenPath)
	if err != nil {
		return nil, err
	}
	admin, err := readToken(layout.AdminTokenPath)
	if err != nil {
		return nil, err
	}
	return &materialSet{
		caCert:          caCert,
		caKey:           caKey,
		serverCert:      serverCert,
		clientCert:      clientCert,
		auditKey:        auditKey,
		rootFingerprint: rootFingerprint,
		licensePubHex:   hex.EncodeToString(licensePub),
		publisherToken:  publisher,
		auditorToken:    auditor,
		adminToken:      admin,
	}, nil
}

// generateTrust mints the roster-root and the Conductor control keys, then
// composes and signs the trust roster the follower pins. Returns the pinned
// root fingerprint.
func generateTrust(layout Layout, opts Options) (string, error) {
	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate roster root key: %w", err)
	}
	rkPub, rkKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate remote-kill key: %w", err)
	}
	rbPub, rbKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate rollback key: %w", err)
	}
	for _, kp := range []struct {
		priv    ed25519.PrivateKey
		pub     ed25519.PublicKey
		keyPath string
		pubPath string
	}{
		{rootKey, rootPub, layout.RosterRootKeyPath, layout.RosterRootPubPath},
		{rkKey, rkPub, layout.RemoteKillKeyPath, layout.RemoteKillPubPath},
		{rbKey, rbPub, layout.RollbackKeyPath, layout.RollbackPubPath},
	} {
		if err := writePrivateKey(kp.keyPath, kp.priv); err != nil {
			return "", err
		}
		if err := writePublicKey(kp.pubPath, kp.pub); err != nil {
			return "", err
		}
	}

	now := opts.Now().UTC().Format(time.RFC3339)
	body := contract.KeyRoster{
		SchemaVersion:  1,
		RosterSignedBy: rosterRootKeyID,
		DataClassRoot:  string(contract.DataClassInternal),
		Keys: []contract.KeyInfo{
			{
				KeyID:        rosterRootKeyID,
				KeyPurpose:   string(signing.PurposeRosterRoot),
				PublicKeyHex: hex.EncodeToString(rootPub),
				ValidFrom:    now,
				Status:       contract.KeyStatusRoot,
				Principal:    "root",
			},
			{
				KeyID:        remoteKillKeyID,
				KeyPurpose:   string(signing.PurposeRemoteKillSigning),
				PublicKeyHex: hex.EncodeToString(rkPub),
				ValidFrom:    now,
				Status:       contract.KeyStatusActive,
				Principal:    "conductor",
			},
			{
				KeyID:        rollbackKeyID,
				KeyPurpose:   string(signing.PurposePolicyBundleRollback),
				PublicKeyHex: hex.EncodeToString(rbPub),
				ValidFrom:    now,
				Status:       contract.KeyStatusActive,
				Principal:    "conductor",
			},
		},
	}
	if err := body.Validate(); err != nil {
		return "", fmt.Errorf("roster body validation: %w", err)
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		return "", fmt.Errorf("roster signable preimage: %w", err)
	}
	envelope := contract.RosterEnvelope{
		Body:      body,
		Signature: ed25519SigPrefix + hex.EncodeToString(ed25519.Sign(rootKey, preimage)),
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal roster: %w", err)
	}
	data = append(data, '\n')
	if err := writeFile(layout.TrustRosterPath, data); err != nil {
		return "", err
	}
	fp, err := signing.Fingerprint(rootPub)
	if err != nil {
		return "", fmt.Errorf("compute roster root fingerprint: %w", err)
	}
	return fp, nil
}

// generateLicense mints a dev license keypair and a fleet-flagged token for the
// spawned fleet, then verifies the token carries the fleet feature against its
// own public key — a fail-closed self-check that the issued token is valid.
func generateLicense(layout Layout, opts Options, identity controlplane.FollowerIdentity) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate license key: %w", err)
	}
	if err := writePrivateKey(layout.LicenseKeyPath, priv); err != nil {
		return "", err
	}
	if err := writePublicKey(layout.LicensePubPath, pub); err != nil {
		return "", err
	}
	now := opts.Now().UTC()
	lic := license.License{
		ID:        "lic_devfleet_" + identity.FleetID,
		Email:     licenseEmail,
		Org:       identity.OrgID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(opts.Validity).Unix(),
		Features:  []string{license.FeatureFleet},
		Tier:      licenseTier,
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		return "", fmt.Errorf("issue fleet license: %w", err)
	}
	// Self-check against the freshly generated public key directly (not
	// VerifyFleet, which prefers a build-embedded production key and would
	// reject this dev token on an official binary). Proves the issued token
	// is signature-valid and carries the fleet entitlement before we write it.
	verified, err := license.Verify(token, pub)
	if err != nil {
		return "", fmt.Errorf("generated fleet license failed self-verification: %w", err)
	}
	if !verified.HasFeature(license.FeatureFleet) {
		return "", errors.New("generated fleet license is missing the fleet feature")
	}
	if err := writeFile(layout.LicenseTokenPath, []byte(token+"\n")); err != nil {
		return "", err
	}
	return hex.EncodeToString(pub), nil
}

type operatorTokens struct {
	publisher string
	auditor   string
	admin     string
}

func generateOperatorTokens(layout Layout) (operatorTokens, error) {
	publisher, err := randomToken()
	if err != nil {
		return operatorTokens{}, err
	}
	auditor, err := randomToken()
	if err != nil {
		return operatorTokens{}, err
	}
	admin, err := randomToken()
	if err != nil {
		return operatorTokens{}, err
	}
	for path, tok := range map[string]string{
		layout.PublisherTokenPath: publisher,
		layout.AuditorTokenPath:   auditor,
		layout.AdminTokenPath:     admin,
	} {
		if err := writeFile(path, []byte(tok+"\n")); err != nil {
			return operatorTokens{}, err
		}
	}
	return operatorTokens{publisher: publisher, auditor: auditor, admin: admin}, nil
}

// generateFollowerConfig writes the follower YAML and proves it loadable by
// running it through config.Load. A config that does not validate is a
// fail-closed bootstrap error, not a file the operator discovers is broken.
func generateFollowerConfig(layout Layout, opts Options, identity controlplane.FollowerIdentity, rootFingerprint string) error {
	yamlBody := followerConfigYAML(layout, opts, identity, rootFingerprint)
	if err := writeFile(layout.FollowerConfigPath, []byte(yamlBody)); err != nil {
		return err
	}
	if _, err := config.Load(layout.FollowerConfigPath); err != nil {
		return fmt.Errorf("generated follower config failed validation: %w", err)
	}
	return nil
}

// --- low-level material I/O ---------------------------------------------

func writeCertKeyPEM(certPath, keyPath string, cert *tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return errors.New("certificate has no DER bytes")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: certPEMType, Bytes: cert.Certificate[0]})
	if err := writeFile(certPath, certPEM); err != nil {
		return err
	}
	ecKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("leaf private key is %T, want *ecdsa.PrivateKey", cert.PrivateKey)
	}
	keyDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return fmt.Errorf("marshal leaf key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: ecKeyPEMType, Bytes: keyDER})
	return writeFile(keyPath, keyPEM)
}

func writePrivateKey(path string, key ed25519.PrivateKey) error {
	return writeFile(path, []byte(signing.EncodePrivateKey(key)))
}

func writePublicKey(path string, key ed25519.PublicKey) error {
	return writeFile(path, []byte(signing.EncodePublicKey(key)))
}

func readToken(path string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read token %s: %w", path, err)
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", fmt.Errorf("token %s is empty", path)
	}
	return tok, nil
}

func randomToken() (string, error) {
	buf := make([]byte, tokenRandSize)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate operator token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func listenIPs(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	return nil
}
