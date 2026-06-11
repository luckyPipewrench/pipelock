//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	testOrgID       = "org-main"
	testFleetID     = "prod"
	testInstanceID  = "pl-prod-1"
	testEnvironment = "prod"
	testAdminToken  = "admin-secret-token"
	testFixedNowStr = "2026-06-11T12:00:00Z"
)

func testFixedNow(t *testing.T) time.Time {
	t.Helper()
	now, err := time.Parse(time.RFC3339, testFixedNowStr)
	if err != nil {
		t.Fatalf("parse fixed now: %v", err)
	}
	return now
}

// installFleetLicense mints a fleet-feature license and points the verifier env
// at its public key so the CLI license gate passes in-process. Builds without
// an embedded production key (the test binary) consult PIPELOCK_LICENSE_PUBLIC_KEY.
func installFleetLicense(t *testing.T) {
	t.Helper()
	if license.EmbeddedPublicKey() != nil {
		// An official build would verify against the embedded key, which we
		// cannot sign for; skip rather than assert a false negative.
		t.Skip("embedded license public key present; cannot inject a test fleet license")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(license): %v", err)
	}
	tok, err := license.Issue(license.License{
		ID:        "fleet-test",
		Email:     "test@example.com",
		IssuedAt:  time.Now().Add(-time.Hour).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Features:  []string{"fleet"},
	}, priv)
	if err != nil {
		t.Fatalf("Issue(license): %v", err)
	}
	t.Setenv(license.EnvLicenseKey, tok)
	t.Setenv(license.EnvLicensePublicKey, hex.EncodeToString(pub))
	t.Setenv(license.EnvLicenseCRLFile, "")
}

// writeSigningKey generates an ed25519 keypair and writes it as a JSON keypair
// file in the exact format `pipelock signing key generate` produces (the format
// loadSigningKeyFile consumes), returning the key id, file path, and public key
// for building the server-side resolver. Defaults to the remote-kill purpose;
// use writeSigningKeyWithPurpose for rollback.
func writeSigningKey(t *testing.T, id string) (keyID, file string, pub ed25519.PublicKey) {
	t.Helper()
	return writeSigningKeyWithPurpose(t, id, signing.PurposeRemoteKillSigning)
}

func writeSigningKeyWithPurpose(t *testing.T, id string, purpose signing.KeyPurpose) (keyID, file string, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", id, err)
	}
	kf := signingKeyFile{
		SchemaVersion: signingKeyFileSchemaVersion,
		Purpose:       string(purpose),
		KeyID:         id,
		Public:        hex.EncodeToString(pub),
		Private:       hex.EncodeToString(priv),
		CreatedAt:     "2026-06-11T00:00:00Z",
	}
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		t.Fatalf("marshal keyfile(%s): %v", id, err)
	}
	path := filepath.Join(t.TempDir(), id+".json")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write keyfile(%s): %v", id, err)
	}
	return id, path, pub
}

// emergencyResolverFromKeys builds a SignatureKeyResolver mapping each signer
// key id to its public key + purpose, mirroring the production
// buildControlKeyResolver output the server uses to verify operator signatures.
func emergencyResolverFromKeys(keys map[string]conductorcore.SignatureKey) conductorcore.SignatureKeyResolver {
	return func(keyID string) (conductorcore.SignatureKey, error) {
		key, ok := keys[keyID]
		if !ok {
			return conductorcore.SignatureKey{}, conductorcore.ErrSignatureVerification
		}
		return key, nil
	}
}

// testServer wraps a real control-plane handler over plain HTTP so the CLI's
// injected transport can drive the genuine server logic (signature threshold
// verification, TTL ceiling, counter replay, admin auth) without standing up
// mTLS. mTLS is a transport concern proven separately; the producer logic under
// test is the message construction + signing + the server's acceptance of it.
type testServer struct {
	url    string
	client *http.Client
}

type testServerOptions struct {
	now           time.Time
	emergencyKeys conductorcore.SignatureKeyResolver
	adminToken    string
	remoteKillTTL time.Duration
	rollbackTTL   time.Duration
}

func newTestServer(t *testing.T, opts testServerOptions) *testServer {
	t.Helper()
	dir := t.TempDir()
	store, err := controlplane.OpenFileBundleStore(filepath.Join(dir, "bundles"))
	if err != nil {
		t.Fatalf("OpenFileBundleStore: %v", err)
	}
	auditStore, err := controlplane.OpenSQLiteAuditStore(context.Background(), filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteAuditStore: %v", err)
	}
	t.Cleanup(func() { _ = auditStore.Close() })
	enrollments, err := controlplane.OpenFileEnrollmentStore(filepath.Join(dir, "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore: %v", err)
	}
	emergencyControls, err := controlplane.OpenFileEmergencyStore(filepath.Join(dir, "emergency"))
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore: %v", err)
	}
	adminToken := opts.adminToken
	if adminToken == "" {
		adminToken = testAdminToken
	}
	adminAuth, err := controlplane.ScopedBearerAdminAuthorizer([]controlplane.ScopedBearerCredential{{
		Token: adminToken,
		Role:  controlplane.RoleAdmin,
	}})
	if err != nil {
		t.Fatalf("ScopedBearerAdminAuthorizer: %v", err)
	}
	// A permissive publisher authorizer satisfies NewHandler's required hook;
	// the emergency endpoints under test gate on adminAuth, not this.
	publisherAuth := func(*http.Request) error { return nil }
	now := opts.now
	handler, err := controlplane.NewHandler(controlplane.HandlerOptions{
		Store:        store,
		Capabilities: controlplane.DefaultCapabilities("conductor-test"),
		Now: func() time.Time {
			if now.IsZero() {
				return time.Now().UTC()
			}
			return now
		},
		FollowerIdentity: func(*http.Request) (controlplane.FollowerIdentity, error) {
			return controlplane.FollowerIdentity{
				OrgID: testOrgID, FleetID: testFleetID, InstanceID: testInstanceID, Environment: testEnvironment,
			}, nil
		},
		AuthorizePublisher: publisherAuth,
		AuthorizeAdmin:     adminAuth,
		AuditSink:          auditStore,
		AuditKeys: func(controlplane.FollowerIdentity, string) (conductorcore.SignatureKey, error) {
			return conductorcore.SignatureKey{}, conductorcore.ErrSignatureVerification
		},
		Enrollments:       enrollments,
		EmergencyControls: emergencyControls,
		EmergencyKeys:     opts.emergencyKeys,
		RemoteKillMaxTTL:  opts.remoteKillTTL,
		RollbackMaxTTL:    opts.rollbackTTL,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &testServer{url: srv.URL, client: srv.Client()}
}

func (s *testServer) Do(req *http.Request) (*http.Response, error) { return s.client.Do(req) }

// writeAdminToken writes the admin bearer token to a 0600 file and returns the
// path, for the CLI's --admin-token-file.
func writeAdminToken(t *testing.T, tok string) string {
	t.Helper()
	if tok == "" {
		tok = testAdminToken
	}
	path := filepath.Join(t.TempDir(), "admin-token")
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatalf("write admin token: %v", err)
	}
	return path
}

// --- helper-level unit tests --------------------------------------------

func TestLoadSigningKeyFile_PurposeAndIntegrity(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		id, f, _ := writeSigningKeyWithPurpose(t, "signer-1", signing.PurposeRemoteKillSigning)
		key, err := loadSigningKeyFile(f, signing.PurposeRemoteKillSigning)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key.id != id || len(key.priv) != 64 {
			t.Fatalf("unexpected loaded key: id=%q len=%d", key.id, len(key.priv))
		}
	})
	t.Run("purpose mismatch", func(t *testing.T) {
		// A rollback keyfile handed to the kill action (remote-kill purpose).
		_, f, _ := writeSigningKeyWithPurpose(t, "rb", signing.PurposePolicyBundleRollback)
		if _, err := loadSigningKeyFile(f, signing.PurposeRemoteKillSigning); !errors.Is(err, errSigningKeyPurposeMismatch) {
			t.Fatalf("error = %v, want errSigningKeyPurposeMismatch", err)
		}
	})
	t.Run("bad schema", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(path, []byte(`{"schema_version":99,"purpose":"remote-kill-signing","key_id":"a","public":"","private":"","created_at":""}`), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := loadSigningKeyFile(path, signing.PurposeRemoteKillSigning); !errors.Is(err, errSigningKeyFileSchema) {
			t.Fatalf("error = %v, want errSigningKeyFileSchema", err)
		}
	})
	t.Run("private does not match public", func(t *testing.T) {
		// Swap in a public key from a different keypair: derivation check fails.
		_, _, otherPub := writeSigningKey(t, "other")
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		kf := signingKeyFile{
			SchemaVersion: signingKeyFileSchemaVersion,
			Purpose:       string(signing.PurposeRemoteKillSigning),
			KeyID:         "tamper",
			Public:        hex.EncodeToString(otherPub),
			Private:       hex.EncodeToString(priv),
			CreatedAt:     "2026-06-11T00:00:00Z",
		}
		data, _ := json.MarshalIndent(kf, "", "  ")
		path := filepath.Join(t.TempDir(), "tamper.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := loadSigningKeyFile(path, signing.PurposeRemoteKillSigning); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("error = %v, want priv/pub mismatch", err)
		}
	})
	t.Run("group-writable rejected", func(t *testing.T) {
		_, f, _ := writeSigningKey(t, "perm")
		// Build the group-writable mode at runtime (0o600 | group-rw) so the
		// gosec G302 static check does not fire on a literal permissive mode;
		// the deliberately-permissive bits are what the loader must reject.
		groupWritable := os.FileMode(0o600 | 0o060)
		if err := os.Chmod(f, groupWritable); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if _, err := loadSigningKeyFile(f, signing.PurposeRemoteKillSigning); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("error = %v, want permission error", err)
		}
	})
	t.Run("trailing JSON rejected", func(t *testing.T) {
		_, f, _ := writeSigningKey(t, "trail")
		data, err := os.ReadFile(filepath.Clean(f))
		if err != nil {
			t.Fatalf("read keyfile: %v", err)
		}
		if err := os.WriteFile(f, append(data, []byte("{}\n")...), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := loadSigningKeyFile(f, signing.PurposeRemoteKillSigning); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
			t.Fatalf("error = %v, want trailing-JSON error", err)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		if _, err := loadSigningKeyFile(filepath.Join(t.TempDir(), "nope.json"), signing.PurposeRemoteKillSigning); err == nil {
			t.Fatal("missing file = nil error, want read error")
		}
	})
	t.Run("empty path", func(t *testing.T) {
		if _, err := loadSigningKeyFile("", signing.PurposeRemoteKillSigning); err == nil {
			t.Fatal("empty path = nil error, want error")
		}
	})
	t.Run("directory rejected", func(t *testing.T) {
		if _, err := loadSigningKeyFile(t.TempDir(), signing.PurposeRemoteKillSigning); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("error = %v, want not-regular-file", err)
		}
	})
	t.Run("invalid key_id", func(t *testing.T) {
		kf := signingKeyFile{
			SchemaVersion: signingKeyFileSchemaVersion,
			Purpose:       string(signing.PurposeRemoteKillSigning),
			KeyID:         "bad id!", // space + bang are not identifier chars
			Public:        hex.EncodeToString(make([]byte, ed25519.PublicKeySize)),
			Private:       hex.EncodeToString(make([]byte, ed25519.PrivateKeySize)),
			CreatedAt:     "2026-06-11T00:00:00Z",
		}
		data, _ := json.MarshalIndent(kf, "", "  ")
		path := filepath.Join(t.TempDir(), "badid.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := loadSigningKeyFile(path, signing.PurposeRemoteKillSigning); err == nil {
			t.Fatal("bad key_id = nil error, want identifier error")
		}
	})
	t.Run("malformed public hex", func(t *testing.T) {
		kf := signingKeyFile{
			SchemaVersion: signingKeyFileSchemaVersion,
			Purpose:       string(signing.PurposeRemoteKillSigning),
			KeyID:         "mpub",
			Public:        "zz", // not valid hex / wrong length
			Private:       hex.EncodeToString(make([]byte, ed25519.PrivateKeySize)),
			CreatedAt:     "2026-06-11T00:00:00Z",
		}
		data, _ := json.MarshalIndent(kf, "", "  ")
		path := filepath.Join(t.TempDir(), "mpub.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := loadSigningKeyFile(path, signing.PurposeRemoteKillSigning); err == nil || !strings.Contains(err.Error(), "malformed public key") {
			t.Fatalf("error = %v, want malformed public key", err)
		}
	})
	t.Run("too large rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "huge.json")
		if err := os.WriteFile(path, make([]byte, maxSigningKeyFileBytes+1), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		// The shared signing-key reader caps the read and reports "size cap".
		if _, err := loadSigningKeyFile(path, signing.PurposeRemoteKillSigning); err == nil || !strings.Contains(err.Error(), "size cap") {
			t.Fatalf("error = %v, want size-cap rejection", err)
		}
	})
	t.Run("malformed private hex", func(t *testing.T) {
		_, _, pub := writeSigningKey(t, "mp")
		kf := signingKeyFile{
			SchemaVersion: signingKeyFileSchemaVersion,
			Purpose:       string(signing.PurposeRemoteKillSigning),
			KeyID:         "mp",
			Public:        hex.EncodeToString(pub),
			Private:       "zzzz", // not hex / wrong length
			CreatedAt:     "2026-06-11T00:00:00Z",
		}
		data, _ := json.MarshalIndent(kf, "", "  ")
		path := filepath.Join(t.TempDir(), "mp.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := loadSigningKeyFile(path, signing.PurposeRemoteKillSigning); err == nil || !strings.Contains(err.Error(), "malformed private key") {
			t.Fatalf("error = %v, want malformed private key", err)
		}
	})
}

func TestLoadSigningKeysThreshold(t *testing.T) {
	_, f1, _ := writeSigningKey(t, "signer-1")
	// One key but a 2-of-N requirement: must fail at the CLI boundary.
	if _, err := loadSigningKeys([]string{f1}, 2, signing.PurposeRemoteKillSigning); err == nil {
		t.Fatal("loadSigningKeys(1 key, min 2) = nil error, want threshold error")
	} else if !errors.Is(err, conductorcore.ErrThresholdRequired) {
		t.Fatalf("unexpected error: %v", err)
	}

	// Two keys satisfies min 2.
	_, f2, _ := writeSigningKey(t, "signer-2")
	keys, err := loadSigningKeys([]string{f1, f2}, 2, signing.PurposeRemoteKillSigning)
	if err != nil {
		t.Fatalf("loadSigningKeys(2 keys, min 2) error = %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("loaded %d keys, want 2", len(keys))
	}

	// Same keyfile twice -> same embedded key_id -> duplicate rejected.
	if _, err := loadSigningKeys([]string{f1, f1}, 2, signing.PurposeRemoteKillSigning); !errors.Is(err, errControlKeyDuplicateKey) {
		t.Fatalf("loadSigningKeys(dup key) error = %v, want errControlKeyDuplicateKey", err)
	}

	// No keys at all.
	if _, err := loadSigningKeys(nil, 2, signing.PurposeRemoteKillSigning); !errors.Is(err, errControlKeyFlagRequired) {
		t.Fatalf("loadSigningKeys(nil) error = %v, want errControlKeyFlagRequired", err)
	}

	// Missing key file surfaces a load error.
	if _, err := loadSigningKeys([]string{"/no/such/key.json"}, 1, signing.PurposeRemoteKillSigning); err == nil {
		t.Fatal("loadSigningKeys(missing file) = nil error, want load error")
	}
}

func TestBuildAudience(t *testing.T) {
	t.Run("instances", func(t *testing.T) {
		a, err := buildAudience([]string{"pl-1", " pl-2 ", ""}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(a.InstanceIDs) != 2 {
			t.Fatalf("got %d instance ids, want 2", len(a.InstanceIDs))
		}
	})
	t.Run("labels", func(t *testing.T) {
		a, err := buildAudience(nil, map[string]string{"tier": "prod"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if a.Labels["tier"] != "prod" {
			t.Fatalf("unexpected labels: %+v", a.Labels)
		}
	})
	t.Run("mutually exclusive", func(t *testing.T) {
		if _, err := buildAudience([]string{"pl-1"}, map[string]string{"tier": "prod"}); err == nil {
			t.Fatal("buildAudience(both) = nil error, want mutual-exclusion error")
		}
	})
	t.Run("empty", func(t *testing.T) {
		if _, err := buildAudience(nil, nil); err == nil {
			t.Fatal("buildAudience(empty) = nil error, want required error")
		}
	})
	t.Run("invalid identifier", func(t *testing.T) {
		// A label value with a forbidden character fails audience.Validate.
		if _, err := buildAudience(nil, map[string]string{"tier": "bad value!"}); err == nil {
			t.Fatal("buildAudience(bad label) = nil error, want validate error")
		}
	})
}

func TestLoadBearerToken(t *testing.T) {
	if _, err := loadBearerToken(""); err == nil {
		t.Fatal("loadBearerToken(empty path) = nil error, want required")
	}
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadBearerToken(empty); err == nil {
		t.Fatal("loadBearerToken(empty file) = nil error, want empty error")
	}
	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, []byte(" tok123 \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	tok, err := loadBearerToken(good)
	if err != nil || tok != "tok123" {
		t.Fatalf("loadBearerToken = %q, %v; want tok123, nil", tok, err)
	}
	// A directory path surfaces a read error, not a panic.
	if _, err := loadBearerToken(dir); err == nil {
		t.Fatal("loadBearerToken(dir) = nil error, want read error")
	}
}

func TestBuildEmergencyClientRequiresTLSMaterial(t *testing.T) {
	for name, opts := range map[string]emergencyClientOptions{
		"no cert": {tlsKey: "k", serverCA: "ca"},
		"no key":  {tlsCert: "c", serverCA: "ca"},
		"no ca":   {tlsCert: "c", tlsKey: "k"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildEmergencyClient(opts); err == nil {
				t.Fatalf("buildEmergencyClient(%s) = nil error, want required", name)
			}
		})
	}
}

func TestPostEmergencyJSONSurfacesServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"under threshold"}`))
	}))
	defer srv.Close()
	err := postEmergencyJSON(context.Background(), srv.Client(), srv.URL, "/x", "tok", map[string]string{"a": "b"}, nil)
	if err == nil || !strings.Contains(err.Error(), "under threshold") {
		t.Fatalf("postEmergencyJSON error = %v, want server snippet", err)
	}
	if !strings.Contains(err.Error(), "status=422") {
		t.Fatalf("postEmergencyJSON error = %v, want status code", err)
	}
}

func captureCmd() (*bytes.Buffer, *bytes.Buffer) {
	return &bytes.Buffer{}, &bytes.Buffer{}
}

// writeLeafCertKeyPEM generates a self-signed ECDSA-free ed25519 leaf
// certificate + private key and writes them as PEM files, returning their
// paths. Enough to satisfy tls.LoadX509KeyPair for the client-build test.
func writeLeafCertKeyPEM(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(leaf): %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test operator client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate(leaf): %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func writeCAPEM(t *testing.T) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(CA): %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "test conductor CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate(CA): %v", err)
	}
	path := filepath.Join(t.TempDir(), "conductor-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	return path
}

func TestBuildEmergencyClientHappyPath(t *testing.T) {
	certPath, keyPath := writeLeafCertKeyPEM(t)
	caPath := writeCAPEM(t)
	client, err := buildEmergencyClient(emergencyClientOptions{
		tlsCert: certPath, tlsKey: keyPath, serverCA: caPath, serverName: "conductor.example",
	})
	if err != nil {
		t.Fatalf("buildEmergencyClient happy path error = %v", err)
	}
	if client == nil || client.Timeout != emergencyHTTPTimeout {
		t.Fatalf("unexpected client: %+v", client)
	}
}

func TestBuildEmergencyClientBadCertMaterial(t *testing.T) {
	caPath := writeCAPEM(t)
	// Point cert/key at the CA file (not a usable keypair) -> load error.
	if _, err := buildEmergencyClient(emergencyClientOptions{
		tlsCert: caPath, tlsKey: caPath, serverCA: caPath,
	}); err == nil {
		t.Fatal("buildEmergencyClient(bad keypair) = nil error, want load error")
	}
	// Empty/garbage CA bundle.
	certPath, keyPath := writeLeafCertKeyPEM(t)
	emptyCA := filepath.Join(t.TempDir(), "empty-ca.pem")
	if err := os.WriteFile(emptyCA, []byte("not pem\n"), 0o600); err != nil {
		t.Fatalf("write empty CA: %v", err)
	}
	if _, err := buildEmergencyClient(emergencyClientOptions{
		tlsCert: certPath, tlsKey: keyPath, serverCA: emptyCA,
	}); err == nil {
		t.Fatal("buildEmergencyClient(empty CA) = nil error, want no-PEM error")
	}
	// Missing CA file.
	if _, err := buildEmergencyClient(emergencyClientOptions{
		tlsCert: certPath, tlsKey: keyPath, serverCA: filepath.Join(t.TempDir(), "nope.pem"),
	}); err == nil {
		t.Fatal("buildEmergencyClient(missing CA) = nil error, want read error")
	}
}

func TestResolveEmergencyTransportBuildsProductionClient(t *testing.T) {
	certPath, keyPath := writeLeafCertKeyPEM(t)
	caPath := writeCAPEM(t)
	tr, err := resolveEmergencyTransport(nil, emergencyClientOptions{
		tlsCert: certPath, tlsKey: keyPath, serverCA: caPath,
	})
	if err != nil {
		t.Fatalf("resolveEmergencyTransport(nil injected) error = %v", err)
	}
	if tr == nil {
		t.Fatal("resolveEmergencyTransport returned nil transport")
	}
}

type errTransport struct{ err error }

func (e errTransport) Do(*http.Request) (*http.Response, error) { return nil, e.err }

func TestPostEmergencyJSON_TransportErrorWrapped(t *testing.T) {
	boom := errors.New("dial refused")
	err := postEmergencyJSON(context.Background(), errTransport{err: boom}, "http://x", "/p", "", map[string]string{"a": "b"}, nil)
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("error = %v, want wrapped transport error", err)
	}
}

func TestPostEmergencyJSON_DecodeErrorOnBadBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	var out struct {
		X string `json:"x"`
	}
	err := postEmergencyJSON(context.Background(), srv.Client(), srv.URL, "/p", "", map[string]string{"a": "b"}, &out)
	if err == nil || !strings.Contains(err.Error(), "decode conductor response") {
		t.Fatalf("error = %v, want decode error", err)
	}
}

func TestPostEmergencyJSON_NoBearerHeaderOmitted(t *testing.T) {
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	if err := postEmergencyJSON(context.Background(), srv.Client(), srv.URL, "/p", "", map[string]string{"a": "b"}, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sawAuth != "" {
		t.Fatalf("Authorization header sent with empty bearer: %q", sawAuth)
	}
}

func TestEmergencySnippetTruncates(t *testing.T) {
	long := strings.Repeat("a", 1000)
	got := emergencySnippet([]byte(long))
	if !strings.HasSuffix(got, "…") || len(got) > 1000 {
		t.Fatalf("snippet not truncated: len=%d", len(got))
	}
}

func TestEmergencySnippetSanitizesAndRedacts(t *testing.T) {
	got := emergencySnippet([]byte("first line\nAuthorization: Bearer admin-token\r\nsecond\x00line"), "admin-token")
	if strings.Contains(got, "\n") || strings.Contains(got, "\r") || strings.Contains(got, "\x00") {
		t.Fatalf("snippet kept control bytes: %q", got)
	}
	if strings.Contains(got, "admin-token") {
		t.Fatalf("snippet leaked bearer token: %q", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Fatalf("snippet did not mark redaction: %q", got)
	}

	// Empty / whitespace-only secrets must NOT redact: an empty token would
	// otherwise turn ReplaceAll into a no-op-or-corruption and, worse, an
	// attacker-controlled empty secret could mask the whole body. The guard
	// skips empty secrets, so the body survives verbatim (minus control bytes).
	plain := emergencySnippet([]byte("plain server error body"), "", "   ")
	if plain != "plain server error body" {
		t.Fatalf("empty secret altered snippet: %q", plain)
	}
	if strings.Contains(plain, "[redacted]") {
		t.Fatalf("empty secret produced spurious redaction: %q", plain)
	}

	// Multiple secrets all redact; a non-matching secret is harmless.
	multi := emergencySnippet([]byte("tokenA and tokenB and tokenA"), "tokenA", "tokenB", "absent")
	if strings.Contains(multi, "tokenA") || strings.Contains(multi, "tokenB") {
		t.Fatalf("multi-secret redaction leaked: %q", multi)
	}
}

func TestZeroBytesAndZeroLoadedSigningKeys(t *testing.T) {
	// zeroBytes wipes in place.
	b := []byte{1, 2, 3, 4}
	zeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("zeroBytes left byte %d = %d, want 0", i, v)
		}
	}
	// zeroLoadedSigningKeys wipes each key's private bytes in place. Because
	// ed25519.PrivateKey(privBytes) aliases the same backing array, wiping the
	// loaded key zeroes the underlying material.
	_, f1, _ := writeSigningKey(t, "wipe-signer")
	key, err := loadSigningKeyFile(f1, signing.PurposeRemoteKillSigning)
	if err != nil {
		t.Fatalf("loadSigningKeyFile: %v", err)
	}
	// Capture the backing array reference; confirm it is non-zero before wipe.
	priv := key.priv
	allZero := true
	for _, v := range priv {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("loaded private key was already all-zero before wipe")
	}
	zeroLoadedSigningKeys([]loadedSigningKey{key})
	for i, v := range priv {
		if v != 0 {
			t.Fatalf("zeroLoadedSigningKeys left private byte %d = %d, want 0", i, v)
		}
	}
}

func TestSignEmergencyPreimagePropagatesError(t *testing.T) {
	_, f1, _ := writeSigningKey(t, "signer-1")
	keys, err := loadSigningKeys([]string{f1}, 1, signing.PurposeRemoteKillSigning)
	if err != nil {
		t.Fatalf("loadSigningKeys: %v", err)
	}
	wantErr := errors.New("preimage boom")
	if _, err := signEmergencyPreimage(func() ([]byte, error) { return nil, wantErr }, signing.PurposeRemoteKillSigning, keys); !errors.Is(err, wantErr) {
		t.Fatalf("signEmergencyPreimage error = %v, want preimage error", err)
	}
}
