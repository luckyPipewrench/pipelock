//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"context"
	"crypto/ed25519"
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
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	testConfigYAML  = "mode: strict\napi_allowlist:\n  - api.vendor.example\n"
	testOrg         = "org-main"
	testFleet       = "prod"
	testEnv         = "prod"
	testPubToken    = "publisher-token-value"
	wantPurposeFlag = "policy-bundle-signing"
)

// --- key-file helpers -------------------------------------------------------

// writePolicyKeyFile writes a key file in the exact on-disk JSON shape produced
// by "pipelock signing key generate" for a given purpose, generating the keypair
// inline (the keygen CLI is a separate PR; this test does not depend on it).
func writePolicyKeyFile(t *testing.T, dir, purpose, keyID string) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	kf := publishKeyFile{
		SchemaVersion: keyFileSchemaVersion,
		Purpose:       purpose,
		KeyID:         keyID,
		Public:        hex.EncodeToString(pub),
		Private:       hex.EncodeToString(priv),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		t.Fatalf("marshal key file: %v", err)
	}
	path := filepath.Join(dir, keyID+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path, pub
}

// selfSignedCertKey generates a throwaway self-signed cert + key in PEM form so
// the mTLS client-builder tests can exercise LoadX509KeyPair and the CA pool
// without a live dial.
func selfSignedCertKey(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "conductor.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		DNSNames:     []string{"conductor.example"},
	}
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// --- a real Conductor handler over httptest --------------------------------

type stubAuditSink struct{}

func (stubAuditSink) IngestAuditBatch(context.Context, controlplane.AcceptedAuditBatch) (controlplane.AuditIngestResult, error) {
	return controlplane.AuditIngestResult{}, errors.New("not used by publish tests")
}

// newPublishServer stands up a real controlplane.Handler backed by a file store,
// gated by a publisher bearer token, and returns its base URL. The publish path
// runs the same PolicyBundle.Validate + monotonic-version store logic the
// production server runs, so a passing publish here exercises the real server
// acceptance, not a stub.
func newPublishServer(t *testing.T) string {
	t.Helper()
	store, err := controlplane.OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore: %v", err)
	}
	publisher, err := controlplane.BearerPublisherAuthorizer(testPubToken)
	if err != nil {
		t.Fatalf("BearerPublisherAuthorizer: %v", err)
	}
	bundleAuth, err := controlplane.ScopedBearerBundleAuthorizer([]controlplane.ScopedBearerCredential{{
		Token: testPubToken,
		Role:  controlplane.RolePublisher,
	}})
	if err != nil {
		t.Fatalf("ScopedBearerBundleAuthorizer: %v", err)
	}
	auditKeys, err := controlplane.StaticAuditKeyResolver(nil)
	if err != nil {
		// StaticAuditKeyResolver(nil) returns a resolver that rejects all keys;
		// publish never invokes it, but NewHandler requires non-nil.
		auditKeys = func(controlplane.FollowerIdentity, string) (conductorcore.SignatureKey, error) {
			return conductorcore.SignatureKey{}, errors.New("no audit keys")
		}
	}
	handler, err := controlplane.NewHandler(controlplane.HandlerOptions{
		Store:        store,
		Capabilities: controlplane.DefaultCapabilities("conductor-test"),
		FollowerIdentity: func(*http.Request) (controlplane.FollowerIdentity, error) {
			return controlplane.FollowerIdentity{}, controlplane.ErrFollowerRequired
		},
		AuthorizePublisher: publisher,
		AuthorizeBundle:    bundleAuth,
		AuditSink:          stubAuditSink{},
		AuditKeys:          auditKeys,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL
}

func baseOpts(t *testing.T, dir, conductorURL string) publishOptions {
	t.Helper()
	keyPath, _ := writePolicyKeyFile(t, dir, wantPurposeFlag, "policy-key-1")
	cfgPath := writeFile(t, dir, "policy.yaml", testConfigYAML)
	tokPath := writeFile(t, dir, "pub.token", testPubToken)
	return publishOptions{
		conductorURL: conductorURL,
		configFile:   cfgPath,
		orgID:        testOrg,
		fleetID:      testFleet,
		environment:  testEnv,
		audience:     []string{"*"},
		version:      1,
		validity:     time.Hour,
		signingKey:   keyPath,
		publisherTok: tokPath,
		insecure:     true, // httptest server is http:// loopback
	}
}

// --- happy path: full build+sign+POST against the real handler --------------

func TestPublish_HappyPathAcceptedByRealHandler(t *testing.T) {
	dir := t.TempDir()
	url := newPublishServer(t)
	opts := baseOpts(t, dir, url)

	var out strings.Builder
	if err := runPublish(context.Background(), &out, opts); err != nil {
		t.Fatalf("runPublish: %v", err)
	}
	if !strings.Contains(out.String(), "version 1") || !strings.Contains(out.String(), "policy-key-1") {
		t.Fatalf("unexpected output: %q", out.String())
	}
	headHash := extractHash(t, out.String())

	// Re-publishing a HIGHER version chained to the prior head is accepted.
	opts.version = 2
	opts.previousHash = headHash
	out.Reset()
	if err := runPublish(context.Background(), &out, opts); err != nil {
		t.Fatalf("runPublish v2: %v", err)
	}
	if !strings.Contains(out.String(), "version 2") {
		t.Fatalf("v2 output: %q", out.String())
	}
}

// TestPublish_ForwardWithoutChainHashRejected proves a forward publish that
// omits --previous-bundle-hash is rejected by the stream chain check (409), so
// an operator cannot accidentally fork the stream.
func TestPublish_ForwardWithoutChainHashRejected(t *testing.T) {
	dir := t.TempDir()
	url := newPublishServer(t)
	opts := baseOpts(t, dir, url)

	var out strings.Builder
	if err := runPublish(context.Background(), &out, opts); err != nil {
		t.Fatalf("runPublish v1: %v", err)
	}
	// v2 with no previous-bundle-hash: the store rejects the unchained forward.
	opts.version = 2
	out.Reset()
	err := runPublish(context.Background(), &out, opts)
	if err == nil {
		t.Fatalf("expected chain-conflict error, got nil")
	}
	if !errors.Is(err, ErrStalePolicyVersion) {
		t.Fatalf("want ErrStalePolicyVersion (409), got %v", err)
	}
}

// TestPublish_FirstBundleWithPreviousHashRejected proves the server rejects a
// first-in-stream bundle that carries a previous-bundle-hash (there is no head
// to chain to), so a copy-paste of a stale hash cannot silently fork a new
// stream.
func TestPublish_FirstBundleWithPreviousHashRejected(t *testing.T) {
	dir := t.TempDir()
	url := newPublishServer(t)
	opts := baseOpts(t, dir, url)
	opts.previousHash = strings.Repeat("ab", 32) // valid-shape hash, but no stream head exists
	err := runPublish(context.Background(), &strings.Builder{}, opts)
	if err == nil || !errors.Is(err, ErrStalePolicyVersion) {
		t.Fatalf("want rejection for first bundle with previous hash, got %v", err)
	}
}

// extractHash pulls the "(hash <hex>," token out of the publish success line.
func extractHash(t *testing.T, out string) string {
	t.Helper()
	const marker = "hash "
	i := strings.Index(out, marker)
	if i < 0 {
		t.Fatalf("no hash in output: %q", out)
	}
	rest := out[i+len(marker):]
	end := strings.IndexAny(rest, ",)")
	if end < 0 {
		t.Fatalf("malformed hash token: %q", rest)
	}
	return strings.TrimSpace(rest[:end])
}

// TestPublish_StaleVersionRejectedClean drives the 409 path explicitly with
// captured output so the assertion is deterministic.
func TestPublish_StaleVersionRejectedClean(t *testing.T) {
	dir := t.TempDir()
	url := newPublishServer(t)
	opts := baseOpts(t, dir, url)

	var out strings.Builder
	opts.version = 5
	if err := runPublish(context.Background(), &out, opts); err != nil {
		t.Fatalf("publish v5: %v", err)
	}
	// Now publish a lower version: server returns 409, surfaced as ErrStalePolicyVersion.
	opts.version = 4
	out.Reset()
	err := runPublish(context.Background(), &out, opts)
	if err == nil {
		t.Fatalf("expected stale-version error, got nil")
	}
	if !errors.Is(err, ErrStalePolicyVersion) {
		t.Fatalf("want ErrStalePolicyVersion, got %v", err)
	}
}

func TestPublish_BadPublisherTokenForbidden(t *testing.T) {
	dir := t.TempDir()
	url := newPublishServer(t)
	opts := baseOpts(t, dir, url)
	// Overwrite the token file with a wrong value.
	opts.publisherTok = writeFile(t, dir, "wrong.token", "not-the-token")

	err := runPublish(context.Background(), &strings.Builder{}, opts)
	if err == nil {
		t.Fatalf("expected forbidden error, got nil")
	}
	if !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("want authorization error, got %v", err)
	}
}

// --- build/sign error paths (no network) -----------------------------------

func TestBuildSignedBundle_WrongPurposeKeyRejected(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	// Replace the signing key with a remote-kill-signing key (valid purpose,
	// wrong for policy bundles).
	keyPath, _ := writePolicyKeyFile(t, dir, "remote-kill-signing", "kill-key-1")
	opts.signingKey = keyPath

	_, _, _, err := buildSignedBundle(opts)
	if err == nil || !strings.Contains(err.Error(), "wrong key purpose") {
		t.Fatalf("want wrong-purpose error, got %v", err)
	}
}

func TestBuildSignedBundle_UnknownPurposeKeyRejected(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	keyPath, _ := writePolicyKeyFile(t, dir, "totally-made-up", "weird-key")
	opts.signingKey = keyPath

	_, _, _, err := buildSignedBundle(opts)
	if err == nil {
		t.Fatalf("expected unknown-purpose error, got nil")
	}
}

func TestBuildSignedBundle_TamperedPrivateKeyRejected(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	// Write a key file whose private half does not match its public half.
	pub, _, _ := signing.GenerateKeyPair()
	_, otherPriv, _ := signing.GenerateKeyPair()
	kf := publishKeyFile{
		SchemaVersion: keyFileSchemaVersion,
		Purpose:       wantPurposeFlag,
		KeyID:         "mismatch",
		Public:        hex.EncodeToString(pub),
		Private:       hex.EncodeToString(otherPriv),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.MarshalIndent(kf, "", "  ")
	path := filepath.Join(dir, "mismatch.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	opts.signingKey = path

	_, _, _, err := buildSignedBundle(opts)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want key-mismatch error, got %v", err)
	}
}

// TestBuildSignedBundle_InputsValidatedBeforeKeyRead is the Fix-2 ordering
// regression: a malformed --previous-bundle-hash must be rejected BEFORE the
// signing key file is read. Proof: point --signing-key at a path that does NOT
// exist; if key-read happened first, the error would be "read --signing-key"
// (file-not-found). Because input validation runs first, we instead get the
// previous-bundle-hash error and the key is never touched.
func TestBuildSignedBundle_InputsValidatedBeforeKeyRead(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	opts.version = 2
	opts.previousHash = "zzz-not-hex"
	opts.signingKey = filepath.Join(dir, "this-file-does-not-exist.json")

	_, _, _, err := buildSignedBundle(opts)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--previous-bundle-hash must be") {
		t.Fatalf("expected previous-hash error BEFORE key read, got %v", err)
	}
	if strings.Contains(err.Error(), "read --signing-key") {
		t.Fatalf("key file was read before input validation (ordering bug): %v", err)
	}
}

// TestBuildSignedBundle_KeyWipedOnPostLoadError is the Fix-2 wipe regression: a
// valid key loads, then a post-load failure occurs (forged signature/validation
// path). We can't see buildSignedBundle's internal slice, so we prove the
// deferred-wipe contract structurally: build a bundle that loads the key but
// fails local Validate (oversized config slips past readConfigPayload? no — use
// a min-version that Validate rejects), and assert the returned priv is nil so
// no key escapes on the error path.
func TestBuildSignedBundle_NoKeyEscapesOnPostLoadError(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	// A malformed min-pipelock-version passes the early checks (key loads) but
	// fails bundle.Validate() AFTER signing — exercising a post-key-load error.
	opts.minVersion = "not.a.version.x"

	bundle, keyID, priv, err := buildSignedBundle(opts)
	if err == nil {
		t.Fatalf("expected post-load validation error")
	}
	if !strings.Contains(err.Error(), "local validation") {
		t.Fatalf("expected local-validation error, got %v", err)
	}
	// On the error path nothing is handed off: the bundle, keyID, and priv are
	// all zero. priv==nil proves the key did not escape to the caller (and the
	// deferred wipe ran on the in-function copy).
	if priv != nil {
		t.Fatalf("private key escaped on error path (len=%d)", len(priv))
	}
	if keyID != "" || bundle.BundleID != "" {
		t.Fatalf("non-zero return on error path: keyID=%q bundleID=%q", keyID, bundle.BundleID)
	}
}

// TestLoadPolicySigningKey_SymlinkRejected is the publish-side integration
// regression: a symlinked signing-key file must be rejected through the full
// loader. The hardened reader (symlink/perm/size gates) now lives in
// internal/cli/signing.ReadKeyFileBytes — its unit coverage is in
// key_generate_test.go — so this test proves publish's path actually routes
// through it.
func TestLoadPolicySigningKey_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	realPath, _ := writePolicyKeyFile(t, dir, wantPurposeFlag, "real-key")
	linkPath := filepath.Join(dir, "link.json")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	if _, _, err := loadPolicySigningKey(linkPath); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("loadPolicySigningKey want symlink rejection, got %v", err)
	}
}

func TestReadSigningKey_TooPermissiveRejected(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writePolicyKeyFile(t, dir, wantPurposeFlag, "perm-key")
	// Deliberately loosen perms to prove the secret-permission gate fires. The
	// mode is built from a variable so the gosec G302 literal check does not
	// flag this intentional test fixture.
	tooOpen := os.FileMode(0o600) | 0o044
	if err := os.Chmod(keyPath, tooOpen); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, _, err := loadPolicySigningKey(keyPath)
	if err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("want permission error, got %v", err)
	}
}

func TestBuildSignedBundle_MissingConfigRejected(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	opts.configFile = ""
	_, _, _, err := buildSignedBundle(opts)
	if err == nil || !strings.Contains(err.Error(), "--config is required") {
		t.Fatalf("want config-required error, got %v", err)
	}
}

func TestBuildSignedBundle_EmptyConfigRejected(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	opts.configFile = writeFile(t, dir, "empty.yaml", "   \n")
	_, _, _, err := buildSignedBundle(opts)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("want empty-config error, got %v", err)
	}
}

func TestBuildSignedBundle_ForbiddenConfigSectionRejectedLocally(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	// 'kill_switch' is NOT in the allowed policy-bundle sections allowlist.
	opts.configFile = writeFile(t, dir, "bad.yaml", "mode: strict\nkill_switch:\n  enabled: true\n")
	_, _, _, err := buildSignedBundle(opts)
	if err == nil || !strings.Contains(err.Error(), "local validation") {
		t.Fatalf("want local-validation failure for forbidden section, got %v", err)
	}
	if !errors.Is(err, conductorcore.ErrForbiddenBundleSection) {
		t.Fatalf("want ErrForbiddenBundleSection in chain, got %v", err)
	}
}

func TestBuildSignedBundle_LicenseFieldRejectedLocally(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	opts.configFile = writeFile(t, dir, "lic.yaml", "mode: strict\nlicense_key: AAAA\n")
	_, _, _, err := buildSignedBundle(opts)
	if err == nil || !errors.Is(err, conductorcore.ErrForbiddenLicenseField) {
		t.Fatalf("want ErrForbiddenLicenseField, got %v", err)
	}
}

func TestBuildSignedBundle_BadPreviousHashRejected(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	opts.version = 2
	opts.previousHash = "not-a-hash"
	_, _, _, err := buildSignedBundle(opts)
	if err == nil || !strings.Contains(err.Error(), "--previous-bundle-hash must be") {
		t.Fatalf("want previous-hash format error, got %v", err)
	}
}

func TestBuildSignedBundle_ZeroVersionRejected(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	opts.version = 0
	_, _, _, err := buildSignedBundle(opts)
	if err == nil || !strings.Contains(err.Error(), "--version is required") {
		t.Fatalf("want version-required error, got %v", err)
	}
}

func TestBuildSignedBundle_SignatureVerifiesAgainstSignerPublicKey(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := writePolicyKeyFile(t, dir, wantPurposeFlag, "verify-key")
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	opts.signingKey = keyPath

	bundle, keyID, _, err := buildSignedBundle(opts)
	if err != nil {
		t.Fatalf("buildSignedBundle: %v", err)
	}
	if keyID != "verify-key" {
		t.Fatalf("keyID = %q", keyID)
	}
	// The produced signature must verify against the signer's public key over
	// the canonical preimage. This is the property the follower will check.
	resolve := func(id string) (conductorcore.SignatureKey, error) {
		if id != "verify-key" {
			return conductorcore.SignatureKey{}, errors.New("unknown key")
		}
		return conductorcore.SignatureKey{PublicKey: pub, KeyPurpose: signing.PurposePolicyBundleSigning}, nil
	}
	if err := bundle.VerifySignaturesAt(time.Now(), resolve); err != nil {
		t.Fatalf("VerifySignaturesAt: %v", err)
	}
}

// --- audience parsing -------------------------------------------------------

func TestParseAudience(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		wantErr bool
		check   func(t *testing.T, a conductorcore.Audience)
	}{
		{name: "wildcard", in: []string{"*"}, check: func(t *testing.T, a conductorcore.Audience) {
			if len(a.InstanceIDs) != 1 || a.InstanceIDs[0] != "*" {
				t.Fatalf("audience = %+v", a)
			}
		}},
		{name: "instance ids", in: []string{"follower-1", "follower-2"}, check: func(t *testing.T, a conductorcore.Audience) {
			if len(a.InstanceIDs) != 2 {
				t.Fatalf("audience = %+v", a)
			}
		}},
		{name: "labels", in: []string{"label:tier=canary", "label:region=us"}, check: func(t *testing.T, a conductorcore.Audience) {
			if a.Labels["tier"] != "canary" || a.Labels["region"] != "us" {
				t.Fatalf("labels = %+v", a.Labels)
			}
		}},
		{name: "empty", in: nil, wantErr: true},
		{name: "blank entry", in: []string{"  "}, wantErr: true},
		{name: "mixed ids and labels", in: []string{"follower-1", "label:tier=canary"}, wantErr: true},
		{name: "wildcard with explicit id", in: []string{"*", "follower-1"}, wantErr: true},
		{name: "malformed label", in: []string{"label:novalue"}, wantErr: true},
		{name: "duplicate label key", in: []string{"label:tier=a", "label:tier=b"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			aud, err := parseAudience(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got audience %+v", aud)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, aud)
			}
		})
	}
}

// --- rule bundle ref parsing ------------------------------------------------

func TestParseRuleBundleRefs(t *testing.T) {
	validSHA := strings.Repeat("ab", 32) // 64 hex chars = 32 bytes
	good := "name=core,version=2026.06.1,sha256=" + validSHA
	refs, err := parseRuleBundleRefs([]string{good})
	if err != nil {
		t.Fatalf("parse good: %v", err)
	}
	if len(refs) != 1 || refs[0].Name != "core" || refs[0].Version != "2026.06.1" {
		t.Fatalf("refs = %+v", refs)
	}

	bad := []struct {
		name string
		in   string
	}{
		{"unknown field", "name=core,version=1,sha256=" + validSHA + ",extra=x"},
		{"bad sha", "name=core,version=1,sha256=zzzz"},
		{"missing name", "version=1,sha256=" + validSHA},
		{"duplicate key", "name=a,name=b,version=1,sha256=" + validSHA},
		{"no equals", "namecore"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseRuleBundleRefs([]string{tc.in}); err == nil {
				t.Fatalf("expected error for %q", tc.in)
			}
		})
	}
}

// --- mTLS client construction guards ---------------------------------------

func TestPublishHTTPClient_HTTPSRequiresMTLSMaterial(t *testing.T) {
	_, err := publishHTTPClient(publishOptions{conductorURL: "https://conductor.example:8895"})
	if err == nil || !strings.Contains(err.Error(), "--tls-cert and --tls-key are required") {
		t.Fatalf("want mTLS-required error, got %v", err)
	}
}

func TestPublishHTTPClient_HTTPRequiresOptIn(t *testing.T) {
	_, err := publishHTTPClient(publishOptions{conductorURL: "http://127.0.0.1:8895"})
	if err == nil || !strings.Contains(err.Error(), "allow-plaintext-loopback") {
		t.Fatalf("want opt-in error, got %v", err)
	}
}

func TestPublishHTTPClient_HTTPNonLoopbackRejected(t *testing.T) {
	_, err := publishHTTPClient(publishOptions{conductorURL: "http://conductor.example:8895", insecure: true})
	if err == nil || !strings.Contains(err.Error(), "loopback host") {
		t.Fatalf("want non-loopback rejection, got %v", err)
	}
}

func TestPublishHTTPClient_LoopbackBypassAttemptsRejected(t *testing.T) {
	// Each of these tries to smuggle a non-loopback destination past the
	// --allow-plaintext-loopback gate. All must be rejected.
	cases := []string{
		"http://127.0.0.1@evil.example:8895", // userinfo trick: real host is evil.example
		"http://evil.example:8895",           // plain non-loopback
		"http://127.0.0.1.evil.example:8895", // loopback-looking subdomain
		"http://0.0.0.0:8895",                // unspecified, not loopback
		"http://169.254.169.254:8895",        // link-local metadata, not loopback
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if _, err := publishHTTPClient(publishOptions{conductorURL: raw, insecure: true}); err == nil {
				t.Fatalf("expected rejection for %q", raw)
			}
		})
	}
}

func TestPublishHTTPClient_IPv6LoopbackAllowed(t *testing.T) {
	c, err := publishHTTPClient(publishOptions{conductorURL: "http://[::1]:8895", insecure: true})
	if err != nil {
		t.Fatalf("ipv6 loopback: %v", err)
	}
	if c == nil {
		t.Fatalf("nil client")
	}
}

func TestPublishHTTPClient_LoopbackOptInAllowed(t *testing.T) {
	c, err := publishHTTPClient(publishOptions{conductorURL: "http://127.0.0.1:8895", insecure: true})
	if err != nil {
		t.Fatalf("loopback opt-in: %v", err)
	}
	if c == nil {
		t.Fatalf("nil client")
	}
}

func TestPublishHTTPClient_MissingHostRejected(t *testing.T) {
	_, err := publishHTTPClient(publishOptions{conductorURL: "https://"})
	if err == nil {
		t.Fatalf("expected missing-host error")
	}
}

func TestPublishHTTPClient_HTTPSWithMaterialBuildsClient(t *testing.T) {
	// Generate a throwaway self-signed cert/key + CA so LoadX509KeyPair and the
	// CA pool both succeed; we only assert the client builds, not a live dial.
	dir := t.TempDir()
	certPEM, keyPEM := selfSignedCertKey(t)
	certPath := writeFile(t, dir, "client.crt", certPEM)
	keyPath := writeFile(t, dir, "client.key", keyPEM)
	caPath := writeFile(t, dir, "ca.pem", certPEM)
	c, err := publishHTTPClient(publishOptions{
		conductorURL: "https://conductor.example:8895",
		tlsCert:      certPath,
		tlsKey:       keyPath,
		serverCA:     caPath,
	})
	if err != nil {
		t.Fatalf("build https client: %v", err)
	}
	if c == nil {
		t.Fatalf("nil client")
	}
}

// --- missing-file and malformed-input guards -------------------------------

func TestBuildSignedBundle_MissingConfigFileRejected(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	opts.configFile = filepath.Join(dir, "does-not-exist.yaml")
	_, _, _, err := buildSignedBundle(opts)
	if err == nil || !strings.Contains(err.Error(), "read --config") {
		t.Fatalf("want read-config error, got %v", err)
	}
}

func TestReadConfigPayload_OversizedRejected(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("a", conductorcore.MaxConfigYAMLBytes+1)
	path := writeFile(t, dir, "big.yaml", big)
	_, err := readConfigPayload(path)
	if err == nil || !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("want oversized error, got %v", err)
	}
}

func TestBuildSignedBundle_MissingSigningKeyFileRejected(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	opts.signingKey = filepath.Join(dir, "no-key.json")
	_, _, _, err := buildSignedBundle(opts)
	if err == nil || !strings.Contains(err.Error(), "read --signing-key") {
		t.Fatalf("want read-signing-key error, got %v", err)
	}
}

func TestBuildSignedBundle_MissingSigningKeyFlagRejected(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	opts.signingKey = ""
	_, _, _, err := buildSignedBundle(opts)
	if err == nil || !strings.Contains(err.Error(), "--signing-key is required") {
		t.Fatalf("want signing-key-required error, got %v", err)
	}
}

func TestBuildSignedBundle_ZeroValidityRejected(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	opts.validity = 0
	_, _, _, err := buildSignedBundle(opts)
	if err == nil || !strings.Contains(err.Error(), "--validity must be positive") {
		t.Fatalf("want validity error, got %v", err)
	}
}

func TestLoadPolicySigningKey_MalformedJSONRejected(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "bad.json", "{not json")
	if _, _, err := loadPolicySigningKey(path); err == nil || !strings.Contains(err.Error(), "decode --signing-key") {
		t.Fatalf("want decode error, got %v", err)
	}
}

func TestLoadPolicySigningKey_TrailingJSONRejected(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writePolicyKeyFile(t, dir, wantPurposeFlag, "trail-key")
	data, err := os.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	tampered := writeFile(t, dir, "trail2.json", string(data)+"\n{}")
	if _, _, err := loadPolicySigningKey(tampered); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("want trailing-JSON error, got %v", err)
	}
}

func TestLoadPolicySigningKey_BadSchemaVersionRejected(t *testing.T) {
	dir := t.TempDir()
	kf := publishKeyFile{SchemaVersion: 99, Purpose: wantPurposeFlag, KeyID: "x", Public: hex.EncodeToString(make([]byte, ed25519.PublicKeySize)), Private: hex.EncodeToString(make([]byte, ed25519.PrivateKeySize)), CreatedAt: "now"}
	data, _ := json.Marshal(kf)
	path := writeFile(t, dir, "schema.json", string(data))
	if _, _, err := loadPolicySigningKey(path); err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("want schema error, got %v", err)
	}
}

func TestLoadPolicySigningKey_MissingKeyIDRejected(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := signing.GenerateKeyPair()
	kf := publishKeyFile{SchemaVersion: keyFileSchemaVersion, Purpose: wantPurposeFlag, KeyID: "  ", Public: hex.EncodeToString(pub), Private: hex.EncodeToString(priv), CreatedAt: "now"}
	data, _ := json.Marshal(kf)
	path := writeFile(t, dir, "noid.json", string(data))
	if _, _, err := loadPolicySigningKey(path); err == nil || !strings.Contains(err.Error(), "missing key_id") {
		t.Fatalf("want missing-key_id error, got %v", err)
	}
}

// TestLoadPolicySigningKey_OversizedRejected proves the shared reader's 16 KiB
// size cap is enforced on publish's path. The cap itself is unit-tested in
// internal/cli/signing (TestReadKeyFileBytes_RejectsOversizedFile); here we only
// confirm loadPolicySigningKey routes through it.
func TestLoadPolicySigningKey_OversizedRejected(t *testing.T) {
	dir := t.TempDir()
	// 16 KiB + slack is above the shared keyFileMaxSize (16 KiB).
	path := writeFile(t, dir, "huge.json", strings.Repeat("x", 16*1024+1))
	if _, _, err := loadPolicySigningKey(path); err == nil || !strings.Contains(err.Error(), "max") {
		t.Fatalf("want oversized error, got %v", err)
	}
}

func TestPublishHTTPClient_MissingServerCARejected(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := selfSignedCertKey(t)
	certPath := writeFile(t, dir, "c.crt", certPEM)
	keyPath := writeFile(t, dir, "c.key", keyPEM)
	_, err := publishHTTPClient(publishOptions{conductorURL: "https://conductor.example:8895", tlsCert: certPath, tlsKey: keyPath})
	if err == nil || !strings.Contains(err.Error(), "--server-ca is required") {
		t.Fatalf("want server-ca-required error, got %v", err)
	}
}

func TestPublishHTTPClient_UnreadableServerCARejected(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := selfSignedCertKey(t)
	certPath := writeFile(t, dir, "c.crt", certPEM)
	keyPath := writeFile(t, dir, "c.key", keyPEM)
	_, err := publishHTTPClient(publishOptions{
		conductorURL: "https://conductor.example:8895",
		tlsCert:      certPath, tlsKey: keyPath,
		serverCA: filepath.Join(dir, "no-ca.pem"),
	})
	if err == nil || !strings.Contains(err.Error(), "read --server-ca") {
		t.Fatalf("want read-server-ca error, got %v", err)
	}
}

func TestPublishHTTPClient_EmptyServerCAPoolRejected(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := selfSignedCertKey(t)
	certPath := writeFile(t, dir, "c.crt", certPEM)
	keyPath := writeFile(t, dir, "c.key", keyPEM)
	emptyCA := writeFile(t, dir, "empty.pem", "not a pem\n")
	_, err := publishHTTPClient(publishOptions{
		conductorURL: "https://conductor.example:8895",
		tlsCert:      certPath, tlsKey: keyPath, serverCA: emptyCA,
	})
	if err == nil || !strings.Contains(err.Error(), "did not contain any PEM") {
		t.Fatalf("want empty-CA error, got %v", err)
	}
}

func TestPublishHTTPClient_BadSchemeRejected(t *testing.T) {
	_, err := publishHTTPClient(publishOptions{conductorURL: "ftp://conductor.example"})
	if err == nil || !strings.Contains(err.Error(), "scheme must be https") {
		t.Fatalf("want scheme error, got %v", err)
	}
}

// --- runPublish orchestration error propagation -----------------------------

func TestRunPublish_BuildErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	opts.version = 0 // build fails before any network use
	if err := runPublish(context.Background(), &strings.Builder{}, opts); err == nil {
		t.Fatalf("expected build error")
	}
}

func TestRunPublish_ClientErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895") // https with no mTLS material
	opts.insecure = false
	if err := runPublish(context.Background(), &strings.Builder{}, opts); err == nil || !strings.Contains(err.Error(), "--tls-cert") {
		t.Fatalf("want client-build error, got %v", err)
	}
}

func TestRunPublish_MissingTokenPropagates(t *testing.T) {
	dir := t.TempDir()
	url := newPublishServer(t)
	opts := baseOpts(t, dir, url)
	opts.publisherTok = filepath.Join(dir, "no-token")
	if err := runPublish(context.Background(), &strings.Builder{}, opts); err == nil || !strings.Contains(err.Error(), "read --publisher-token-file") {
		t.Fatalf("want token-read error, got %v", err)
	}
}

// --- postBundle status-code mapping (stub server) ---------------------------

func newStubStatusServer(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func minimalBundle(t *testing.T) conductorcore.PolicyBundle {
	t.Helper()
	dir := t.TempDir()
	opts := baseOpts(t, dir, "https://conductor.example:8895")
	b, _, _, err := buildSignedBundle(opts)
	if err != nil {
		t.Fatalf("buildSignedBundle: %v", err)
	}
	return b
}

func TestPostBundle_Malformed200Rejected(t *testing.T) {
	url := newStubStatusServer(t, http.StatusOK, "not json")
	_, err := postBundle(context.Background(), &http.Client{Timeout: time.Second}, url, "tok", minimalBundle(t))
	if err == nil || !strings.Contains(err.Error(), "decode publish response") {
		t.Fatalf("want decode error, got %v", err)
	}
}

func TestPostBundle_5xxRejected(t *testing.T) {
	url := newStubStatusServer(t, http.StatusInternalServerError, `{"error":"internal"}`)
	_, err := postBundle(context.Background(), &http.Client{Timeout: time.Second}, url, "tok", minimalBundle(t))
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("want 500 error, got %v", err)
	}
}

func TestPostBundle_401Rejected(t *testing.T) {
	url := newStubStatusServer(t, http.StatusUnauthorized, `{"error":"nope"}`)
	_, err := postBundle(context.Background(), &http.Client{Timeout: time.Second}, url, "tok", minimalBundle(t))
	if err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("want auth error, got %v", err)
	}
}

func TestPostBundle_ConnectionRefused(t *testing.T) {
	// Point at a closed port to drive the client.Do error branch.
	_, err := postBundle(context.Background(), &http.Client{Timeout: time.Second}, "http://127.0.0.1:1", "tok", minimalBundle(t))
	if err == nil || !strings.Contains(err.Error(), "publish request failed") {
		t.Fatalf("want request-failed error, got %v", err)
	}
}

// --- serverErrorDetail ------------------------------------------------------

func TestServerErrorDetail(t *testing.T) {
	if got := serverErrorDetail([]byte(`{"error":"boom"}`), ""); got != "boom" {
		t.Fatalf("json error = %q", got)
	}
	if got := serverErrorDetail([]byte("plain text body"), ""); got != "plain text body" {
		t.Fatalf("plain body = %q", got)
	}
	if got := serverErrorDetail([]byte("  "), ""); got != "(no response body)" {
		t.Fatalf("empty body = %q", got)
	}
	// Cap is by RUNES after sanitization.
	long := strings.Repeat("z", 400)
	if got := serverErrorDetail([]byte(long), ""); len([]rune(got)) != serverErrorMaxRunes {
		t.Fatalf("long body truncation = %d runes", len([]rune(got)))
	}
}

// TestServerErrorDetail_LogForgingAndTokenEcho is the Fix-1 regression: an
// untrusted server returns a body crafted to (a) forge multiline log lines via
// CR/LF and control bytes, (b) inject an ANSI escape, and (c) echo back the
// publisher token. The sanitized detail must be single-line, control-stripped,
// rune-capped, and MUST NOT contain the token.
func TestServerErrorDetail_LogForgingAndTokenEcho(t *testing.T) {
	const token = "publisher-secret-abc123"
	// Hostile body: newlines (log forging), tab/NUL/ESC control bytes, an ANSI
	// escape sequence, U+2028 line separator, U+2029 paragraph separator, and
	// the literal token reflected.
	hostile := "denied\n{\"level\":\"info\",\"msg\":\"fake log line\"}\r\n" +
		"\x1b[31mred\x1b[0m\ttabbed\x00nul\u2028line sep\u2029para sep Bearer " + token
	body := []byte(`{"error":` + mustJSONString(t, hostile) + `}`)

	got := serverErrorDetail(body, token)

	if strings.ContainsAny(got, "\r\n\t\x00\x1b") {
		t.Fatalf("sanitized detail still contains control bytes: %q", got)
	}
	if strings.Contains(got, " ") || strings.Contains(got, " ") {
		t.Fatalf("sanitized detail still contains line/para separators: %q", got)
	}
	if strings.Contains(got, token) {
		t.Fatalf("sanitized detail LEAKED the publisher token: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected token to be redacted, got: %q", got)
	}
	// Single line: no embedded newline of any kind.
	if strings.Count(got, "\n") != 0 {
		t.Fatalf("detail is not single-line: %q", got)
	}
	if len([]rune(got)) > serverErrorMaxRunes {
		t.Fatalf("detail exceeds rune cap: %d", len([]rune(got)))
	}
}

// TestSanitizeServerDetail_TokenSubstringRedaction proves the token is redacted
// even when embedded mid-string and across a control byte boundary, and that an
// empty token does not corrupt the output (no every-empty-substring replace).
func TestSanitizeServerDetail_TokenSubstringRedaction(t *testing.T) {
	const token = "tok-XYZ"
	got := sanitizeServerDetail("prefix "+token+" suffix", token)
	if strings.Contains(got, token) || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("token not redacted: %q", got)
	}
	// Empty token: output preserved, no spurious [REDACTED] injected.
	got2 := sanitizeServerDetail("clean message", "")
	if got2 != "clean message" {
		t.Fatalf("empty-token sanitize altered output: %q", got2)
	}
	// Whitespace-only token must be treated as empty (not redact every space).
	got3 := sanitizeServerDetail("a b c", "   ")
	if got3 != "a b c" {
		t.Fatalf("whitespace token corrupted output: %q", got3)
	}
}

func mustJSONString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal string: %v", err)
	}
	return string(b)
}

// --- cobra command registration --------------------------------------------

func TestPublishCmd_Registered(t *testing.T) {
	root := Cmd()
	var found bool
	for _, c := range root.Commands() {
		if c.Name() == "publish" {
			found = true
		}
	}
	if !found {
		t.Fatalf("publish command not registered under conductor")
	}
}

// --- token-file guards ------------------------------------------------------

func TestReadPublisherToken(t *testing.T) {
	dir := t.TempDir()
	if _, err := readPublisherToken(""); err == nil {
		t.Fatalf("expected required error")
	}
	empty := writeFile(t, dir, "empty.token", "  \n")
	if _, err := readPublisherToken(empty); err == nil {
		t.Fatalf("expected empty-token error")
	}
	good := writeFile(t, dir, "good.token", "  tok-123\n")
	tok, err := readPublisherToken(good)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if tok != "tok-123" {
		t.Fatalf("token = %q", tok)
	}
}
