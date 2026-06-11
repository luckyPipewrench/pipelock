//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	clisigning "github.com/luckyPipewrench/pipelock/internal/cli/signing"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	// emergencyHTTPTimeout bounds operator control-plane calls. These are
	// single-shot administrative requests, not long polls; a tight timeout
	// surfaces an unreachable Conductor quickly instead of hanging the
	// operator's terminal.
	emergencyHTTPTimeout = 30 * time.Second
	// maxEmergencyResponseBytes caps the response body the CLI will read from
	// the Conductor. The success bodies are small JSON acknowledgements; the
	// cap stops a hostile or misbehaving endpoint from streaming unbounded
	// data into the operator process.
	maxEmergencyResponseBytes = 64 * 1024
)

const (
	// signingKeyFileSchemaVersion is the schema version of the JSON keypair
	// file produced by `pipelock signing key generate`. It is duplicated here
	// (not imported) because the canonical reader lives unexported in
	// internal/cli/signing; the format is a stable wire contract.
	signingKeyFileSchemaVersion = 1
	// maxSigningKeyFileBytes mirrors the shared signing-key reader's 16 KiB cap
	// (internal/cli/signing keyFileMaxSize). The actual read is bounded there;
	// this value exists so the over-size regression test can construct a file
	// that exceeds the cap without importing the unexported constant.
	maxSigningKeyFileBytes = 16 * 1024
)

var (
	errControlKeyFlagRequired    = errors.New("at least one --signing-key is required")
	errControlKeyDuplicateKey    = errors.New("the same signing key was supplied twice")
	errSigningKeyFileSchema      = errors.New("unsupported signing key file schema_version")
	errSigningKeyPurposeMismatch = errors.New("signing key file purpose does not match this action")
)

// signingKeyFile is the JSON keypair file written by
// `pipelock signing key generate`. Only the fields this CLI consumes are
// declared; unknown fields are rejected by the strict decoder so a tampered or
// wrong-format file fails loudly instead of silently loading a zero key.
type signingKeyFile struct {
	SchemaVersion int    `json:"schema_version"`
	Purpose       string `json:"purpose"`
	KeyID         string `json:"key_id"`
	Public        string `json:"public"`
	Private       string `json:"private"`
	CreatedAt     string `json:"created_at"`
}

// emergencyTransport is the minimal HTTP surface the emergency commands need.
// It mirrors emergency.HTTPDoer so unit tests can inject an httptest.Server
// client (or a stub) without standing up mTLS, while production wires a real
// mutually-authenticated *http.Client built from operator flags.
type emergencyTransport interface {
	Do(*http.Request) (*http.Response, error)
}

// loadedSigningKey pairs a signer key id (read from the keypair file, not
// operator-supplied) with its decoded private key.
type loadedSigningKey struct {
	id   string
	priv ed25519.PrivateKey
}

// loadSigningKeyFile reads one JSON keypair file produced by
// `pipelock signing key generate` and returns its embedded key_id and private
// key. It enforces the security-relevant invariants the canonical
// internal/cli/signing reader does (which is unexported, so we re-implement the
// gate rather than import it): a 0600/0640-only file, strict JSON (unknown
// fields rejected), schema match, the embedded purpose EXACTLY equal to the
// action's required purpose, valid key sizes, and a private->public derivation
// match so a tampered keyfile cannot pass a private half that does not own the
// declared public key. Inline key material is never accepted: --signing-key is
// a file path only, so a private key never lands in shell history or the
// process table.
func loadSigningKeyFile(path string, requiredPurpose signing.KeyPurpose) (loadedSigningKey, error) {
	if strings.TrimSpace(path) == "" {
		return loadedSigningKey{}, errors.New("--signing-key path is empty")
	}
	clean := filepath.Clean(path)
	// Reuse the shared signing-key reader (exported by internal/cli/signing for
	// exactly this): it rejects symlinks, FIFOs/devices, group/world-permissive
	// modes (0o037 mask, same as our private-key invariant), and bounds the read
	// to 16 KiB. Keeping one reader means the keyfile trust boundary cannot drift
	// between the keygen CLI and the conductor emergency CLIs.
	raw, err := clisigning.ReadKeyFileBytes(clean, true)
	if err != nil {
		return loadedSigningKey{}, fmt.Errorf("read signing key %q: %w", clean, err)
	}
	defer zeroBytes(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var kf signingKeyFile
	if err := dec.Decode(&kf); err != nil {
		return loadedSigningKey{}, fmt.Errorf("decode signing key %q: %w", clean, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return loadedSigningKey{}, fmt.Errorf("decode signing key %q: trailing JSON", clean)
	}
	if kf.SchemaVersion != signingKeyFileSchemaVersion {
		return loadedSigningKey{}, fmt.Errorf("%w: %d (want %d) in %q", errSigningKeyFileSchema, kf.SchemaVersion, signingKeyFileSchemaVersion, clean)
	}
	if signing.KeyPurpose(kf.Purpose) != requiredPurpose {
		return loadedSigningKey{}, fmt.Errorf("%w: file=%q required=%q in %q", errSigningKeyPurposeMismatch, kf.Purpose, requiredPurpose, clean)
	}
	if err := conductorcore.ValidateIdentifier("key_id", kf.KeyID); err != nil {
		return loadedSigningKey{}, fmt.Errorf("signing key %q: %w", clean, err)
	}
	pubBytes, err := hex.DecodeString(kf.Public)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return loadedSigningKey{}, fmt.Errorf("signing key %q has a malformed public key", clean)
	}
	privBytes, err := hex.DecodeString(kf.Private)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		return loadedSigningKey{}, fmt.Errorf("signing key %q has a malformed private key", clean)
	}
	priv := ed25519.PrivateKey(privBytes)
	derived, ok := priv.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derived, pubBytes) {
		zeroBytes(privBytes)
		return loadedSigningKey{}, fmt.Errorf("signing key %q: private key does not match its declared public key", clean)
	}
	return loadedSigningKey{id: kf.KeyID, priv: priv}, nil
}

// loadSigningKeys loads each operator signing keyfile, binds them to the
// action's required purpose, and enforces the M-of-N minimum at the CLI
// boundary so the operator gets a clear error before any network call. It
// rejects duplicate key_ids (two files declaring the same id) so they cannot be
// mistaken for two distinct signers — the server enforces the same distinct-key
// rule, but failing fast here gives a clearer message.
func loadSigningKeys(files []string, minSigners int, purpose signing.KeyPurpose) ([]loadedSigningKey, error) {
	if len(files) == 0 {
		return nil, errControlKeyFlagRequired
	}
	keys := make([]loadedSigningKey, 0, len(files))
	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		key, err := loadSigningKeyFile(file, purpose)
		if err != nil {
			zeroLoadedSigningKeys(keys)
			return nil, err
		}
		if _, dup := seen[key.id]; dup {
			zeroBytes(key.priv)
			zeroLoadedSigningKeys(keys)
			return nil, fmt.Errorf("%w: key_id %q", errControlKeyDuplicateKey, key.id)
		}
		seen[key.id] = struct{}{}
		keys = append(keys, key)
	}
	if minSigners > 0 && len(keys) < minSigners {
		zeroLoadedSigningKeys(keys)
		return nil, fmt.Errorf("%w: this action requires %d distinct signers, got %d",
			conductorcore.ErrThresholdRequired, minSigners, len(keys))
	}
	return keys, nil
}

func zeroLoadedSigningKeys(keys []loadedSigningKey) {
	for _, key := range keys {
		zeroBytes(key.priv)
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// signEmergencyPreimage attaches one ed25519 SignatureProof per loaded key for
// the given purpose. The preimage is produced once (from the unsigned message)
// and every signer signs that identical canonical preimage, matching the
// server-side threshold verifier which re-derives the same preimage and checks
// each proof against it.
func signEmergencyPreimage(preimage func() ([]byte, error), purpose signing.KeyPurpose, keys []loadedSigningKey) ([]conductorcore.SignatureProof, error) {
	data, err := preimage()
	if err != nil {
		return nil, err
	}
	proofs := make([]conductorcore.SignatureProof, 0, len(keys))
	for _, key := range keys {
		if len(key.priv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: signing key %q has wrong length", conductorcore.ErrInvalidSignature, key.id)
		}
		proofs = append(proofs, conductorcore.SignatureProof{
			SignerKeyID: key.id,
			KeyPurpose:  purpose,
			Algorithm:   conductorcore.SignatureAlgorithmEd25519,
			Signature:   conductorcore.SignaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(key.priv, data)),
		})
	}
	return proofs, nil
}

// emergencyClientOptions carries the transport material an operator supplies to
// reach the Conductor control plane. The Conductor requires mutually
// authenticated TLS, so the operator presents a client certificate and trusts
// the Conductor's CA. A bearer admin token authorizes the privileged endpoints.
type emergencyClientOptions struct {
	baseURL    string
	tlsCert    string
	tlsKey     string
	serverCA   string
	serverName string
}

// buildEmergencyClient constructs a mutually-authenticated HTTPS client from the
// operator's certificate material. It fails closed: every TLS input is required
// because the Conductor refuses plain-HTTP and unauthenticated clients, so a
// missing flag is an operator error surfaced before any request, not a silent
// downgrade to an insecure transport.
func buildEmergencyClient(opts emergencyClientOptions) (*http.Client, error) {
	switch {
	case strings.TrimSpace(opts.tlsCert) == "":
		return nil, errors.New("--tls-cert is required")
	case strings.TrimSpace(opts.tlsKey) == "":
		return nil, errors.New("--tls-key is required")
	case strings.TrimSpace(opts.serverCA) == "":
		return nil, errors.New("--server-ca is required")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Clean(opts.tlsCert), filepath.Clean(opts.tlsKey))
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Clean(opts.serverCA))
	if err != nil {
		return nil, fmt.Errorf("read server CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("server CA bundle contains no PEM certificates")
	}
	return &http.Client{
		Timeout: emergencyHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
				ServerName:   strings.TrimSpace(opts.serverName),
			},
		},
	}, nil
}

// loadBearerToken reads and trims the admin bearer token from a file. Like the
// server-side loadTokenFile, it requires a non-empty value: an empty admin
// token would otherwise be sent as `Authorization: Bearer ` and rejected with
// an opaque 403, so the CLI catches it up front. The "--admin-token-file" flag
// name is inlined (not a named const): a credential-keyword const value trips
// gosec G101, and the repo's goconst threshold (30) makes a few repeats fine.
func loadBearerToken(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%s is required", "--admin-token-file")
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", "--admin-token-file", err)
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", fmt.Errorf("%s is empty", "--admin-token-file")
	}
	return tok, nil
}

// postEmergencyJSON sends a signed control-plane request and decodes the JSON
// acknowledgement. A non-2xx response is turned into an error carrying a bounded
// snippet of the server's body so the operator sees WHY the Conductor rejected
// the request (under-threshold, expired window, wrong purpose) instead of a bare
// status code. The body read is capped to maxEmergencyResponseBytes.
func postEmergencyJSON(ctx context.Context, client emergencyTransport, baseURL, path, bearer string, reqBody, out any) error {
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("conductor request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEmergencyResponseBytes))
	if err != nil {
		return fmt.Errorf("read conductor response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("conductor rejected request: status=%d body=%s", resp.StatusCode, emergencySnippet(body, bearer))
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decode conductor response: %w", err)
		}
	}
	return nil
}

func emergencySnippet(b []byte, secrets ...string) string {
	s := strings.TrimSpace(string(b))
	for _, cred := range secrets {
		cred = strings.TrimSpace(cred)
		if cred != "" {
			s = strings.ReplaceAll(s, cred, "[redacted]")
		}
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	const maxLen = 512
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return s
}

// buildAudience constructs and validates a conductor.Audience from the
// operator's --instance / --label flags. The two are mutually exclusive (the
// signed-message validator rejects mixing them); building + validating here
// gives the operator a clear error before any signing or network call. At least
// one selector is required: an empty audience would target no follower and the
// validator rejects it.
func buildAudience(instanceIDs []string, labels map[string]string) (conductorcore.Audience, error) {
	trimmed := make([]string, 0, len(instanceIDs))
	for _, id := range instanceIDs {
		if s := strings.TrimSpace(id); s != "" {
			trimmed = append(trimmed, s)
		}
	}
	if len(trimmed) > 0 && len(labels) > 0 {
		return conductorcore.Audience{}, errors.New("--instance and --label are mutually exclusive")
	}
	if len(trimmed) == 0 && len(labels) == 0 {
		return conductorcore.Audience{}, errors.New("at least one --instance or --label selector is required")
	}
	audience := conductorcore.Audience{}
	if len(trimmed) > 0 {
		audience.InstanceIDs = trimmed
	} else {
		audience.Labels = labels
	}
	if err := audience.Validate(); err != nil {
		return conductorcore.Audience{}, fmt.Errorf("invalid audience: %w", err)
	}
	return audience, nil
}

// resolveEmergencyTransport returns the injected test transport when present,
// otherwise builds the production mTLS client from the supplied options. Keeping
// this in one place means kill/resume/rollback/enrollment all share the exact
// same client-construction and test-injection seam.
func resolveEmergencyTransport(injected emergencyTransport, opts emergencyClientOptions) (emergencyTransport, error) {
	if injected != nil {
		return injected, nil
	}
	return buildEmergencyClient(opts)
}
