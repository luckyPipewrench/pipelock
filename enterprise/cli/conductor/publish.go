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
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	clisigning "github.com/luckyPipewrench/pipelock/internal/cli/signing"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	publishHTTPTimeout = 30 * time.Second
	// defaultPublishValidity bounds a published bundle's applicability window.
	// A signed bundle that never expires is a standing liability if the signing
	// key later leaks; an operator should re-publish on a cadence shorter than
	// this default.
	defaultPublishValidity = 90 * 24 * time.Hour
	// publishMaxResponseBytes caps the response body we will read from the
	// Conductor. The publish responses are tiny JSON objects; this stops a
	// hostile or wedged endpoint from streaming an unbounded body into memory.
	publishMaxResponseBytes = 64 * 1024
	// keyFileSchemaVersion mirrors the on-disk key file schema written by
	// "pipelock signing key generate" (internal/cli/signing). Kept in sync so
	// the publisher rejects a stale or future key file rather than mis-parsing
	// it. The secret-permission, regular-file, symlink, and size gates are
	// shared via clisigning.ReadKeyFileBytes, so no duplicate consts for those.
	keyFileSchemaVersion = 1
)

// A publish can be rejected by the Conductor with HTTP 409 Conflict for several
// operationally distinct reasons. The control plane reports which one in the
// "code" field of the JSON error body (see controlplane.PublishConflict*); the
// CLI maps each to a distinct sentinel below so an operator gets an accurate,
// actionable message instead of one collapsed "version is stale". Every sentinel
// is errors.Is-testable. Conflating them once cost a real operator a failed
// publish during a live recovery (the head was rolled back to vN while vN+1..vM
// still existed, so the forward publish needed a version above the stream MAX,
// not merely above the head — but the message only said "stale").
var (
	// ErrPolicyVersionBelowStreamMax: the supplied --version is not strictly
	// greater than the stream's HIGHEST-ever published version. After a rollback
	// the head sits at vN while vN+1..vM already exist, so a forward publish must
	// use a version greater than M, not merely greater than the current head N.
	// Query the stream's head/max version through the operator's Conductor status
	// surface and re-publish with --version greater than the max.
	ErrPolicyVersionBelowStreamMax = errors.New("policy bundle version must exceed the stream's highest published version (after a rollback, newer versions still exist above the current head; publish a version above the stream max, not just above the head)")

	// ErrPolicyRollbackViaPublish: the supplied --version is below the current
	// (rolled-back) stream head. A forward publish cannot perform a rollback; use
	// the rollback authorization flow (`pipelock conductor rollback`) instead.
	ErrPolicyRollbackViaPublish = errors.New("policy bundle version is below the current (rolled-back) stream head; a publish cannot roll back — use the rollback authorization flow instead")

	// ErrPolicyPreviousHashMismatch: --previous-bundle-hash does not match the
	// current stream head hash. The version is fine; the chain pointer is wrong
	// (typically a stale or copy-pasted hash). Use the hash printed by the most
	// recent successful publish for this stream (also reported by the stream
	// head/status query) as --previous-bundle-hash.
	ErrPolicyPreviousHashMismatch = errors.New("policy bundle --previous-bundle-hash does not match the current stream head hash; use the hash printed by the most recent successful publish for this stream")

	// ErrPolicyPublishConflict: a 409 Conflict that is none of the more specific
	// cases above (e.g. a bundle_id/version already published with a different
	// hash, or a first-in-stream bundle that carries a --previous-bundle-hash).
	ErrPolicyPublishConflict = errors.New("policy bundle conflicts with the active stream")
)

// publishOptions collects every operator-supplied input for `conductor publish`.
// Grouped into a struct (rather than a long parameter list) per the project
// convention for functions with many inputs.
type publishOptions struct {
	conductorURL string
	configFile   string
	ruleBundles  []string
	orgID        string
	fleetID      string
	environment  string
	bundleID     string
	audience     []string
	version      uint64
	previousHash string
	validity     time.Duration
	minVersion   string
	signingKey   string
	publisherTok string
	tlsCert      string
	tlsKey       string
	serverCA     string
	licenseCRL   string
	insecure     bool // accept absent mTLS material ONLY against an http:// URL (loopback dev)
}

// publishKeyFile is the on-disk JSON shape produced by
// "pipelock signing key generate". It is duplicated here (rather than imported)
// because the loader in internal/cli/signing is unexported; keeping an
// independent, equally strict parser means the publisher cannot be loosened by a
// change to the keygen package and vice versa.
type publishKeyFile struct {
	SchemaVersion int    `json:"schema_version"`
	Purpose       string `json:"purpose"`
	KeyID         string `json:"key_id"`
	Public        string `json:"public"`
	Private       string `json:"private"`
	CreatedAt     string `json:"created_at"`
}

func publishCmd() *cobra.Command {
	opts := publishOptions{
		validity: defaultPublishValidity,
	}
	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Build, sign, and publish a Conductor policy bundle",
		Long: `Publish builds a policy bundle from a pipelock config (and optional
rule-bundle references), signs it with a policy-bundle-signing key, and POSTs it
to a running Conductor's policy-bundle endpoint over mutual TLS using a publisher
bearer token. Followers then pull and apply it on their next poll.

The --version must be strictly greater than the stream's highest published
version. After a rollback the stream head sits below the highest version that was
ever published, so a forward publish must use a version above the stream MAX, not
merely above the current head. The Conductor distinguishes a rollback attempt, a
below-stream-max version, and a previous_bundle_hash mismatch, and this command
reports each as a distinct, actionable error (query the stream head/max version
through your Conductor status workflow).

The signing key is a file produced by:
  pipelock signing key generate --purpose policy-bundle-signing --out <abs>

Example:
  pipelock conductor publish \
    --conductor-url https://conductor.example:8895 \
    --config policy.yaml \
    --org acme --fleet prod --env prod \
    --audience '*' \
    --version 7 \
    --signing-key /etc/pipelock/keys/policy-signing.json \
    --publisher-token-file /etc/pipelock/publisher.token \
    --tls-cert client.crt --tls-key client.key --server-ca ca.pem`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// License gate: publishing fleet policy is an Enterprise fleet
			// operation. Fail closed before reading any key material or opening
			// a connection, mirroring serveCmd / bootstrapCmd.
			if _, err := license.VerifyFleet("", "", opts.licenseCRL); err != nil {
				return err
			}
			return runPublish(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.conductorURL, "conductor-url", "", "base URL of the Conductor control plane (e.g. https://conductor.example:8895)")
	cmd.Flags().StringVar(&opts.configFile, "config", "", "path to the pipelock config YAML to publish as the bundle policy")
	cmd.Flags().StringArrayVar(&opts.ruleBundles, "rule-bundle", nil, "rule bundle reference as comma-separated kv pairs: 'name=NAME,version=VER,sha256=HEX'; repeatable")
	cmd.Flags().StringVar(&opts.orgID, "org", "", "org id the bundle targets")
	cmd.Flags().StringVar(&opts.fleetID, "fleet", "", "fleet id the bundle targets")
	cmd.Flags().StringVar(&opts.environment, "env", "", "environment the bundle targets")
	cmd.Flags().StringVar(&opts.bundleID, "bundle-id", "", "bundle id (default: <fleet>-<env>-v<version>)")
	cmd.Flags().StringArrayVar(&opts.audience, "audience", nil, "audience selector: '*' for the whole fleet, an instance id, or 'label:KEY=VALUE'; repeatable. Instance ids and labels cannot be mixed")
	cmd.Flags().Uint64Var(&opts.version, "version", 0, "monotonic bundle version; must exceed the stream's highest published version (after a rollback, newer versions can exist above the current head, so this must beat the stream max, not just the head)")
	cmd.Flags().StringVar(&opts.previousHash, "previous-bundle-hash", "", "hash of the currently published bundle for this stream (printed by the prior publish); use 'auto' to fetch the current stream head hash from the Conductor; omit only for the first bundle in a stream")
	cmd.Flags().DurationVar(&opts.validity, "validity", opts.validity, "validity window for the bundle starting now (not_before=now, expires_at=now+validity)")
	cmd.Flags().StringVar(&opts.minVersion, "min-pipelock-version", "", "minimum pipelock version a follower must run to apply this bundle (major.minor.patch)")
	cmd.Flags().StringVar(&opts.signingKey, "signing-key", "", "path to a policy-bundle-signing key file from 'pipelock signing key generate'")
	cmd.Flags().StringVar(&opts.publisherTok, "publisher-token-file", "", "file containing the publisher bearer token")
	cmd.Flags().StringVar(&opts.tlsCert, "tls-cert", "", "mTLS client certificate file")
	cmd.Flags().StringVar(&opts.tlsKey, "tls-key", "", "mTLS client private key file")
	cmd.Flags().StringVar(&opts.serverCA, "server-ca", "", "PEM bundle of CAs that may validate the Conductor server certificate")
	cmd.Flags().StringVar(&opts.licenseCRL, "license-crl-file", "", "signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
	cmd.Flags().BoolVar(&opts.insecure, "allow-plaintext-loopback", false, "permit publishing without mTLS material against an http:// loopback URL (dev only)")
	return cmd
}

// previousHashAuto is the sentinel value for --previous-bundle-hash that
// triggers automatic resolution of the current stream head hash via the
// Conductor's stream-status endpoint.
const previousHashAuto = "auto"

func runPublish(ctx context.Context, out io.Writer, opts publishOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// Resolve "auto" previous-bundle-hash before building the bundle. This
	// requires a round trip to the Conductor to fetch the current stream head.
	if strings.EqualFold(strings.TrimSpace(opts.previousHash), previousHashAuto) {
		resolved, err := resolveAutoHash(ctx, opts)
		if err != nil {
			return fmt.Errorf("resolve --previous-bundle-hash auto: %w", err)
		}
		opts.previousHash = resolved
		_, _ = fmt.Fprintf(out, "resolved --previous-bundle-hash auto to %s\n", resolved)
	}
	bundle, keyID, priv, err := buildSignedBundle(opts)
	if err != nil {
		return err
	}
	// buildSignedBundle hands the private key to us; we now own zeroization on
	// every path out of this function, including the error returns below.
	defer zeroizeKey(priv)
	client, err := publishHTTPClient(opts)
	if err != nil {
		return err
	}
	token, err := readPublisherToken(opts.publisherTok)
	if err != nil {
		return err
	}
	resp, err := postBundle(ctx, client, opts.conductorURL, token, bundle)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "published policy bundle %s version %d (hash %s, created=%t) signed by %s\n",
		resp.BundleID, resp.Version, resp.BundleHash, resp.Created, keyID)
	return nil
}

// zeroizeKey overwrites an Ed25519 private key in place. Best-effort: Go's GC
// may retain copies, but clearing the slice we hold removes the obvious one and
// shrinks the window the secret sits in memory.
func zeroizeKey(priv ed25519.PrivateKey) {
	for i := range priv {
		priv[i] = 0
	}
}

// buildSignedBundle assembles, validates the inputs for, signs, and locally
// validates the policy bundle. It returns the signed bundle plus the signer key
// id and private key so the caller can report and zeroize them.
//
// Ordering is deliberate: EVERY non-key input is validated BEFORE the signing
// key is read off disk, so a malformed flag (bad --previous-bundle-hash, bad
// audience, etc.) fails without ever decoding the private key. Once the key IS
// loaded, a deferred conditional wipe guarantees every subsequent error path
// zeroizes it; only the successful hand-off to the caller suppresses the wipe
// (the caller then owns zeroization).
func buildSignedBundle(opts publishOptions) (conductorcore.PolicyBundle, string, ed25519.PrivateKey, error) {
	if opts.version == 0 {
		return conductorcore.PolicyBundle{}, "", nil, errors.New("--version is required and must be greater than 0")
	}
	if opts.validity <= 0 {
		return conductorcore.PolicyBundle{}, "", nil, errors.New("--validity must be positive")
	}
	if strings.TrimSpace(opts.signingKey) == "" {
		return conductorcore.PolicyBundle{}, "", nil, errors.New("--signing-key is required")
	}
	configYAML, err := readConfigPayload(opts.configFile)
	if err != nil {
		return conductorcore.PolicyBundle{}, "", nil, err
	}
	audience, err := parseAudience(opts.audience)
	if err != nil {
		return conductorcore.PolicyBundle{}, "", nil, err
	}
	ruleBundles, err := parseRuleBundleRefs(opts.ruleBundles)
	if err != nil {
		return conductorcore.PolicyBundle{}, "", nil, err
	}
	minVersion := strings.TrimSpace(opts.minVersion)
	if minVersion == "" {
		minVersion = "0.0.0"
	}
	bundleID := strings.TrimSpace(opts.bundleID)
	if bundleID == "" {
		bundleID = fmt.Sprintf("%s-%s-v%d", opts.fleetID, opts.environment, opts.version)
	}
	previousHash := strings.TrimSpace(opts.previousHash)
	if previousHash != "" {
		if _, err := hex.DecodeString(previousHash); err != nil || len(previousHash) != 64 {
			return conductorcore.PolicyBundle{}, "", nil, errors.New("--previous-bundle-hash must be a 64-character hex sha256 (use the hash printed by the prior publish)")
		}
	}

	payload := conductorcore.PolicyBundlePayload{
		ConfigYAML:  configYAML,
		RuleBundles: ruleBundles,
	}
	payloadHash, err := payload.PayloadHash()
	if err != nil {
		return conductorcore.PolicyBundle{}, "", nil, fmt.Errorf("compute payload hash: %w", err)
	}
	policyHash, err := payload.PolicyHash()
	if err != nil {
		return conductorcore.PolicyBundle{}, "", nil, fmt.Errorf("compute policy hash: %w", err)
	}

	// Key read happens LAST among the inputs, so all the validation above
	// short-circuits without ever touching key material. From here on, the
	// deferred wipe fires on every error path; handedOff cancels it only when we
	// successfully return the key to the caller.
	keyID, priv, err := loadPolicySigningKey(opts.signingKey)
	if err != nil {
		return conductorcore.PolicyBundle{}, "", nil, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			zeroizeKey(priv)
		}
	}()

	now := time.Now().UTC()
	bundle := conductorcore.PolicyBundle{
		SchemaVersion:      conductorcore.SchemaVersion,
		BundleID:           bundleID,
		OrgID:              opts.orgID,
		FleetID:            opts.fleetID,
		Environment:        opts.environment,
		Audience:           audience,
		Version:            opts.version,
		PreviousBundleHash: previousHash,
		CreatedAt:          now,
		NotBefore:          now,
		ExpiresAt:          now.Add(opts.validity),
		MinPipelockVersion: minVersion,
		PolicyHash:         policyHash,
		PayloadSHA256:      payloadHash,
		Payload:            payload,
	}

	preimage, err := bundle.SignablePreimage()
	if err != nil {
		return conductorcore.PolicyBundle{}, "", nil, fmt.Errorf("compute signable preimage: %w", err)
	}
	signature := ed25519.Sign(priv, preimage)
	bundle.Signatures = []conductorcore.SignatureProof{{
		SignerKeyID: keyID,
		KeyPurpose:  signing.PurposePolicyBundleSigning,
		Algorithm:   conductorcore.SignatureAlgorithmEd25519,
		Signature:   conductorcore.SignaturePrefixEd25519 + hex.EncodeToString(signature),
	}}

	// Validate locally so the operator gets the exact field error here instead
	// of a generic 4xx from the Conductor. Validate also re-derives and checks
	// both hashes against the payload, so a hash/payload mismatch is caught
	// before any network call.
	if err := bundle.Validate(); err != nil {
		return conductorcore.PolicyBundle{}, "", nil, fmt.Errorf("policy bundle failed local validation: %w", err)
	}
	handedOff = true
	return bundle, keyID, priv, nil
}

// readConfigPayload reads the config YAML the bundle carries. The empty/blank
// guard mirrors PolicyBundle.Validate so the operator gets a clear message
// before signing rather than an opaque validation failure afterward.
func readConfigPayload(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("--config is required")
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read --config: %w", err)
	}
	if len(data) > conductorcore.MaxConfigYAMLBytes {
		return "", fmt.Errorf("--config payload (%d bytes) exceeds cap %d", len(data), conductorcore.MaxConfigYAMLBytes)
	}
	if strings.TrimSpace(string(data)) == "" {
		return "", errors.New("--config is empty")
	}
	return string(data), nil
}

// parseAudience converts the repeatable --audience selectors into the wire
// Audience. A single "*" means the whole fleet. "label:KEY=VALUE" entries build
// the label map; bare entries are instance ids. Instance ids and labels cannot
// be combined (PolicyBundle.Validate enforces this too, but rejecting here gives
// a precise message).
func parseAudience(values []string) (conductorcore.Audience, error) {
	if len(values) == 0 {
		return conductorcore.Audience{}, errors.New("--audience is required (use '*' for the whole fleet, an instance id, or 'label:KEY=VALUE')")
	}
	var (
		instanceIDs []string
		labels      = map[string]string{}
	)
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			return conductorcore.Audience{}, errors.New("--audience entry is empty")
		}
		if rest, ok := strings.CutPrefix(v, "label:"); ok {
			k, val, found := strings.Cut(rest, "=")
			k = strings.TrimSpace(k)
			val = strings.TrimSpace(val)
			if !found || k == "" || val == "" {
				return conductorcore.Audience{}, fmt.Errorf("invalid --audience label %q: expected 'label:KEY=VALUE'", raw)
			}
			if _, dup := labels[k]; dup {
				return conductorcore.Audience{}, fmt.Errorf("invalid --audience: duplicate label key %q", k)
			}
			labels[k] = val
			continue
		}
		instanceIDs = append(instanceIDs, v)
	}
	if len(instanceIDs) > 0 && len(labels) > 0 {
		return conductorcore.Audience{}, errors.New("--audience cannot mix instance ids with labels")
	}
	aud := conductorcore.Audience{}
	if len(instanceIDs) > 0 {
		aud.InstanceIDs = instanceIDs
	}
	if len(labels) > 0 {
		aud.Labels = labels
	}
	// Validate now so wildcard/selector mixing and identifier shape are caught
	// before signing.
	if err := aud.Validate(); err != nil {
		return conductorcore.Audience{}, fmt.Errorf("invalid --audience: %w", err)
	}
	return aud, nil
}

// parseRuleBundleRefs parses repeatable --rule-bundle 'name=,version=,sha256='
// specs into RuleBundleRef entries.
func parseRuleBundleRefs(values []string) ([]conductorcore.RuleBundleRef, error) {
	if len(values) == 0 {
		return nil, nil
	}
	refs := make([]conductorcore.RuleBundleRef, 0, len(values))
	for _, raw := range values {
		ref := conductorcore.RuleBundleRef{}
		seen := map[string]struct{}{}
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			k, val, ok := strings.Cut(part, "=")
			k = strings.TrimSpace(k)
			val = strings.TrimSpace(val)
			if !ok || k == "" {
				return nil, fmt.Errorf("invalid --rule-bundle %q: expected k=v pairs", raw)
			}
			if _, dup := seen[k]; dup {
				return nil, fmt.Errorf("invalid --rule-bundle %q: duplicate key %q", raw, k)
			}
			seen[k] = struct{}{}
			switch k {
			case "name":
				ref.Name = val
			case "version":
				ref.Version = val
			case "sha256":
				ref.SHA256 = val
			default:
				return nil, fmt.Errorf("invalid --rule-bundle %q: unknown field %q", raw, k)
			}
		}
		if err := ref.Validate(); err != nil {
			return nil, fmt.Errorf("invalid --rule-bundle %q: %w", raw, err)
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// loadPolicySigningKey reads a key file produced by
// "pipelock signing key generate" and returns its key id and private key after
// confirming it is bound to the policy-bundle-signing purpose. A key with any
// other purpose is rejected so an operator cannot accidentally sign a policy
// bundle with, e.g., a remote-kill key (the Conductor verifier would reject it,
// but failing here is clearer and avoids a wasted round trip).
func loadPolicySigningKey(path string) (string, ed25519.PrivateKey, error) {
	cleanPath := filepath.Clean(path)
	// Reuse the signing package's hardened key-file reader (symlink reject +
	// regular-file + secret-perm + 16 KiB size cap) rather than duplicating the
	// open/stat/perm/size dance and re-introducing a gosec G304 suppression here.
	raw, err := clisigning.ReadKeyFileBytes(cleanPath, true)
	if err != nil {
		return "", nil, fmt.Errorf("read --signing-key %q: %w", cleanPath, err)
	}
	var kf publishKeyFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&kf); err != nil {
		return "", nil, fmt.Errorf("decode --signing-key %q: %w", cleanPath, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", nil, fmt.Errorf("decode --signing-key %q: trailing JSON after key object", cleanPath)
	}
	if kf.SchemaVersion != keyFileSchemaVersion {
		return "", nil, fmt.Errorf("--signing-key %q: unsupported schema_version %d (expected %d)", cleanPath, kf.SchemaVersion, keyFileSchemaVersion)
	}
	purpose := signing.KeyPurpose(kf.Purpose)
	if err := purpose.Validate(); err != nil {
		return "", nil, fmt.Errorf("--signing-key %q: %w", cleanPath, err)
	}
	if purpose != signing.PurposePolicyBundleSigning {
		return "", nil, fmt.Errorf("--signing-key %q: wrong key purpose %q, want %q", cleanPath, kf.Purpose, signing.PurposePolicyBundleSigning)
	}
	if strings.TrimSpace(kf.KeyID) == "" {
		return "", nil, fmt.Errorf("--signing-key %q: missing key_id", cleanPath)
	}
	pubBytes, err := hex.DecodeString(kf.Public)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("--signing-key %q: malformed public key", cleanPath)
	}
	privBytes, err := hex.DecodeString(kf.Private)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		return "", nil, fmt.Errorf("--signing-key %q: malformed private key", cleanPath)
	}
	priv := ed25519.PrivateKey(privBytes)
	derived, ok := priv.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derived, pubBytes) {
		return "", nil, fmt.Errorf("--signing-key %q: private key does not match its public key", cleanPath)
	}
	return kf.KeyID, priv, nil
}

// readPublisherToken loads the publisher bearer token from a file, trimming
// surrounding whitespace, and rejects an empty token. Mirrors loadTokenFile in
// cmd.go (the server side) so producer and server agree on token-file handling.
func readPublisherToken(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("--publisher-token-file is required")
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read --publisher-token-file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("--publisher-token-file is empty")
	}
	return token, nil
}

// publishHTTPClient builds the mTLS HTTP client used to reach the Conductor.
// mTLS material is mandatory against an https:// URL; the only way to omit it is
// --allow-plaintext-loopback against an http:// loopback URL, which exists for
// the in-process dev fleet and is rejected for any non-loopback host.
func publishHTTPClient(opts publishOptions) (*http.Client, error) {
	u, err := url.Parse(strings.TrimSpace(opts.conductorURL))
	if err != nil {
		return nil, fmt.Errorf("parse --conductor-url: %w", err)
	}
	if u.Host == "" {
		return nil, errors.New("--conductor-url is required and must include a host")
	}
	switch u.Scheme {
	case "https":
		// mTLS path.
	case "http":
		if !opts.insecure {
			return nil, errors.New("--conductor-url uses http://; pass --allow-plaintext-loopback to permit it (loopback dev only)")
		}
		if !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("--allow-plaintext-loopback only permits a loopback host, got %q", u.Hostname())
		}
		return &http.Client{Timeout: publishHTTPTimeout}, nil
	default:
		return nil, fmt.Errorf("--conductor-url scheme must be https (or http for loopback), got %q", u.Scheme)
	}

	if strings.TrimSpace(opts.tlsCert) == "" || strings.TrimSpace(opts.tlsKey) == "" {
		return nil, errors.New("--tls-cert and --tls-key are required for an https Conductor URL")
	}
	if strings.TrimSpace(opts.serverCA) == "" {
		return nil, errors.New("--server-ca is required for an https Conductor URL")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Clean(opts.tlsCert), filepath.Clean(opts.tlsKey))
	if err != nil {
		return nil, fmt.Errorf("load mTLS client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Clean(opts.serverCA))
	if err != nil {
		return nil, fmt.Errorf("read --server-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("--server-ca did not contain any PEM-encoded certificates")
	}
	return &http.Client{
		Timeout: publishHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
				ServerName:   u.Hostname(),
			},
		},
	}, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// postBundle marshals the bundle into the publish request envelope and POSTs it.
// It translates the Conductor's status codes into clear operator errors. A 409
// Conflict is de-conflated via conflictSentinel into one of the distinct publish
// conflict sentinels (rollback attempt, version-below-stream-max, or
// previous-hash mismatch) so the operator gets an accurate, actionable message.
func postBundle(ctx context.Context, client *http.Client, baseURL, token string, bundle conductorcore.PolicyBundle) (publishResult, error) {
	envelope := struct {
		Bundle conductorcore.PolicyBundle `json:"bundle"`
	}{Bundle: bundle}
	body, err := json.Marshal(envelope)
	if err != nil {
		return publishResult{}, fmt.Errorf("marshal publish request: %w", err)
	}
	endpoint := strings.TrimRight(baseURL, "/") + controlplane.PublishPolicyBundlePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return publishResult{}, fmt.Errorf("build publish request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return publishResult{}, fmt.Errorf("publish request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, publishMaxResponseBytes))

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		var result publishResult
		if err := json.Unmarshal(respBody, &result); err != nil {
			return publishResult{}, fmt.Errorf("decode publish response: %w", err)
		}
		return result, nil
	case http.StatusConflict:
		return publishResult{}, fmt.Errorf("%w: %s", conflictSentinel(respBody), serverErrorDetail(respBody, token))
	case http.StatusForbidden, http.StatusUnauthorized:
		return publishResult{}, fmt.Errorf("publisher not authorized (HTTP %d): %s", resp.StatusCode, serverErrorDetail(respBody, token))
	default:
		return publishResult{}, fmt.Errorf("conductor rejected publish (HTTP %d): %s", resp.StatusCode, serverErrorDetail(respBody, token))
	}
}

type publishResult struct {
	BundleID    string    `json:"bundle_id"`
	BundleHash  string    `json:"bundle_hash"`
	Version     uint64    `json:"version"`
	PublishedAt time.Time `json:"published_at"`
	Created     bool      `json:"created"`
}

// conflictSentinel selects the distinct CLI sentinel for an HTTP 409 publish
// rejection by reading the machine-readable "code" field the control plane
// attaches to the JSON error body (controlplane.PublishConflict*). This is the
// de-conflation: the three operationally distinct conflicts map to three
// distinct, errors.Is-testable sentinels rather than one "version is stale".
//
// An older control plane that does not emit a code (or a malformed body) yields
// the generic ErrPolicyPublishConflict, so the CLI still reports a correct
// (if less specific) conflict rather than mis-attributing the cause.
func conflictSentinel(body []byte) error {
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ErrPolicyPublishConflict
	}
	switch payload.Code {
	case controlplane.PublishConflictRollbackAttempt:
		return ErrPolicyRollbackViaPublish
	case controlplane.PublishConflictVersionBelowStreamMax:
		return ErrPolicyVersionBelowStreamMax
	case controlplane.PublishConflictPreviousHashMismatch:
		return ErrPolicyPreviousHashMismatch
	default:
		return ErrPolicyPublishConflict
	}
}

// serverErrorMaxRunes bounds the sanitized server-error detail we surface in an
// operator-facing error string. Applied AFTER control-byte sanitization so the
// cap counts visible runes, not raw bytes a hostile server could pad with.
const serverErrorMaxRunes = 256

// serverErrorDetail extracts the Conductor's JSON {"error":"..."} message when
// present, falling back to the raw body. The server is UNTRUSTED: a malicious or
// compromised Conductor can return a body crafted to forge multiline terminal
// log lines or echo back the publisher bearer token. So before this value ever
// reaches an error string (which lands in operator logs/terminals), we:
//  1. redact the exact publisher token if the server reflected it,
//  2. collapse every control byte (CR/LF/tab/NUL/escape/...) to a single space
//     so the output is one line and cannot inject log records or ANSI escapes,
//  3. cap by RUNES after sanitization so a padded body cannot blow up the line.
func serverErrorDetail(body []byte, token string) string {
	var payload struct {
		Error string `json:"error"`
	}
	var detail string
	if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
		detail = payload.Error
	} else {
		detail = string(body)
	}
	detail = sanitizeServerDetail(detail, token)
	if detail == "" {
		return "(no response body)"
	}
	return detail
}

// sanitizeServerDetail redacts the publisher token, strips control characters to
// single spaces, collapses whitespace runs, trims, and rune-caps. Exported-shape
// kept small and pure so it is directly unit-testable.
func sanitizeServerDetail(s, token string) string {
	// Redact the token FIRST, before any transformation, so a server that
	// reflects it verbatim cannot leak it into the operator's logs. Guard the
	// empty-token case so we never replace every empty substring.
	if t := strings.TrimSpace(token); t != "" {
		s = strings.ReplaceAll(s, t, "[REDACTED]")
	}
	// Collapse every control or non-printable rune (CR, LF, tab, NUL, ESC, the
	// BOM/zero-width chars, and the U+2028/U+2029 line/paragraph separators that
	// some log viewers treat as newlines) to a single space. This is what
	// defeats log forging and ANSI-escape injection: the result is one printable
	// line. utf8.RuneError from invalid UTF-8 is also folded to a space.
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || !unicode.IsPrint(r) {
			r = ' '
		}
		if r == ' ' {
			if prevSpace {
				continue
			}
			prevSpace = true
		} else {
			prevSpace = false
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	// Cap by RUNES, after sanitization, so the cap reflects visible characters.
	runes := []rune(out)
	if len(runes) > serverErrorMaxRunes {
		out = string(runes[:serverErrorMaxRunes])
	}
	return out
}

// resolveAutoHash fetches the current stream head hash from the Conductor's
// stream-status endpoint and selects the stream matching the bundle this publish
// is about to create: same org/fleet query, same environment, and same audience.
// An empty match returns "" so a first-in-stream publish proceeds without a
// previous hash.
func resolveAutoHash(ctx context.Context, opts publishOptions) (string, error) {
	audience, err := parseAudience(opts.audience)
	if err != nil {
		return "", err
	}
	environment := strings.TrimSpace(opts.environment)
	if environment == "" {
		return "", errors.New("--env is required when --previous-bundle-hash auto is used")
	}
	client, err := publishHTTPClient(opts)
	if err != nil {
		return "", err
	}
	token, err := readPublisherToken(opts.publisherTok)
	if err != nil {
		return "", err
	}
	params := url.Values{}
	if strings.TrimSpace(opts.orgID) != "" {
		params.Set("org_id", opts.orgID)
	}
	if strings.TrimSpace(opts.fleetID) != "" {
		params.Set("fleet_id", opts.fleetID)
	}
	endpoint := strings.TrimRight(opts.conductorURL, "/") + controlplane.StreamStatusPath
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build stream-status request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("stream-status request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, publishMaxResponseBytes))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("stream-status returned HTTP %d: %s", resp.StatusCode, serverErrorDetail(body, token))
	}
	var status struct {
		Streams []struct {
			Environment    string                 `json:"environment"`
			Audience       conductorcore.Audience `json:"audience"`
			HeadBundleHash string                 `json:"head_bundle_hash"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		return "", fmt.Errorf("decode stream-status: %w", err)
	}
	var matches []string
	for _, stream := range status.Streams {
		if stream.Environment != environment {
			continue
		}
		if !audiencesEquivalent(stream.Audience, audience) {
			continue
		}
		matches = append(matches, stream.HeadBundleHash)
	}
	if len(matches) == 0 {
		return "", nil
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("stream-status returned %d matching streams for env %q and audience; refusing to choose a previous hash", len(matches), environment)
	}
	return matches[0], nil
}

func audiencesEquivalent(a, b conductorcore.Audience) bool {
	aIDs := canonicalInstanceIDs(a.InstanceIDs)
	bIDs := canonicalInstanceIDs(b.InstanceIDs)
	if !slices.Equal(aIDs, bIDs) {
		return false
	}
	if len(a.Labels) != len(b.Labels) {
		return false
	}
	for key, aVal := range a.Labels {
		if b.Labels[key] != aVal {
			return false
		}
	}
	return true
}

func canonicalInstanceIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	out := slices.Clone(ids)
	slices.Sort(out)
	return slices.Compact(out)
}
