//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

const (
	// manifestSchema versions the on-disk completion sentinel. A manifest with
	// a recognised schema marks a COMPLETE prior bootstrap; its absence beside
	// other material is treated as a partial/foreign directory and fails closed.
	manifestSchema = 1
	manifestFile   = "bootstrap-manifest.json"

	// defaults for a local dev fleet. All are conductor-valid identifiers.
	defaultTrustDomain   = "pipelock.local"
	defaultOrgID         = "org-local"
	defaultFleetID       = "dev"
	defaultInstanceID    = "follower-1"
	defaultEnvironment   = "dev"
	defaultConductorID   = "conductor-local"
	defaultListenHost    = "127.0.0.1"
	defaultConductorPort = 8895
	defaultValidity      = 90 * 24 * time.Hour

	// auditKeyID and recorderKeyID name the follower's audit-batch signer and
	// recorder signer. The runtime reuses one Ed25519 key for both (the two
	// signing schemes operate on disjoint byte sets), but the ids stay distinct
	// so a sink-side roster can tell purpose apart.
	auditKeyID    = "follower-audit-1"
	recorderKeyID = "follower-recorder-1"

	dirPerm  = 0o750
	filePerm = 0o600
)

// Options configures a dev-fleet bootstrap. Zero-valued fields take dev
// defaults via normalize so `bootstrap --dir X` works with no other flags.
type Options struct {
	Dir           string
	TrustDomain   string
	OrgID         string
	FleetID       string
	InstanceID    string
	Environment   string
	ConductorID   string
	ListenHost    string
	ConductorPort int
	Validity      time.Duration
	// Force regenerates material in place even when a complete prior bootstrap
	// is present. Without it, a complete directory is reused (idempotent) and a
	// partial/foreign directory fails closed.
	Force bool
	// SkipProof generates and persists material without running the live
	// round-trip. The default (false) runs the full conductor+follower proof.
	SkipProof bool
	// Now and Out are injected for testability; nil takes time.Now / io.Discard.
	Now func() time.Time
	Out io.Writer
}

// Result reports what a bootstrap produced. Proof is nil when SkipProof is set.
type Result struct {
	Layout          Layout
	Identity        controlplane.FollowerIdentity
	TrustDomain     string
	ConductorID     string
	ConductorURL    string
	RootFingerprint string
	LicensePubHex   string
	// Reused is true when a complete prior bootstrap was found and its material
	// was reused unchanged (no double-issue).
	Reused bool
	Proof  *ProofResult
}

// manifest is the on-disk completion sentinel, written last and atomically so
// its presence means "a prior bootstrap finished writing every artifact".
type manifest struct {
	Schema          int       `json:"schema"`
	CreatedAt       time.Time `json:"created_at"`
	TrustDomain     string    `json:"trust_domain"`
	OrgID           string    `json:"org_id"`
	FleetID         string    `json:"fleet_id"`
	InstanceID      string    `json:"instance_id"`
	Environment     string    `json:"environment"`
	ConductorID     string    `json:"conductor_id"`
	ConductorURL    string    `json:"conductor_url"`
	RootFingerprint string    `json:"root_fingerprint"`
}

// materialSet carries the in-memory artifacts the live proof needs. It is the
// product of generation and the result of loading a reused directory, so the
// proof path is identical whether material is fresh or reused.
type materialSet struct {
	caCert          *x509.Certificate
	caKey           *ecdsa.PrivateKey
	serverCert      tls.Certificate
	clientCert      tls.Certificate
	auditKey        ed25519.PrivateKey
	rootFingerprint string
	licensePubHex   string
	publisherToken  string
	auditorToken    string
	adminToken      string
}

// Run performs a dev-fleet bootstrap: it ensures the material set exists
// (generating it fail-closed and idempotently), then — unless SkipProof —
// stands up one Conductor and one follower in-process and proves a signed
// audit-batch round-trip that also verifies offline.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalize(&opts)
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	layout, err := newLayout(opts.Dir)
	if err != nil {
		return nil, err
	}
	identity := controlplane.FollowerIdentity{
		OrgID:       opts.OrgID,
		FleetID:     opts.FleetID,
		InstanceID:  opts.InstanceID,
		Environment: opts.Environment,
	}

	material, reused, err := ensureMaterial(layout, opts, identity)
	if err != nil {
		return nil, err
	}

	result := &Result{
		Layout:          layout,
		Identity:        identity,
		TrustDomain:     opts.TrustDomain,
		ConductorID:     opts.ConductorID,
		ConductorURL:    opts.conductorURL(),
		RootFingerprint: material.rootFingerprint,
		LicensePubHex:   material.licensePubHex,
		Reused:          reused,
	}

	if opts.SkipProof {
		_, _ = fmt.Fprintf(opts.Out, "pipelock: dev fleet material ready at %s (proof skipped)\n", layout.Dir)
		return result, nil
	}

	proof, err := runProof(ctx, layout, opts, identity, material)
	if err != nil {
		return nil, fmt.Errorf("fleet round-trip proof failed: %w", err)
	}
	result.Proof = proof
	writeQuickstart(opts.Out, result)
	return result, nil
}

// ensureMaterial implements the idempotency / fail-closed contract:
//   - complete prior bootstrap (manifest present) + !Force -> reuse, load material
//   - complete prior bootstrap + Force                     -> regenerate in place
//   - no manifest but known material exists + !Force       -> fail closed (partial/foreign)
//   - empty / fresh directory                              -> generate
func ensureMaterial(layout Layout, opts Options, identity controlplane.FollowerIdentity) (*materialSet, bool, error) {
	manifestExists, err := pathExists(layout.ManifestPath)
	if err != nil {
		return nil, false, err
	}
	materialExists, err := layoutHasMaterial(layout)
	if err != nil {
		return nil, false, err
	}

	switch {
	case manifestExists && !opts.Force:
		m, err := loadManifest(layout.ManifestPath)
		if err != nil {
			return nil, false, fmt.Errorf("loading existing bootstrap manifest (use --force to regenerate): %w", err)
		}
		if err := validateManifest(m, opts, identity); err != nil {
			return nil, false, fmt.Errorf("existing bootstrap manifest does not match this invocation (use --force to regenerate): %w", err)
		}
		material, err := loadMaterial(layout)
		if err != nil {
			return nil, false, fmt.Errorf("loading existing fleet material (use --force to regenerate): %w", err)
		}
		if material.rootFingerprint != m.RootFingerprint {
			return nil, false, fmt.Errorf("existing bootstrap manifest root_fingerprint %q does not match roster root %q (use --force to regenerate)",
				m.RootFingerprint, material.rootFingerprint)
		}
		return material, true, nil
	case !manifestExists && materialExists && !opts.Force:
		return nil, false, fmt.Errorf(
			"%s contains partial or foreign bootstrap material but no completed bootstrap manifest; "+
				"refusing to mix trust material — re-run with --force to regenerate, or choose an empty --dir",
			layout.Dir)
	default:
		material, err := generateMaterial(layout, opts, identity)
		if err != nil {
			return nil, false, err
		}
		if err := writeManifest(layout, opts, identity, material.rootFingerprint); err != nil {
			return nil, false, err
		}
		return material, false, nil
	}
}

func writeManifest(layout Layout, opts Options, identity controlplane.FollowerIdentity, rootFingerprint string) error {
	m := manifest{
		Schema:          manifestSchema,
		CreatedAt:       opts.Now().UTC(),
		TrustDomain:     opts.TrustDomain,
		OrgID:           identity.OrgID,
		FleetID:         identity.FleetID,
		InstanceID:      identity.InstanceID,
		Environment:     identity.Environment,
		ConductorID:     opts.ConductorID,
		ConductorURL:    opts.conductorURL(),
		RootFingerprint: rootFingerprint,
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode bootstrap manifest: %w", err)
	}
	data = append(data, '\n')
	return writeFile(layout.ManifestPath, data)
}

func loadManifest(path string) (manifest, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return manifest{}, fmt.Errorf("read bootstrap manifest: %w", err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return manifest{}, fmt.Errorf("decode bootstrap manifest: %w", err)
	}
	return m, nil
}

func validateManifest(m manifest, opts Options, identity controlplane.FollowerIdentity) error {
	if m.Schema != manifestSchema {
		return fmt.Errorf("unsupported manifest schema %d", m.Schema)
	}
	if m.CreatedAt.IsZero() {
		return errors.New("manifest created_at is empty")
	}
	want := manifest{
		Schema:       manifestSchema,
		TrustDomain:  opts.TrustDomain,
		OrgID:        identity.OrgID,
		FleetID:      identity.FleetID,
		InstanceID:   identity.InstanceID,
		Environment:  identity.Environment,
		ConductorID:  opts.ConductorID,
		ConductorURL: opts.conductorURL(),
	}
	for _, c := range []struct {
		field     string
		got, want string
	}{
		{"trust_domain", m.TrustDomain, want.TrustDomain},
		{"org_id", m.OrgID, want.OrgID},
		{"fleet_id", m.FleetID, want.FleetID},
		{"instance_id", m.InstanceID, want.InstanceID},
		{"environment", m.Environment, want.Environment},
		{"conductor_id", m.ConductorID, want.ConductorID},
		{"conductor_url", m.ConductorURL, want.ConductorURL},
	} {
		if c.got != c.want {
			return fmt.Errorf("%s=%q, want %q", c.field, c.got, c.want)
		}
	}
	if m.RootFingerprint == "" {
		return errors.New("manifest root_fingerprint is empty")
	}
	return nil
}

func normalize(opts *Options) {
	opts.TrustDomain = strings.ToLower(strings.TrimSpace(opts.TrustDomain))
	opts.OrgID = strings.TrimSpace(opts.OrgID)
	opts.FleetID = strings.TrimSpace(opts.FleetID)
	opts.InstanceID = strings.TrimSpace(opts.InstanceID)
	opts.Environment = strings.TrimSpace(opts.Environment)
	opts.ConductorID = strings.TrimSpace(opts.ConductorID)
	opts.ListenHost = strings.TrimSpace(opts.ListenHost)
	if opts.TrustDomain == "" {
		opts.TrustDomain = defaultTrustDomain
	}
	if opts.OrgID == "" {
		opts.OrgID = defaultOrgID
	}
	if opts.FleetID == "" {
		opts.FleetID = defaultFleetID
	}
	if opts.InstanceID == "" {
		opts.InstanceID = defaultInstanceID
	}
	if opts.Environment == "" {
		opts.Environment = defaultEnvironment
	}
	if opts.ConductorID == "" {
		opts.ConductorID = defaultConductorID
	}
	if opts.ListenHost == "" {
		opts.ListenHost = defaultListenHost
	}
	if opts.ConductorPort == 0 {
		opts.ConductorPort = defaultConductorPort
	}
	if opts.Validity <= 0 {
		opts.Validity = defaultValidity
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
}

func validateOptions(opts Options) error {
	if opts.Dir == "" {
		return errors.New("bootstrap: --dir is required")
	}
	if !envelope.IsValidTrustDomain(opts.TrustDomain) {
		return fmt.Errorf("bootstrap: trust-domain %q must be a DNS-shaped SPIFFE trust domain", opts.TrustDomain)
	}
	if err := validateListenHost(opts.ListenHost); err != nil {
		return err
	}
	if opts.ConductorPort < 1 || opts.ConductorPort > 65535 {
		return fmt.Errorf("bootstrap: conductor port %d out of range", opts.ConductorPort)
	}
	if err := conductorcore.ValidateIdentifier("conductor-id", opts.ConductorID); err != nil {
		return err
	}
	// Identity components must be valid conductor identifiers; SPIFFE SAN
	// construction re-checks but failing here gives the operator a precise
	// per-field error before any key material is written.
	for field, value := range map[string]string{
		"org":      opts.OrgID,
		"fleet":    opts.FleetID,
		"instance": opts.InstanceID,
		"env":      opts.Environment,
	} {
		if err := conductorcore.ValidateIdentifier(field, value); err != nil {
			return err
		}
	}
	return nil
}

func validateListenHost(host string) error {
	if host == "" {
		return errors.New("bootstrap: listen-host is required")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return fmt.Errorf("bootstrap: listen-host %q must be loopback for the dev fleet", host)
		}
		return nil
	}
	if strings.ContainsAny(host, "/\\@:?# \t\r\n") {
		return fmt.Errorf("bootstrap: listen-host %q must be a bare loopback hostname or IP", host)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	return fmt.Errorf("bootstrap: listen-host %q must be localhost or a loopback IP", host)
}

func (o Options) conductorURL() string {
	return "https://" + net.JoinHostPort(o.ListenHost, strconv.Itoa(o.ConductorPort))
}

// --- filesystem helpers -------------------------------------------------

func pathExists(path string) (bool, error) {
	_, err := os.Stat(filepath.Clean(path))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("stat %s: %w", path, err)
}

func layoutHasMaterial(layout Layout) (bool, error) {
	for _, path := range layoutMaterialPaths(layout) {
		exists, err := pathExists(path)
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

func layoutMaterialPaths(layout Layout) []string {
	return []string{
		layout.CACertPath,
		layout.CAKeyPath,
		layout.ConductorServerCertPath,
		layout.ConductorServerKeyPath,
		layout.ConductorStorageDir,
		layout.PublisherTokenPath,
		layout.AuditorTokenPath,
		layout.AdminTokenPath,
		layout.FollowerClientCertPath,
		layout.FollowerClientKeyPath,
		layout.FollowerAuditKeyPath,
		layout.FollowerAuditPubPath,
		layout.FollowerConfigPath,
		layout.FollowerBundleCacheDir,
		layout.FollowerAuditQueueDir,
		layout.FollowerRecorderDir,
		layout.TrustRosterPath,
		layout.RosterRootKeyPath,
		layout.RosterRootPubPath,
		layout.RemoteKillKeyPath,
		layout.RemoteKillPubPath,
		layout.RollbackKeyPath,
		layout.RollbackPubPath,
		layout.LicenseKeyPath,
		layout.LicensePubPath,
		layout.LicenseTokenPath,
		layout.AuditBatchPath,
	}
}

// writeFile writes data atomically with 0o600 permissions, creating the parent
// directory (0o750) if needed. Private-key material and tokens never go through
// any path that logs their bytes.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return fmt.Errorf("create directory for %s: %w", path, err)
	}
	if err := writeAtomic(path, data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
