//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package bootstrap

import (
	"fmt"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
)

// Layout is the on-disk file map for a dev fleet. Every path is absolute and
// canonical so the generated follower config passes Conductor's
// absolute-path/canonical-form validation without any post-processing.
type Layout struct {
	Dir          string
	ManifestPath string

	// Shared CA (signs the Conductor server cert and the follower client cert).
	CACertPath string
	CAKeyPath  string

	// Conductor server material + operator tokens + durable storage.
	ConductorServerCertPath string
	ConductorServerKeyPath  string
	ConductorStorageDir     string
	PublisherTokenPath      string
	AuditorTokenPath        string
	AdminTokenPath          string

	// Follower mTLS identity, audit/recorder signing key, runtime dirs, config.
	FollowerClientCertPath string
	FollowerClientKeyPath  string
	FollowerAuditKeyPath   string
	FollowerAuditPubPath   string
	FollowerConfigPath     string
	FollowerBundleCacheDir string
	FollowerAuditQueueDir  string
	FollowerRecorderDir    string

	// Trust roster + its root keypair + the Conductor control keys it pins.
	TrustRosterPath   string
	RosterRootKeyPath string
	RosterRootPubPath string
	RemoteKillKeyPath string
	RemoteKillPubPath string
	RollbackKeyPath   string
	RollbackPubPath   string

	// Dev license keypair + fleet-flagged token.
	LicenseKeyPath   string
	LicensePubPath   string
	LicenseTokenPath string

	// Proof artifact: the signed audit batch that verified offline.
	AuditBatchPath string
}

func newLayout(dir string) (Layout, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Layout{}, fmt.Errorf("resolve bootstrap dir: %w", err)
	}
	abs = filepath.Clean(abs)
	j := func(parts ...string) string {
		return filepath.Join(append([]string{abs}, parts...)...)
	}
	return Layout{
		Dir:          abs,
		ManifestPath: j(manifestFile),

		CACertPath: j("ca", "ca.crt"),
		CAKeyPath:  j("ca", "ca.key"),

		ConductorServerCertPath: j("conductor", "server.crt"),
		ConductorServerKeyPath:  j("conductor", "server.key"),
		ConductorStorageDir:     j("conductor", "storage"),
		PublisherTokenPath:      j("conductor", "publisher.token"),
		AuditorTokenPath:        j("conductor", "auditor.token"),
		AdminTokenPath:          j("conductor", "admin.token"),

		FollowerClientCertPath: j("follower", "client.crt"),
		FollowerClientKeyPath:  j("follower", "client.key"),
		FollowerAuditKeyPath:   j("follower", "audit-signing.key"),
		FollowerAuditPubPath:   j("follower", "audit-signing.pub"),
		FollowerConfigPath:     j("follower", "follower.yaml"),
		FollowerBundleCacheDir: j("follower", "bundles"),
		FollowerAuditQueueDir:  j("follower", "audit-queue"),
		FollowerRecorderDir:    j("follower", "recorder"),

		TrustRosterPath:   j("trust", "trust-roster.json"),
		RosterRootKeyPath: j("trust", "roster-root.key"),
		RosterRootPubPath: j("trust", "roster-root.pub"),
		RemoteKillKeyPath: j("trust", "remote-kill.key"),
		RemoteKillPubPath: j("trust", "remote-kill.pub"),
		RollbackKeyPath:   j("trust", "rollback.key"),
		RollbackPubPath:   j("trust", "rollback.pub"),

		LicenseKeyPath:   j("license", "license.key"),
		LicensePubPath:   j("license", "license.pub"),
		LicenseTokenPath: j("license", "license.token"),

		AuditBatchPath: j("audit-batch.json"),
	}, nil
}

// writeAtomic writes data with 0o600 permissions via the shared atomic-write
// helper (temp file + rename) so a crash mid-write never leaves a partially
// overwritten key or token at the target path.
func writeAtomic(path string, data []byte) error {
	return atomicfile.Write(path, data, filePerm)
}
