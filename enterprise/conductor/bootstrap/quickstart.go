//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package bootstrap

import (
	"fmt"
	"io"
)

// writeQuickstart prints the proof summary and the copy-pasteable runbook that
// lets a stranger go from this command to a verifying fleet they run
// themselves. It prints only file PATHS for secrets, never their bytes.
//
// The claims here are deliberately honest: bootstrap makes a verifying fleet
// DEPLOYABLE and proves the signed audit round-trip end to end. Mediation
// completeness — the guarantee that the agent reaches the network only through
// Pipelock — remains DEPLOYMENT-ENFORCED (capability separation, network
// policy), exactly as the rest of the product documents. Bootstrap does not and
// cannot enforce that boundary from a single command.
func writeQuickstart(out io.Writer, r *Result) {
	p := r.Proof
	w := func(format string, args ...any) { _, _ = fmt.Fprintf(out, format, args...) }

	w("\n")
	if r.Reused {
		w("pipelock: reused existing dev fleet material at %s (no keys re-issued)\n", r.Layout.Dir)
	} else {
		w("pipelock: generated dev fleet material at %s\n", r.Layout.Dir)
	}
	w("\n✓ verifying fleet stood up: 1 conductor + 1 follower + 1 signed audit batch\n")
	if p != nil {
		w("  conductor (in-process proof) listened on  %s\n", p.ConductorAddr)
		w("  follower enrolled audit key               %s\n", p.EnrolledAuditKeyID)
		w("  signed audit batch                        %s (seq %d-%d, %d events)\n", p.BatchID, p.SeqStart, p.SeqEnd, p.EventCount)
		w("  conductor ingest                          HTTP %d (accepted over mTLS)\n", p.IngestStatus)
		w("  queried back via auditor API              %t\n", p.QueriedBack)
		w("  verified OFFLINE with existing verifier   %t\n", p.OfflineVerified)
		w("  signed batch written to                   %s\n", p.BatchPath)
	}

	w("\nIdentity: spiffe://%s/orgs/%s/fleets/%s/instances/%s/environments/%s\n",
		r.TrustDomain, r.Identity.OrgID, r.Identity.FleetID, r.Identity.InstanceID, r.Identity.Environment)
	w("Trust root fingerprint: %s\n", r.RootFingerprint)

	w("\n── Run the real fleet ──────────────────────────────────────────────\n")
	w("Export the generated dev license (the spawned fleet's own key, not your\nEnterprise license):\n")
	w("  export PIPELOCK_LICENSE_KEY=\"$(cat %s)\"\n", r.Layout.LicenseTokenPath)
	w("  export PIPELOCK_LICENSE_PUBLIC_KEY=%s\n", r.LicensePubHex)
	w("\n1) Start the Conductor:\n")
	w("  pipelock conductor serve \\\n")
	w("    --listen %s \\\n", trimScheme(r.ConductorURL))
	w("    --conductor-id %s \\\n", r.ConductorID)
	w("    --follower-trust-domain %s \\\n", r.TrustDomain)
	w("    --storage-dir %s \\\n", r.Layout.ConductorStorageDir)
	w("    --tls-cert %s --tls-key %s \\\n", r.Layout.ConductorServerCertPath, r.Layout.ConductorServerKeyPath)
	w("    --client-ca %s \\\n", r.Layout.CACertPath)
	w("    --publisher-token-file %s \\\n", r.Layout.PublisherTokenPath)
	w("    --auditor-token-file %s \\\n", r.Layout.AuditorTokenPath)
	w("    --admin-token-file %s \\\n", r.Layout.AdminTokenPath)
	w("    --trusted-control-key id=%s,purpose=remote-kill-signing,file=%s \\\n", remoteKillKeyID, r.Layout.RemoteKillPubPath)
	w("    --trusted-control-key id=%s,purpose=policy-bundle-rollback,file=%s \\\n", rollbackKeyID, r.Layout.RollbackPubPath)
	w("    --probe-listen 127.0.0.1:9092\n")
	w("\n2) Start the follower (separate shell, same exported license):\n")
	w("  pipelock run -c %s\n", r.Layout.FollowerConfigPath)

	w("\n── What this proves (and what it does not) ─────────────────────────\n")
	w("Bootstrap makes a verifying fleet DEPLOYABLE: real PKI, real mTLS, real\n")
	w("enrollment, and a follower-signed audit batch a Conductor accepted and that\n")
	w("verifies offline. Mediation completeness — the agent reaching the network\n")
	w("ONLY through Pipelock — stays DEPLOYMENT-ENFORCED via capability separation\n")
	w("and network policy; no single command can enforce that boundary for you.\n")
	w("\nThis is a DEV fleet: every key (CA, roster root, control, audit, license)\n")
	w("is co-located on this machine for a fast local round-trip. A production\n")
	w("fleet keeps signing keys in KMS/HSM and off Conductor disk per the\n")
	w("Conductor design's hard gates.\n")
}

// trimScheme reduces an https://host:port URL to host:port for --listen.
func trimScheme(url string) string {
	const prefix = "https://"
	if len(url) > len(prefix) && url[:len(prefix)] == prefix {
		return url[len(prefix):]
	}
	return url
}
