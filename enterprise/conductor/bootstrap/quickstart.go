//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package bootstrap

import (
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
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
	w("    --auditor-org %s \\\n", r.Identity.OrgID)
	w("    --admin-org %s \\\n", r.Identity.OrgID)
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
	w("\n2) Enroll the follower. Bootstrap proved enrollment in-process; a standalone\n")
	w("   follower still has to enroll itself, and it only does that when its config\n")
	w("   names a one-shot token. Skip this and the follower LOOKS healthy — policy\n")
	w("   and remote-kill polls return 204 — while its audit batches are rejected 401\n")
	w("   and it never appears in `conductor fleet status`:\n")
	tokenPath := filepath.Join(r.Layout.FollowerBundleCacheDir, "enrollment.token")
	// Two things are load-bearing here, and the umask alone is not enough.
	// This one-hour token authorizes enrollment, so it must never land group- or
	// world-readable. `umask 077` covers only a file the redirect CREATES; on a
	// rerun the target already exists and `>` truncates it in place, preserving
	// whatever mode it already had. Removing it first makes every run take the
	// create path, so the rerun gets the same protection as the first run.
	w("  (umask 077 && rm -f %s && pipelock conductor enrollment-token mint \\\n", shellQuote(tokenPath))
	w("    --conductor-url %s \\\n", shellQuote(r.ConductorURL))
	w("    --admin-token-file %s \\\n", shellQuote(r.Layout.AdminTokenPath))
	w("    --server-ca %s \\\n", shellQuote(r.Layout.CACertPath))
	w("    --tls-cert %s --tls-key %s \\\n", shellQuote(r.Layout.FollowerClientCertPath), shellQuote(r.Layout.FollowerClientKeyPath))
	w("    --org %s --fleet %s --env %s --instance %s \\\n", shellQuote(r.Identity.OrgID), shellQuote(r.Identity.FleetID), shellQuote(r.Identity.Environment), shellQuote(r.Identity.InstanceID))
	w("    --token-id bootstrap-enroll-1 --ttl 1h > %s)\n", shellQuote(tokenPath))
	w("   then add this line under `conductor:` in %s\n", r.Layout.FollowerConfigPath)
	// Emit the path as a real YAML scalar rather than wrapping it in double
	// quotes by hand. A path containing a quote or a backslash would otherwise
	// produce a config that either fails to parse or parses to a different path
	// than the one the token was written to.
	w("     enrollment_token_path: %s\n", yamlScalar(tokenPath))
	w("\n3) Start the follower (separate shell, same exported license):\n")
	w("  pipelock run -c %s\n", r.Layout.FollowerConfigPath)
	w("   It auto-enrolls on first start and prints \"follower enrollment completed\".\n")
	w("   Do NOT run `conductor enroll` first: that registers the audit key without\n")
	w("   writing the follower's local marker, and auto-enroll then fails 409 for good.\n")

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

// shellQuote wraps s in single quotes so a generated path is safe to paste
// verbatim even when it contains spaces or shell metacharacters. Embedded
// single quotes are escaped by closing the quoted string, adding an escaped
// quote, and reopening it.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// yamlScalar encodes s as a YAML scalar suitable for pasting as a mapping value.
// It defers the quoting rules to the YAML encoder instead of hand-wrapping the
// value, which is what keeps a path containing a quote or a backslash both valid
// and unchanged. The encoder appends a newline; callers place their own.
func yamlScalar(s string) string {
	enc, err := yaml.Marshal(s)
	if err != nil {
		// Marshalling a string does not fail. Fall back to the encoder's own
		// double-quoted form rather than emitting a bare value that could be
		// misparsed.
		return strconv.Quote(s)
	}
	return strings.TrimRight(string(enc), "\n")
}

// trimScheme reduces an https://host:port URL to host:port for --listen.
func trimScheme(url string) string {
	const prefix = "https://"
	if len(url) > len(prefix) && url[:len(prefix)] == prefix {
		return url[len(prefix):]
	}
	return url
}
