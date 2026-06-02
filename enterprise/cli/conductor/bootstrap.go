//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/bootstrap"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

func bootstrapCmd() *cobra.Command {
	var (
		opts           bootstrap.Options
		licenseCRLFile string
	)
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Stand up and verify a local Conductor dev fleet end to end",
		Long: `Bootstrap generates a complete dev fleet in --dir and proves it works:

  - a local CA
  - a Conductor TLS server certificate
  - a follower mTLS client certificate with a SPIFFE URI SAN identity
  - a follower audit/recorder signing key
  - a signed trust roster (root + Conductor control keys)
  - a fleet-flagged license token for the spawned fleet
  - operator bearer tokens (publisher / auditor / admin)
  - a validated follower config

It then stands up one Conductor and one follower in-process, enrolls the
follower over mTLS, has it sign one audit batch from a real flight-recorder
checkpoint, ingests that batch through the Conductor's audit endpoint, queries
it back through the auditor API, and verifies it OFFLINE with the existing
verifier. The signed batch is written to audit-batch.json.

Bootstrap makes a verifying fleet DEPLOYABLE. Mediation completeness — the agent
reaching the network only through Pipelock — remains deployment-enforced via
capability separation and network policy; no single command can enforce that
boundary for you.

Re-running against an existing fleet directory reuses the material (no keys are
re-issued); pass --force to regenerate in place.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// License gate: bootstrap is the Enterprise fleet deployability
			// tool. Fail closed before any key material is written, exactly as
			// `conductor serve` and `fleet-sink` do. The dev license bootstrap
			// MINTS for the spawned fleet is separate from this entitlement.
			if _, err := license.VerifyFleet("", "", licenseCRLFile); err != nil {
				return err
			}
			opts.Out = cmd.OutOrStdout()
			_, err := bootstrap.Run(cmd.Context(), opts)
			return err
		},
	}
	cmd.Flags().StringVar(&opts.Dir, "dir", "", "directory to write the dev fleet material into (required)")
	cmd.Flags().StringVar(&opts.TrustDomain, "trust-domain", "", "SPIFFE trust domain for fleet identities (default pipelock.local)")
	cmd.Flags().StringVar(&opts.OrgID, "org", "", "fleet org id (default org-local)")
	cmd.Flags().StringVar(&opts.FleetID, "fleet", "", "fleet id (default dev)")
	cmd.Flags().StringVar(&opts.InstanceID, "instance", "", "follower instance id (default follower-1)")
	cmd.Flags().StringVar(&opts.Environment, "env", "", "follower environment (default dev)")
	cmd.Flags().StringVar(&opts.ConductorID, "conductor-id", "", "Conductor id (default conductor-local)")
	cmd.Flags().StringVar(&opts.ListenHost, "listen-host", "", "loopback host for the Conductor listener and certificate SAN (default 127.0.0.1)")
	cmd.Flags().IntVar(&opts.ConductorPort, "conductor-port", 0, "Conductor port baked into the follower config (default 8895)")
	cmd.Flags().DurationVar(&opts.Validity, "validity", 0, "validity window for the generated CA, certificates, and license (default 90 days)")
	cmd.Flags().BoolVar(&opts.Force, "force", false, "regenerate material even if a complete prior bootstrap is present")
	cmd.Flags().BoolVar(&opts.SkipProof, "skip-proof", false, "generate material without running the live round-trip proof")
	cmd.Flags().StringVar(&licenseCRLFile, "license-crl-file", "", "signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
	_ = cmd.MarkFlagRequired("dir")
	return cmd
}
