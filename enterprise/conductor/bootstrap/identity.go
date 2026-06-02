//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package bootstrap stands up a complete, self-verifying Conductor dev fleet on
// a single machine: a local CA, mTLS identities, a signed trust roster, a
// fleet-flagged license, one Conductor, one follower, and one signed audit
// batch that verifies offline. It is the deployability gate for Conductor GA —
// the <10-minute "verifying fleet" a buyer can reproduce from docs alone.
//
// Bootstrap is glue, not greenfield Conductor: it composes the already-merged
// PKI/mTLS, enrollment, audit-batcher, and follower-runtime primitives and
// proves a real round-trip. It makes a verifying fleet DEPLOYABLE; mediation
// completeness (the agent never reaching the network except through Pipelock)
// remains deployment-enforced, exactly as the rest of the product documents.
package bootstrap

import (
	"fmt"
	"net/url"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
)

// followerSPIFFEID builds the SPIFFE URI SAN for a fleet follower in the
// canonical Conductor form the mTLS identity resolver parses:
//
//	spiffe://<trust-domain>/orgs/<org>/fleets/<fleet>/instances/<instance>/environments/<environment>
//
// It validates the identity components as Conductor identifiers (the same gate
// the transport boundary applies) before constructing the URI, and re-parses
// the result through controlplane.ParseFollowerIdentityURI so a bootstrap can
// never emit a follower cert whose SAN the Conductor would reject. This is the
// SPIFFE identity vocabulary for fleet members; deeper offline X.509-SVID
// validation against a pinned trust-bundle history layers on top of it.
func followerSPIFFEID(trustDomain string, id controlplane.FollowerIdentity) (*url.URL, error) {
	if trustDomain == "" {
		return nil, fmt.Errorf("%w: trust_domain", controlplane.ErrFollowerRequired)
	}
	if err := id.Validate(); err != nil {
		return nil, fmt.Errorf("follower identity: %w", err)
	}
	uri := &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path: fmt.Sprintf("/orgs/%s/fleets/%s/instances/%s/environments/%s",
			id.OrgID, id.FleetID, id.InstanceID, id.Environment),
	}
	// Defensive round-trip: the SAN we are about to bake into a client cert
	// must parse back to the exact identity the Conductor will derive from the
	// authenticated transport. If it does not, fail closed here rather than
	// issue a cert the control plane silently refuses at connect time.
	parsed, err := controlplane.ParseFollowerIdentityURI(uri, trustDomain)
	if err != nil {
		return nil, fmt.Errorf("follower SPIFFE SAN does not round-trip through the Conductor identity resolver: %w", err)
	}
	if parsed.OrgID != id.OrgID || parsed.FleetID != id.FleetID ||
		parsed.InstanceID != id.InstanceID || parsed.Environment != id.Environment {
		return nil, fmt.Errorf("follower SPIFFE SAN round-trips to a different identity (got %+v, want %+v)", parsed, id)
	}
	return uri, nil
}
