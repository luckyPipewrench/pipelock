// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const followerURIScheme = "spiffe"

type StaticAuditKey struct {
	KeyID      string
	Key        conductor.SignatureKey
	OrgID      string
	FleetID    string
	InstanceID string
}

func MTLSFollowerIdentityResolver(trustDomain string) (FollowerIdentityResolver, error) {
	trustDomain = strings.TrimSpace(trustDomain)
	if trustDomain == "" {
		return nil, fmt.Errorf("%w: trust_domain", ErrFollowerRequired)
	}
	return func(r *http.Request) (FollowerIdentity, error) {
		if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
			return FollowerIdentity{}, ErrFollowerRequired
		}
		for _, uri := range r.TLS.PeerCertificates[0].URIs {
			identity, err := ParseFollowerIdentityURI(uri, trustDomain)
			if err == nil {
				return identity, nil
			}
		}
		return FollowerIdentity{}, ErrFollowerRequired
	}, nil
}

// ParseFollowerIdentityURI extracts a [FollowerIdentity] from a SPIFFE SAN URI
// of the form
//
//	spiffe://<trust-domain>/orgs/<org>/fleets/<fleet>/instances/<instance>/environments/<environment>
//
// Trust domain comparison is case-insensitive per the SPIFFE spec (RFC: trust
// domains are restricted to lowercase ASCII), so a peer cert that ships with a
// non-conforming uppercase host still matches a lowercase configured trust
// domain. Path components are case-sensitive and validated as conductor
// identifiers via [FollowerIdentity.Validate].
func ParseFollowerIdentityURI(uri *url.URL, trustDomain string) (FollowerIdentity, error) {
	if uri == nil || uri.Scheme != followerURIScheme || !strings.EqualFold(uri.Host, trustDomain) {
		return FollowerIdentity{}, ErrFollowerRequired
	}
	parts := strings.Split(strings.Trim(uri.EscapedPath(), "/"), "/")
	if len(parts) != 8 ||
		parts[0] != "orgs" ||
		parts[2] != "fleets" ||
		parts[4] != "instances" ||
		parts[6] != "environments" {
		return FollowerIdentity{}, ErrFollowerRequired
	}
	values := make([]string, 4)
	for i, idx := range []int{1, 3, 5, 7} {
		value, err := url.PathUnescape(parts[idx])
		if err != nil {
			return FollowerIdentity{}, ErrFollowerRequired
		}
		values[i] = value
	}
	identity := FollowerIdentity{
		OrgID:       values[0],
		FleetID:     values[1],
		InstanceID:  values[2],
		Environment: values[3],
	}
	if err := identity.Validate(); err != nil {
		return FollowerIdentity{}, err
	}
	return identity, nil
}

func BearerPublisherAuthorizer(rawCredential string) (PublisherAuthorizer, error) {
	expectedCredential := strings.TrimSpace(rawCredential)
	if expectedCredential == "" {
		return nil, ErrPublisherForbidden
	}
	return func(r *http.Request) error {
		if r == nil {
			return ErrPublisherForbidden
		}
		raw := r.Header.Get("Authorization")
		prefix, got, ok := strings.Cut(raw, " ")
		if !ok || !strings.EqualFold(prefix, "Bearer") || subtle.ConstantTimeCompare([]byte(got), []byte(expectedCredential)) != 1 {
			return ErrPublisherForbidden
		}
		return nil
	}, nil
}

// StaticAuditKeyResolver builds an [AuditKeyResolver] from a fixed roster of
// trusted audit keys. Each key MUST be scoped to at least an OrgID. A key with
// an empty OrgID would let any enrolled follower across any org sign audit
// batches authenticated by that key — the per-batch
// validateAuditBatchForIdentity check rejects envelopes that claim a different
// identity than the authenticated transport, but it cannot detect a resolver
// that hands out cross-org signing material. FleetID and InstanceID remain
// optional so operators can scope keys to org-wide, fleet-wide, or
// instance-specific use.
func StaticAuditKeyResolver(keys []StaticAuditKey) (AuditKeyResolver, error) {
	if len(keys) == 0 {
		return nil, ErrAuditKeyRequired
	}
	byID := make(map[string]StaticAuditKey, len(keys))
	for _, key := range keys {
		key.KeyID = strings.TrimSpace(key.KeyID)
		if err := conductor.ValidateIdentifier("key_id", key.KeyID); err != nil {
			return nil, fmt.Errorf("%w: key_id %q", ErrAuditKeyRequired, key.KeyID)
		}
		if len(key.Key.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: public_key for key %q", ErrAuditKeyRequired, key.KeyID)
		}
		if key.Key.KeyPurpose != signing.PurposeAuditBatchSigning {
			return nil, fmt.Errorf("%w: key_purpose for key %q", ErrAuditKeyRequired, key.KeyID)
		}
		if strings.TrimSpace(key.OrgID) == "" {
			return nil, fmt.Errorf("%w: org_id required for key %q (cross-org audit keys are not permitted)", ErrAuditKeyRequired, key.KeyID)
		}
		if err := conductor.ValidateIdentifier("org_id", key.OrgID); err != nil {
			return nil, fmt.Errorf("%w: org_id for key %q", ErrAuditKeyRequired, key.KeyID)
		}
		if key.FleetID != "" {
			if err := conductor.ValidateIdentifier("fleet_id", key.FleetID); err != nil {
				return nil, fmt.Errorf("%w: fleet_id for key %q", ErrAuditKeyRequired, key.KeyID)
			}
		}
		if key.InstanceID != "" {
			if err := conductor.ValidateIdentifier("instance_id", key.InstanceID); err != nil {
				return nil, fmt.Errorf("%w: instance_id for key %q", ErrAuditKeyRequired, key.KeyID)
			}
		}
		if _, exists := byID[key.KeyID]; exists {
			return nil, fmt.Errorf("%w: duplicate key_id %q", ErrAuditKeyRequired, key.KeyID)
		}
		byID[key.KeyID] = key
	}
	return func(identity FollowerIdentity, signerKeyID string) (conductor.SignatureKey, error) {
		key, ok := byID[signerKeyID]
		if !ok || !staticAuditKeyMatches(key, identity) {
			return conductor.SignatureKey{}, conductor.ErrSignatureVerification
		}
		return key.Key, nil
	}, nil
}

func staticAuditKeyMatches(key StaticAuditKey, identity FollowerIdentity) bool {
	switch {
	case key.OrgID != "" && key.OrgID != identity.OrgID:
		return false
	case key.FleetID != "" && key.FleetID != identity.FleetID:
		return false
	case key.InstanceID != "" && key.InstanceID != identity.InstanceID:
		return false
	default:
		return true
	}
}

func IsAuthConfigError(err error) bool {
	return errors.Is(err, ErrFollowerRequired) ||
		errors.Is(err, ErrPublisherForbidden) ||
		errors.Is(err, ErrAuditKeyRequired)
}
