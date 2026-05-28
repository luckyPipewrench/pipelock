//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// SignEnvelope signs an audit batch envelope with the follower audit key.
// Existing signatures are replaced because follower audit batches require one
// standard audit-batch signer in the current schema.
func SignEnvelope(envelope conductor.AuditBatchEnvelope, signerKeyID string, priv ed25519.PrivateKey) (conductor.AuditBatchEnvelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return conductor.AuditBatchEnvelope{}, fmt.Errorf("auditbatcher: private key length=%d want=%d", len(priv), ed25519.PrivateKeySize)
	}
	envelope.Signatures = nil
	preimage, err := envelope.SignablePreimage()
	if err != nil {
		return conductor.AuditBatchEnvelope{}, fmt.Errorf("auditbatcher: signable preimage: %w", err)
	}
	sig := ed25519.Sign(priv, preimage)
	proof := conductor.SignatureProof{
		SignerKeyID: signerKeyID,
		KeyPurpose:  signing.PurposeAuditBatchSigning,
		Algorithm:   conductor.SignatureAlgorithmEd25519,
		Signature:   "ed25519:" + hex.EncodeToString(sig),
	}
	if err := proof.Validate(signing.PurposeAuditBatchSigning); err != nil {
		return conductor.AuditBatchEnvelope{}, fmt.Errorf("auditbatcher: signature proof: %w", err)
	}
	envelope.Signatures = []conductor.SignatureProof{proof}
	if err := envelope.Validate(); err != nil {
		return conductor.AuditBatchEnvelope{}, fmt.Errorf("auditbatcher: signed envelope: %w", err)
	}
	return envelope, nil
}
