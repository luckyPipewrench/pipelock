// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/posture"
)

func TestAssessContainmentDefaultUnknown(t *testing.T) {
	got := AssessContainment(ContainmentAssessmentOptions{})
	if got.Grade != ContainUnknown || got.AllowClaim {
		t.Fatalf("assessment = %+v, want unknown no claim", got)
	}
}

func TestAssessContainmentGradesAndFailClosed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	base := validContainmentCapsule(t, priv, posture.ContainmentEvidence{
		Mode:                     posture.ContainmentModeKernelNFTOwnerMatch,
		BoundaryVerified:         true,
		ProbeRefusedDirectEgress: true,
		KernelRuleHash:           strings.Repeat("a", 64),
		TargetUID:                "966",
	})
	opts := ContainmentAssessmentOptions{
		Capsule:              base,
		TrustedKey:           pub,
		ReceiptFrom:          base.GeneratedAt.Add(time.Second),
		ReceiptTo:            base.ExpiresAt.Add(-time.Second),
		ActorUID:             "966",
		CapsuleSHA256:        capsuleSHA256(t, base),
		ReceiptCapsuleSHA256: capsuleSHA256(t, base),
		ReceiptSignerKeyID:   base.SignerKeyID,
		Now:                  base.GeneratedAt.Add(2 * time.Second),
	}
	kernel := AssessContainment(opts)
	if kernel.Grade != ContainKernelEnforced || !kernel.AllowClaim {
		t.Fatalf("kernel assessment = %+v", kernel)
	}
	if !strings.Contains(FormatContainmentAssessment(kernel), "direct egress by the contained UID was kernel-refused") {
		t.Fatalf("kernel line missing gated claim: %s", FormatContainmentAssessment(kernel))
	}

	proxy := validContainmentCapsule(t, priv, posture.ContainmentEvidence{
		Mode:      posture.ContainmentModeBestEffortProxyEnv,
		TargetUID: "966",
	})
	opts.Capsule = proxy
	bestEffort := AssessContainment(opts)
	if bestEffort.Grade != ContainProxyEnv || bestEffort.AllowClaim {
		t.Fatalf("proxy assessment = %+v", bestEffort)
	}

	tests := []struct {
		name   string
		mutate func(*ContainmentAssessmentOptions)
	}{
		{"bad_sig", func(o *ContainmentAssessmentOptions) { o.Capsule.Signature = strings.Repeat("0", 128) }},
		{"untrusted_signer", func(o *ContainmentAssessmentOptions) { other, _, _ := ed25519.GenerateKey(nil); o.TrustedKey = other }},
		{"expired", func(o *ContainmentAssessmentOptions) { o.Now = o.Capsule.ExpiresAt.Add(time.Second) }},
		{"window_miss_start", func(o *ContainmentAssessmentOptions) { o.ReceiptFrom = o.Capsule.GeneratedAt.Add(-time.Second) }},
		{"window_miss_end", func(o *ContainmentAssessmentOptions) { o.ReceiptTo = o.Capsule.ExpiresAt.Add(time.Second) }},
		{"uid_mismatch", func(o *ContainmentAssessmentOptions) { o.ActorUID = "123" }},
		{"uid_missing", func(o *ContainmentAssessmentOptions) { o.ActorUID = "" }},
		{"target_uid_missing", func(o *ContainmentAssessmentOptions) {
			o.Capsule = validContainmentCapsule(t, priv, posture.ContainmentEvidence{
				Mode:                     posture.ContainmentModeKernelNFTOwnerMatch,
				BoundaryVerified:         true,
				ProbeRefusedDirectEgress: true,
				KernelRuleHash:           strings.Repeat("a", 64),
			})
			o.CapsuleSHA256 = capsuleSHA256(t, o.Capsule)
			o.ReceiptCapsuleSHA256 = o.CapsuleSHA256
			o.ReceiptSignerKeyID = o.Capsule.SignerKeyID
		}},
		{"rule_hash_missing", func(o *ContainmentAssessmentOptions) {
			o.Capsule = validContainmentCapsule(t, priv, posture.ContainmentEvidence{
				Mode:                     posture.ContainmentModeKernelNFTOwnerMatch,
				BoundaryVerified:         true,
				ProbeRefusedDirectEgress: true,
				TargetUID:                "966",
			})
			o.CapsuleSHA256 = capsuleSHA256(t, o.Capsule)
			o.ReceiptCapsuleSHA256 = o.CapsuleSHA256
			o.ReceiptSignerKeyID = o.Capsule.SignerKeyID
		}},
		{"capsule_hash_missing", func(o *ContainmentAssessmentOptions) { o.ReceiptCapsuleSHA256 = "" }},
		{"capsule_hash_mismatch", func(o *ContainmentAssessmentOptions) { o.ReceiptCapsuleSHA256 = strings.Repeat("b", 64) }},
		{"posture_signer_missing", func(o *ContainmentAssessmentOptions) { o.ReceiptSignerKeyID = "" }},
		{"posture_signer_mismatch", func(o *ContainmentAssessmentOptions) { o.ReceiptSignerKeyID = strings.Repeat("c", 64) }},
		{"old_capsule", func(o *ContainmentAssessmentOptions) { o.Capsule = validOldCapsule(t, priv) }},
		{"boundary_false", func(o *ContainmentAssessmentOptions) {
			o.Capsule = validContainmentCapsule(t, priv, posture.ContainmentEvidence{
				Mode:                     posture.ContainmentModeKernelNFTOwnerMatch,
				BoundaryVerified:         false,
				ProbeRefusedDirectEgress: true,
				KernelRuleHash:           strings.Repeat("a", 64),
				TargetUID:                "966",
			})
			o.CapsuleSHA256 = capsuleSHA256(t, o.Capsule)
			o.ReceiptCapsuleSHA256 = o.CapsuleSHA256
			o.ReceiptSignerKeyID = o.Capsule.SignerKeyID
		}},
		{"probe_false", func(o *ContainmentAssessmentOptions) {
			o.Capsule = validContainmentCapsule(t, priv, posture.ContainmentEvidence{
				Mode:                     posture.ContainmentModeKernelNFTOwnerMatch,
				BoundaryVerified:         true,
				ProbeRefusedDirectEgress: false,
				KernelRuleHash:           strings.Repeat("a", 64),
				TargetUID:                "966",
			})
			o.CapsuleSHA256 = capsuleSHA256(t, o.Capsule)
			o.ReceiptCapsuleSHA256 = o.CapsuleSHA256
			o.ReceiptSignerKeyID = o.Capsule.SignerKeyID
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cloneCapsule(base)
			local := opts
			local.Capsule = c
			tt.mutate(&local)
			got := AssessContainment(local)
			if got.Grade != ContainUnknown || got.AllowClaim {
				t.Fatalf("assessment = %+v, want unknown no claim", got)
			}
			if strings.Contains(FormatContainmentAssessment(got), "direct egress by the contained UID was kernel-refused") {
				t.Fatalf("wording gate failed: %s", FormatContainmentAssessment(got))
			}
		})
	}
}

func validContainmentCapsule(t *testing.T, priv ed25519.PrivateKey, ev posture.ContainmentEvidence) *posture.Capsule {
	t.Helper()
	capsule, err := posture.Emit(config.Defaults(), posture.Options{
		SigningKey: priv,
		EvidenceBundle: &posture.EvidenceBundle{
			Containment: &ev,
		},
	})
	if err != nil {
		t.Fatalf("posture.Emit: %v", err)
	}
	return capsule
}

func validOldCapsule(t *testing.T, priv ed25519.PrivateKey) *posture.Capsule {
	t.Helper()
	capsule, err := posture.Emit(config.Defaults(), posture.Options{
		SigningKey:     priv,
		EvidenceBundle: &posture.EvidenceBundle{},
	})
	if err != nil {
		t.Fatalf("posture.Emit old capsule: %v", err)
	}
	return capsule
}

func cloneCapsule(in *posture.Capsule) *posture.Capsule {
	out := *in
	out.Evidence = in.Evidence
	if in.Evidence.Containment != nil {
		ev := *in.Evidence.Containment
		out.Evidence.Containment = &ev
	}
	return &out
}

func capsuleSHA256(t *testing.T, c *posture.Capsule) string {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal capsule: %v", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
