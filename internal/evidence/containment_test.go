// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
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
	if kernel.Grade != ContainKernelObserved || !kernel.AllowClaim {
		t.Fatalf("kernel assessment = %+v", kernel)
	}
	kernelLine := FormatContainmentAssessment(kernel)
	if !strings.Contains(kernelLine, "direct egress by the contained UID was kernel-refused") {
		t.Fatalf("kernel line missing gated claim: %s", kernelLine)
	}
	// The point-in-time nft owner-match tier must render as KERNEL-OBSERVED and
	// must NOT overclaim continuous enforcement (kernel_enforced is reserved for
	// the future eBPF/LSM gate). It must disclose the point-in-time nature.
	if !strings.Contains(kernelLine, "KERNEL-OBSERVED") {
		t.Fatalf("observed tier not labelled KERNEL-OBSERVED: %s", kernelLine)
	}
	if strings.Contains(kernelLine, "KERNEL-ENFORCED") {
		t.Fatalf("point-in-time tier overclaims KERNEL-ENFORCED: %s", kernelLine)
	}
	if !strings.Contains(kernelLine, "not continuous enforcement") {
		t.Fatalf("observed tier does not disclose point-in-time nature: %s", kernelLine)
	}
	if kernel.Grade != "kernel_observed" {
		t.Fatalf("observed grade string drifted: %q", kernel.Grade)
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
		{"rule_hash_malformed", func(o *ContainmentAssessmentOptions) {
			o.Capsule = validContainmentCapsule(t, priv, posture.ContainmentEvidence{
				Mode:                     posture.ContainmentModeKernelNFTOwnerMatch,
				BoundaryVerified:         true,
				ProbeRefusedDirectEgress: true,
				KernelRuleHash:           "x",
				TargetUID:                "966",
			})
			o.CapsuleSHA256 = capsuleSHA256(t, o.Capsule)
			o.ReceiptCapsuleSHA256 = o.CapsuleSHA256
			o.ReceiptSignerKeyID = o.Capsule.SignerKeyID
		}},
		{"rule_hash_uppercase", func(o *ContainmentAssessmentOptions) {
			o.Capsule = validContainmentCapsule(t, priv, posture.ContainmentEvidence{
				Mode:                     posture.ContainmentModeKernelNFTOwnerMatch,
				BoundaryVerified:         true,
				ProbeRefusedDirectEgress: true,
				KernelRuleHash:           strings.Repeat("A", 64),
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

func TestAssessContainmentUsesOptionNowForCapsuleExpiry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	capsule := validContainmentCapsule(t, priv, posture.ContainmentEvidence{
		Mode:                     posture.ContainmentModeKernelNFTOwnerMatch,
		BoundaryVerified:         true,
		ProbeRefusedDirectEgress: true,
		KernelRuleHash:           strings.Repeat("a", 64),
		TargetUID:                "966",
	})
	capsule.GeneratedAt = time.Now().UTC().Add(-48 * time.Hour)
	capsule.ExpiresAt = time.Now().UTC().Add(-24 * time.Hour)
	capsule.Signature = resignContainmentCapsule(t, capsule, priv)

	opts := ContainmentAssessmentOptions{
		Capsule:              capsule,
		TrustedKey:           pub,
		ReceiptFrom:          capsule.GeneratedAt.Add(time.Hour),
		ReceiptTo:            capsule.ExpiresAt.Add(-time.Hour),
		ActorUID:             "966",
		CapsuleSHA256:        capsuleSHA256(t, capsule),
		ReceiptCapsuleSHA256: capsuleSHA256(t, capsule),
		ReceiptSignerKeyID:   capsule.SignerKeyID,
		Now:                  capsule.GeneratedAt.Add(2 * time.Hour),
	}
	got := AssessContainment(opts)
	if got.Grade != ContainKernelObserved || !got.AllowClaim {
		t.Fatalf("assessment = %+v, want kernel-observed pass", got)
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

func resignContainmentCapsule(t *testing.T, capsule *posture.Capsule, priv ed25519.PrivateKey) string {
	t.Helper()
	type signableCapsule struct {
		SchemaVersion string                 `json:"schema_version"`
		GeneratedAt   time.Time              `json:"generated_at"`
		ExpiresAt     time.Time              `json:"expires_at"`
		ToolVersion   string                 `json:"tool_version"`
		ConfigHash    string                 `json:"config_hash"`
		Evidence      posture.EvidenceBundle `json:"evidence"`
	}
	payload, err := canonicalJSONForContainmentTest(signableCapsule{
		SchemaVersion: capsule.SchemaVersion,
		GeneratedAt:   capsule.GeneratedAt,
		ExpiresAt:     capsule.ExpiresAt,
		ToolVersion:   capsule.ToolVersion,
		ConfigHash:    capsule.ConfigHash,
		Evidence:      capsule.Evidence,
	})
	if err != nil {
		t.Fatalf("marshal signable capsule: %v", err)
	}
	return hex.EncodeToString(ed25519.Sign(priv, payload))
}

func canonicalJSONForContainmentTest(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := appendCanonicalForContainmentTest(&buf, parsed); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func appendCanonicalForContainmentTest(buf *bytes.Buffer, v any) error {
	switch value := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if value {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		buf.Write(data)
	case json.Number:
		buf.WriteString(value.String())
	case []any:
		buf.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := appendCanonicalForContainmentTest(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for k := range value {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			key, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(key)
			buf.WriteByte(':')
			if err := appendCanonicalForContainmentTest(buf, value[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		buf.Write(data)
	}
	return nil
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
