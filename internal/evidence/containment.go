// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/posture"
)

type ContainmentGrade string

const (
	ContainUnknown  ContainmentGrade = "unknown"
	ContainProxyEnv ContainmentGrade = "proxy_env"
	// ContainKernelObserved grades a signed nftables owner-match posture capsule
	// whose direct-egress probe was kernel-refused at attestation time, with the
	// receipt window bound inside the capsule validity window. It attests the
	// boundary AT the attestation moment, not continuous kernel enforcement
	// across the whole window: a point-in-time probe cannot rule out a
	// teardown-and-restore of the rule between probes (which requires root, out
	// of scope for the contained agent), and the nft owner-match keys on the
	// socket fsuid (meta skuid), so a setuid or file-capability helper reachable
	// by the agent is a residual seam. This is the honest near-term tier for the
	// agent-adversary threat model.
	ContainKernelObserved ContainmentGrade = "kernel_observed"
	// ContainKernelEnforced is RESERVED for a future eBPF/LSM kernel-gate that
	// denies egress unless identity+epoch match and can therefore prove
	// continuous enforcement. No current code path emits it; the nftables
	// owner-match tier grades ContainKernelObserved. Kept defined so the grade
	// ladder is explicit and the airtight label stays reserved for the capstone.
	ContainKernelEnforced ContainmentGrade = "kernel_enforced"
)

type ContainmentAssessment struct {
	Grade      ContainmentGrade
	Mode       string
	CapsuleID  string
	Window     string
	Reasons    []string
	AllowClaim bool
}

type ContainmentAssessmentOptions struct {
	Capsule     *posture.Capsule
	TrustedKey  ed25519.PublicKey
	ReceiptFrom time.Time
	ReceiptTo   time.Time
	ActorUID    string
	// CapsuleSHA256 is the verifier-computed SHA-256 over the supplied posture
	// capsule's canonical JSON. ReceiptCapsuleSHA256 is the value signed into
	// session_open. Kernel containment claims require equality so a posture capsule
	// for another run cannot be replayed against these receipts.
	CapsuleSHA256        string
	ReceiptCapsuleSHA256 string
	ReceiptSignerKeyID   string
	Now                  time.Time
}

func AssessContainment(opts ContainmentAssessmentOptions) ContainmentAssessment {
	out := ContainmentAssessment{Grade: ContainUnknown}
	if opts.Capsule == nil {
		out.Reasons = append(out.Reasons, "no posture capsule supplied")
		return out
	}
	out.CapsuleID = capsuleID(opts.Capsule)
	out.Window = fmt.Sprintf("%s..%s", opts.Capsule.GeneratedAt.UTC().Format(time.RFC3339), opts.Capsule.ExpiresAt.UTC().Format(time.RFC3339))
	if len(opts.TrustedKey) != ed25519.PublicKeySize {
		out.Reasons = append(out.Reasons, "posture signer key is not trusted")
		return out
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := posture.VerifyAt(opts.Capsule, opts.TrustedKey, now); err != nil {
		out.Reasons = append(out.Reasons, "posture verification failed: "+err.Error())
		return out
	}
	if opts.Capsule.GeneratedAt.IsZero() || opts.Capsule.ExpiresAt.IsZero() || !opts.Capsule.GeneratedAt.Before(opts.Capsule.ExpiresAt) {
		out.Reasons = append(out.Reasons, "posture capsule window is invalid")
		return out
	}
	if now.After(opts.Capsule.ExpiresAt) {
		out.Reasons = append(out.Reasons, "posture capsule expired")
		return out
	}
	if !opts.ReceiptFrom.IsZero() && opts.ReceiptFrom.Before(opts.Capsule.GeneratedAt) {
		out.Reasons = append(out.Reasons, "posture window starts after receipt window")
		return out
	}
	if !opts.ReceiptTo.IsZero() && opts.ReceiptTo.After(opts.Capsule.ExpiresAt) {
		out.Reasons = append(out.Reasons, "posture window ends before receipt window")
		return out
	}
	ev := opts.Capsule.Evidence.Containment
	if ev == nil {
		out.Reasons = append(out.Reasons, "posture capsule has no live containment evidence")
		return out
	}
	out.Mode = ev.Mode
	if ev.Mode == posture.ContainmentModeKernelNFTOwnerMatch {
		if reason := kernelContainmentBindingFailure(opts, ev); reason != "" {
			out.Reasons = append(out.Reasons, reason)
			return out
		}
	}
	switch {
	case ev.Mode == posture.ContainmentModeKernelNFTOwnerMatch && ev.BoundaryVerified && ev.ProbeRefusedDirectEgress:
		out.Grade = ContainKernelObserved
		out.AllowClaim = true
	case ev.Mode == posture.ContainmentModeBestEffortProxyEnv:
		out.Grade = ContainProxyEnv
	default:
		out.Reasons = append(out.Reasons, "live containment evidence is incomplete")
	}
	return out
}

func kernelContainmentBindingFailure(opts ContainmentAssessmentOptions, ev *posture.ContainmentEvidence) string {
	if strings.TrimSpace(opts.ActorUID) == "" {
		return "receipt actor/principal binding has no contained uid"
	}
	if strings.TrimSpace(ev.TargetUID) == "" || ev.TargetUID != opts.ActorUID {
		return "containment target uid does not match receipt actor/principal binding"
	}
	if strings.TrimSpace(ev.KernelRuleHash) == "" {
		return "containment kernel rule hash is missing"
	}
	if !isLowerSHA256Hex(ev.KernelRuleHash) {
		return "containment kernel rule hash is not a lowercase SHA-256 hex digest"
	}
	if strings.TrimSpace(opts.CapsuleSHA256) == "" ||
		strings.TrimSpace(opts.ReceiptCapsuleSHA256) == "" ||
		opts.CapsuleSHA256 != opts.ReceiptCapsuleSHA256 {
		return "receipt session_open is not bound to this posture capsule"
	}
	if strings.TrimSpace(opts.ReceiptSignerKeyID) == "" || opts.ReceiptSignerKeyID != opts.Capsule.SignerKeyID {
		return "receipt session_open posture signer does not match capsule signer"
	}
	return ""
}

func isLowerSHA256Hex(s string) bool {
	if len(s) != sha256HexLen || strings.ToLower(s) != s {
		return false
	}
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == sha256DigestLen
}

const (
	sha256HexLen    = 64
	sha256DigestLen = 32
)

func FormatContainmentAssessment(a ContainmentAssessment) string {
	switch a.Grade {
	case ContainKernelObserved:
		return fmt.Sprintf("Containment: KERNEL-OBSERVED — signed nftables owner-match boundary attested at capsule time (capsule %s, window %s); direct egress by the contained UID was kernel-refused when probed. This attests the boundary at attestation time within the window, not continuous enforcement across it, and does not cover a setuid/file-capability helper that changes the socket UID (kernel_enforced is reserved for the eBPF/LSM gate).", a.CapsuleID, a.Window)
	case ContainKernelEnforced:
		return fmt.Sprintf("Containment: KERNEL-ENFORCED — eBPF/LSM kernel-gate attested continuous enforcement (capsule %s, window %s); direct egress by the contained UID was kernel-refused.", a.CapsuleID, a.Window)
	case ContainProxyEnv:
		return "Containment: PROXY-ENV (best-effort) — cooperative egress observed; an agent that clears HTTP(S)_PROXY can bypass (L-CONTAINMENT-UNPROVEN)."
	default:
		return "Containment: UNKNOWN — this bundle proves what was routed through the proxy; it does NOT prove the agent could not bypass it (see L-CONTAINMENT-UNPROVEN). Supply --posture to attest containment."
	}
}

func capsuleID(c *posture.Capsule) string {
	if c == nil || c.Signature == "" {
		return "unknown"
	}
	if len(c.Signature) <= 12 {
		return c.Signature
	}
	return c.Signature[:12]
}

func DecodePostureKey(hexKey string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("posture key length=%d want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
