// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:generate go run ./cmd/limitsdoc

package evidence

type LimitID string

type Limit struct {
	ID       LimitID
	Title    string
	Summary  string
	Bound    string
	Category string
}

const (
	LimitKeyholderOmit       LimitID = "L-KEYHOLDER-OMIT"
	LimitOmitPreAnchor       LimitID = "L-OMIT-PRE-ANCHOR"
	LimitForgedKey           LimitID = "L-FORGED-KEY"
	LimitRecorderBinary      LimitID = "L-RECORDER-BINARY"
	LimitRecorderDisabled    LimitID = "L-RECORDER-DISABLED"
	LimitVerifierDrift       LimitID = "L-VERIFIER-DRIFT"
	LimitMetadataPrivacy     LimitID = "L-METADATA-PRIVACY"
	LimitConnectOpacity      LimitID = "L-CONNECT-OPACITY"
	LimitFsyncHonesty        LimitID = "L-FSYNC-HONESTY"
	LimitFsyncDOS            LimitID = "L-FSYNC-DOS"
	LimitContainmentUnproven LimitID = "L-CONTAINMENT-UNPROVEN"
)

var Limits = []Limit{
	{ID: LimitKeyholderOmit, Title: "Keyholder Omission", Category: "completeness", Summary: "No in-domain mechanism proves completeness against the party holding the signing key.", Bound: "C2 second recorder / C4 counterparty (separately keyed)."},
	{ID: LimitOmitPreAnchor, Title: "Pre-Anchor Omission", Category: "completeness", Summary: "Whole-session omission BEFORE the first anchor is undetectable.", Bound: "Anchor interval + genesis anchor_head binding."},
	{ID: LimitForgedKey, Title: "Compromised Signing Key", Category: "completeness", Summary: "A record forged under a COMPROMISED signing key is in-domain indistinguishable from a real one.", Bound: "Anchor interval + C2 (attacker lacks the agent-side key)."},
	{ID: LimitRecorderBinary, Title: "Recorder Binary Trust", Category: "recorder-integrity", Summary: "A malicious/modified recorder binary IS the attacker; its output cannot vouch for itself.", Bound: "Release signing + contain-install binary-hash TOFU pin + external attestation."},
	{ID: LimitRecorderDisabled, Title: "Recorder Disabled", Category: "config", Summary: "A disabled recorder / receipts-off config is a no-op success; nothing is proven.", Bound: "Recorder-enabled state attested and MIN'd into the grade."},
	{ID: LimitVerifierDrift, Title: "Verifier Drift", Category: "cross-impl", Summary: "Divergent verdicts across verifier implementations/versions break the shared-truth property.", Bound: "Cross-language mutation harness (identical verdicts on identical bytes)."},
	{ID: LimitMetadataPrivacy, Title: "Metadata Privacy", Category: "privacy", Summary: "Fingerprints/headers/session-id/timestamps/signer-keys in shared or anchored bundles leak metadata.", Bound: "Metadata-privacy budget; redact shareable bundles."},
	{ID: LimitConnectOpacity, Title: "CONNECT Opacity", Category: "observability", Summary: "CONNECT/TLS passthrough yields only host:port + byte counts; inner method/path/body are uninspectable.", Bound: "TLS interception where deployed; else the fingerprint degrades honestly."},
	{ID: LimitFsyncHonesty, Title: "Fsync Honesty", Category: "recorder-integrity", Summary: "Hardware fsync honesty vs lying storage is unprovable.", Bound: "Attest storage config + capture the syscall return."},
	{ID: LimitFsyncDOS, Title: "Fsync Backpressure", Category: "availability", Summary: "fsync/backpressure is a DoS surface; fail-closed blocking under storage stall can stall egress.", Bound: "fsync_errors_total SLO + alerting; a deliberate integrity-over-availability tradeoff."},
	{ID: LimitContainmentUnproven, Title: "Containment Unproven", Category: "completeness", Summary: "\"The boundary is the witness\" holds only under attested containment; the binary alone cannot prove non-bypass.", Bound: "Containment-attestation grade (item d)."},
}

func ByID(id LimitID) (Limit, bool) {
	for _, limit := range Limits {
		if limit.ID == id {
			return limit, true
		}
	}
	return Limit{}, false
}

func MustSummary(id LimitID) string {
	limit, ok := ByID(id)
	if !ok {
		return string(id)
	}
	return string(limit.ID) + ": " + limit.Summary
}
