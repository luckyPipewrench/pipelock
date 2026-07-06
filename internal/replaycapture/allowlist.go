// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package replaycapture

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// The public-safe field allowlist is the load-bearing privacy control for the
// gallery. It runs BEFORE a packet is assembled and is fail-closed: any
// populated field outside the allowlist, any non-synthetic target host, or any
// raw secret shape aborts publication. It is a gate, not a scrubber — a captured
// receipt that fails here is never published (the fix is the capture config, not
// editing signed bytes).

// errAllowlist is the sentinel wrapping every allowlist rejection.
var errAllowlist = errors.New("public-safe allowlist violation")

// allowedPrincipals / allowedActors are the only identity values a published
// receipt may carry. They name the synthetic lab, never a real org or agent.
var (
	allowedPrincipals = map[string]struct{}{labPrincipal: {}}
	allowedActors     = map[string]struct{}{labActor: {}}
)

// reservedHostSuffixes are RFC 2606 / 6761 reserved labels that never resolve to
// real infrastructure. A published receipt's target hostname must end in one.
var reservedHostSuffixes = []string{
	".example", ".test", ".invalid",
	".example.com", ".example.net", ".example.org",
}

// reservedHostExact are bare reserved hostnames permitted as-is.
var reservedHostExact = map[string]struct{}{
	"example.com": {},
	"example.net": {},
	"example.org": {},
}

// safeEnumRE constrains the benign taint/authority classification labels a
// published receipt may carry. These are enumerated snake_case decision codes
// (e.g. "trusted", "user_broad", "taint_safe_read_only_action"), never
// free-form text — so a space, a hostname, or a colon means something
// unexpected leaked, and the gate fails closed.
var safeEnumRE = regexp.MustCompile(`^[a-z0-9_]+$`)

// safeRequestIDRE matches pipelock's own internal request id: a "req-" prefix
// followed by a monotonic counter. This carries no provider/account correlation
// and no private data — it is a sequence number. Any other shape (e.g. a real
// provider request id) is rejected.
var safeRequestIDRE = regexp.MustCompile(`^req-[0-9]+$`)

// safeRunNonceRE matches the per-process receipt nonce emitted as 16 random
// bytes encoded lowercase hex. It carries no private context, but the public
// packet gate still constrains the shape so arbitrary strings cannot publish.
var safeRunNonceRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

var safeSessionOpenGenesisRE = regexp.MustCompile(`^g1:[0-9a-f]{64}$`)

var safeSignerEpochRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// secretShapeRE is a backstop: if any of these shapes survive into a target or
// pattern, redaction-before-sign failed and the artifact must not publish. This
// is defense-in-depth behind the emitter's pre-sign sanitizer.
var secretShapeRE = regexp.MustCompile(
	`AKIA[0-9A-Z]{16}` + // AWS access key id
		`|sk-ant-[A-Za-z0-9\-_]{10,}` + // Anthropic
		`|sk-proj-[A-Za-z0-9\-_]{10,}` + // OpenAI
		`|gh[pousr]_[A-Za-z0-9_]{20,}` + // GitHub
		`|xox[baprs]-[A-Za-z0-9-]{10,}`, // Slack
)

// ValidateReceiptPublicSafe enforces the published-receipt field allowlist on
// one action record. It returns an error wrapping errAllowlist on any violation.
func ValidateReceiptPublicSafe(ar receipt.ActionRecord) error {
	// Required, safe-by-construction identity.
	if _, ok := allowedPrincipals[ar.Principal]; !ok {
		return fmt.Errorf("%w: principal %q not in lab allowlist", errAllowlist, ar.Principal)
	}
	if _, ok := allowedActors[ar.Actor]; !ok {
		return fmt.Errorf("%w: actor %q not in lab allowlist", errAllowlist, ar.Actor)
	}
	if ar.SessionControl != nil {
		return validatePublicSessionOpen(ar)
	}

	// Target host must be synthetic / reserved / documentation-space.
	if err := validateSafeTarget(ar.Target); err != nil {
		return err
	}

	// Secret-shape backstop on the free-text fields.
	for label, val := range map[string]string{"target": ar.Target, "pattern": ar.Pattern} {
		if secretShapeRE.MatchString(val) {
			return fmt.Errorf("%w: %s carries a raw secret shape (redaction-before-sign failed)", errAllowlist, label)
		}
	}

	// request_id, when present, must be pipelock's own internal counter shape.
	if ar.RequestID != "" && !safeRequestIDRE.MatchString(ar.RequestID) {
		return fmt.Errorf("%w: request_id %q is not the internal counter shape", errAllowlist, ar.RequestID)
	}
	if ar.RunNonce != "" && !safeRunNonceRE.MatchString(ar.RunNonce) {
		return fmt.Errorf("%w: run_nonce %q is not the expected nonce shape", errAllowlist, ar.RunNonce)
	}

	// Benign taint/authority classification labels: allowed only when they match
	// the enumerated snake_case shape (empty is also fine).
	for name, val := range map[string]string{
		"session_taint_level":   ar.SessionTaintLevel,
		"authority_kind":        ar.AuthorityKind,
		"taint_decision":        ar.TaintDecision,
		"taint_decision_reason": ar.TaintDecisionReason,
	} {
		if val != "" && !safeEnumRE.MatchString(val) {
			return fmt.Errorf("%w: %s %q is not a safe enumerated label", errAllowlist, name, val)
		}
	}

	// Fields that must be empty: anything that could carry session correlation,
	// contract/manifest identity, jurisdiction, intent, or data-class labels.
	// None of these are populated in the synthetic lab; a non-empty value means
	// an unexpected code path leaked context.
	return validateDisallowedEmpty(ar)
}

func validatePublicSessionOpen(ar receipt.ActionRecord) error {
	if ar.Target != "pipelock://session/open" {
		return fmt.Errorf("%w: session_open target %q is not the expected control target", errAllowlist, ar.Target)
	}
	if ar.SessionControl.Kind != receipt.SessionControlOpen || ar.SessionControl.Open == nil ||
		ar.SessionControl.Heartbeat != nil || ar.SessionControl.Close != nil {
		return fmt.Errorf("%w: only session_open control receipts are public-safe", errAllowlist)
	}
	open := ar.SessionControl.Open
	if ar.RunNonce == "" || open.RunNonce != ar.RunNonce || !safeRunNonceRE.MatchString(ar.RunNonce) {
		return fmt.Errorf("%w: session_open run_nonce is not the expected nonce shape", errAllowlist)
	}
	if !safeRunNonceRE.MatchString(open.OpenNonce) {
		return fmt.Errorf("%w: session_open open_nonce is not the expected nonce shape", errAllowlist)
	}
	if open.RecorderSession != "proxy" {
		return fmt.Errorf("%w: session_open recorder_session %q is not public-safe", errAllowlist, open.RecorderSession)
	}
	if !strings.HasPrefix(open.PolicyHash, policyHashLabelPrefix) {
		return fmt.Errorf("%w: session_open policy_hash %q is not labeled", errAllowlist, open.PolicyHash)
	}
	if !safeSignerEpochRE.MatchString(open.SignerKeyEpoch) {
		return fmt.Errorf("%w: session_open signer_key_epoch is not a hex public key", errAllowlist)
	}
	if open.HeartbeatSeconds != 0 {
		return fmt.Errorf("%w: session_open heartbeat_seconds = %d, want 0 for this build", errAllowlist, open.HeartbeatSeconds)
	}
	if open.ChainOpenSeq != ar.ChainSeq {
		return fmt.Errorf("%w: session_open chain_open_seq does not match chain_seq", errAllowlist)
	}
	if open.GenesisHash != ar.ChainPrevHash || !safeSessionOpenGenesisRE.MatchString(open.GenesisHash) {
		return fmt.Errorf("%w: session_open genesis hash is not the expected g1 shape", errAllowlist)
	}
	if open.PriorChainHead != "" || open.PriorChainSeq != 0 ||
		open.GenesisAnchorHead != "" || open.GenesisAnchorLog != "" ||
		open.PostureCapsuleSHA256 != "" || open.PostureSignerKeyID != "" ||
		open.ContainmentNonce != "" || open.ContainedUID != "" {
		return fmt.Errorf("%w: session_open carries unsupported public-gallery binding fields", errAllowlist)
	}
	return validateDisallowedEmpty(ar)
}

// validateSafeTarget parses a receipt target and confirms its host is synthetic
// or documentation-space (reserved hostname, the exact cloud metadata address,
// or RFC 5737 literal). Loopback literals are intentionally rejected so local
// fixture details cannot land in signed public artifacts.
func validateSafeTarget(target string) error {
	if target == "" {
		return fmt.Errorf("%w: empty target", errAllowlist)
	}
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("%w: unparseable target %q: %w", errAllowlist, target, err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: target %q has no host", errAllowlist, target)
	}
	if ip := net.ParseIP(host); ip != nil {
		if safeLabIP(ip) {
			return nil
		}
		return fmt.Errorf("%w: target IP %q is not a lab/reserved address", errAllowlist, host)
	}
	if safeReservedHost(host) {
		return nil
	}
	return fmt.Errorf("%w: target host %q is not a reserved/synthetic name", errAllowlist, host)
}

// safeLabIP reports whether an IP literal is safe to publish: the well-known
// cloud metadata address or the RFC 5737 documentation ranges.
func safeLabIP(ip net.IP) bool {
	if ip.Equal(net.ParseIP(synthMetadataIP)) {
		return true
	}
	for _, cidr := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"} {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// safeReservedHost reports whether a hostname is RFC-reserved/synthetic.
func safeReservedHost(host string) bool {
	host = strings.ToLower(host)
	if _, ok := reservedHostExact[host]; ok {
		return true
	}
	for _, suffix := range reservedHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// validateDisallowedEmpty fails if any context-bearing field is populated.
func validateDisallowedEmpty(ar receipt.ActionRecord) error {
	type check struct {
		name     string
		nonEmpty bool
	}
	checks := []check{
		{"parent_action_id", ar.ParentActionID != ""},
		{"decision_phase", ar.DecisionPhase != ""},
		{"defer_id", ar.DeferID != ""},
		{"resolution_policy", ar.ResolutionPolicy != ""},
		{"resolution_source", ar.ResolutionSource != ""},
		{"session_id", ar.SessionID != ""},
		{"session_id_original", ar.SessionIDOriginal != ""},
		{"intent", ar.Intent != ""},
		{"data_classes_in", len(ar.DataClassesIn) > 0},
		{"data_classes_out", len(ar.DataClassesOut) > 0},
		{"delegation_chain", len(ar.DelegationChain) > 0},
		{"session_contaminated", ar.SessionContaminated},
		{"recent_taint_sources", len(ar.RecentTaintSources) > 0},
		{"session_task_id", ar.SessionTaskID != ""},
		{"session_task_label", ar.SessionTaskLabel != ""},
		{"task_override_applied", ar.TaskOverrideApplied},
		{"contract_winning_source", ar.ContractWinningSource != ""},
		{"contract_live_verdict", ar.ContractLiveVerdict != ""},
		{"contract_policy_sources", len(ar.ContractPolicySources) > 0},
		{"contract_rule_id", ar.ContractRuleID != ""},
		{"active_manifest_hash", ar.ActiveManifestHash != ""},
		{"contract_hash", ar.ContractHash != ""},
		{"contract_selector_id", ar.ContractSelectorID != ""},
		{"contract_generation", ar.ContractGeneration != 0},
		{"redaction", ar.Redaction != nil},
		{"shield", ar.Shield != nil},
		// key_transition is stamped only on a chain segment boundary after a
		// signing-key rotation. The synthetic lab captures clean genesis
		// chains under a single key and never rotates mid-capture, so a
		// populated marker means an unexpected rotation path leaked into a
		// published packet. Fail closed.
		{"key_transition", ar.KeyTransition != nil},
		{"venue", ar.Venue != ""},
		{"jurisdiction", ar.Jurisdiction != ""},
		{"rulebook_id", ar.RulebookID != ""},
		{"remedy_class", ar.RemedyClass != ""},
		{"contestation_window", ar.ContestationWindow != ""},
		{"precedent_refs", len(ar.PrecedentRefs) > 0},
	}
	for _, c := range checks {
		if c.nonEmpty {
			return fmt.Errorf("%w: disallowed field %s is populated", errAllowlist, c.name)
		}
	}
	return nil
}
