// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
)

const claimsDictionaryPath = "../claims/aarp-v0.1-claims.json"

// Enum and pattern constraints mirror aarp-v0.1-claims.schema.json. The published
// schema is otherwise unenforced by any build step, so a typo in the JSON (e.g.
// kind: "verified_clam") would ship green. These guards keep the JSON from
// drifting from its own declared schema.
var (
	validClaimKinds    = []string{"verified_claim", "does_not_assert", "overclaim_risk"}
	validClaimAxes     = []string{"identity", "authority", "integrity", "freshness", "transparency", "deployment", "limitation", "risk"}
	validClaimStatuses = []string{"emitted", "reserved"}
	claimNamePattern   = regexp.MustCompile(`^[a-z0-9_\-]+$`)
	topLevelKeys       = []string{"schema_version", "profile", "entries"}
	entryKeys          = []string{"claim", "kind", "axis", "status", "proves", "does_not_prove", "tested_by"}
)

type claimsDictionary struct {
	SchemaVersion string                `json:"schema_version"`
	Profile       string                `json:"profile"`
	Entries       []claimsDictionaryRow `json:"entries"`
}

type claimsDictionaryRow struct {
	Claim        string   `json:"claim"`
	Kind         string   `json:"kind"`
	Axis         string   `json:"axis"`
	Status       string   `json:"status"`
	Proves       string   `json:"proves"`
	DoesNotProve []string `json:"does_not_prove"`
	TestedBy     string   `json:"tested_by"`
}

func loadClaimsDictionary(t *testing.T) claimsDictionary {
	t.Helper()

	raw, err := os.ReadFile(claimsDictionaryPath)
	if err != nil {
		t.Fatalf("read claims dictionary: %v", err)
	}
	var dict claimsDictionary
	if err := json.Unmarshal(raw, &dict); err != nil {
		t.Fatalf("unmarshal claims dictionary: %v", err)
	}
	return dict
}

func assertKnownJSONKeys(t *testing.T, raw json.RawMessage, context string, want []string) {
	t.Helper()

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal %s object: %v", context, err)
	}
	for _, key := range want {
		if _, ok := obj[key]; !ok {
			t.Fatalf("%s missing required key %q", context, key)
		}
	}
	for key := range obj {
		if !slices.Contains(want, key) {
			t.Fatalf("%s has unknown key %q", context, key)
		}
	}
}

func claimRowsByName(t *testing.T, dict claimsDictionary) map[string]claimsDictionaryRow {
	t.Helper()

	rows := make(map[string]claimsDictionaryRow, len(dict.Entries))
	for _, row := range dict.Entries {
		if _, ok := rows[row.Claim]; ok {
			t.Fatalf("duplicate claim dictionary entry %q", row.Claim)
		}
		rows[row.Claim] = row
	}
	return rows
}

func TestAARPClaimsDictionaryRequiredFields(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(claimsDictionaryPath)
	if err != nil {
		t.Fatalf("read claims dictionary: %v", err)
	}
	assertKnownJSONKeys(t, raw, "claims dictionary", topLevelKeys)

	var rawDict struct {
		SchemaVersion string            `json:"schema_version"`
		Profile       string            `json:"profile"`
		Entries       []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(raw, &rawDict); err != nil {
		t.Fatalf("unmarshal raw claims dictionary: %v", err)
	}
	if len(rawDict.Entries) == 0 {
		t.Fatal("claims dictionary has no entries")
	}
	for i, rawEntry := range rawDict.Entries {
		assertKnownJSONKeys(t, rawEntry, "claims dictionary entry", entryKeys)
		if len(rawEntry) == 0 {
			t.Fatalf("entry %d is empty", i)
		}
	}

	var dict claimsDictionary
	if err := json.Unmarshal(raw, &dict); err != nil {
		t.Fatalf("unmarshal claims dictionary: %v", err)
	}
	if dict.SchemaVersion != "aarp-claims-dictionary/v0.1" {
		t.Fatalf("schema_version = %q", dict.SchemaVersion)
	}
	if dict.Profile != aarp.Profile {
		t.Fatalf("profile = %q, want %q", dict.Profile, aarp.Profile)
	}
	for _, row := range dict.Entries {
		if row.Claim == "" {
			t.Fatal("entry with empty claim")
		}
		if !claimNamePattern.MatchString(row.Claim) {
			t.Fatalf("claim %q violates schema pattern %s", row.Claim, claimNamePattern)
		}
		if row.Kind == "" || row.Axis == "" || row.Status == "" {
			t.Fatalf("%s missing kind/axis/status: %+v", row.Claim, row)
		}
		if !slices.Contains(validClaimKinds, row.Kind) {
			t.Fatalf("%s kind %q not in schema enum %v", row.Claim, row.Kind, validClaimKinds)
		}
		if !slices.Contains(validClaimAxes, row.Axis) {
			t.Fatalf("%s axis %q not in schema enum %v", row.Claim, row.Axis, validClaimAxes)
		}
		if !slices.Contains(validClaimStatuses, row.Status) {
			t.Fatalf("%s status %q not in schema enum %v", row.Claim, row.Status, validClaimStatuses)
		}
		switch row.Kind {
		case "verified_claim":
			if row.Axis == "limitation" || row.Axis == "risk" {
				t.Fatalf("%s verified_claim has non-proof axis %q", row.Claim, row.Axis)
			}
		case "does_not_assert":
			if row.Axis != "limitation" {
				t.Fatalf("%s does_not_assert axis = %q, want limitation", row.Claim, row.Axis)
			}
		case "overclaim_risk":
			if row.Axis != "risk" {
				t.Fatalf("%s overclaim_risk axis = %q, want risk", row.Claim, row.Axis)
			}
		}
		if row.Proves == "" {
			t.Fatalf("%s missing proves", row.Claim)
		}
		if len(row.DoesNotProve) == 0 {
			t.Fatalf("%s missing does_not_prove", row.Claim)
		}
		for _, dnp := range row.DoesNotProve {
			if dnp == "" {
				t.Fatalf("%s has empty does_not_prove item", row.Claim)
			}
		}
		if row.TestedBy == "" {
			t.Fatalf("%s missing tested_by", row.Claim)
		}
	}
}

func TestAARPClaimsDictionaryEmittedClaimsMirrorGoConstants(t *testing.T) {
	t.Parallel()

	rows := claimRowsByName(t, loadClaimsDictionary(t))

	wantEmitted := []string{
		aarp.ClaimReceiptSignatureValid,
		aarp.ClaimMediatorKeyPinned,
		aarp.ClaimReceiptTimestampMonotonicChainPresent,
		aarp.ClaimSigningWorkloadSVIDChainValidated,
		aarp.ClaimSigningWorkloadSVIDBound,
		aarp.ClaimSigningWorkloadSVIDValidAtActionTime,
	}
	for _, claim := range wantEmitted {
		row, ok := rows[claim]
		if !ok {
			t.Fatalf("missing emitted verified claim %q", claim)
		}
		if row.Kind != "verified_claim" || row.Status != "emitted" {
			t.Fatalf("%s row kind/status = %s/%s", claim, row.Kind, row.Status)
		}
	}

	row, ok := rows[aarp.ClaimPolicyHashBound]
	if !ok {
		t.Fatalf("missing reserved policy hash claim %q", aarp.ClaimPolicyHashBound)
	}
	if row.Kind != "verified_claim" || row.Status != "reserved" {
		t.Fatalf("%s row kind/status = %s/%s", aarp.ClaimPolicyHashBound, row.Kind, row.Status)
	}
}

// emittedSurfaceFixtureMap lists the single-envelope appraisal fixtures whose
// does_not_assert / overclaim_risks surface the emitted limitation and risk
// vocabulary. g01 covers the always-emitted baseline; s01 adds the SVID-paired
// negatives and risk; g03 (a genesis chain-link envelope) adds the chain-link
// claim and chain overclaim risk. The chain-corpus c01 file is a stream-level
// verdict ({chain_linked,length}), not a single-envelope appraisal, so it carries
// no surface to pin against and is deliberately not listed here.
func emittedSurfaceFixtureMap() map[string]string {
	return map[string]string{
		"g01-single-ed25519-mediated":   filepath.Join("testdata", "aarp-corpus", "golden", "g01-single-ed25519-mediated.appraisal.json"),
		"s01-valid-ecdsa-p256-baseline": filepath.Join("testdata", "aarp-corpus", "svid", "s01-valid-ecdsa-p256-baseline.appraisal.json"),
		"g03-chain-genesis-linked":      filepath.Join("testdata", "aarp-corpus", "golden", "g03-chain-genesis-linked.appraisal.json"),
	}
}

func readAppraisalSurface(t *testing.T, fixture string) (verifiedClaims, doesNotAssert, overclaimRisk []string) {
	t.Helper()

	cleanFixture := filepath.Clean(fixture)
	raw, err := os.ReadFile(cleanFixture)
	if err != nil {
		t.Fatalf("read %s: %v", cleanFixture, err)
	}
	var got struct {
		VerifiedClaims []string `json:"verified_claims"`
		DoesNotAssert  []string `json:"does_not_assert"`
		OverclaimRisk  []string `json:"overclaim_risks"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", cleanFixture, err)
	}
	return got.VerifiedClaims, got.DoesNotAssert, got.OverclaimRisk
}

func TestAARPClaimsDictionaryCoversFixtureLimitationsAndRisks(t *testing.T) {
	t.Parallel()

	rows := claimRowsByName(t, loadClaimsDictionary(t))
	for _, fixture := range emittedSurfaceFixtureMap() {
		cleanFixture := filepath.Clean(fixture)
		_, gotDoesNotAssert, gotOverclaimRisk := readAppraisalSurface(t, fixture)
		for _, claim := range gotDoesNotAssert {
			row, ok := rows[claim]
			if !ok {
				t.Fatalf("%s does_not_assert %q missing from dictionary", cleanFixture, claim)
			}
			if row.Kind != "does_not_assert" || row.Status != "emitted" {
				t.Fatalf("%s limitation %s kind/status = %s/%s", cleanFixture, claim, row.Kind, row.Status)
			}
		}
		for _, claim := range gotOverclaimRisk {
			row, ok := rows[claim]
			if !ok {
				t.Fatalf("%s overclaim_risk %q missing from dictionary", cleanFixture, claim)
			}
			if row.Kind != "overclaim_risk" || row.Status != "emitted" {
				t.Fatalf("%s risk %s kind/status = %s/%s", cleanFixture, claim, row.Kind, row.Status)
			}
		}
	}
}

// TestAARPClaimsDictionaryEmittedSurfaceIsFixtureBacked is the reverse of
// TestAARPClaimsDictionaryCoversFixtureLimitationsAndRisks: it proves every
// dictionary entry marked emitted (verified_claim, does_not_assert, or
// overclaim_risk) is actually produced by at least one appraisal fixture. Without
// this direction, an entry can sit "emitted" in the dictionary while no fixture
// emits it and no test pins it — exactly the state the chain overclaim risk was in
// when its tested_by pointed at the empty c01 stream verdict.
func TestAARPClaimsDictionaryEmittedSurfaceIsFixtureBacked(t *testing.T) {
	t.Parallel()

	emitted := make(map[string]struct{})
	byFixture := make(map[string]map[string]struct{})
	for slug, fixture := range emittedSurfaceFixtureMap() {
		verifiedClaims, doesNotAssert, overclaimRisk := readAppraisalSurface(t, fixture)
		claims := make(map[string]struct{})
		for _, group := range [][]string{verifiedClaims, doesNotAssert, overclaimRisk} {
			for _, claim := range group {
				emitted[claim] = struct{}{}
				claims[claim] = struct{}{}
			}
		}
		byFixture[slug] = claims
	}

	for _, row := range loadClaimsDictionary(t).Entries {
		if row.Status != "emitted" {
			continue
		}
		switch row.Kind {
		case "verified_claim", "does_not_assert", "overclaim_risk":
		default:
			continue
		}
		if _, ok := emitted[row.Claim]; !ok {
			t.Fatalf("dictionary marks %s %q emitted, but no appraisal fixture emits it (tested_by=%q is unbacked)",
				row.Kind, row.Claim, row.TestedBy)
		}
		fixtureClaims, ok := byFixture[row.TestedBy]
		if !ok {
			t.Fatalf("dictionary marks %s %q emitted, but tested_by=%q is not an emitted appraisal fixture",
				row.Kind, row.Claim, row.TestedBy)
		}
		if _, ok := fixtureClaims[row.Claim]; !ok {
			t.Fatalf("dictionary marks %s %q emitted, but tested_by=%q does not emit it",
				row.Kind, row.Claim, row.TestedBy)
		}
	}
}

func TestAARPClaimsDictionaryReservedVocabulary(t *testing.T) {
	t.Parallel()

	rows := claimRowsByName(t, loadClaimsDictionary(t))
	for _, claim := range []string{
		"external_witness_checkpoint_signature_valid",
		"receipt_chain_root_matches_witnessed_checkpoint",
		"witness_checkpoint_covers_chain_seq_range",
		"witness_checkpoint_observed_at_time",
		"witness_checkpoint_gap_bounded_observed",
		"k8s_namespace_egress_policy_restricts_workload_to_mediator_observed",
		"k8s_pod_spec_proxy_injection_observed",
		"k8s_workload_identity_bound_to_mediator_policy",
		"k8s_admission_policy_hash_bound",
		"linux_process_egress_owner_rule_observed",
		"does_not_assert_all_receipts_submitted_to_witness",
		"does_not_assert_pre_witness_omission_absence",
		"does_not_assert_no_split_view_without_gossip",
		"does_not_assert_action_stream_completeness",
		"does_not_assert_cluster_admin_cannot_bypass",
		"does_not_assert_node_root_cannot_bypass",
		"does_not_assert_cni_enforcement_correctness",
		"does_not_assert_saas_side_actions_mediated",
		"does_not_assert_runtime_state_unchanged_after_snapshot",
		"does_not_assert_all_namespaces_or_workloads_covered",
	} {
		row, ok := rows[claim]
		if !ok {
			t.Fatalf("missing reserved vocabulary %q", claim)
		}
		if row.Status != "reserved" {
			t.Fatalf("%s status = %s, want reserved", claim, row.Status)
		}
	}
}

func TestAARPClaimsDictionaryOmissionWindowCorrection(t *testing.T) {
	t.Parallel()

	rows := claimRowsByName(t, loadClaimsDictionary(t))
	if _, ok := rows["omission_window_bounded"]; ok {
		t.Fatal("dictionary must not publish the overclaiming omission_window_bounded name")
	}

	row, ok := rows["witness_checkpoint_gap_bounded_observed"]
	if !ok {
		t.Fatal("missing witness_checkpoint_gap_bounded_observed")
	}
	if row.Status != "reserved" {
		t.Fatalf("witness checkpoint gap status = %s, want reserved", row.Status)
	}
	if !slices.Contains(row.DoesNotProve, "absence of omitted actions") {
		t.Fatalf("witness checkpoint gap does_not_prove = %v, want absence of omitted actions", row.DoesNotProve)
	}
}
