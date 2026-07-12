//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cli/presets"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"gopkg.in/yaml.v3"
)

var testNow = time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)

func TestPolicyBundle_SignablePreimageExcludesSignatures(t *testing.T) {
	a := testPolicyBundle()
	b := testPolicyBundle()
	b.Signatures[0].Signature = testSignature("ab")
	b.Signatures[0].SignerKeyID = "different-signer"

	preA, err := a.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(a): %v", err)
	}
	preB, err := b.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(b): %v", err)
	}
	if string(preA) != string(preB) {
		t.Fatalf("preimage changed when detached signatures changed:\na=%s\nb=%s", preA, preB)
	}
}

func TestPolicyBundle_Validate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		if err := testPolicyBundle().Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("forbidden_license_field", func(t *testing.T) {
		b := testPolicyBundle()
		b.Payload.ConfigYAML = "mode: strict\nlicense_key: token\n"
		err := b.Validate()
		if !errors.Is(err, ErrForbiddenLicenseField) {
			t.Fatalf("Validate() = %v, want ErrForbiddenLicenseField", err)
		}
	})

	t.Run("wrong_signature_purpose", func(t *testing.T) {
		b := testPolicyBundle()
		b.Signatures[0].KeyPurpose = signing.PurposeRemoteKillSigning
		err := b.Validate()
		if !errors.Is(err, ErrWrongKeyPurpose) {
			t.Fatalf("Validate() = %v, want ErrWrongKeyPurpose", err)
		}
	})

	t.Run("audience_mismatch", func(t *testing.T) {
		b := testPolicyBundle()
		err := b.ValidateForFollower("org-test", "fleet-prod", "instance-other", map[string]string{"tier": "prod"})
		if !errors.Is(err, ErrAudienceMismatch) {
			t.Fatalf("ValidateForFollower() = %v, want ErrAudienceMismatch", err)
		}
	})

	t.Run("label_audience_match", func(t *testing.T) {
		b := testPolicyBundle()
		b.Audience = Audience{Labels: map[string]string{"tier": "prod"}}
		err := b.ValidateForFollower("org-test", "fleet-prod", "instance-other", map[string]string{"tier": "prod"})
		if err != nil {
			t.Fatalf("ValidateForFollower() = %v, want nil", err)
		}
	})

	t.Run("payload_hash_mismatch", func(t *testing.T) {
		b := testPolicyBundle()
		b.PayloadSHA256 = testHash("03")
		err := b.Validate()
		if !errors.Is(err, ErrHashMismatch) {
			t.Fatalf("Validate() = %v, want ErrHashMismatch", err)
		}
	})

	t.Run("policy_hash_mismatch", func(t *testing.T) {
		b := testPolicyBundle()
		b.PolicyHash = testHash("02")
		err := b.Validate()
		if !errors.Is(err, ErrHashMismatch) {
			t.Fatalf("Validate() = %v, want ErrHashMismatch", err)
		}
	})
}

func TestRemoteKillMessage_RequiresTwoDistinctSigners(t *testing.T) {
	msg := testRemoteKillMessage()
	if err := msg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	msg.Signatures = msg.Signatures[:1]
	err := msg.Validate()
	if !errors.Is(err, ErrThresholdRequired) {
		t.Fatalf("Validate() = %v, want ErrThresholdRequired", err)
	}

	msg = testRemoteKillMessage()
	msg.Signatures[1].SignerKeyID = msg.Signatures[0].SignerKeyID
	err = msg.Validate()
	if !errors.Is(err, ErrThresholdRequired) {
		t.Fatalf("Validate() duplicate signer = %v, want ErrThresholdRequired", err)
	}
}

func TestRollbackAuthorization_RequiresLowerTargetVersion(t *testing.T) {
	auth := testRollbackAuthorization()
	if err := auth.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	auth.TargetVersion = auth.CurrentVersion
	err := auth.Validate()
	if !errors.Is(err, ErrInvalidRollback) {
		t.Fatalf("Validate() = %v, want ErrInvalidRollback", err)
	}
}

func TestAuditBatchEnvelope_ValidateV2ChainAndForkDetection(t *testing.T) {
	batch := testAuditBatch()
	if err := batch.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	v1 := batch
	v1.Chain.EntryVersion = 1
	err := v1.Validate()
	if !errors.Is(err, ErrInvalidSequenceRange) {
		t.Fatalf("Validate() with v1 chain = %v, want ErrInvalidSequenceRange", err)
	}

	other := batch
	other.PayloadSHA256 = testHash("20")
	if !batch.ForksWith(other) {
		t.Fatal("ForksWith() = false for overlapping seq range with different payload hash")
	}

	nonOverlap := other
	nonOverlap.SeqStart = batch.SeqEnd + 1
	nonOverlap.SeqEnd = batch.SeqEnd + 10
	if batch.ForksWith(nonOverlap) {
		t.Fatal("ForksWith() = true for non-overlapping seq range")
	}
}

func TestAuditBatchEnvelope_DroppedAccounting(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		batch := testAuditBatch()
		batch.Dropped = DroppedAccounting{
			Count: 3,
			Reasons: []DroppedReason{
				{Reason: "queue_full", Count: 2},
				{Reason: "payload_too_large", Count: 1},
			},
		}
		if err := batch.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("count_mismatch", func(t *testing.T) {
		batch := testAuditBatch()
		batch.Dropped = DroppedAccounting{
			Count:   3,
			Reasons: []DroppedReason{{Reason: "queue_full", Count: 2}},
		}
		err := batch.Validate()
		if !errors.Is(err, ErrInvalidDroppedAccounting) {
			t.Fatalf("Validate() = %v, want ErrInvalidDroppedAccounting", err)
		}
	})

	t.Run("duplicate_reason", func(t *testing.T) {
		batch := testAuditBatch()
		batch.Dropped = DroppedAccounting{
			Count: 2,
			Reasons: []DroppedReason{
				{Reason: "queue_full", Count: 1},
				{Reason: "queue_full", Count: 1},
			},
		}
		err := batch.Validate()
		if !errors.Is(err, ErrInvalidDroppedAccounting) {
			t.Fatalf("Validate() = %v, want ErrInvalidDroppedAccounting", err)
		}
	})
}

func TestCapabilitiesResponse_RequiresMTLSAndThresholds(t *testing.T) {
	caps := CapabilitiesResponse{
		SchemaVersion:          SchemaVersion,
		ConductorID:            "conductor-us-1",
		RequiredMTLS:           true,
		ConductorBundle:        SchemaRange{Min: 1, Max: 1},
		RemoteKill:             SchemaRange{Min: 1, Max: 1},
		RollbackAuthorization:  SchemaRange{Min: 1, Max: 1},
		AuditBatch:             SchemaRange{Min: 1, Max: 3},
		ReceiptEntryVersions:   []int{2},
		MaxCreatedSkewSeconds:  int(DefaultAuditMaxSkew / time.Second),
		EmergencyStream:        true,
		RemoteKillThreshold:    RequiredCatastrophicSigners,
		RollbackThreshold:      RequiredCatastrophicSigners,
		TrustRotationThreshold: RequiredCatastrophicSigners,
	}
	if err := caps.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	caps.RequiredMTLS = false
	err := caps.Validate()
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Validate() = %v, want ErrInvalidState", err)
	}

	caps = validCapabilitiesResponse()
	caps.ReceiptEntryVersions = []int{1}
	err = caps.Validate()
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Validate() without v2 receipt entries = %v, want ErrInvalidState", err)
	}

	caps = validCapabilitiesResponse()
	caps.MaxCreatedSkewSeconds = int(MaxAllowedAuditSkew/time.Second) + 1
	err = caps.Validate()
	if !errors.Is(err, ErrSkewExceeded) {
		t.Fatalf("Validate() over skew cap = %v, want ErrSkewExceeded", err)
	}

	caps = validCapabilitiesResponse()
	caps.RemoteKill = SchemaRange{Min: 2, Max: 3}
	err = caps.Validate()
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Validate() range excluding current schema = %v, want ErrInvalidState", err)
	}

	caps = validCapabilitiesResponse()
	caps.RemoteKillThreshold = MaxCapabilityThreshold + 1
	err = caps.Validate()
	if !errors.Is(err, ErrThresholdRequired) {
		t.Fatalf("Validate() over local threshold cap = %v, want ErrThresholdRequired", err)
	}

	caps = validCapabilitiesResponse()
	caps.RemoteKillThreshold = MaxCapabilityThreshold + 1
	if err := caps.ValidateWithLocalThresholdCap(MaxCapabilityThreshold + 2); err != nil {
		t.Fatalf("ValidateWithLocalThresholdCap(custom cap) = %v, want nil", err)
	}
}

func TestPolicyBundle_VerifySignatures(t *testing.T) {
	bundle := testPolicyBundle()
	pub, proof := signedProof(t, bundle.SignablePreimage, "policy-signer-1", signing.PurposePolicyBundleSigning)
	bundle.Signatures = []SignatureProof{proof}
	resolver := mapResolver(map[string]SignatureKey{
		"policy-signer-1": {PublicKey: pub, KeyPurpose: signing.PurposePolicyBundleSigning},
	})

	if err := bundle.VerifySignatures(resolver); err != nil {
		t.Fatalf("VerifySignatures() = %v, want nil", err)
	}

	tampered := bundle
	tampered.PolicyHash = testHash("09")
	err := tampered.VerifySignatures(resolver)
	if !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("VerifySignatures(tampered) = %v, want ErrSignatureVerification", err)
	}

	err = bundle.VerifySignatures(mapResolver(map[string]SignatureKey{
		"policy-signer-1": {PublicKey: pub, KeyPurpose: signing.PurposeRemoteKillSigning},
	}))
	if !errors.Is(err, ErrWrongKeyPurpose) {
		t.Fatalf("VerifySignatures(wrong roster purpose) = %v, want ErrWrongKeyPurpose", err)
	}

	wrongPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(wrong pub): %v", err)
	}
	err = bundle.VerifySignatures(mapResolver(map[string]SignatureKey{
		"policy-signer-1": {PublicKey: wrongPub, KeyPurpose: signing.PurposePolicyBundleSigning},
	}))
	if !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("VerifySignatures(key_id collision with wrong public key) = %v, want ErrSignatureVerification", err)
	}
}

func TestPolicyBundlePayloadPolicyHashAcceptsBalancedPresetFractionalFloats(t *testing.T) {
	presetYAML, err := presets.YAML(config.ModeBalanced)
	if err != nil {
		t.Fatalf("balanced preset YAML: %v", err)
	}
	if !strings.Contains(string(presetYAML), "4.5") {
		t.Fatalf("balanced preset fixture no longer contains the fractional threshold this regression covers")
	}
	payload := PolicyBundlePayload{ConfigYAML: string(presetYAML)}
	first, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash(balanced preset with fractional floats): %v", err)
	}
	second, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash second pass: %v", err)
	}
	if first == "" || first != second {
		t.Fatalf("PolicyHash not deterministic: first=%q second=%q", first, second)
	}
	loaded, err := config.LoadBytes(presetYAML)
	if err != nil {
		t.Fatalf("config.LoadBytes(balanced preset): %v", err)
	}
	if want := loaded.CanonicalPolicyHash(); first != want {
		t.Fatalf("PolicyHash() = %s, want loaded CanonicalPolicyHash %s", first, want)
	}
}

func TestPolicyBundlePayloadPolicyHashUsesLoadedConfig(t *testing.T) {
	yamlSrc := "mode: strict\napi_allowlist:\n  - api.vendor.example\nfetch_proxy:\n  monitoring:\n    entropy_threshold: 4.5\n"
	payload := PolicyBundlePayload{ConfigYAML: yamlSrc}
	hash, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash(): %v", err)
	}
	loadedFromBytes, err := config.LoadBytes([]byte(yamlSrc))
	if err != nil {
		t.Fatalf("config.LoadBytes(): %v", err)
	}
	loadedFromDisk, err := loadConfigFromYAML(t, yamlSrc)
	if err != nil {
		t.Fatalf("config.Load(): %v", err)
	}
	if want := loadedFromBytes.CanonicalPolicyHash(); hash != want {
		t.Fatalf("PolicyHash() = %s, want LoadBytes CanonicalPolicyHash %s", hash, want)
	}
	if want := loadedFromDisk.CanonicalPolicyHash(); hash != want {
		t.Fatalf("PolicyHash() = %s, want follower Load CanonicalPolicyHash %s", hash, want)
	}
}

func TestPolicyBundlePayloadPolicyHashDoesNotUseAmbientLicenseGate(t *testing.T) {
	oldGate := config.EnforceLicenseGateFunc
	config.EnforceLicenseGateFunc = func(*config.Config) {
		t.Fatal("PolicyHash must not run ambient license gating")
	}
	t.Cleanup(func() { config.EnforceLicenseGateFunc = oldGate })
	t.Setenv(config.EnvLicenseKey, "ambient-license-value")

	if _, err := (PolicyBundlePayload{ConfigYAML: "mode: balanced\n"}).PolicyHash(); err != nil {
		t.Fatalf("PolicyHash(): %v", err)
	}
}

func TestPolicyBundlePayloadPolicyHashIncludesRuleBundles(t *testing.T) {
	payload := PolicyBundlePayload{ConfigYAML: "mode: strict\napi_allowlist:\n  - api.vendor.example\n"}
	configOnlyHash, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash(config only): %v", err)
	}

	payload.RuleBundles = []RuleBundleRef{{
		Name:    "official",
		Version: "2026.07.12",
		SHA256:  testHash("10"),
	}}
	withRulesHash, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash(with rules): %v", err)
	}
	if withRulesHash == configOnlyHash {
		t.Fatalf("rule bundle refs did not affect policy hash: %s", withRulesHash)
	}

	payload.RuleBundles[0].SHA256 = testHash("11")
	changedRulesHash, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash(changed rules): %v", err)
	}
	if changedRulesHash == withRulesHash {
		t.Fatalf("changed rule bundle ref did not affect policy hash: %s", changedRulesHash)
	}
}

func TestPolicyBundlePayloadPolicyHashLoadedConfigEquivalence(t *testing.T) {
	t.Run("field_order_and_set_order_are_deterministic", func(t *testing.T) {
		first := PolicyBundlePayload{ConfigYAML: "mode: balanced\nfetch_proxy:\n  monitoring:\n    entropy_threshold: 4.5\n    max_requests_per_minute: 120\napi_allowlist:\n  - b.vendor.example\n  - a.vendor.example\n"}
		second := PolicyBundlePayload{ConfigYAML: "api_allowlist:\n  - a.vendor.example\n  - b.vendor.example\nfetch_proxy:\n  monitoring:\n    max_requests_per_minute: 120\n    entropy_threshold: 4.5\nmode: balanced\n"}
		firstHash, err := first.PolicyHash()
		if err != nil {
			t.Fatalf("PolicyHash(first): %v", err)
		}
		for i := 0; i < 20; i++ {
			got, err := first.PolicyHash()
			if err != nil {
				t.Fatalf("PolicyHash repeat %d: %v", i, err)
			}
			if got != firstHash {
				t.Fatalf("PolicyHash repeat %d changed: got %s want %s", i, got, firstHash)
			}
		}
		secondHash, err := second.PolicyHash()
		if err != nil {
			t.Fatalf("PolicyHash(second): %v", err)
		}
		if secondHash != firstHash {
			t.Fatalf("equivalent loaded configs diverged:\nfirst=%s\nsecond=%s", firstHash, secondHash)
		}
	})

	t.Run("omitted_default_matches_explicit_default", func(t *testing.T) {
		omitted := PolicyBundlePayload{ConfigYAML: "mode: balanced\nlearn:\n  inference: {}\n"}
		explicit := PolicyBundlePayload{ConfigYAML: "mode: balanced\nlearn:\n  inference:\n    floors:\n      min_sessions: 5\n      min_events: 20\n      min_windows: 3\n"}
		omittedHash, err := omitted.PolicyHash()
		if err != nil {
			t.Fatalf("PolicyHash(omitted): %v", err)
		}
		explicitHash, err := explicit.PolicyHash()
		if err != nil {
			t.Fatalf("PolicyHash(explicit): %v", err)
		}
		if explicitHash != omittedHash {
			t.Fatalf("default-equivalent configs diverged:\nomitted=%s\nexplicit=%s", omittedHash, explicitHash)
		}
	})

	t.Run("equivalent_float_spellings_match_typed_config", func(t *testing.T) {
		plain := PolicyBundlePayload{ConfigYAML: "fetch_proxy:\n  monitoring:\n    entropy_threshold: 4.5\n"}
		trailingZero := PolicyBundlePayload{ConfigYAML: "fetch_proxy:\n  monitoring:\n    entropy_threshold: 4.50\n"}
		scientific := PolicyBundlePayload{ConfigYAML: "fetch_proxy:\n  monitoring:\n    entropy_threshold: 45e-1\n"}
		plainHash, err := plain.PolicyHash()
		if err != nil {
			t.Fatalf("PolicyHash(plain): %v", err)
		}
		trailingHash, err := trailingZero.PolicyHash()
		if err != nil {
			t.Fatalf("PolicyHash(trailing zero): %v", err)
		}
		scientificHash, err := scientific.PolicyHash()
		if err != nil {
			t.Fatalf("PolicyHash(scientific): %v", err)
		}
		if trailingHash != plainHash || scientificHash != plainHash {
			t.Fatalf("equivalent typed float configs diverged:\nplain=%s\ntrailing=%s\nscientific=%s", plainHash, trailingHash, scientificHash)
		}
	})

	t.Run("alias_matches_expanded_typed_config", func(t *testing.T) {
		withAlias := "fetch_proxy:\n  monitoring:\n    entropy_threshold: &threshold !!float 4.5\n    subdomain_entropy_threshold: *threshold\n"
		expanded := "fetch_proxy:\n  monitoring:\n    entropy_threshold: 4.5\n    subdomain_entropy_threshold: 4.5\n"
		aliasHash, err := (PolicyBundlePayload{ConfigYAML: withAlias}).PolicyHash()
		if err != nil {
			t.Fatalf("PolicyHash(alias): %v", err)
		}
		expandedHash, err := (PolicyBundlePayload{ConfigYAML: expanded}).PolicyHash()
		if err != nil {
			t.Fatalf("PolicyHash(expanded): %v", err)
		}
		if aliasHash != expandedHash {
			t.Fatalf("alias hash drifted from expanded loaded config:\nalias=%s\nexpanded=%s", aliasHash, expandedHash)
		}
	})
}

func TestPolicyBundlePayloadPolicyHashLoadedConfigFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
	}{
		{name: "unknown field", yaml: "threshold: 4.5\n"},
		{name: "quoted numeric float", yaml: "fetch_proxy:\n  monitoring:\n    entropy_threshold: \"4.5\"\n"},
		{name: "duplicate top level key", yaml: "mode: strict\nmode: balanced\n"},
		{name: "malformed yaml", yaml: "mode: [\n"},
		{name: "multiple documents", yaml: "mode: strict\n---\nmode: balanced\n"},
		{name: "recursive alias", yaml: "api_allowlist: &hosts\n  - *hosts\n"},
		{name: "unsafe huge float rejected by typed validation", yaml: "learn:\n  inference:\n    normalization:\n      entropy_threshold_bits: 9007199254740993.0\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := (PolicyBundlePayload{ConfigYAML: tc.yaml}).PolicyHash(); !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("PolicyHash(%q) = %v, want ErrInvalidHash", strings.TrimSpace(tc.yaml), err)
			}
		})
	}
}

func TestPolicyBundlePayloadPolicyHashDistinctLoadedConfigsDiffer(t *testing.T) {
	left := PolicyBundlePayload{ConfigYAML: "fetch_proxy:\n  monitoring:\n    entropy_threshold: 4.5\n"}
	right := PolicyBundlePayload{ConfigYAML: "fetch_proxy:\n  monitoring:\n    entropy_threshold: 4.6\n"}
	leftHash, err := left.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash(left): %v", err)
	}
	rightHash, err := right.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash(right): %v", err)
	}
	if leftHash == rightHash {
		t.Fatalf("different enforced configs collided: %s", leftHash)
	}

	for _, yamlSrc := range []string{
		"learn:\n  inference:\n    normalization:\n      entropy_threshold_bits: 9007199254740993.0\n",
		"learn:\n  inference:\n    normalization:\n      entropy_threshold_bits: 9007199254740992\n",
	} {
		if _, err := (PolicyBundlePayload{ConfigYAML: yamlSrc}).PolicyHash(); !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("PolicyHash(%q) = %v, want ErrInvalidHash", strings.TrimSpace(yamlSrc), err)
		}
	}
}

func TestPolicyBundlePayloadPolicyHashRejectsLocalCompanionFields(t *testing.T) {
	cwd := t.TempDir()
	secretsPath := filepath.Join(cwd, "secrets.env")
	if err := os.WriteFile(secretsPath, []byte("# publisher-local companion file\n"), 0o600); err != nil {
		t.Fatalf("write cwd secrets file: %v", err)
	}
	t.Chdir(cwd)

	for _, tc := range []struct {
		name string
		yaml string
		path string
	}{
		{
			name: "relative dlp secrets file",
			yaml: "mode: balanced\ndlp:\n  secrets_file: secrets.env\n",
			path: "dlp.secrets_file",
		},
		{
			name: "learn file salt source",
			yaml: "mode: balanced\nlearn:\n  privacy:\n    salt_source: file:/var/lib/pipelock/learn-salt\n",
			path: "learn.privacy.salt_source",
		},
		{
			name: "mcp integrity manifest path",
			yaml: "mode: balanced\nmcp_binary_integrity:\n  manifest_path: /var/lib/pipelock/mcp-integrity.json\n",
			path: "mcp_binary_integrity.manifest_path",
		},
		{
			name: "behavioral baseline profile dir",
			yaml: "mode: balanced\nsession_profiling:\n  enabled: true\nbehavioral_baseline:\n  profile_dir: /var/lib/pipelock/baselines\n",
			path: "behavioral_baseline.profile_dir",
		},
		{
			name: "learn lock roster path",
			yaml: "mode: balanced\nlearn_lock:\n  roster_path: /etc/pipelock/roster.json\n",
			path: "learn_lock.roster_path",
		},
		{
			name: "merged dlp secrets file",
			yaml: "mode: balanced\ndlp_defaults: &dlp_defaults\n  secrets_file: secrets.env\ndlp:\n  <<: *dlp_defaults\n",
			path: "dlp.secrets_file",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := (PolicyBundlePayload{ConfigYAML: tc.yaml}).PolicyHash()
			if !errors.Is(err, ErrForbiddenBundleCompanionField) {
				t.Fatalf("PolicyHash() = %v, want ErrForbiddenBundleCompanionField", err)
			}
			if !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("error should name %s, got %v", tc.path, err)
			}
		})
	}
}

func TestPolicyBundlePayloadPolicyHashRejectsMergedCompanionFieldsAllForbidden(t *testing.T) {
	for path := range forbiddenPolicyBundleCompanionFields {
		t.Run(path, func(t *testing.T) {
			_, err := (PolicyBundlePayload{ConfigYAML: yamlWithMergedCompanionPath(path)}).PolicyHash()
			if !errors.Is(err, ErrForbiddenBundleCompanionField) {
				t.Fatalf("PolicyHash() = %v, want ErrForbiddenBundleCompanionField", err)
			}
			if !strings.Contains(err.Error(), path) {
				t.Fatalf("error should name merged path %s, got %v", path, err)
			}
		})
	}
}

func TestPolicyBundleValidateRejectsCompanionField(t *testing.T) {
	bundle := testPolicyBundle()
	bundle.Payload.ConfigYAML = "mode: balanced\ndlp:\n  secrets_file: secrets.env\n"
	err := bundle.Validate()
	if !errors.Is(err, ErrForbiddenBundleCompanionField) {
		t.Fatalf("Validate() = %v, want ErrForbiddenBundleCompanionField", err)
	}
}

func TestRejectPolicyBundleCompanionFieldsEdgeCases(t *testing.T) {
	for _, tc := range []struct {
		name    string
		yaml    string
		wantErr error
	}{
		{name: "empty", yaml: "", wantErr: ErrForbiddenBundleCompanionField},
		{name: "malformed", yaml: "mode: [\n", wantErr: ErrForbiddenBundleCompanionField},
		{name: "extra document", yaml: "mode: balanced\n---\nmode: strict\n", wantErr: ErrForbiddenLicenseField},
		{
			name:    "merge sequence",
			yaml:    "mode: balanced\ndlp_empty: &dlp_empty\n  secrets_file: ''\ndlp_forbidden: &dlp_forbidden\n  secrets_file: secrets.env\ndlp:\n  <<: [*dlp_empty, *dlp_forbidden]\n",
			wantErr: ErrForbiddenBundleCompanionField,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := rejectPolicyBundleCompanionFields(tc.yaml)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("rejectPolicyBundleCompanionFields() = %v, want %v", err, tc.wantErr)
			}
		})
	}

	if err := walkRejectPolicyBundleCompanionFieldsAt(nil, "", map[*yaml.Node]bool{}); err != nil {
		t.Fatalf("walk nil node: %v", err)
	}
	if err := walkRejectPolicyBundleCompanionFieldsAlias(&yaml.Node{Kind: yaml.AliasNode}, "root", map[*yaml.Node]bool{}); err != nil {
		t.Fatalf("walk nil alias: %v", err)
	}
	aliasCycle := &yaml.Node{Kind: yaml.AliasNode}
	aliasCycle.Alias = aliasCycle
	if err := walkRejectPolicyBundleCompanionFieldsAlias(aliasCycle, "root", map[*yaml.Node]bool{}); !errors.Is(err, ErrForbiddenBundleCompanionField) {
		t.Fatalf("walk alias cycle = %v, want ErrForbiddenBundleCompanionField", err)
	}
	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.ScalarNode, Value: "ok"}}}
	if err := walkRejectPolicyBundleCompanionFieldsAt(doc, "", map[*yaml.Node]bool{}); err != nil {
		t.Fatalf("walk document node: %v", err)
	}
}

func yamlWithMergedCompanionPath(path string) string {
	var b strings.Builder
	parts := strings.Split(path, ".")
	b.WriteString("mode: balanced\nx_forbidden: &forbidden\n")
	for i, part := range parts {
		b.WriteString(strings.Repeat("  ", i+1))
		b.WriteString(part)
		b.WriteString(":")
		if i == len(parts)-1 {
			b.WriteString(" local-file\n")
		} else {
			b.WriteByte('\n')
		}
	}
	b.WriteString("<<: *forbidden\n")
	return b.String()
}

func TestPolicyBundlePolicyHashVerifiesAndMatchesFollowerLoad(t *testing.T) {
	yamlSrc := "mode: strict\napi_allowlist:\n  - api.vendor.example\nrequest_body_scanning:\n  max_body_bytes: 1048576\n"
	payload := PolicyBundlePayload{ConfigYAML: yamlSrc}
	policyHash, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash(): %v", err)
	}
	payloadHash, err := payload.PayloadHash()
	if err != nil {
		t.Fatalf("PayloadHash(): %v", err)
	}
	followerConfig, err := loadConfigFromYAML(t, yamlSrc)
	if err != nil {
		t.Fatalf("follower config.Load(): %v", err)
	}
	if got := followerConfig.CanonicalPolicyHash(); got != policyHash {
		t.Fatalf("follower CanonicalPolicyHash() = %s, want published policy hash %s", got, policyHash)
	}

	bundle := testPolicyBundle()
	bundle.Payload = payload
	bundle.PayloadSHA256 = payloadHash
	bundle.PolicyHash = policyHash
	bundle.Signatures = nil
	pub, proof := signedProof(t, bundle.SignablePreimage, "policy-signer-1", signing.PurposePolicyBundleSigning)
	bundle.Signatures = []SignatureProof{proof}

	resolver := mapResolver(map[string]SignatureKey{
		"policy-signer-1": {PublicKey: pub, KeyPurpose: signing.PurposePolicyBundleSigning},
	})
	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}
	if err := bundle.VerifySignaturesAt(testNow, resolver); err != nil {
		t.Fatalf("VerifySignaturesAt(): %v", err)
	}
}

func loadConfigFromYAML(t *testing.T, yamlSrc string) (*config.Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yamlSrc), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return config.Load(path)
}

func TestRemoteKillMessage_VerifySignaturesThreshold(t *testing.T) {
	msg := testRemoteKillMessage()
	pub1, proof1 := signedProof(t, msg.SignablePreimage, "kill-signer-1", signing.PurposeRemoteKillSigning)
	pub2, proof2 := signedProof(t, msg.SignablePreimage, "kill-signer-2", signing.PurposeRemoteKillSigning)
	msg.Signatures = []SignatureProof{proof1, proof2}
	resolver := mapResolver(map[string]SignatureKey{
		"kill-signer-1": {PublicKey: pub1, KeyPurpose: signing.PurposeRemoteKillSigning},
		"kill-signer-2": {PublicKey: pub2, KeyPurpose: signing.PurposeRemoteKillSigning},
	})

	if err := msg.VerifySignatures(resolver); err != nil {
		t.Fatalf("VerifySignatures() = %v, want nil", err)
	}

	msg.Signatures = []SignatureProof{proof1}
	err := msg.VerifySignatures(resolver)
	if !errors.Is(err, ErrThresholdRequired) {
		t.Fatalf("VerifySignatures(one signer) = %v, want ErrThresholdRequired", err)
	}
}

func testPolicyBundle() PolicyBundle {
	payload := PolicyBundlePayload{
		ConfigYAML: "mode: strict\napi_allowlist:\n  - api.vendor.example\n",
		RuleBundles: []RuleBundleRef{{
			Name:    "official",
			Version: "2026.05.23",
			SHA256:  testHash("04"),
		}},
	}
	return PolicyBundle{
		SchemaVersion:      SchemaVersion,
		BundleID:           "bundle-0001",
		OrgID:              "org-test",
		FleetID:            "fleet-prod",
		Environment:        "prod",
		Audience:           Audience{InstanceIDs: []string{"instance-1"}},
		Version:            1,
		PreviousBundleHash: testHash("01"),
		CreatedAt:          testNow,
		NotBefore:          testNow.Add(-time.Minute),
		ExpiresAt:          testNow.Add(time.Hour),
		MinPipelockVersion: "1.2.3",
		PolicyHash:         mustPolicyHash(payload),
		PayloadSHA256:      mustPayloadHash(payload),
		Payload:            payload,
		Signatures: []SignatureProof{
			testProof("policy-signer-1", signing.PurposePolicyBundleSigning),
		},
	}
}

func validCapabilitiesResponse() CapabilitiesResponse {
	return CapabilitiesResponse{
		SchemaVersion:          SchemaVersion,
		ConductorID:            "conductor-us-1",
		RequiredMTLS:           true,
		ConductorBundle:        SchemaRange{Min: 1, Max: 1},
		RemoteKill:             SchemaRange{Min: 1, Max: 1},
		RollbackAuthorization:  SchemaRange{Min: 1, Max: 1},
		AuditBatch:             SchemaRange{Min: 1, Max: 3},
		ReceiptEntryVersions:   []int{2},
		MaxCreatedSkewSeconds:  int(DefaultAuditMaxSkew / time.Second),
		EmergencyStream:        true,
		RemoteKillThreshold:    RequiredCatastrophicSigners,
		RollbackThreshold:      RequiredCatastrophicSigners,
		TrustRotationThreshold: RequiredCatastrophicSigners,
	}
}

func testRemoteKillMessage() RemoteKillMessage {
	return RemoteKillMessage{
		SchemaVersion: SchemaVersion,
		MessageID:     "kill-0001",
		OrgID:         "org-test",
		FleetID:       "fleet-prod",
		Audience:      Audience{InstanceIDs: []string{"*"}},
		State:         KillSwitchActive,
		Counter:       42,
		Reason:        "incident",
		CreatedAt:     testNow,
		NotBefore:     testNow.Add(-time.Minute),
		ExpiresAt:     testNow.Add(5 * time.Minute),
		Signatures: []SignatureProof{
			testProof("kill-signer-1", signing.PurposeRemoteKillSigning),
			testProof("kill-signer-2", signing.PurposeRemoteKillSigning),
		},
	}
}

func testRollbackAuthorization() RollbackAuthorization {
	return RollbackAuthorization{
		SchemaVersion:   SchemaVersion,
		AuthorizationID: "rollback-0001",
		OrgID:           "org-test",
		FleetID:         "fleet-prod",
		CurrentBundleID: "bundle-0002",
		CurrentVersion:  2,
		TargetBundleID:  "bundle-0001",
		TargetVersion:   1,
		Counter:         5,
		Reason:          "bad bundle",
		CreatedAt:       testNow,
		ExpiresAt:       testNow.Add(10 * time.Minute),
		Signatures: []SignatureProof{
			testProof("rollback-signer-1", signing.PurposePolicyBundleRollback),
			testProof("rollback-signer-2", signing.PurposePolicyBundleRollback),
		},
	}
}

func testStreamSwitchAuthorization() StreamSwitchAuthorization {
	return StreamSwitchAuthorization{
		SchemaVersion:     SchemaVersion,
		AuthorizationID:   "switch-0001",
		OrgID:             "org-test",
		FleetID:           "fleet-prod",
		Environment:       "prod",
		CurrentAudience:   Audience{InstanceIDs: []string{"instance-1"}},
		CurrentBundleID:   "bundle-0001",
		CurrentVersion:    1,
		CurrentBundleHash: testHash("11"),
		TargetAudience:    Audience{Labels: map[string]string{"ring": "canary"}},
		TargetBundleID:    "bundle-0002",
		TargetVersion:     2,
		TargetBundleHash:  testHash("22"),
		Reason:            "move canary stream",
		CreatedAt:         testNow,
		ExpiresAt:         testNow.Add(10 * time.Minute),
		Signatures: []SignatureProof{
			testProof("switch-signer-1", signing.PurposePolicyBundleRollback),
			testProof("switch-signer-2", signing.PurposePolicyBundleRollback),
		},
	}
}

func testAuditBatch() AuditBatchEnvelope {
	payload := testAuditPayload()
	return AuditBatchEnvelope{
		SchemaVersion:      SchemaVersion,
		BatchID:            "audit-batch-0001",
		OrgID:              "org-test",
		FleetID:            "fleet-prod",
		InstanceID:         "instance-1",
		AuditSchemaVersion: 2,
		EmittedAt:          testNow,
		SeqStart:           10,
		SeqEnd:             20,
		EventCount:         11,
		PayloadSHA256:      testBytesHash(payload),
		PayloadBytes:       uint64(len(payload)),
		Chain: EvidenceChain{
			EntryVersion:           2,
			SegmentID:              "segment-1",
			SeqStart:               10,
			SeqEnd:                 20,
			PreviousSegmentTail:    testHash("11"),
			SegmentHeadHash:        testHash("12"),
			SegmentTailHash:        testHash("13"),
			CheckpointSeq:          20,
			CheckpointHash:         testHash("14"),
			CheckpointSignature:    testSignature("15"),
			CheckpointSignerKeyID:  "recorder-signer-1",
			FollowerRecorderKeyID:  "recorder-key-1",
			FollowerRecorderPubHex: strings.Repeat("16", 32),
		},
		Signatures: []SignatureProof{
			testProof("instance-audit-signer-1", signing.PurposeAuditBatchSigning),
		},
	}
}

func TestPolicyBundle_PreimageStableAcrossTimezones(t *testing.T) {
	// Two bundles that describe the same logical instant but in different
	// timezones must produce identical canonical preimages. Without the
	// UTC normalization in SignablePreimage, Go's default time.Time JSON
	// marshal embeds the source zone offset and the signed bytes diverge.
	utc := testPolicyBundle()
	utc.CreatedAt = utc.CreatedAt.UTC()
	utc.NotBefore = utc.NotBefore.UTC()
	utc.ExpiresAt = utc.ExpiresAt.UTC()

	tokyo, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skipf("timezone data unavailable: %v", err)
	}
	jst := testPolicyBundle()
	jst.CreatedAt = jst.CreatedAt.In(tokyo)
	jst.NotBefore = jst.NotBefore.In(tokyo)
	jst.ExpiresAt = jst.ExpiresAt.In(tokyo)

	preUTC, err := utc.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(utc): %v", err)
	}
	preJST, err := jst.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(jst): %v", err)
	}
	if string(preUTC) != string(preJST) {
		t.Fatalf("preimage diverged across timezones:\nutc=%s\njst=%s", preUTC, preJST)
	}
}

func TestPolicyBundle_PreimageChangesWithPolicyFields(t *testing.T) {
	// Detached-signature stability is one half of the contract; the other
	// half is that changing actual policy content MUST change the preimage.
	// A regression that drops a field from the canonicalization (refactor,
	// json tag change, etc.) silently breaks the entire signing chain.
	base := testPolicyBundle()
	basePre, err := base.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(base): %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*PolicyBundle)
	}{
		{"min_pipelock_version", func(b *PolicyBundle) { b.MinPipelockVersion = "9.9.9" }},
		{"previous_bundle_hash", func(b *PolicyBundle) { b.PreviousBundleHash = testHash("ff") }},
		{"environment", func(b *PolicyBundle) { b.Environment = "staging" }},
		{"audience_instance", func(b *PolicyBundle) { b.Audience = Audience{InstanceIDs: []string{"instance-other"}} }},
		{"version", func(b *PolicyBundle) { b.Version = 999 }},
		{"config_yaml", func(b *PolicyBundle) { b.Payload.ConfigYAML = "mode: balanced\n" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mut := testPolicyBundle()
			tc.mutate(&mut)
			pre, err := mut.SignablePreimage()
			if err != nil {
				t.Fatalf("SignablePreimage: %v", err)
			}
			if string(pre) == string(basePre) {
				t.Fatalf("preimage unchanged after mutating %s — field is missing from canonicalization", tc.name)
			}
		})
	}
}

func TestPolicyBundle_RejectsNestedLicenseField(t *testing.T) {
	// Shallow rejection misses license keys smuggled under agents.<name>
	// or any other submap. The recursive walker must surface the full path.
	b := testPolicyBundle()
	b.Payload.ConfigYAML = "mode: strict\nagents:\n  claude-code:\n    license_key: smuggled\n"
	err := b.Validate()
	if !errors.Is(err, ErrForbiddenLicenseField) {
		t.Fatalf("Validate() = %v, want ErrForbiddenLicenseField", err)
	}
	if !strings.Contains(err.Error(), "agents.claude-code.license_key") {
		t.Fatalf("error should name nested path; got %v", err)
	}
}

func TestPolicyBundle_RequiresMinPipelockVersion(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		b := testPolicyBundle()
		b.MinPipelockVersion = ""
		err := b.Validate()
		if !errors.Is(err, ErrMissingField) {
			t.Fatalf("Validate() = %v, want ErrMissingField", err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		b := testPolicyBundle()
		b.MinPipelockVersion = "1.2"
		err := b.Validate()
		if !errors.Is(err, ErrInvalidMinVersion) {
			t.Fatalf("Validate() = %v, want ErrInvalidMinVersion", err)
		}
	})
	t.Run("non_numeric_component", func(t *testing.T) {
		b := testPolicyBundle()
		b.MinPipelockVersion = "1.2.beta"
		err := b.Validate()
		if !errors.Is(err, ErrInvalidMinVersion) {
			t.Fatalf("Validate() = %v, want ErrInvalidMinVersion", err)
		}
	})
	t.Run("leading_zero_component", func(t *testing.T) {
		b := testPolicyBundle()
		b.MinPipelockVersion = "1.02.3"
		err := b.Validate()
		if !errors.Is(err, ErrInvalidMinVersion) {
			t.Fatalf("Validate() = %v, want ErrInvalidMinVersion", err)
		}
	})
}

func TestPolicyBundle_ConfigYAMLSizeCap(t *testing.T) {
	b := testPolicyBundle()
	b.Payload.ConfigYAML = "mode: strict\n" + strings.Repeat("# noise\n", MaxConfigYAMLBytes)
	err := b.Validate()
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("Validate() = %v, want ErrPayloadTooLarge", err)
	}
}

func TestPolicyBundle_ValidateAtTime(t *testing.T) {
	b := testPolicyBundle()
	// Inside window passes.
	if err := b.ValidateAtTime(testNow); err != nil {
		t.Fatalf("ValidateAtTime(inside) = %v, want nil", err)
	}
	// Before NotBefore → ErrNotYetValid.
	err := b.ValidateAtTime(b.NotBefore.Add(-time.Hour))
	if !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("ValidateAtTime(before) = %v, want ErrNotYetValid", err)
	}
	// After ExpiresAt → ErrExpired.
	err = b.ValidateAtTime(b.ExpiresAt.Add(time.Hour))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("ValidateAtTime(after) = %v, want ErrExpired", err)
	}
}

func TestRemoteKillMessage_ValidateAtTimeAndReasonCap(t *testing.T) {
	m := testRemoteKillMessage()
	if err := m.ValidateAtTime(testNow); err != nil {
		t.Fatalf("ValidateAtTime(inside) = %v, want nil", err)
	}
	err := m.ValidateAtTime(m.ExpiresAt.Add(time.Minute))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("ValidateAtTime(after) = %v, want ErrExpired", err)
	}

	oversized := testRemoteKillMessage()
	oversized.Reason = strings.Repeat("x", MaxReasonBytes+1)
	if err := oversized.Validate(); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("Validate(oversized reason) = %v, want ErrPayloadTooLarge", err)
	}

	control := testRemoteKillMessage()
	control.Reason = "incident\nsecond-line"
	if err := control.Validate(); !errors.Is(err, ErrInvalidReason) {
		t.Fatalf("Validate(control reason) = %v, want ErrInvalidReason", err)
	}
}

func TestRollbackAuthorization_ValidateAtTime(t *testing.T) {
	r := testRollbackAuthorization()
	if err := r.ValidateAtTime(testNow); err != nil {
		t.Fatalf("ValidateAtTime(inside) = %v, want nil", err)
	}
	err := r.ValidateAtTime(r.ExpiresAt.Add(time.Second))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("ValidateAtTime(after) = %v, want ErrExpired", err)
	}
}

func TestAuditBatchEnvelope_ValidateForConductorSkew(t *testing.T) {
	batch := testAuditBatch()
	// Inside default skew.
	if err := batch.ValidateForConductor(testNow.Add(30*time.Second), DefaultAuditMaxSkew); err != nil {
		t.Fatalf("ValidateForConductor(inside) = %v, want nil", err)
	}
	// Past default skew → ErrSkewExceeded.
	err := batch.ValidateForConductor(testNow.Add(2*time.Minute), DefaultAuditMaxSkew)
	if !errors.Is(err, ErrSkewExceeded) {
		t.Fatalf("ValidateForConductor(past) = %v, want ErrSkewExceeded", err)
	}
	// Future emission > skew (clock drift) → ErrSkewExceeded.
	err = batch.ValidateForConductor(testNow.Add(-2*time.Minute), DefaultAuditMaxSkew)
	if !errors.Is(err, ErrSkewExceeded) {
		t.Fatalf("ValidateForConductor(future) = %v, want ErrSkewExceeded", err)
	}
	// Operator misconfig > MaxAllowedAuditSkew → ErrSkewExceeded.
	err = batch.ValidateForConductor(testNow, MaxAllowedAuditSkew+time.Second)
	if !errors.Is(err, ErrSkewExceeded) {
		t.Fatalf("ValidateForConductor(over-cap config) = %v, want ErrSkewExceeded", err)
	}
}

func TestAuditBatchEnvelope_ValidateForConductorWithPayload(t *testing.T) {
	batch := testAuditBatch()
	payload := testAuditPayload()
	if err := batch.ValidateForConductorWithPayload(testNow, DefaultAuditMaxSkew, payload); err != nil {
		t.Fatalf("ValidateForConductorWithPayload(valid) = %v, want nil", err)
	}

	err := batch.ValidateForConductorWithPayload(testNow, DefaultAuditMaxSkew, append(payload, 'x'))
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("ValidateForConductorWithPayload(size mismatch) = %v, want ErrHashMismatch", err)
	}

	sameSizeDifferentHash := append([]byte(nil), payload...)
	sameSizeDifferentHash[0] ^= 0x01
	err = batch.ValidateForConductorWithPayload(testNow, DefaultAuditMaxSkew, sameSizeDifferentHash)
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("ValidateForConductorWithPayload(hash mismatch) = %v, want ErrHashMismatch", err)
	}
}

func TestAuditBatchEnvelope_PayloadBytesClassification(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		batch := testAuditBatch()
		batch.PayloadBytes = 0
		err := batch.Validate()
		if !errors.Is(err, ErrMissingField) {
			t.Fatalf("Validate() = %v, want ErrMissingField", err)
		}
	})

	t.Run("too_large", func(t *testing.T) {
		batch := testAuditBatch()
		batch.PayloadBytes = MaxAuditPayloadBytes + 1
		err := batch.Validate()
		if !errors.Is(err, ErrPayloadTooLarge) {
			t.Fatalf("Validate() = %v, want ErrPayloadTooLarge", err)
		}
	})
}

func TestAudience_RejectsMixedWildcard(t *testing.T) {
	a := Audience{InstanceIDs: []string{"*", "instance-1"}}
	err := a.Validate()
	if !errors.Is(err, ErrInvalidAudienceWildcard) {
		t.Fatalf("Validate() = %v, want ErrInvalidAudienceWildcard", err)
	}
	if !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("Validate() = %v, want ErrInvalidAudience classification", err)
	}
	// Pure wildcard still passes.
	if err := (Audience{InstanceIDs: []string{"*"}}).Validate(); err != nil {
		t.Fatalf("Validate(pure wildcard) = %v, want nil", err)
	}
}

func TestAudience_RejectsMixedSelectorTypes(t *testing.T) {
	a := Audience{
		InstanceIDs: []string{"instance-1"},
		Labels:      map[string]string{"ring": "canary"},
	}
	err := a.Validate()
	if !errors.Is(err, ErrInvalidAudienceSelectors) {
		t.Fatalf("Validate() = %v, want ErrInvalidAudienceSelectors", err)
	}
	if !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("Validate() = %v, want ErrInvalidAudience classification", err)
	}
}

func TestIsIdentifierRejectsEmpty(t *testing.T) {
	if isIdentifier("") {
		t.Fatal("isIdentifier(empty) = true, want false")
	}
}

func TestValidateIdentifierExport(t *testing.T) {
	if err := ValidateIdentifier("org_id", "org-main"); err != nil {
		t.Fatalf("ValidateIdentifier(valid) error = %v", err)
	}
	if err := ValidateIdentifier("org_id", "-org"); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("ValidateIdentifier(invalid) error = %v, want ErrInvalidIdentifier", err)
	}
}

func TestRemoteKillMessage_RejectsSamePublicKeyAcrossSignerIDs(t *testing.T) {
	// A roster that maps two distinct IDs to the same public key would
	// otherwise satisfy threshold with one underlying signer. This is the
	// exact failure mode the catastrophic-threshold rule exists to prevent.
	msg := testRemoteKillMessage()
	pub, proof1 := signedProof(t, msg.SignablePreimage, "kill-signer-A", signing.PurposeRemoteKillSigning)
	_, proof2 := signedProof(t, msg.SignablePreimage, "kill-signer-B", signing.PurposeRemoteKillSigning)
	// Force proof2's signature to a valid sig produced by pub by re-signing
	// is not possible without the priv key; instead simulate the roster
	// trick: both IDs map to the SAME pub. Use proof1's signature for both
	// IDs so verification passes per-signature.
	proof2.Signature = proof1.Signature
	msg.Signatures = []SignatureProof{proof1, proof2}

	resolver := mapResolver(map[string]SignatureKey{
		"kill-signer-A": {PublicKey: pub, KeyPurpose: signing.PurposeRemoteKillSigning},
		"kill-signer-B": {PublicKey: pub, KeyPurpose: signing.PurposeRemoteKillSigning},
	})
	err := msg.VerifySignaturesAt(testNow, resolver)
	if !errors.Is(err, ErrThresholdRequired) {
		t.Fatalf("VerifySignaturesAt(same pubkey under different IDs) = %v, want ErrThresholdRequired", err)
	}
}

func TestPolicyBundle_VerifySignaturesRejectsRevokedAndExpiredRoster(t *testing.T) {
	bundle := testPolicyBundle()
	pub, proof := signedProof(t, bundle.SignablePreimage, "policy-signer-1", signing.PurposePolicyBundleSigning)
	bundle.Signatures = []SignatureProof{proof}

	t.Run("revoked", func(t *testing.T) {
		revoked := testNow.Add(-time.Hour)
		resolver := mapResolver(map[string]SignatureKey{
			"policy-signer-1": {
				PublicKey:  pub,
				KeyPurpose: signing.PurposePolicyBundleSigning,
				RevokedAt:  &revoked,
			},
		})
		err := bundle.VerifySignaturesAt(testNow, resolver)
		if !errors.Is(err, ErrSignatureVerification) {
			t.Fatalf("VerifySignaturesAt(revoked) = %v, want ErrSignatureVerification", err)
		}
	})

	t.Run("not_yet_valid", func(t *testing.T) {
		resolver := mapResolver(map[string]SignatureKey{
			"policy-signer-1": {
				PublicKey:  pub,
				KeyPurpose: signing.PurposePolicyBundleSigning,
				NotBefore:  testNow.Add(time.Hour),
			},
		})
		err := bundle.VerifySignaturesAt(testNow, resolver)
		if !errors.Is(err, ErrNotYetValid) {
			t.Fatalf("VerifySignaturesAt(not yet valid) = %v, want ErrNotYetValid", err)
		}
	})

	t.Run("expired_key", func(t *testing.T) {
		resolver := mapResolver(map[string]SignatureKey{
			"policy-signer-1": {
				PublicKey:  pub,
				KeyPurpose: signing.PurposePolicyBundleSigning,
				NotAfter:   testNow.Add(-time.Hour),
			},
		})
		err := bundle.VerifySignaturesAt(testNow, resolver)
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("VerifySignaturesAt(expired) = %v, want ErrExpired", err)
		}
	})

	t.Run("nil_resolver", func(t *testing.T) {
		err := bundle.VerifySignaturesAt(testNow, nil)
		if !errors.Is(err, ErrSignatureVerification) {
			t.Fatalf("VerifySignaturesAt(nil resolver) = %v, want ErrSignatureVerification", err)
		}
	})
}

func TestDroppedAccounting_OverflowGuard(t *testing.T) {
	// Crafted Reason.Count values whose sum wraps uint64 back to d.Count
	// would otherwise pass the count==total equality check.
	d := DroppedAccounting{
		Count: 5,
		Reasons: []DroppedReason{
			{Reason: "queue_full", Count: math.MaxUint64 - 4},
			{Reason: "payload_too_large", Count: 10}, // sum wraps to 5
		},
	}
	err := d.Validate()
	if !errors.Is(err, ErrInvalidDroppedAccounting) {
		t.Fatalf("Validate(overflow) = %v, want ErrInvalidDroppedAccounting", err)
	}
}

func TestMessageIdentifiersAreBounded(t *testing.T) {
	b := testPolicyBundle()
	b.BundleID = "bad id with spaces"
	err := b.Validate()
	if !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("Validate() = %v, want ErrInvalidIdentifier", err)
	}

	b = testPolicyBundle()
	b.BundleID = strings.Repeat("a", MaxIDBytes+1)
	err = b.Validate()
	if !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("Validate(long id) = %v, want ErrInvalidIdentifier", err)
	}
}

func TestPolicyBundlePayload_PolicyHashYAMLDocumentHandling(t *testing.T) {
	payload := PolicyBundlePayload{ConfigYAML: "mode: strict\napi_allowlist:\n  - api.vendor.example\n"}
	if _, err := payload.PolicyHash(); err != nil {
		t.Fatalf("PolicyHash(single document) = %v, want nil", err)
	}

	payload.ConfigYAML = "mode: strict\napi_allowlist:\n  - api.vendor.example\n---\n"
	_, err := payload.PolicyHash()
	if !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("PolicyHash(empty trailing doc) = %v, want ErrInvalidHash", err)
	}

	payload.ConfigYAML = "mode: strict\napi_allowlist:\n  - api.vendor.example\n---\nmode: balanced\n"
	_, err = payload.PolicyHash()
	if !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("PolicyHash(non-empty trailing doc) = %v, want ErrInvalidHash", err)
	}

	payload.ConfigYAML = "mode: [\n"
	if _, err := payload.PolicyHash(); err == nil {
		t.Fatal("PolicyHash(malformed yaml) = nil, want error")
	}
}

func TestCanonicalHashMethods(t *testing.T) {
	if got, err := testPolicyBundle().CanonicalHash(); err != nil || got == "" {
		t.Fatalf("PolicyBundle.CanonicalHash() = %q, %v; want hash", got, err)
	}
	if got, err := testRemoteKillMessage().CanonicalHash(); err != nil || got == "" {
		t.Fatalf("RemoteKillMessage.CanonicalHash() = %q, %v; want hash", got, err)
	}
	if got, err := testRollbackAuthorization().CanonicalHash(); err != nil || got == "" {
		t.Fatalf("RollbackAuthorization.CanonicalHash() = %q, %v; want hash", got, err)
	}
	if got, err := testStreamSwitchAuthorization().CanonicalHash(); err != nil || got == "" {
		t.Fatalf("StreamSwitchAuthorization.CanonicalHash() = %q, %v; want hash", got, err)
	}
	if got, err := testAuditBatch().CanonicalHash(); err != nil || got == "" {
		t.Fatalf("AuditBatchEnvelope.CanonicalHash() = %q, %v; want hash", got, err)
	}
}

func TestRemoteKillMessage_ValidateForFollower(t *testing.T) {
	msg := testRemoteKillMessage()
	if err := msg.ValidateForFollower("org-test", "fleet-prod", "instance-1", nil); err != nil {
		t.Fatalf("ValidateForFollower(wildcard) = %v, want nil", err)
	}
	if err := msg.ValidateForFollower("org-other", "fleet-prod", "instance-1", nil); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("ValidateForFollower(org mismatch) = %v, want ErrAudienceMismatch", err)
	}

	msg.Audience = Audience{Labels: map[string]string{"ring": "canary"}}
	if err := msg.ValidateForFollower("org-test", "fleet-prod", "instance-2", map[string]string{"ring": "canary"}); err != nil {
		t.Fatalf("ValidateForFollower(label match) = %v, want nil", err)
	}
	if err := msg.ValidateForFollower("org-test", "fleet-prod", "instance-2", map[string]string{"ring": "prod"}); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("ValidateForFollower(label mismatch) = %v, want ErrAudienceMismatch", err)
	}
}

func TestRollbackAuthorization_VerifySignatures(t *testing.T) {
	auth := testRollbackAuthorization()
	pub1, proof1 := signedProof(t, auth.SignablePreimage, "rollback-signer-1", signing.PurposePolicyBundleRollback)
	pub2, proof2 := signedProof(t, auth.SignablePreimage, "rollback-signer-2", signing.PurposePolicyBundleRollback)
	auth.Signatures = []SignatureProof{proof1, proof2}
	resolver := mapResolver(map[string]SignatureKey{
		"rollback-signer-1": {PublicKey: pub1, KeyPurpose: signing.PurposePolicyBundleRollback},
		"rollback-signer-2": {PublicKey: pub2, KeyPurpose: signing.PurposePolicyBundleRollback},
	})
	if err := auth.VerifySignatures(resolver); err != nil {
		t.Fatalf("VerifySignatures() = %v, want nil", err)
	}

	auth.TargetBundleID = "bundle-other"
	if err := auth.VerifySignaturesAt(testNow, resolver); !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("VerifySignaturesAt(tampered) = %v, want ErrSignatureVerification", err)
	}
}

func TestStreamSwitchAuthorization_SignablePreimageExcludesSignatures(t *testing.T) {
	authA := testStreamSwitchAuthorization()
	authB := testStreamSwitchAuthorization()
	authB.Signatures[0].Signature = testSignature("ab")
	authB.Signatures[0].SignerKeyID = "different-signer"

	preA, err := authA.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(authA): %v", err)
	}
	preB, err := authB.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(authB): %v", err)
	}
	if string(preA) != string(preB) {
		t.Fatalf("preimage changed when detached signatures changed:\na=%s\nb=%s", preA, preB)
	}
}

func TestStreamSwitchAuthorization_VerifySignatures(t *testing.T) {
	auth := testStreamSwitchAuthorization()
	pub1, proof1 := signedProof(t, auth.SignablePreimage, "switch-signer-1", signing.PurposePolicyBundleRollback)
	pub2, proof2 := signedProof(t, auth.SignablePreimage, "switch-signer-2", signing.PurposePolicyBundleRollback)
	auth.Signatures = []SignatureProof{proof1, proof2}
	resolver := mapResolver(map[string]SignatureKey{
		"switch-signer-1": {PublicKey: pub1, KeyPurpose: signing.PurposePolicyBundleRollback},
		"switch-signer-2": {PublicKey: pub2, KeyPurpose: signing.PurposePolicyBundleRollback},
	})

	if err := auth.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if err := auth.ValidateAtTime(testNow); err != nil {
		t.Fatalf("ValidateAtTime() = %v, want nil", err)
	}
	if err := auth.VerifySignatures(resolver); err != nil {
		t.Fatalf("VerifySignatures() = %v, want nil", err)
	}
	if err := auth.VerifySignaturesAt(testNow, resolver); err != nil {
		t.Fatalf("VerifySignaturesAt() = %v, want nil", err)
	}

	auth.TargetBundleHash = testHash("88")
	if err := auth.VerifySignaturesAt(testNow, resolver); !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("VerifySignaturesAt(tampered) = %v, want ErrSignatureVerification", err)
	}
}

func TestStreamSwitchAuthorization_ValidateRejectsSameAudience(t *testing.T) {
	auth := testStreamSwitchAuthorization()
	auth.TargetAudience = auth.CurrentAudience
	if err := auth.Validate(); !errors.Is(err, ErrInvalidRollback) {
		t.Fatalf("Validate(same audience) = %v, want ErrInvalidRollback", err)
	}
}

func TestStreamSwitchAuthorization_ValidateRejectsMalformedFields(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*StreamSwitchAuthorization)
		wantErr error
	}{
		{"schema", func(a *StreamSwitchAuthorization) { a.SchemaVersion = 99 }, ErrUnsupportedSchemaVersion},
		{"authorization_id", func(a *StreamSwitchAuthorization) { a.AuthorizationID = "bad id" }, ErrInvalidIdentifier},
		{"org", func(a *StreamSwitchAuthorization) { a.OrgID = "" }, ErrMissingField},
		{"environment", func(a *StreamSwitchAuthorization) { a.Environment = "bad env" }, ErrInvalidIdentifier},
		{"current_audience", func(a *StreamSwitchAuthorization) { a.CurrentAudience = Audience{} }, ErrInvalidAudience},
		{"target_audience", func(a *StreamSwitchAuthorization) { a.TargetAudience = Audience{} }, ErrInvalidAudience},
		{"current_bundle_id", func(a *StreamSwitchAuthorization) { a.CurrentBundleID = "bad id" }, ErrInvalidIdentifier},
		{"target_bundle_id", func(a *StreamSwitchAuthorization) { a.TargetBundleID = "bad id" }, ErrInvalidIdentifier},
		{"versions", func(a *StreamSwitchAuthorization) { a.CurrentVersion = 0 }, ErrMissingField},
		{"current_bundle_hash", func(a *StreamSwitchAuthorization) { a.CurrentBundleHash = "bad" }, ErrInvalidHash},
		{"target_bundle_hash", func(a *StreamSwitchAuthorization) { a.TargetBundleHash = "bad" }, ErrInvalidHash},
		{"validity", func(a *StreamSwitchAuthorization) { a.ExpiresAt = a.CreatedAt }, ErrInvalidValidityWindow},
		{"reason", func(a *StreamSwitchAuthorization) { a.Reason = "bad\nreason" }, ErrInvalidReason},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := testStreamSwitchAuthorization()
			tc.mutate(&auth)
			if err := auth.Validate(); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestPolicyBundle_ValidateStreamSwitchAuthorizationBinding(t *testing.T) {
	bundle := testPolicyBundle()
	bundle.Audience = Audience{Labels: map[string]string{"ring": "canary"}}
	detached := bundle
	detached.Signatures = nil
	detached.StreamSwitchAuthorization = nil
	targetHash, err := detached.CanonicalHash()
	if err != nil {
		t.Fatalf("target CanonicalHash: %v", err)
	}

	auth := testStreamSwitchAuthorization()
	auth.OrgID = bundle.OrgID
	auth.FleetID = bundle.FleetID
	auth.Environment = bundle.Environment
	auth.TargetAudience = bundle.Audience
	auth.TargetBundleID = bundle.BundleID
	auth.TargetVersion = bundle.Version
	auth.TargetBundleHash = targetHash
	bundle.StreamSwitchAuthorization = &auth
	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate(bound stream switch authorization) = %v, want nil", err)
	}

	mismatchedTarget := bundle
	mismatchedAuth := auth
	mismatchedAuth.TargetBundleID = "bundle-other"
	mismatchedTarget.StreamSwitchAuthorization = &mismatchedAuth
	if err := mismatchedTarget.Validate(); !errors.Is(err, ErrInvalidRollback) {
		t.Fatalf("Validate(mismatched target) = %v, want ErrInvalidRollback", err)
	}

	badHash := bundle
	badHashAuth := auth
	badHashAuth.TargetBundleHash = testHash("99")
	badHash.StreamSwitchAuthorization = &badHashAuth
	if err := badHash.Validate(); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("Validate(bad target hash) = %v, want ErrHashMismatch", err)
	}
}

func TestAudiencesEqual(t *testing.T) {
	if !AudiencesEqual(
		Audience{InstanceIDs: []string{"instance-b", "instance-a"}, Labels: map[string]string{"ring": "prod"}},
		Audience{InstanceIDs: []string{"instance-a", "instance-b"}, Labels: map[string]string{"ring": "prod"}},
	) {
		t.Fatal("AudiencesEqual() = false for reordered instance IDs and identical labels")
	}
	if AudiencesEqual(
		Audience{InstanceIDs: []string{"instance-a"}, Labels: map[string]string{"ring": "prod"}},
		Audience{InstanceIDs: []string{"instance-a"}, Labels: map[string]string{"ring": "canary"}},
	) {
		t.Fatal("AudiencesEqual() = true for different label values")
	}
	if AudiencesEqual(
		Audience{InstanceIDs: []string{"instance-a"}},
		Audience{InstanceIDs: []string{"instance-a", "instance-b"}},
	) {
		t.Fatal("AudiencesEqual() = true for different instance ID sets")
	}
}

func TestAuditBatchEnvelope_VerifySignatures(t *testing.T) {
	batch := testAuditBatch()
	pub, proof := signedProof(t, batch.SignablePreimage, "audit-signer-1", signing.PurposeAuditBatchSigning)
	batch.Signatures = []SignatureProof{proof}
	resolver := mapResolver(map[string]SignatureKey{
		"audit-signer-1": {PublicKey: pub, KeyPurpose: signing.PurposeAuditBatchSigning},
	})
	if err := batch.VerifySignatures(resolver); err != nil {
		t.Fatalf("VerifySignatures() = %v, want nil", err)
	}

	batch.PayloadBytes++
	if err := batch.VerifySignaturesAt(testNow, resolver); !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("VerifySignaturesAt(tampered) = %v, want ErrSignatureVerification", err)
	}
}

func TestValidationEdgeCases(t *testing.T) {
	t.Run("signature_proof_missing_signer", func(t *testing.T) {
		err := (SignatureProof{KeyPurpose: signing.PurposePolicyBundleSigning, Algorithm: SignatureAlgorithmEd25519, Signature: testSignature("aa")}).
			Validate(signing.PurposePolicyBundleSigning)
		if !errors.Is(err, ErrMissingField) {
			t.Fatalf("Validate() = %v, want ErrMissingField", err)
		}
	})

	t.Run("signature_proof_bad_algorithm", func(t *testing.T) {
		proof := testProof("signer-1", signing.PurposePolicyBundleSigning)
		proof.Algorithm = "ecdsa"
		err := proof.Validate(signing.PurposePolicyBundleSigning)
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("Validate() = %v, want ErrInvalidSignature", err)
		}
	})

	t.Run("dropped_reasons_with_zero_count", func(t *testing.T) {
		err := (DroppedAccounting{Reasons: []DroppedReason{{Reason: "queue_full", Count: 1}}}).Validate()
		if !errors.Is(err, ErrInvalidDroppedAccounting) {
			t.Fatalf("Validate() = %v, want ErrInvalidDroppedAccounting", err)
		}
	})

	t.Run("dropped_count_without_reasons", func(t *testing.T) {
		err := (DroppedAccounting{Count: 1}).Validate()
		if !errors.Is(err, ErrInvalidDroppedAccounting) {
			t.Fatalf("Validate() = %v, want ErrInvalidDroppedAccounting", err)
		}
	})

	t.Run("dropped_reason_invalid_identifier", func(t *testing.T) {
		err := (DroppedReason{Reason: "bad reason", Count: 1}).Validate()
		if !errors.Is(err, ErrInvalidDroppedAccounting) {
			t.Fatalf("Validate() = %v, want ErrInvalidDroppedAccounting", err)
		}
	})

	t.Run("rule_bundle_missing_version", func(t *testing.T) {
		err := (RuleBundleRef{Name: "official", SHA256: testHash("04")}).Validate()
		if !errors.Is(err, ErrMissingField) {
			t.Fatalf("Validate() = %v, want ErrMissingField", err)
		}
	})

	t.Run("evidence_chain_checkpoint_out_of_range", func(t *testing.T) {
		chain := testAuditBatch().Chain
		chain.CheckpointSeq = chain.SeqEnd + 1
		err := chain.Validate(chain.SeqStart, chain.SeqEnd)
		if !errors.Is(err, ErrInvalidSequenceRange) {
			t.Fatalf("Validate() = %v, want ErrInvalidSequenceRange", err)
		}
	})

	t.Run("invalid_signature_string_prefix", func(t *testing.T) {
		err := validateEd25519SignatureString("bad:" + strings.Repeat("aa", 64))
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("validateEd25519SignatureString() = %v, want ErrInvalidSignature", err)
		}
	})

	t.Run("invalid_public_key_hex", func(t *testing.T) {
		err := validatePublicKeyHex("pub", "ff")
		if !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("validatePublicKeyHex() = %v, want ErrInvalidHash", err)
		}
	})
}

func TestRemoteKillMessage_ValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		edit func(*RemoteKillMessage)
		want error
	}{
		{"unsupported_schema", func(m *RemoteKillMessage) { m.SchemaVersion = 99 }, ErrUnsupportedSchemaVersion},
		{"missing_message_id", func(m *RemoteKillMessage) { m.MessageID = "" }, ErrMissingField},
		{"missing_org", func(m *RemoteKillMessage) { m.OrgID = "" }, ErrMissingField},
		{"empty_audience", func(m *RemoteKillMessage) { m.Audience = Audience{} }, ErrInvalidAudience},
		{"invalid_state", func(m *RemoteKillMessage) { m.State = "paused" }, ErrInvalidState},
		{"missing_counter", func(m *RemoteKillMessage) { m.Counter = 0 }, ErrMissingField},
		{"invalid_window", func(m *RemoteKillMessage) { m.ExpiresAt = m.NotBefore }, ErrInvalidValidityWindow},
		{"missing_created_at", func(m *RemoteKillMessage) { m.CreatedAt = time.Time{} }, ErrMissingField},
		{"invalid_utf8_reason", func(m *RemoteKillMessage) { m.Reason = string([]byte{0xff}) }, ErrInvalidReason},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := testRemoteKillMessage()
			tt.edit(&msg)
			if err := msg.Validate(); !errors.Is(err, tt.want) {
				t.Fatalf("Validate() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestRollbackAuthorization_ValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		edit func(*RollbackAuthorization)
		want error
	}{
		{"unsupported_schema", func(r *RollbackAuthorization) { r.SchemaVersion = 99 }, ErrUnsupportedSchemaVersion},
		{"missing_authorization_id", func(r *RollbackAuthorization) { r.AuthorizationID = "" }, ErrMissingField},
		{"missing_fleet", func(r *RollbackAuthorization) { r.FleetID = "" }, ErrMissingField},
		{"missing_current_bundle", func(r *RollbackAuthorization) { r.CurrentBundleID = "" }, ErrMissingField},
		{"missing_target_bundle", func(r *RollbackAuthorization) { r.TargetBundleID = "" }, ErrMissingField},
		{"missing_counter", func(r *RollbackAuthorization) { r.Counter = 0 }, ErrMissingField},
		{"invalid_validity", func(r *RollbackAuthorization) { r.ExpiresAt = r.CreatedAt }, ErrInvalidValidityWindow},
		{"control_reason", func(r *RollbackAuthorization) { r.Reason = "bad\tbundle" }, ErrInvalidReason},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := testRollbackAuthorization()
			tt.edit(&auth)
			if err := auth.Validate(); !errors.Is(err, tt.want) {
				t.Fatalf("Validate() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestRollbackAuthorization_ValidateToleratesLegacyAudience(t *testing.T) {
	for _, audience := range []Audience{
		{InstanceIDs: []string{"instance-1"}},
		{Labels: map[string]string{"tier": "prod"}},
	} {
		auth := testRollbackAuthorization()
		auth.Audience = audience
		if err := auth.Validate(); err != nil {
			t.Fatalf("Validate() with audience %+v error = %v, want nil", audience, err)
		}
	}
}

func TestAuditBatchEnvelope_ValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		edit func(*AuditBatchEnvelope)
		want error
	}{
		{"unsupported_schema", func(a *AuditBatchEnvelope) { a.SchemaVersion = 99 }, ErrUnsupportedSchemaVersion},
		{"missing_batch_id", func(a *AuditBatchEnvelope) { a.BatchID = "" }, ErrMissingField},
		{"missing_instance_id", func(a *AuditBatchEnvelope) { a.InstanceID = "" }, ErrMissingField},
		{"missing_audit_schema", func(a *AuditBatchEnvelope) { a.AuditSchemaVersion = 0 }, ErrMissingField},
		{"missing_emitted_at", func(a *AuditBatchEnvelope) { a.EmittedAt = time.Time{} }, ErrMissingField},
		{"invalid_seq", func(a *AuditBatchEnvelope) { a.SeqEnd = a.SeqStart - 1 }, ErrInvalidSequenceRange},
		{"missing_event_count", func(a *AuditBatchEnvelope) { a.EventCount = 0 }, ErrMissingField},
		{"invalid_payload_hash", func(a *AuditBatchEnvelope) { a.PayloadSHA256 = "not-hex" }, ErrInvalidHash},
		{"invalid_dropped", func(a *AuditBatchEnvelope) { a.Dropped = DroppedAccounting{Count: 1} }, ErrInvalidDroppedAccounting},
		{"invalid_chain", func(a *AuditBatchEnvelope) { a.Chain.SeqEnd++ }, ErrInvalidSequenceRange},
		{"missing_signatures", func(a *AuditBatchEnvelope) { a.Signatures = nil }, ErrThresholdRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			batch := testAuditBatch()
			tt.edit(&batch)
			if err := batch.Validate(); !errors.Is(err, tt.want) {
				t.Fatalf("Validate() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestEvidenceChain_ValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		edit func(*EvidenceChain)
		want error
	}{
		{"wrong_entry_version", func(c *EvidenceChain) { c.EntryVersion = 3 }, ErrInvalidSequenceRange},
		{"missing_segment", func(c *EvidenceChain) { c.SegmentID = "" }, ErrMissingField},
		{"seq_mismatch", func(c *EvidenceChain) { c.SeqStart++ }, ErrInvalidSequenceRange},
		{"bad_hash", func(c *EvidenceChain) { c.CheckpointHash = "bad" }, ErrInvalidHash},
		{"bad_previous_tail", func(c *EvidenceChain) { c.PreviousSegmentTail = "bad" }, ErrInvalidHash},
		{"bad_checkpoint_signature", func(c *EvidenceChain) { c.CheckpointSignature = "bad" }, ErrInvalidSignature},
		{"missing_checkpoint_key", func(c *EvidenceChain) { c.CheckpointSignerKeyID = "" }, ErrMissingField},
		{"missing_recorder_key", func(c *EvidenceChain) { c.FollowerRecorderKeyID = "" }, ErrMissingField},
		{"bad_recorder_pub", func(c *EvidenceChain) { c.FollowerRecorderPubHex = "bad" }, ErrInvalidHash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := testAuditBatch().Chain
			tt.edit(&chain)
			if err := chain.Validate(10, 20); !errors.Is(err, tt.want) {
				t.Fatalf("Validate() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAudienceAndLabelValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		aud  Audience
	}{
		{"empty_instance", Audience{InstanceIDs: []string{""}}},
		{"bad_instance", Audience{InstanceIDs: []string{"-bad"}}},
		{"empty_label_value", Audience{Labels: map[string]string{"ring": ""}}},
		{"long_label_key", Audience{Labels: map[string]string{strings.Repeat("a", MaxLabelKeyBytes+1): "v"}}},
		{"long_label_value", Audience{Labels: map[string]string{"ring": strings.Repeat("a", MaxLabelValueBytes+1)}}},
		{"bad_label_identifier", Audience{Labels: map[string]string{"-ring": "canary"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.aud.Validate(); !errors.Is(err, ErrInvalidAudience) {
				t.Fatalf("Validate() = %v, want ErrInvalidAudience", err)
			}
		})
	}
}

func TestRejectLicenseFieldsYAMLDocumentHandling(t *testing.T) {
	if err := rejectLicenseFields(""); !errors.Is(err, ErrForbiddenLicenseField) {
		t.Fatalf("rejectLicenseFields(empty) = %v, want ErrForbiddenLicenseField", err)
	}
	if err := rejectLicenseFields("mode: strict\n---\n"); err != nil {
		t.Fatalf("rejectLicenseFields(empty trailing doc) = %v, want nil", err)
	}
	if err := rejectLicenseFields("mode: strict\n---\nmode: balanced\n"); !errors.Is(err, ErrForbiddenLicenseField) {
		t.Fatalf("rejectLicenseFields(non-empty trailing doc) = %v, want ErrForbiddenLicenseField", err)
	}
	if err := rejectLicenseFields("mode: [\n"); !errors.Is(err, ErrForbiddenLicenseField) {
		t.Fatalf("rejectLicenseFields(malformed) = %v, want ErrForbiddenLicenseField", err)
	}
}

func testProof(keyID string, purpose signing.KeyPurpose) SignatureProof {
	return SignatureProof{
		SignerKeyID: keyID,
		KeyPurpose:  purpose,
		Algorithm:   SignatureAlgorithmEd25519,
		Signature:   testSignature("aa"),
	}
}

func signedProof(
	t *testing.T,
	preimage func() ([]byte, error),
	keyID string,
	purpose signing.KeyPurpose,
) (ed25519.PublicKey, SignatureProof) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg, err := preimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	sig := ed25519.Sign(priv, msg)
	return pub, SignatureProof{
		SignerKeyID: keyID,
		KeyPurpose:  purpose,
		Algorithm:   SignatureAlgorithmEd25519,
		Signature:   SignaturePrefixEd25519 + hex.EncodeToString(sig),
	}
}

func mapResolver(keys map[string]SignatureKey) SignatureKeyResolver {
	return func(signerKeyID string) (SignatureKey, error) {
		key, ok := keys[signerKeyID]
		if !ok {
			return SignatureKey{}, ErrSignatureVerification
		}
		return key, nil
	}
}

func mustPayloadHash(payload PolicyBundlePayload) string {
	hash, err := payload.PayloadHash()
	if err != nil {
		panic(err)
	}
	return hash
}

func mustPolicyHash(payload PolicyBundlePayload) string {
	hash, err := payload.PolicyHash()
	if err != nil {
		panic(err)
	}
	return hash
}

func testAuditPayload() []byte {
	return []byte(`{"events":[{"seq":10,"kind":"scan","verdict":"allow"},{"seq":11,"kind":"scan","verdict":"block"}]}`)
}

func testBytesHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func testHash(seed string) string {
	return strings.Repeat(seed, 32)
}

func testSignature(seed string) string {
	return SignaturePrefixEd25519 + strings.Repeat(seed, 64)
}

func TestStreamSwitchAuthorization_ValidateMaxValidity(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name    string
		created time.Time
		expires time.Time
		max     time.Duration
		wantErr error
	}{
		{
			name:    "within_max",
			created: now,
			expires: now.Add(time.Hour),
			max:     24 * time.Hour,
			wantErr: nil,
		},
		{
			name:    "exactly_at_max",
			created: now,
			expires: now.Add(24 * time.Hour),
			max:     24 * time.Hour,
			wantErr: nil,
		},
		{
			name:    "over_max_by_one_second",
			created: now,
			expires: now.Add(24*time.Hour + time.Second),
			max:     24 * time.Hour,
			wantErr: ErrStreamSwitchWindowTooLong,
		},
		{
			name:    "ten_year_window",
			created: now,
			expires: now.Add(10 * 365 * 24 * time.Hour),
			max:     24 * time.Hour,
			wantErr: ErrStreamSwitchWindowTooLong,
		},
		{
			name:    "non_positive_max_skips",
			created: now,
			expires: now.Add(10 * 365 * 24 * time.Hour),
			max:     0,
			wantErr: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := StreamSwitchAuthorization{
				CreatedAt: tc.created,
				ExpiresAt: tc.expires,
			}
			err := auth.ValidateMaxValidity(tc.max)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ValidateMaxValidity(%s) = %v, want %v", tc.name, err, tc.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("ValidateMaxValidity(%s) = %v, want nil", tc.name, err)
				}
			}
		})
	}
}
