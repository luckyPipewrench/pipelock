// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestRunRatifyRefusesOutputAliasingSigningKey(t *testing.T) {
	for _, tc := range []struct {
		name     string
		keyAgent string
		set      func(*ratifyFlags, string)
	}{
		{name: "out-compile", keyAgent: "compile-signer", set: func(f *ratifyFlags, key string) { f.outPath = key }},
		{name: "receipt-out-compile", keyAgent: "compile-signer", set: func(f *ratifyFlags, key string) { f.receiptOut = key }},
		{name: "out-receipt", keyAgent: defaultReceiptKeyAgent, set: func(f *ratifyFlags, key string) { f.outPath = key }},
		{name: "receipt-out-receipt", keyAgent: defaultReceiptKeyAgent, set: func(f *ratifyFlags, key string) { f.receiptOut = key }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ks := signing.NewKeystore(dir)
			if _, err := ks.ForceGenerateAgent("compile-signer"); err != nil {
				t.Fatalf("ForceGenerateAgent compile: %v", err)
			}
			if _, err := ks.ForceGenerateAgent(defaultReceiptKeyAgent); err != nil {
				t.Fatalf("ForceGenerateAgent receipt: %v", err)
			}
			keyPath, err := ks.PrivateKeyPath(tc.keyAgent)
			if err != nil {
				t.Fatalf("PrivateKeyPath %s: %v", tc.keyAgent, err)
			}
			before, err := os.ReadFile(filepath.Clean(keyPath))
			if err != nil {
				t.Fatalf("read key: %v", err)
			}
			flags := ratifyFlags{
				candidatePath:       writeCandidateEnvelope(t, dir, testRatifyContract()),
				outPath:             filepath.Join(dir, "ratified.yaml"),
				receiptOut:          filepath.Join(dir, "ratify.jsonl"),
				keystore:            dir,
				compileKeyAgent:     "compile-signer",
				receiptKey:          defaultReceiptKeyAgent,
				acceptLowConfidence: true,
			}
			tc.set(&flags, keyPath)
			cmd, _ := learnTestCmd("")
			err = runRatify(cmd, flags)
			after, readErr := os.ReadFile(filepath.Clean(keyPath))
			if readErr != nil {
				t.Fatalf("re-read key: %v", readErr)
			}
			if err == nil {
				t.Fatalf("runRatify succeeded writing over the %s key", tc.keyAgent)
			}
			if !strings.Contains(err.Error(), "must not name") {
				t.Fatalf("runRatify error = %v, want alias refusal", err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("signing key was overwritten")
			}
		})
	}
}

func TestRunRatifyRefusesReceiptOutAliasingCandidate(t *testing.T) {
	dir := t.TempDir()
	candidate := writeCandidateEnvelope(t, dir, testRatifyContract())
	before, err := os.ReadFile(filepath.Clean(candidate))
	if err != nil {
		t.Fatalf("read candidate: %v", err)
	}
	cmd, _ := learnTestCmd("")
	err = runRatify(cmd, ratifyFlags{
		candidatePath:       candidate,
		outPath:             filepath.Join(dir, "ratified.yaml"),
		receiptOut:          candidate,
		deterministic:       true,
		acceptLowConfidence: true,
	})
	after, readErr := os.ReadFile(filepath.Clean(candidate))
	if readErr != nil {
		t.Fatalf("re-read candidate: %v", readErr)
	}
	if err == nil {
		t.Fatal("runRatify succeeded writing --receipt-out over the loaded candidate")
	}
	if !strings.Contains(err.Error(), "--receipt-out must not name the loaded candidate") {
		t.Fatalf("runRatify error = %v, want candidate receipt alias refusal", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("loaded candidate was overwritten")
	}
}

func TestRunForgetRefusesOutputsAliasingCandidate(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		set  func(*forgetFlags, string)
		want string
	}{
		{name: "receipt-out", set: func(f *forgetFlags, candidate string) { f.receiptOut = candidate }, want: "--receipt-out must not name the loaded candidate"},
		{name: "out", set: func(f *forgetFlags, candidate string) { f.outPath = candidate }, want: "--out must not name the loaded candidate"},
		{name: "tombstone", set: func(f *forgetFlags, candidate string) { f.tombstoneDir = filepath.Dir(candidate) }, want: "tombstone must not name the loaded candidate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := writeCandidateEnvelope(t, dir, testRatifyContract())
			if tc.name == "tombstone" {
				candidate = candidateAtDerivedTombstonePath(t, dir)
			}
			before, err := os.ReadFile(filepath.Clean(candidate))
			if err != nil {
				t.Fatalf("read candidate: %v", err)
			}
			flags := forgetFlags{
				candidatePath: candidate,
				ruleID:        "r-enforce",
				reason:        "legal-ticket-123",
				outPath:       filepath.Join(dir, "forgotten-"+tc.name+".yaml"),
				tombstoneDir:  filepath.Join(dir, "tombstones-"+tc.name),
				receiptOut:    filepath.Join(dir, "redaction-"+tc.name+".jsonl"),
				deterministic: true,
			}
			tc.set(&flags, candidate)
			cmd, _ := learnTestCmd("")
			err = runForget(cmd, flags)
			after, readErr := os.ReadFile(filepath.Clean(candidate))
			if readErr != nil {
				t.Fatalf("re-read candidate: %v", readErr)
			}
			if err == nil {
				t.Fatalf("runForget succeeded writing %s over the loaded candidate", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("runForget error = %v, want %q", err, tc.want)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("loaded candidate was overwritten")
			}
		})
	}
}

func TestRunForgetRefusesOutputAliasingSigningKey(t *testing.T) {
	for _, tc := range []struct {
		name     string
		keyAgent string
		set      func(*testing.T, *forgetFlags, string, string)
	}{
		{name: "out-compile", keyAgent: "compile-signer", set: func(_ *testing.T, f *forgetFlags, key, _ string) { f.outPath = key }},
		{name: "receipt-out-compile", keyAgent: "compile-signer", set: func(_ *testing.T, f *forgetFlags, key, _ string) { f.receiptOut = key }},
		{name: "out-activation", keyAgent: "activation-signer", set: func(_ *testing.T, f *forgetFlags, key, _ string) { f.outPath = key }},
		{name: "receipt-out-activation", keyAgent: "activation-signer", set: func(_ *testing.T, f *forgetFlags, key, _ string) { f.receiptOut = key }},
		{name: "tombstone-activation", keyAgent: "activation-signer", set: plantForgetTombstoneOverKey},
		{name: "tombstone-compile", keyAgent: "compile-signer", set: plantForgetTombstoneOverKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ks := signing.NewKeystore(dir)
			if _, err := ks.ForceGenerateAgent("compile-signer"); err != nil {
				t.Fatalf("ForceGenerateAgent compile: %v", err)
			}
			if _, err := ks.ForceGenerateAgent("activation-signer"); err != nil {
				t.Fatalf("ForceGenerateAgent activation: %v", err)
			}
			keyPath, err := ks.PrivateKeyPath(tc.keyAgent)
			if err != nil {
				t.Fatalf("PrivateKeyPath %s: %v", tc.keyAgent, err)
			}
			before, err := os.ReadFile(filepath.Clean(keyPath))
			if err != nil {
				t.Fatalf("read key: %v", err)
			}
			candidate := writeCandidateEnvelope(t, dir, testRatifyContract())
			flags := forgetFlags{
				candidatePath:   candidate,
				ruleID:          "r-enforce",
				reason:          "legal-ticket-123",
				outPath:         filepath.Join(dir, "forgotten.yaml"),
				tombstoneDir:    filepath.Join(dir, "tombstones"),
				receiptOut:      filepath.Join(dir, "redaction.jsonl"),
				keystore:        dir,
				compileKeyAgent: "compile-signer",
				activationKey:   "activation-signer",
			}
			tc.set(t, &flags, keyPath, candidate)
			cmd, _ := learnTestCmd("")
			err = runForget(cmd, flags)
			after, readErr := os.ReadFile(filepath.Clean(keyPath))
			if readErr != nil {
				t.Fatalf("re-read key: %v", readErr)
			}
			if err == nil {
				t.Fatalf("runForget succeeded writing over the %s key", tc.keyAgent)
			}
			if !strings.Contains(err.Error(), "must not name") {
				t.Fatalf("runForget error = %v, want alias refusal", err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("signing key was overwritten")
			}
		})
	}
}

func TestLearnCmdRegistersRatifyAndForget(t *testing.T) {
	cmd := Cmd()
	for _, name := range []string{"ratify", "forget"} {
		t.Run(name, func(t *testing.T) {
			for _, child := range cmd.Commands() {
				if child.Name() == name {
					return
				}
			}
			t.Fatalf("learn command missing %q", name)
		})
	}
}

func TestRatifyInteractiveRejectsOneRuleAndSignsReceipt(t *testing.T) {
	dir := t.TempDir()
	candidate := writeCandidateEnvelope(t, dir, testRatifyContract())
	out := filepath.Join(dir, "ratified.yaml")
	receiptOut := filepath.Join(dir, "ratify.jsonl")
	cmd, stdout := learnTestCmd("r\ne\n")

	err := runRatify(cmd, ratifyFlags{
		candidatePath: candidate,
		outPath:       out,
		receiptOut:    receiptOut,
		interactive:   true,
		deterministic: true,
	})
	if err != nil {
		t.Fatalf("runRatify: %v", err)
	}
	if !strings.Contains(stdout.String(), "Rule 1/2") || !strings.Contains(stdout.String(), "data_class: internal") {
		t.Fatalf("interactive review output missing rule/data-class context:\n%s", stdout.String())
	}
	_, env, err := loadCandidateEnvelope(out)
	if err != nil {
		t.Fatalf("load ratified candidate: %v", err)
	}
	if len(env.Body.Rules) != 1 || env.Body.Rules[0].RuleID != "r-reject" {
		t.Fatalf("ratified rules = %#v", env.Body.Rules)
	}
	if env.Body.Rules[0].LifecycleState != ratifyDecisionEnforce {
		t.Fatalf("lifecycle_state = %q", env.Body.Rules[0].LifecycleState)
	}
	if env.Body.FieldDataClasses["/rules/0"] != "internal" {
		t.Fatalf("field_data_classes[/rules/0] = %q, want internal", env.Body.FieldDataClasses["/rules/0"])
	}
	if _, ok := env.Body.FieldDataClasses["/rules/1"]; ok {
		t.Fatalf("stale field_data_classes[/rules/1] remains: %#v", env.Body.FieldDataClasses)
	}
	rcpt := readOneReceipt(t, receiptOut)
	if rcpt.PayloadKind != contractreceipt.PayloadContractRatified {
		t.Fatalf("payload_kind = %q", rcpt.PayloadKind)
	}
	var payload contractreceipt.PayloadContractRatifiedStruct
	if err := json.Unmarshal(rcpt.Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.RatificationDecisionPerRule["r-enforce"] != ratifyDecisionReject {
		t.Fatalf("decision map = %#v", payload.RatificationDecisionPerRule)
	}
}

func TestForgetRemovesRuleWritesTombstoneAndRedactionReceipt(t *testing.T) {
	dir := t.TempDir()
	candidate := writeCandidateEnvelope(t, dir, testRatifyContract())
	out := filepath.Join(dir, "forgotten.yaml")
	receiptOut := filepath.Join(dir, "redaction.jsonl")
	tombstoneDir := filepath.Join(dir, "tombstones")
	cmd, stdout := learnTestCmd("")

	err := runForget(cmd, forgetFlags{
		candidatePath: candidate,
		ruleID:        "r-enforce",
		reason:        "legal-ticket-123",
		outPath:       out,
		tombstoneDir:  tombstoneDir,
		receiptOut:    receiptOut,
		deterministic: true,
	})
	if err != nil {
		t.Fatalf("runForget: %v", err)
	}
	if !strings.Contains(stdout.String(), "tombstone written") {
		t.Fatalf("stdout missing tombstone path: %s", stdout.String())
	}
	_, env, err := loadCandidateEnvelope(out)
	if err != nil {
		t.Fatalf("load forgotten candidate: %v", err)
	}
	if len(env.Body.Rules) != 1 || env.Body.Rules[0].RuleID != "r-reject" {
		t.Fatalf("forgotten rules = %#v", env.Body.Rules)
	}
	if env.Body.FieldDataClasses["/rules/0"] != "internal" {
		t.Fatalf("field_data_classes[/rules/0] = %q, want internal", env.Body.FieldDataClasses["/rules/0"])
	}
	if _, ok := env.Body.FieldDataClasses["/rules/1"]; ok {
		t.Fatalf("stale field_data_classes[/rules/1] remains: %#v", env.Body.FieldDataClasses)
	}
	matches, err := filepath.Glob(filepath.Join(tombstoneDir, "*.tombstone.yaml"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("tombstone matches=%v err=%v", matches, err)
	}
	var tombstone contract.TombstoneEnvelope
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read tombstone: %v", err)
	}
	if err := yaml.Unmarshal(raw, &tombstone); err != nil {
		t.Fatalf("unmarshal tombstone: %v", err)
	}
	if !tombstone.Body.Tombstone || tombstone.Signature == "" {
		t.Fatalf("bad tombstone envelope: %+v", tombstone)
	}
	rcpt := readOneReceipt(t, receiptOut)
	if rcpt.PayloadKind != contractreceipt.PayloadContractRedactionRequest {
		t.Fatalf("payload_kind = %q", rcpt.PayloadKind)
	}
	var payload contractreceipt.PayloadContractRedactionRequestStruct
	if err := json.Unmarshal(rcpt.Payload, &payload); err != nil {
		t.Fatalf("unmarshal redaction payload: %v", err)
	}
	if payload.RequestKind != localErasureTombstone || payload.ReasonClass != "legal-ticket-123" || payload.TombstoneHash == "" {
		t.Fatalf("redaction payload = %+v", payload)
	}
}

func testRatifyContract() contract.Contract {
	return contract.Contract{
		SchemaVersion:    contract.SchemaVersionContract,
		ContractKind:     contract.ContractKind,
		SignerKeyID:      "compile-signer",
		KeyPurpose:       "contract-compile-signing",
		DataClassRoot:    "internal",
		FieldDataClasses: map[string]string{"/rules/0": "internal", "/rules/1": "internal"},
		Selector:         contract.Selector{Agent: "agent-a", SelectorID: "sha256:selector"},
		ObservationWindow: contract.ObservationWindow{
			Start:                 time.Date(2026, 4, 30, 10, 0, 0, 0, time.UTC),
			End:                   time.Date(2026, 4, 30, 11, 0, 0, 0, time.UTC),
			EventCount:            42,
			SessionCount:          3,
			ObservationWindowRoot: "sha256:window",
		},
		Defaults: contract.ContractDefaults{
			Privacy: contract.ContractDefaultsPrivacy{DefaultDataClass: "internal"},
		},
		Rules: []contract.Rule{
			testRule("r-enforce", "api.example.com", "/v1/users"),
			testRule("r-reject", "api.example.com", "/v1/admin"),
		},
	}
}

func testRule(id, host, path string) contract.Rule {
	return contract.Rule{
		RuleID:               id,
		DisplayName:          id,
		RuleKind:             "http_destination",
		LifecycleState:       "capture_only",
		RequiredCaptureGrade: contract.CaptureGradeFull,
		ObservedCaptureGrade: contract.CaptureGradeFull,
		Confidence:           "stable",
		WilsonLower:          "0.990000",
		Observation:          map[string]any{"event_count": "21", "redacted_samples": []any{"sha256:sample"}},
		Selector:             map[string]any{"host": host, "path": path},
		Rationale:            map[string]any{"fp_risk_class": "low"},
		RecurringSupport:     map[string]any{},
		OpportunityHealth:    map[string]any{},
	}
}

func plantForgetTombstoneOverKey(t *testing.T, flags *forgetFlags, keyPath, candidate string) {
	t.Helper()
	_, env, err := loadCandidateEnvelope(candidate)
	if err != nil {
		t.Fatalf("loadCandidateEnvelope: %v", err)
	}
	name := strings.NewReplacer(":", "-", "/", "-").Replace(env.Body.ContractHash) + ".tombstone.yaml"
	tombDir := filepath.Join(filepath.Dir(candidate), "tombstones-key-alias")
	if err := os.MkdirAll(tombDir, 0o750); err != nil {
		t.Fatalf("MkdirAll tombstone dir: %v", err)
	}
	dest := filepath.Join(tombDir, name)
	if err := os.Link(keyPath, dest); err != nil {
		t.Fatalf("Link tombstone dest to key: %v", err)
	}
	flags.tombstoneDir = tombDir
}

func candidateAtDerivedTombstonePath(t *testing.T, dir string) string {
	t.Helper()
	src := writeCandidateEnvelope(t, dir, testRatifyContract())
	_, env, err := loadCandidateEnvelope(src)
	if err != nil {
		t.Fatalf("loadCandidateEnvelope: %v", err)
	}
	name := strings.NewReplacer(":", "-", "/", "-").Replace(env.Body.ContractHash) + ".tombstone.yaml"
	dest := filepath.Join(dir, name)
	raw, err := os.ReadFile(filepath.Clean(src))
	if err != nil {
		t.Fatalf("read candidate: %v", err)
	}
	if err := os.WriteFile(dest, raw, 0o600); err != nil {
		t.Fatalf("WriteFile tombstone-named candidate: %v", err)
	}
	return dest
}

func writeCandidateEnvelope(t *testing.T, dir string, c contract.Contract) string {
	t.Helper()
	seed := sha256.Sum256([]byte("test candidate signer"))
	env := contract.ContractEnvelope{Body: c}
	if err := signContractEnvelope(&env, privateKeySigner{
		keyID: "compile-signer",
		key:   ed25519.NewKeyFromSeed(seed[:]),
	}); err != nil {
		t.Fatalf("signContractEnvelope: %v", err)
	}
	path := filepath.Join(dir, "candidate.yaml")
	if err := writeContractEnvelopeYAML(path, env); err != nil {
		t.Fatalf("write candidate: %v", err)
	}
	return path
}

func learnTestCmd(input string) (*cobra.Command, *bytes.Buffer) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader(input))
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	return cmd, stdout
}

func readOneReceipt(t *testing.T, path string) contractreceipt.EvidenceReceipt {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // test path is generated inside t.TempDir
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("receipt lines = %d, want 1\n%s", len(lines), string(raw))
	}
	var rcpt contractreceipt.EvidenceReceipt
	if err := json.Unmarshal([]byte(lines[0]), &rcpt); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	if err := rcpt.Validate(); err != nil {
		t.Fatalf("receipt Validate: %v", err)
	}
	return rcpt
}
