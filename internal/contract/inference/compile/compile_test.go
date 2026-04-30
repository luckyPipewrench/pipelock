// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference/aggregate"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference/emit"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type testSigner struct {
	priv ed25519.PrivateKey
}

func newTestSigner() testSigner {
	seed := sha256.Sum256([]byte("compile fixture signer"))
	return testSigner{priv: ed25519.NewKeyFromSeed(seed[:])}
}

func (s testSigner) KeyID() string { return "compile-fixture" }

func (s testSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

func TestCompile_DeterministicRecompile(t *testing.T) {
	t.Parallel()
	input := fixtureJSONL(t)
	cfg := testConfig()
	opts := CompileOptions{Deterministic: true, Signer: newTestSigner()}

	first, err := Compile(CompileInput{Stream: strings.NewReader(input), Config: cfg}, opts)
	if err != nil {
		t.Fatalf("first Compile: %v", err)
	}
	second, err := Compile(CompileInput{Stream: strings.NewReader(input), Config: cfg}, opts)
	if err != nil {
		t.Fatalf("second Compile: %v", err)
	}

	if !bytes.Equal(first.ContractPreimage, second.ContractPreimage) {
		t.Fatal("contract preimage differs")
	}
	if !bytes.Equal(first.ManifestPreimage, second.ManifestPreimage) {
		t.Fatal("manifest preimage differs")
	}
	if !bytes.Equal(first.YAML, second.YAML) {
		t.Fatal("contract yaml differs")
	}
	if !bytes.Equal(first.ManifestJSON, second.ManifestJSON) {
		t.Fatal("manifest json differs")
	}
	if first.Stats.RulesEmitted == 0 {
		t.Fatal("expected rules")
	}
	if first.Contract.ObservationWindow.SessionCount != 3 {
		t.Fatalf("SessionCount = %d, want 3", first.Contract.ObservationWindow.SessionCount)
	}
	if first.Contract.Rules[0].LifecycleState != "capture_only" {
		t.Fatalf("LifecycleState = %q, want capture_only", first.Contract.Rules[0].LifecycleState)
	}
	if !strings.Contains(first.Review, "Classification Debt") {
		t.Fatalf("review missing Classification Debt:\n%s", first.Review)
	}
}

func TestCompile_FatalIngestError(t *testing.T) {
	t.Parallel()
	bad := recorderEntry(t, 1, recorder.GenesisHash, "https://example.com/a")
	bad.Hash = "wrong"

	_, err := Compile(CompileInput{
		Stream: strings.NewReader(jsonLines(t, bad)),
		Config: testConfig(),
	}, CompileOptions{Deterministic: true, Signer: newTestSigner()})
	if !errors.Is(err, ErrIngestFailed) {
		t.Fatalf("Compile error = %v, want ErrIngestFailed", err)
	}
}

func TestCompile_ObservationWindowRootMarshalError(t *testing.T) {
	oldMarshal := observationWindowMarshal
	t.Cleanup(func() { observationWindowMarshal = oldMarshal })
	observationWindowMarshal = func(any) ([]byte, error) {
		return nil, errMarshalBoom
	}

	_, err := Compile(CompileInput{
		Stream: strings.NewReader(fixtureJSONL(t)),
		Config: testConfig(),
	}, CompileOptions{Deterministic: true, Signer: newTestSigner()})
	if !errors.Is(err, errMarshalBoom) {
		t.Fatalf("Compile error = %v, want errMarshalBoom", err)
	}
}

func TestCompile_InvalidAggregateConfigFailsBeforeIngest(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.WindowDuration = -time.Second

	_, err := Compile(CompileInput{
		Stream: strings.NewReader(fixtureJSONL(t)),
		Config: cfg,
	}, CompileOptions{Deterministic: true, Signer: newTestSigner()})
	if !errors.Is(err, aggregate.ErrInvalidConfig) {
		t.Fatalf("Compile error = %v, want ErrInvalidConfig", err)
	}
}

func TestCompile_RequiresInputs(t *testing.T) {
	t.Parallel()
	_, err := Compile(CompileInput{Config: testConfig()}, CompileOptions{Signer: newTestSigner()})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil stream error = %v, want ErrInvalidInput", err)
	}
	_, err = Compile(CompileInput{Stream: strings.NewReader("")}, CompileOptions{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil signer error = %v, want ErrInvalidInput", err)
	}
}

func TestReviewMarkdown_TailCoverageBlocks(t *testing.T) {
	t.Parallel()
	input := fixtureJSONL(t)
	cfg := testConfig()
	cfg.Cardinality.CardinalityCapPerHost = 1
	cfg.Cardinality.TailPromotionBlockPct = 1

	got, err := Compile(CompileInput{Stream: strings.NewReader(input), Config: cfg}, CompileOptions{
		Deterministic: true,
		Signer:        newTestSigner(),
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !strings.Contains(got.Review, "promotion blocked") {
		t.Fatalf("review missing promotion block:\n%s", got.Review)
	}
}

func TestReviewMarkdown_Badges(t *testing.T) {
	t.Parallel()
	c := baseReviewContract()
	c.Rules[0].Budgets = map[string]any{
		"payload_size_bytes": map[string]any{"sample_count": 1},
	}
	c.Rules[0].Observation = map[string]any{
		"events_observed":           1,
		"sessions_with_opportunity": 10,
		"sessions_observed":         1,
		"windows_with_opportunity":  1,
		"windows_observed":          1,
	}
	review := ReviewMarkdown(c, emptyAggregates(), CompileConfig{
		Floors: inference.Floors{MinSessions: 1, MinEvents: 2, MinWindows: 1},
	})
	for _, want := range []string{"thin sample", "opportunity dropped"} {
		if !strings.Contains(review, want) {
			t.Fatalf("review missing %q:\n%s", want, review)
		}
	}
}

func TestHelpersCoverEdgeBranches(t *testing.T) {
	t.Parallel()
	if IntToUint64(-1) != 0 {
		t.Fatal("negative IntToUint64 should clamp to 0")
	}
	if displayName(map[string]string{}) != "observed_rule" {
		t.Fatal("empty displayName should use fallback")
	}
	if sanitizeNamePart("///") != "root" {
		t.Fatal("empty sanitized part should use root")
	}
	parts := parseRuleKey("host=api.example.com;path=/v1%3Busers%3Did;method=GET;action=allow%3Bdebug%3Dtrue")
	if parts["path"] != "/v1;users=id" || parts["action"] != "allow;debug=true" {
		t.Fatalf("parseRuleKey decoded parts = %#v", parts)
	}
}

func testConfig() CompileConfig {
	return CompileConfig{
		Agent:             "agent-a",
		Floors:            inference.Floors{MinSessions: 1, MinEvents: 1, MinWindows: 1},
		CompileConfigHash: "sha256:test-config",
		Settings: map[string]any{
			"confidence":    map[string]any{"min_events": 1},
			"normalization": map[string]any{},
		},
		InputRefs: []contract.InputRef{{
			Path:       "/tmp/fixture.jsonl",
			SHA256:     "sha256:fixture",
			EventCount: 3,
		}},
	}
}

func baseReviewContract() contract.Contract {
	return contract.Contract{
		Selector: contract.Selector{Agent: "agent-a"},
		ObservationWindow: contract.ObservationWindow{
			Start:      time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
			End:        time.Date(2026, 4, 29, 13, 0, 0, 0, time.UTC),
			EventCount: 1,
		},
		Rules: []contract.Rule{{
			RuleID:         "r-one",
			LifecycleState: "capture_only",
			Confidence:     "never_confirmed",
			Observation:    map[string]any{},
			Budgets:        map[string]any{},
		}},
	}
}

func emptyAggregates() aggregate.Aggregates {
	return aggregate.Aggregates{
		Rules:                map[string]aggregate.RuleCounts{},
		Budgets:              map[string]aggregate.BudgetSamples{},
		HostPathFamilies:     map[string]map[string]int{},
		ActionClassHistogram: map[string]int{},
	}
}

func fixtureJSONL(t *testing.T) string {
	t.Helper()
	first := recorderEntry(t, 1, recorder.GenesisHash, "https://api.example.com/v1/users")
	second := recorderEntry(t, 2, first.Hash, "https://api.example.com/v1/repos")
	third := recorderEntry(t, 3, second.Hash, "https://api.example.com/v1/users")
	return jsonLines(t, first, second, third)
}

func recorderEntry(t *testing.T, seq int, prevHash, rawURL string) recorder.Entry {
	t.Helper()
	rec := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  testUint64(seq),
		Timestamp: time.Date(2026, 4, 29, 12, 0, seq, 0, time.UTC),
		SessionID: fmt.Sprintf("session-%d", seq),
		Type:      capture.EntryTypeCapture,
		EventKind: "read",
		Transport: "fetch",
		Summary:   "captured",
		Detail: capture.CaptureSummary{
			CaptureSchemaVersion: capture.CaptureSchemaV1,
			Surface:              capture.SurfaceURL,
			ActionClass:          "read",
			PayloadBytes:         seq * 10,
			ScannerBytes:         seq * 100,
			EffectiveAction:      "allow",
			Request: capture.CaptureRequest{
				Method: "GET",
				URL:    rawURL,
			},
		},
		PrevHash: prevHash,
	}
	rec.Hash = recorder.ComputeHash(rec)
	return rec
}

func testUint64(v int) uint64 {
	if v <= 0 {
		return 0
	}
	return uint64(v)
}

func jsonLines(t *testing.T, entries ...recorder.Entry) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, entry := range entries {
		if err := enc.Encode(entry); err != nil {
			t.Fatalf("encode entry: %v", err)
		}
	}
	return buf.String()
}

var _ emit.Signer = testSigner{}

var errMarshalBoom = errors.New("marshal boom")
