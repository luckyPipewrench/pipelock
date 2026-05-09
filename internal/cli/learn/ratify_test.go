// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

const (
	testRatifyConfidenceStable         = "stable"
	testRatifyConfidenceBrittle        = "brittle"
	testRatifyConfidenceNeverConfirmed = "never_confirmed"
	testRatifyConfidenceRefuted        = "refuted"
)

func TestRatifyLowConfidenceGuards(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		interactive         bool
		acceptLowConfidence bool
		input               string
		confidences         []string
		wantErr             bool
		wantErrRules        []string
		wantLifecycle       map[string]string
		wantPrompt          bool
	}{
		{
			name:        "non-interactive all confirmed enforces",
			confidences: []string{testRatifyConfidenceStable, testRatifyConfidenceBrittle},
			wantLifecycle: map[string]string{
				"r-enforce": ratifyDecisionEnforce,
				"r-reject":  ratifyDecisionEnforce,
			},
		},
		{
			name:         "non-interactive mixed never-confirmed refuses with named error",
			confidences:  []string{testRatifyConfidenceStable, testRatifyConfidenceNeverConfirmed},
			wantErr:      true,
			wantErrRules: []string{"r-reject", testRatifyConfidenceNeverConfirmed},
		},
		{
			name:         "non-interactive mixed refuted refuses with named error",
			confidences:  []string{testRatifyConfidenceStable, testRatifyConfidenceRefuted},
			wantErr:      true,
			wantErrRules: []string{"r-reject", testRatifyConfidenceRefuted},
		},
		{
			name:         "non-interactive empty confidence refuses fail-closed",
			confidences:  []string{testRatifyConfidenceStable, ""},
			wantErr:      true,
			wantErrRules: []string{"r-reject", "confidence="},
		},
		{
			name:         "non-interactive novel confidence refuses fail-closed",
			confidences:  []string{testRatifyConfidenceStable, "maybe_ok"},
			wantErr:      true,
			wantErrRules: []string{"r-reject", "maybe_ok"},
		},
		{
			name:         "non-interactive homoglyph confidence refuses fail-closed",
			confidences:  []string{testRatifyConfidenceStable, "stаble"},
			wantErr:      true,
			wantErrRules: []string{"r-reject", "stаble"},
		},
		{
			name:         "non-interactive whitespace confidence refuses fail-closed",
			confidences:  []string{testRatifyConfidenceStable, "   "},
			wantErr:      true,
			wantErrRules: []string{"r-reject", "confidence="},
		},
		{
			name:        "non-interactive uppercase stable accepted via case-fold",
			confidences: []string{testRatifyConfidenceStable, "STABLE"},
			wantLifecycle: map[string]string{
				"r-enforce": ratifyDecisionEnforce,
				"r-reject":  ratifyDecisionEnforce,
			},
		},
		{
			name:                "non-interactive accept-low-confidence mixed enforces",
			acceptLowConfidence: true,
			confidences:         []string{testRatifyConfidenceStable, testRatifyConfidenceNeverConfirmed},
			wantLifecycle: map[string]string{
				"r-enforce": ratifyDecisionEnforce,
				"r-reject":  ratifyDecisionEnforce,
			},
		},
		{
			name:        "interactive mixed remains per-rule prompt",
			interactive: true,
			input:       "e\nc\n",
			confidences: []string{testRatifyConfidenceStable, testRatifyConfidenceNeverConfirmed},
			wantLifecycle: map[string]string{
				"r-enforce": ratifyDecisionEnforce,
				"r-reject":  ratifyDecisionCapture,
			},
			wantPrompt: true,
		},
		{
			name:         "interactive all low-confidence refuses without override",
			interactive:  true,
			input:        "e\ne\n",
			confidences:  []string{testRatifyConfidenceNeverConfirmed, testRatifyConfidenceNeverConfirmed},
			wantErr:      true,
			wantErrRules: []string{"r-enforce", "r-reject", testRatifyConfidenceNeverConfirmed},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			candidate := writeCandidateEnvelope(t, dir, ratifyContractWithConfidences(t, tt.confidences...))
			out := filepath.Join(dir, "ratified.yaml")
			cmd, stdout := learnTestCmd(tt.input)

			err := runRatify(cmd, ratifyFlags{
				candidatePath:       candidate,
				outPath:             out,
				receiptOut:          filepath.Join(dir, "ratify.jsonl"),
				interactive:         tt.interactive,
				acceptLowConfidence: tt.acceptLowConfidence,
				deterministic:       true,
			})
			if tt.wantErr {
				if !errors.Is(err, ErrLowConfidenceRatification) {
					t.Fatalf("runRatify err = %v, want ErrLowConfidenceRatification", err)
				}
				for _, want := range tt.wantErrRules {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("runRatify err = %q, want substring %q", err.Error(), want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("runRatify: %v", err)
			}
			if tt.wantPrompt && !strings.Contains(stdout.String(), "Rule 1/2") {
				t.Fatalf("interactive stdout missing prompt:\n%s", stdout.String())
			}
			_, env, err := loadCandidateEnvelope(out)
			if err != nil {
				t.Fatalf("load ratified candidate: %v", err)
			}
			if len(env.Body.Rules) != len(tt.wantLifecycle) {
				t.Fatalf("ratified rules count = %d (%#v), want %d from expected lifecycle map %#v",
					len(env.Body.Rules), env.Body.Rules, len(tt.wantLifecycle), tt.wantLifecycle)
			}
			for _, rule := range env.Body.Rules {
				want, ok := tt.wantLifecycle[rule.RuleID]
				if !ok {
					t.Fatalf("unexpected rule %q in ratified candidate", rule.RuleID)
				}
				if rule.LifecycleState != want {
					t.Fatalf("%s lifecycle_state = %q, want %q", rule.RuleID, rule.LifecycleState, want)
				}
			}
		})
	}
}

func ratifyContractWithConfidences(t *testing.T, confidences ...string) contract.Contract {
	t.Helper()
	c := testRatifyContract()
	if len(confidences) != len(c.Rules) {
		t.Fatalf("confidence count = %d, want %d", len(confidences), len(c.Rules))
	}
	for i := range c.Rules {
		c.Rules[i].Confidence = confidences[i]
	}
	return c
}
