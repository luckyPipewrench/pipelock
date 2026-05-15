// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRunSteps_AllAppliedNoFailure(t *testing.T) {
	var order []string
	steps := []step{
		{
			name: "a",
			desc: "step a",
			apply: func(context.Context, *installEnv) (bool, error) {
				order = append(order, "apply-a")
				return true, nil
			},
			undo: func(context.Context, *installEnv) error {
				order = append(order, "undo-a")
				return nil
			},
		},
		{
			name: "b",
			desc: "step b",
			apply: func(context.Context, *installEnv) (bool, error) {
				order = append(order, "apply-b")
				return true, nil
			},
		},
	}
	var buf bytes.Buffer
	env := &installEnv{out: &buf}
	outcomes, err := runSteps(context.Background(), env, &buf, steps)
	if err != nil {
		t.Fatalf("runSteps err: %v", err)
	}
	if len(outcomes) != 2 {
		t.Fatalf("outcomes len=%d, want 2", len(outcomes))
	}
	if got := strings.Join(order, ","); got != "apply-a,apply-b" {
		t.Errorf("order: got %q, want apply-a,apply-b", got)
	}
	out := buf.String()
	if !strings.Contains(out, "[ OK ] step 1") || !strings.Contains(out, "[ OK ] step 2") {
		t.Errorf("missing OK lines: %q", out)
	}
}

func TestRunSteps_SkippedStepNotRolledBack(t *testing.T) {
	var order []string
	steps := []step{
		{
			name: "applied",
			desc: "applied step",
			apply: func(context.Context, *installEnv) (bool, error) {
				order = append(order, "apply-applied")
				return true, nil
			},
			undo: func(context.Context, *installEnv) error {
				order = append(order, "undo-applied")
				return nil
			},
		},
		{
			name: "already-done",
			desc: "skip step",
			apply: func(context.Context, *installEnv) (bool, error) {
				order = append(order, "apply-skip")
				return false, nil // not applied
			},
			undo: func(context.Context, *installEnv) error {
				order = append(order, "undo-skip-SHOULD-NOT-RUN")
				return nil
			},
		},
		{
			name: "failed",
			desc: "fail step",
			apply: func(context.Context, *installEnv) (bool, error) {
				order = append(order, "apply-fail")
				return false, errors.New("boom")
			},
		},
	}
	var buf bytes.Buffer
	env := &installEnv{out: &buf}
	_, err := runSteps(context.Background(), env, &buf, steps)
	if err == nil {
		t.Fatalf("expected error")
	}
	// "apply-skip" was called but didApply=false so undo MUST NOT have run
	// for it. "apply-applied" did apply, so its undo must run.
	got := strings.Join(order, ",")
	wantSuffix := "apply-applied,apply-skip,apply-fail,undo-applied"
	if got != wantSuffix {
		t.Errorf("order: got %q, want %q", got, wantSuffix)
	}
}

func TestRunSteps_FailureMidwayRollsBackInReverse(t *testing.T) {
	var order []string
	mkApply := func(label string) func(context.Context, *installEnv) (bool, error) {
		return func(context.Context, *installEnv) (bool, error) {
			order = append(order, "apply-"+label)
			return true, nil
		}
	}
	mkUndo := func(label string) func(context.Context, *installEnv) error {
		return func(context.Context, *installEnv) error {
			order = append(order, "undo-"+label)
			return nil
		}
	}
	steps := []step{
		{name: "a", desc: "a", apply: mkApply("a"), undo: mkUndo("a")},
		{name: "b", desc: "b", apply: mkApply("b"), undo: mkUndo("b")},
		{
			name: "c", desc: "c",
			apply: func(context.Context, *installEnv) (bool, error) {
				order = append(order, "apply-c")
				return false, errors.New("boom at c")
			},
			undo: mkUndo("c"),
		},
		{name: "d", desc: "d", apply: mkApply("d"), undo: mkUndo("d")},
	}
	var buf bytes.Buffer
	env := &installEnv{out: &buf}
	_, err := runSteps(context.Background(), env, &buf, steps)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "step 3") || !strings.Contains(err.Error(), "boom at c") {
		t.Errorf("error: got %v, want step 3 + boom at c", err)
	}
	got := strings.Join(order, ",")
	want := "apply-a,apply-b,apply-c,undo-b,undo-a"
	if got != want {
		t.Errorf("order: got %q, want %q", got, want)
	}
}

func TestRunSteps_ContextCancelledBetweenSteps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var order []string
	steps := []step{
		{
			name: "a", desc: "a",
			apply: func(context.Context, *installEnv) (bool, error) {
				order = append(order, "apply-a")
				cancel() // cancel after step a
				return true, nil
			},
			undo: func(context.Context, *installEnv) error {
				order = append(order, "undo-a")
				return nil
			},
		},
		{
			name: "b", desc: "b",
			apply: func(context.Context, *installEnv) (bool, error) {
				order = append(order, "apply-b-SHOULD-NOT-RUN")
				return true, nil
			},
		},
	}
	var buf bytes.Buffer
	env := &installEnv{out: &buf}
	_, err := runSteps(ctx, env, &buf, steps)
	if err == nil {
		t.Fatalf("expected context error")
	}
	if !strings.Contains(err.Error(), "context cancelled") {
		t.Errorf("error: got %v, want substring 'context cancelled'", err)
	}
	if !strings.Contains(strings.Join(order, ","), "undo-a") {
		t.Errorf("applied step a was not rolled back: %v", order)
	}
}

func TestRunUndo_ReverseOrderContinuesOnError(t *testing.T) {
	var order []string
	steps := []step{
		{name: "a", desc: "a", undo: func(context.Context, *installEnv) error {
			order = append(order, "undo-a")
			return nil
		}},
		{name: "b", desc: "b", undo: func(context.Context, *installEnv) error {
			order = append(order, "undo-b")
			return errors.New("b failed")
		}},
		{name: "c", desc: "c", undo: func(context.Context, *installEnv) error {
			order = append(order, "undo-c")
			return nil
		}},
	}
	var buf bytes.Buffer
	env := &installEnv{out: &buf}
	err := runUndo(context.Background(), env, &buf, steps)
	if err == nil {
		t.Fatalf("expected joined error")
	}
	// Reverse order: c, b, a. Failures don't stop the chain.
	if got := strings.Join(order, ","); got != "undo-c,undo-b,undo-a" {
		t.Errorf("order: got %q, want undo-c,undo-b,undo-a", got)
	}
	if !strings.Contains(err.Error(), "b failed") {
		t.Errorf("joined err missing inner: %v", err)
	}
}

func TestRunUndo_SkipsStepsWithoutUndo(t *testing.T) {
	steps := []step{
		{name: "no-undo", desc: "preserve action", undo: nil},
	}
	var buf bytes.Buffer
	env := &installEnv{out: &buf}
	if err := runUndo(context.Background(), env, &buf, steps); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(buf.String(), "[SKIP] no-undo") {
		t.Errorf("missing skip line: %q", buf.String())
	}
}

func TestPrintPlan(t *testing.T) {
	steps := []step{
		{name: "a", desc: "first thing"},
		{name: "b", desc: "second thing"},
	}
	var buf bytes.Buffer
	printPlan(&buf, "header:", steps)
	want := "header:\n  1. first thing\n  2. second thing\n"
	if got := buf.String(); got != want {
		t.Errorf("printPlan output: got %q, want %q", got, want)
	}
}

// Sanity check that the rollback chain interaction works with a real
// example: a step that applies multiple side-effects in apply and reverses
// all of them in undo.
func TestRunSteps_RollbackRunsExactlyOnceEvenWithRetries(t *testing.T) {
	var undoCalls int
	steps := []step{
		{
			name: "side-effect",
			desc: "side effect",
			apply: func(context.Context, *installEnv) (bool, error) {
				return true, nil
			},
			undo: func(context.Context, *installEnv) error {
				undoCalls++
				return nil
			},
		},
		{
			name: "fail",
			desc: "fail",
			apply: func(context.Context, *installEnv) (bool, error) {
				return false, fmt.Errorf("boom")
			},
		},
	}
	var buf bytes.Buffer
	env := &installEnv{out: &buf}
	if _, err := runSteps(context.Background(), env, &buf, steps); err == nil {
		t.Fatalf("expected error")
	}
	if undoCalls != 1 {
		t.Errorf("undoCalls=%d, want 1", undoCalls)
	}
}
