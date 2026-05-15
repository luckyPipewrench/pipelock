// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// step is one idempotent unit of work in the install/rollback orchestration.
//
// Each step owns its own idempotency check: apply must be safe to call on
// already-correct state and return (false, nil) to indicate "nothing to do".
// When apply returns (true, nil) the step is considered applied and is added
// to the rollback chain — if a later step fails, this step's undo runs to
// restore the prior state.
//
// undo must itself be idempotent: rollback may be invoked when the step never
// finished applying, or against state that has already drifted (operator did
// a manual partial uninstall, prior rollback was interrupted, etc.).
type step struct {
	name string
	desc string
	// apply mutates state. Returns (applied, err): applied=true when a real
	// mutation happened, applied=false when the state was already correct.
	apply func(ctx context.Context, env *installEnv) (bool, error)
	// undo reverses apply. Must be safe to call against partial state.
	undo func(ctx context.Context, env *installEnv) error
}

// stepOutcome records what happened for a single step during an install or
// rollback run. Surfaced to the operator via dry-run / verbose output.
type stepOutcome struct {
	name    string
	desc    string
	applied bool
	err     error
}

// runSteps walks steps in order. When a step fails, every previously-applied
// step's undo runs in reverse order before returning the original error.
//
// A step whose apply returns (false, nil) — i.e. already done — is NOT added
// to the rollback chain. We must not undo state we did not create.
func runSteps(ctx context.Context, env *installEnv, w io.Writer, steps []step) ([]stepOutcome, error) {
	outcomes := make([]stepOutcome, 0, len(steps))
	var applied []step

	for i, s := range steps {
		if err := ctx.Err(); err != nil {
			outcomes = append(outcomes, stepOutcome{name: s.name, desc: s.desc, err: err})
			rollbackApplied(context.Background(), env, w, applied)
			return outcomes, fmt.Errorf("context cancelled before step %d (%s): %w", i+1, s.name, err)
		}

		didApply, err := s.apply(ctx, env)
		outcomes = append(outcomes, stepOutcome{name: s.name, desc: s.desc, applied: didApply, err: err})
		if didApply {
			applied = append(applied, s)
		}

		if err != nil {
			_, _ = fmt.Fprintf(w, "  [FAIL] step %d %s: %v\n", i+1, s.name, err)
			rollbackApplied(context.Background(), env, w, applied)
			return outcomes, fmt.Errorf("step %d (%s): %w", i+1, s.name, err)
		}

		tag := "[SKIP]"
		if didApply {
			tag = "[ OK ]"
		}
		_, _ = fmt.Fprintf(w, "  %s step %d: %s\n", tag, i+1, s.desc)
	}

	return outcomes, nil
}

// rollbackApplied walks the applied steps in reverse and invokes each undo.
// Errors are collected and printed but do not stop the chain — a partial
// rollback is always better than a half-installed state with an early exit.
func rollbackApplied(ctx context.Context, env *installEnv, w io.Writer, applied []step) {
	if len(applied) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "rolling back applied steps:")
	for i := len(applied) - 1; i >= 0; i-- {
		s := applied[i]
		if s.undo == nil {
			_, _ = fmt.Fprintf(w, "  [SKIP] undo %s (no undo defined)\n", s.name)
			continue
		}
		if err := s.undo(ctx, env); err != nil {
			_, _ = fmt.Fprintf(w, "  [FAIL] undo %s: %v\n", s.name, err)
			continue
		}
		_, _ = fmt.Fprintf(w, "  [ OK ] undo %s\n", s.name)
	}
}

// runUndo walks an explicit step list in REVERSE order and calls each undo.
// Used by the rollback subcommand against the full install sequence: every
// step gets a best-effort undo regardless of whether install actually ran
// it. Errors are accumulated and joined into a single returned error so the
// caller can decide whether to exit non-zero.
func runUndo(ctx context.Context, env *installEnv, w io.Writer, steps []step) error {
	var errs []error
	for i := len(steps) - 1; i >= 0; i-- {
		s := steps[i]
		if s.undo == nil {
			_, _ = fmt.Fprintf(w, "  [SKIP] %s (no undo defined)\n", s.name)
			continue
		}
		if err := s.undo(ctx, env); err != nil {
			_, _ = fmt.Fprintf(w, "  [FAIL] %s: %v\n", s.name, err)
			errs = append(errs, fmt.Errorf("%s: %w", s.name, err))
			continue
		}
		_, _ = fmt.Fprintf(w, "  [ OK ] %s\n", s.name)
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// printPlan emits a dry-run plan listing every step with its description.
// No apply/undo is invoked. Used for `install --dry-run` and friends.
func printPlan(w io.Writer, header string, steps []step) {
	_, _ = fmt.Fprintln(w, header)
	for i, s := range steps {
		_, _ = fmt.Fprintf(w, "  %d. %s\n", i+1, s.desc)
	}
}
