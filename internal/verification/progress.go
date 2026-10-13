// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package verification carries cancellation and observed work through evidence
// verification. It holds no evidence and grants no trust to its callers.
package verification

import "context"

// Progress identifies actual work performed by an evidence reader or verifier.
// Records counts authenticated records; Bytes counts bytes read from evidence.
type Progress struct {
	Kind    string
	Session string
	Records uint64
	Bytes   int64
}

// Options belongs to one verification ceremony. A parallel caller must provide
// a concurrency-safe Progress callback. A callback error invalidates the walk.
type Options struct {
	Context  context.Context
	Progress func(Progress) error
}

// Check refuses cancellation even when no progress callback is installed.
func (o Options) Check() error {
	if o.Context != nil {
		return o.Context.Err()
	}
	return nil
}

// Report checks cancellation before delivering actual work.
func (o Options) Report(p Progress) error {
	if err := o.Check(); err != nil {
		return err
	}
	if o.Progress != nil {
		return o.Progress(p)
	}
	return nil
}
