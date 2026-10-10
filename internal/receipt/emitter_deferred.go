// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// maxInflightDurableEmits bounds durable receipts appended but not yet
// confirmed on one chain. A caller over the bound waits before taking the
// chain lock, so pressure never turns into a confirmation wait under it.
const maxInflightDurableEmits = 1024

// emitCompletion orders the post-confirmation step (observer callback and the
// caller's success) by chain position. Confirmations can finish out of order;
// completions cannot.
type emitCompletion struct {
	prev *emitCompletion
	done chan struct{}
}

// nextCompletionLocked reserves the next completion slot. Callers hold chainMu.
func (e *Emitter) nextCompletionLocked() *emitCompletion {
	c := &emitCompletion{prev: e.completionTail, done: make(chan struct{})}
	e.completionTail = c
	return c
}

// finishCompletion runs after chainMu is released. It waits for every earlier
// completion, then notifies the observer only on success. It always closes
// the slot, so a failure never holds back later receipts.
func (e *Emitter) finishCompletion(c *emitCompletion, rcpt Receipt, err error) {
	if c.prev != nil {
		<-c.prev.done
		c.prev = nil
	}
	defer close(c.done)
	if err == nil && e.onReceipt != nil {
		// Observers are contractually non-blocking (EmitterConfig.OnReceipt).
		rc := rcpt
		e.onReceipt(&rc)
	}
}

func (e *Emitter) acquireInflight() func() {
	e.inflightOnce.Do(func() { e.inflight = make(chan struct{}, maxInflightDurableEmits) })
	e.inflight <- struct{}{}
	return func() { <-e.inflight }
}

// deferredDurableEmission carries one appended receipt from the chain lock to
// its confirmation.
type deferredDurableEmission struct {
	rcpt       Receipt
	ticket     *recorder.DurableTicket
	waitAEL    func() error
	aelErr     error
	completion *emitCompletion
}

// confirmDeferred runs outside chainMu. The ticket is always waited, even
// when the paired AEL write already failed, so the recorder stream keeps its
// append order. A request is answered only after both confirmations.
func (e *Emitter) confirmDeferred(d deferredDurableEmission) error {
	recordErr := d.ticket.Wait()
	if recordErr != nil {
		switch {
		case errors.Is(recordErr, recorder.ErrDurability):
			e.durabilityBlocks.Add(1)
			e.recordFailure(FailReasonSync)
		case errors.Is(recordErr, recorder.ErrDurabilityInherited):
			e.recordFailure(FailReasonDurabilityInherited)
		default:
			e.recordFailure(FailReasonRecord)
		}
		recordErr = fmt.Errorf("%w: recording receipt: %w", ErrReceiptPostAdvance, recordErr)
	}
	aelErr := d.aelErr
	if aelErr == nil && d.waitAEL != nil {
		if waitErr := d.waitAEL(); waitErr != nil {
			aelErr = fmt.Errorf("emitting native AEL record: %w", waitErr)
			e.recordFailure(FailReasonAEL)
			// The receipt's chain position is consumed and its pair is not
			// durable; quarantine so a retry cannot claim a complete pair.
			e.MarkUnhealthy(aelErr)
		}
	}
	err := errors.Join(recordErr, aelErr)
	e.finishCompletion(d.completion, d.rcpt, err)
	return err
}
