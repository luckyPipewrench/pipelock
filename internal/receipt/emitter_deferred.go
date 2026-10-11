// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// maxInflightDurableEmits bounds the durable receipts on one chain that are
// appended but not yet confirmed. A caller over the bound waits before taking
// the chain lock, so pressure never turns into a confirmation wait under it.
// It counts durable emits only: ordinary receipts queued behind them and
// direct recorder writers are not counted, and it bounds calls, not bytes.
const maxInflightDurableEmits = 1024

// emitCompletion orders the post-confirmation step (observer callback and the
// caller's success) by chain position. Confirmations can finish out of order;
// completions cannot.
type emitCompletion struct {
	prev *emitCompletion
	done chan struct{}
	// err is this receipt's outcome, readable once done is closed.
	err error
	// unconfirmed, readable once done is closed, reports that this receipt's
	// chain position was never confirmed: its sync failed, its native AEL
	// pair failed, or it inherited either. Only then does a successor fail
	// too; a maintenance error after a confirmed sync stays with its receipt.
	unconfirmed bool
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
func (e *Emitter) finishCompletion(c *emitCompletion, rcpt Receipt, err error, unconfirmed bool) error {
	if c.prev != nil {
		<-c.prev.done
		if prevErr := c.prev.err; c.prev.unconfirmed && err == nil {
			unconfirmed = true
			// Inherited, never ErrDurability itself: the storage failure is
			// counted once, on the receipt whose sync failed.
			err = fmt.Errorf("%w: an earlier receipt on this chain was not confirmed: %s", recorder.ErrDurabilityInherited, prevErr.Error())
			e.recordFailure(FailReasonDurabilityInherited)
		}
		c.prev = nil
	}
	c.err = err
	c.unconfirmed = unconfirmed
	defer close(c.done)
	if err == nil && e.onReceipt != nil {
		// Observers are contractually non-blocking (EmitterConfig.OnReceipt).
		rc := rcpt
		e.onReceipt(&rc)
	}
	return err
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
	unconfirmed := false
	if recordErr != nil {
		switch {
		case errors.Is(recordErr, recorder.ErrDurability):
			e.durabilityBlocks.Add(1)
			e.recordFailure(FailReasonSync)
			unconfirmed = true
		case errors.Is(recordErr, recorder.ErrDurabilityInherited):
			e.recordFailure(FailReasonDurabilityInherited)
			unconfirmed = true
		default:
			// Checkpoint or rotation maintenance failed after the sync
			// confirmed this receipt; its position is durable.
			e.recordFailure(FailReasonRecord)
		}
		recordErr = fmt.Errorf("%w: recording receipt: %w", ErrReceiptPostAdvance, recordErr)
		if unconfirmed {
			e.markUnconfirmed(d.rcpt.ActionRecord.ChainSeq)
		}
	}
	aelErr := d.aelErr
	if aelErr != nil {
		unconfirmed = true
	}
	if aelErr == nil && d.waitAEL != nil {
		if waitErr := d.waitAEL(); waitErr != nil {
			aelErr = fmt.Errorf("emitting native AEL record: %w", waitErr)
			e.recordFailure(FailReasonAEL)
			// The receipt's chain position is consumed and its pair is not
			// durable; quarantine so a retry cannot claim a complete pair.
			e.MarkUnhealthy(aelErr)
			unconfirmed = true
		}
	}
	return e.finishCompletion(d.completion, d.rcpt, errors.Join(recordErr, aelErr), unconfirmed)
}

// markUnconfirmed records the first receipt whose write reached the file but
// whose confirmation failed, for the evidence health audit.
func (e *Emitter) markUnconfirmed(seq uint64) {
	e.chainMu.Lock()
	defer e.chainMu.Unlock()
	if !e.unconfirmed {
		e.unconfirmed, e.unconfirmedSeq = true, seq
	}
}
