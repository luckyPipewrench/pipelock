// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"sync"
)

// ErrDurabilityInherited means a durable append was refused or could not be
// confirmed because an earlier sync on the same evidence stream failed. After
// a failed File.Sync the kernel may report later syncs as successful even
// though the earlier pages were dropped, so nothing after the failure can be
// confirmed as part of an intact chain. It deliberately does not wrap
// ErrDurability: it is a consequence of one storage failure, not a new one,
// and counting it as such would break the fsync/block accounting invariant.
// The stream stays failed until the process starts a new run.
var ErrDurabilityInherited = errors.New("recorder stream durability failed earlier; restart to open a new run")

// DurableTicket is one appended entry whose durability has not yet been
// confirmed. The append position, file generation and chain advance are fixed
// when the ticket is issued; Wait confirms them. Every issued ticket must be
// waited exactly once: tickets on a stream finish in append order, so an
// abandoned ticket would hold back every later one.
type DurableTicket struct {
	r       *Recorder
	state   *SessionState // nil for a single-session (legacy) stream
	session string
	pending durableWrite
	prev    *DurableTicket

	once     sync.Once
	finished chan struct{}
	err      error
}

// AppendDurableWithReceiptScanPreAdvance appends e, advances the caller's
// chain through advance, and reserves a durability confirmation. It returns
// as soon as the bytes are written, so callers can release their own
// ordering locks before waiting. Wait on the returned ticket before treating
// the entry as recorded.
func (r *Recorder) AppendDurableWithReceiptScanPreAdvance(e Entry, scan *ReceiptScan, advance func()) (*DurableTicket, error) {
	if r.nop {
		if advance != nil {
			advance()
		}
		return completedTicket(nil), nil
	}
	var err error
	scan, err = r.prepareReceiptScan(e, scan)
	if err != nil {
		return nil, err
	}
	r.groupMu.Lock()
	if r.groupSessions == nil {
		r.legacyStarted = true
		r.groupMu.Unlock()
		return r.appendDurableLegacy(e, scan, advance)
	}
	state := r.groupSessions[e.SessionID]
	r.groupMu.Unlock()
	if state == nil {
		return nil, fmt.Errorf("recorder: session %q is not an acquired group member", e.SessionID)
	}
	// writeMu orders this shard's appends against its other writers; it is not
	// held across the confirmation, which the ticket chain orders instead.
	state.writeMu.Lock()
	defer state.writeMu.Unlock()
	r.groupMu.Lock()
	defer r.groupMu.Unlock()
	if r.groupClosing {
		return nil, errors.New("recorder: receipt group is closing")
	}
	var ticket *DurableTicket
	err = r.withGroupSessionLocked(e.SessionID, func() error {
		var appendErr error
		ticket, appendErr = r.appendDurableLocked(e, scan, advance, state)
		return appendErr
	})
	if err != nil {
		return nil, err
	}
	// Close and finalization drain this count, so a group cannot seal while a
	// confirmation is outstanding.
	r.groupWrites.Add(1)
	return ticket, nil
}

func (r *Recorder) appendDurableLegacy(e Entry, scan *ReceiptScan, advance func()) (*DurableTicket, error) {
	r.legacyTickets.Add(1)
	ticket, err := r.appendDurableLocked(e, scan, advance, nil)
	if err != nil {
		r.legacyTickets.Done()
	}
	return ticket, err
}

// appendDurableLocked writes and reserves one entry on the active stream. For
// a group the caller holds groupMu with state loaded.
func (r *Recorder) appendDurableLocked(e Entry, scan *ReceiptScan, advance func(), state *SessionState) (*DurableTicket, error) {
	// prepareDurableWrite refuses a stream whose sync already failed.
	pending, err := r.prepareDurableWrite(e, scan, advance)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	ticket := &DurableTicket{
		r: r, state: state, session: e.SessionID, pending: pending,
		prev: r.lastDurableTicket, finished: make(chan struct{}),
	}
	r.lastDurableTicket = ticket
	r.mu.Unlock()
	return ticket, nil
}

func completedTicket(err error) *DurableTicket {
	t := &DurableTicket{finished: make(chan struct{}), err: err}
	t.once.Do(func() { close(t.finished) })
	return t
}

// Wait confirms the ticket's durability, then runs post-record maintenance
// and observer notification in append order. Later calls return the first
// result. A confirmation failure is never turned into success, including for
// tickets that joined a batch whose sync failed or that follow one.
func (t *DurableTicket) Wait() error {
	if t == nil {
		return nil
	}
	t.once.Do(t.complete)
	<-t.finished
	return t.err
}

// afterDurableConfirm is a test seam between a ticket's confirmation and its
// post-record step. Production leaves it a no-op.
var afterDurableConfirm = func() {}

func (t *DurableTicket) complete() {
	r := t.r
	err := r.confirmDurableWrite(t.pending)
	afterDurableConfirm()
	if t.prev != nil {
		// A ticket's maintenance and observer callback run after its
		// predecessor's, so observers see entries in chain order and a
		// rotation never runs ahead of an earlier entry's checkpoint.
		<-t.prev.finished
		t.prev = nil
	}
	if err == nil {
		if t.state == nil {
			err = r.finishDurableWrite(t.pending.written)
		} else {
			r.groupMu.Lock()
			err = r.withGroupSessionLocked(t.session, func() error { return r.finishDurableWrite(t.pending.written) })
			r.groupMu.Unlock()
		}
	}
	if t.state != nil {
		r.groupWrites.Done()
	} else {
		r.legacyTickets.Done()
	}
	t.err = err
	close(t.finished)
}
