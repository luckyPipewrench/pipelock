// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type sealedGroupSegment struct {
	path string
	info os.FileInfo
}

type groupSegmentProgress struct {
	// This is the sealed-file identity inventory, not an executable work queue.
	// Retaining one identity per segment is necessary to refuse removed files.
	sealed   []sealedGroupSegment
	verified int
	err      error
}

// groupSegmentWorker coalesces arbitrary rotations into one wake-up token.
// The bounded channel never blocks an append. Per-shard cursors ensure that
// coalescing loses no verification work and preserves each chain's order.
// Only the worker touches verifier state until finish has joined it.
type groupSegmentWorker struct {
	mu        sync.Mutex
	dir       string
	verifiers map[string]*groupCloseVerifier
	progress  map[string]*groupSegmentProgress
	notices   io.Writer
	wake      chan struct{}
	barrier   chan chan struct{}
	start     chan struct{}
	startOnce sync.Once
	stop      chan struct{}
	done      chan struct{}
	once      sync.Once
	err       error
	unknown   error
	reverify  func(string) error
	verify    func(string, sealedGroupSegment) error
}

func newGroupSegmentWorker(ctx context.Context, dir string, verifiers map[string]*groupCloseVerifier, notices io.Writer) *groupSegmentWorker {
	if notices == nil {
		notices = os.Stderr
	}
	w := &groupSegmentWorker{dir: dir, verifiers: verifiers, progress: make(map[string]*groupSegmentProgress, len(verifiers)), notices: notices, wake: make(chan struct{}, 1), barrier: make(chan chan struct{}), start: make(chan struct{}), stop: make(chan struct{}), done: make(chan struct{})}
	for session := range verifiers {
		w.progress[session] = &groupSegmentProgress{}
	}
	w.verify = w.verifySegment
	go w.run(ctx)
	return w
}

func (w *groupSegmentWorker) register(session, path string, info os.FileInfo) error {
	w.mu.Lock()
	p := w.progress[session]
	if p != nil {
		p.sealed = append(p.sealed, sealedGroupSegment{path: path, info: info})
	}
	w.mu.Unlock()
	if p == nil {
		w.fail(session, errors.New("receipt group verifier has no matching shard"))
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
	// A verification failure is a close-publication failure, not a new live
	// request admission policy. finish returns the retained error.
	return nil
}

func (w *groupSegmentWorker) fail(session string, err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	if p := w.progress[session]; p != nil {
		if p.err == nil {
			p.err = err
		}
	} else if w.unknown == nil {
		w.unknown = err
	}
	first := w.err == nil
	if first {
		w.err = err
	}
	w.mu.Unlock()
	if first {
		_, _ = fmt.Fprintf(w.notices, "receipt group background verification failed; close requires fresh verification: %q\n", err.Error())
	}
}

func (w *groupSegmentWorker) verifySegment(session string, segment sealedGroupSegment) error {
	v := w.verifiers[session]
	if v == nil {
		return errors.New("receipt group verifier has no matching shard")
	}
	if err := v.seal(w.dir, segment.path); err != nil {
		return err
	}
	actual := v.files[filepath.Base(segment.path)].info
	if segment.info == nil || actual == nil || !os.SameFile(segment.info, actual) || segment.info.Size() != actual.Size() {
		v.err = errors.New("receipt group sealed segment was changed or replaced before verification")
		return v.err
	}
	return nil
}

func (w *groupSegmentWorker) advance(ctx context.Context) {
	for {
		progressed := false
		for session, p := range w.progress {
			if ctx.Err() != nil {
				return
			}
			w.mu.Lock()
			if p.verified == len(p.sealed) {
				w.mu.Unlock()
				continue
			}
			segment := p.sealed[p.verified]
			w.mu.Unlock()
			w.fail(session, w.verify(session, segment))
			w.mu.Lock()
			p.verified++
			w.mu.Unlock()
			progressed = true
		}
		if !progressed {
			return
		}
	}
}

func (w *groupSegmentWorker) activate() { w.startOnce.Do(func() { close(w.start) }) }

func (w *groupSegmentWorker) run(ctx context.Context) {
	defer close(w.done)
	select {
	case <-ctx.Done():
		return
	case <-w.stop:
		return
	case <-w.start:
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stop:
			return
		case <-w.wake:
			w.advance(ctx)
		case done := <-w.barrier:
			w.advance(ctx)
			close(done)
		}
	}
}

// waitIdle is a barrier for observers of retained verifier state. Production
// close uses finish instead, after the recorder has refused new appends.
func (w *groupSegmentWorker) waitIdle() {
	done := make(chan struct{})
	select {
	case w.barrier <- done:
		<-done
	case <-w.done:
	}
}

func (w *groupSegmentWorker) finish() error {
	w.once.Do(func() {
		close(w.stop)
		<-w.done
		// Cancellation stops background work without discarding its inventory.
		// Complete any remaining prefixes and tails while recorder ownership is
		// still held. This also handles a worker that fell behind under load.
		w.advance(context.Background())
		w.mu.Lock()
		reverify := w.reverify
		w.mu.Unlock()
		if reverify != nil {
			// Unknown registrations have no signed shard to re-verify.
			result := w.unknown
			for session, p := range w.progress {
				if p.err != nil {
					result = errors.Join(result, reverify(session))
				}
			}
			w.mu.Lock()
			w.err = result
			w.mu.Unlock()
		}
	})
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

// prepareClose enables fresh shard verification only for close publication.
// Recorder.Close without PublishClose still returns the retained worker error.
func (w *groupSegmentWorker) prepareClose(reverify func(string) error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reverify = reverify
}

// checkInventory retains the file-change guards independently of failed
// decoding state. The caller also fully authenticates the shard from disk.
func (w *groupSegmentWorker) checkInventory(session string) error {
	v, p := w.verifiers[session], w.progress[session]
	if v == nil || p == nil {
		return errors.New("receipt group has no verified shard state")
	}
	sealed := make(map[string]os.FileInfo, len(p.sealed))
	for _, segment := range p.sealed {
		name := filepath.Base(segment.path)
		if _, exists := sealed[name]; exists {
			return errors.New("receipt group segment was already sealed")
		}
		sealed[name] = segment.info
	}
	location, err := recorder.ResolveEvidenceLocation(w.dir, "")
	if err != nil {
		return err
	}
	seen := 0
	err = recorder.WalkSessionHistoryFiles(location, session, func(shard recorder.SessionHistoryShard, input io.Reader) error {
		expected, ok := sealed[shard.Name]
		if !ok || expected == nil || shard.Info == nil || !os.SameFile(expected, shard.Info) || expected.Size() != shard.Info.Size() {
			return errors.New("receipt group sealed segment was added, changed or replaced")
		}
		if _, verified := v.files[shard.Name]; verified {
			if err := v.checkFile(shard, input); err != nil {
				return err
			}
		}
		seen++
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(sealed) {
		return errors.New("receipt group sealed segment is missing")
	}
	if v.native != nil {
		return v.native.VerifyPrefixUnchanged()
	}
	return nil
}
