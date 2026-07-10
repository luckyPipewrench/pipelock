//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
)

const deliveryInboxVersion = 1

type DeliveryStatus string

const (
	DeliveryQueued    DeliveryStatus = "queued"
	DeliveryDelivered DeliveryStatus = "delivered"
	DeliveryFailed    DeliveryStatus = "failed"
)

type DeliveryAttempt struct {
	ID          string         `json:"id"`
	AlertID     string         `json:"alert_id"`
	Status      DeliveryStatus `json:"status"`
	AttemptedAt time.Time      `json:"attempted_at"`
	Error       string         `json:"error,omitempty"`
}

type DeliveryHealth struct {
	Queued      uint64    `json:"queued"`
	Delivered   uint64    `json:"delivered"`
	Failed      uint64    `json:"failed"`
	Dropped     uint64    `json:"dropped"`
	DeadLetters int       `json:"dead_letters"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type deliveryInboxState struct {
	Version     int               `json:"version"`
	Attempts    []DeliveryAttempt `json:"attempts"`
	DeadLetters []DeliveryAttempt `json:"dead_letters"`
	Dropped     uint64            `json:"dropped"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type DeliveryInboxOptions struct {
	Path          string
	QueueSize     int
	BeforePersist func()
}

// DeliveryInbox is a bounded, fire-and-forget local delivery sink. Record is
// always nonblocking; saturation increments a durable drop counter.
type DeliveryInbox struct {
	path          string
	queue         chan DeliveryAttempt
	dropSignal    chan struct{}
	stop          chan struct{}
	done          chan struct{}
	beforePersist func()
	beforeEnqueue func()
	mu            sync.RWMutex
	state         deliveryInboxState
	pendingDrops  atomic.Uint64
	activeRecords atomic.Int64
	processing    atomic.Uint32
	closeOnce     sync.Once
	closed        atomic.Bool
	workerErr     error
}

func OpenDeliveryInbox(opts DeliveryInboxOptions) (*DeliveryInbox, error) {
	if opts.QueueSize <= 0 {
		return nil, errors.New("delivery inbox queue size must be positive")
	}
	path := filepath.Clean(opts.Path)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("delivery inbox: create dir: %w", err)
	}
	state := deliveryInboxState{Version: deliveryInboxVersion}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := decodeStrictJSON(data, &state); err != nil || validateDeliveryState(state) != nil {
			return nil, errors.New("delivery inbox: invalid persisted state")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("delivery inbox: read: %w", err)
	}
	inbox := &DeliveryInbox{path: path, queue: make(chan DeliveryAttempt, opts.QueueSize), dropSignal: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}), beforePersist: opts.BeforePersist, state: state}
	go inbox.run()
	return inbox, nil
}

func (i *DeliveryInbox) Record(attempt DeliveryAttempt) bool {
	if i == nil || validateDeliveryAttempt(attempt) != nil {
		return false
	}
	i.activeRecords.Add(1)
	defer i.activeRecords.Add(-1)
	if i.closed.Load() {
		return false
	}
	if i.beforeEnqueue != nil {
		i.beforeEnqueue()
	}
	select {
	case i.queue <- attempt:
		return true
	default:
		i.pendingDrops.Add(1)
		select {
		case i.dropSignal <- struct{}{}:
		default:
		}
		return false
	}
}

func validateDeliveryAttempt(a DeliveryAttempt) error {
	if a.ID == "" || a.AlertID == "" || a.AttemptedAt.IsZero() {
		return errors.New("delivery attempt requires id, alert id, and attempted time")
	}
	switch a.Status {
	case DeliveryQueued, DeliveryDelivered:
		if a.Error != "" {
			return errors.New("non-failed delivery attempt cannot carry an error")
		}
	case DeliveryFailed:
		if a.Error == "" {
			return errors.New("failed delivery attempt requires an error")
		}
	default:
		return errors.New("unknown delivery status")
	}
	return nil
}

func validateDeliveryState(state deliveryInboxState) error {
	if state.Version != deliveryInboxVersion {
		return errors.New("unknown delivery inbox version")
	}
	for _, attempt := range state.Attempts {
		if err := validateDeliveryAttempt(attempt); err != nil {
			return err
		}
	}
	for _, attempt := range state.DeadLetters {
		if err := validateDeliveryAttempt(attempt); err != nil || attempt.Status != DeliveryFailed {
			return errors.New("invalid dead-letter attempt")
		}
	}
	return nil
}

func (i *DeliveryInbox) run() {
	defer close(i.done)
	for {
		select {
		case attempt := <-i.queue:
			i.processing.Store(1)
			i.apply(attempt)
			i.processing.Store(0)
		case <-i.dropSignal:
			i.flushDrops()
		case <-i.stop:
			for {
				select {
				case attempt := <-i.queue:
					i.apply(attempt)
				default:
					i.flushDrops()
					return
				}
			}
		}
	}
}

func (i *DeliveryInbox) apply(attempt DeliveryAttempt) {
	if i.beforePersist != nil {
		i.beforePersist()
	}
	i.mu.Lock()
	release, err := i.acquireMutationLock()
	if err != nil {
		i.workerErr = errors.Join(i.workerErr, err)
		i.mu.Unlock()
		return
	}
	defer release()
	if err := i.reloadLocked(); err != nil {
		i.workerErr = errors.Join(i.workerErr, err)
		i.mu.Unlock()
		return
	}
	priorState := i.state
	i.state.Attempts = append(i.state.Attempts, attempt)
	if attempt.Status == DeliveryFailed {
		i.state.DeadLetters = append(i.state.DeadLetters, attempt)
	}
	i.state.UpdatedAt = attempt.AttemptedAt.UTC()
	drops := i.pendingDrops.Swap(0)
	i.state.Dropped += drops
	if err := i.persistLocked(); err != nil {
		i.workerErr = errors.Join(i.workerErr, err)
		i.state = priorState
		i.pendingDrops.Add(drops)
	}
	i.mu.Unlock()
}

func (i *DeliveryInbox) flushDrops() {
	drops := i.pendingDrops.Swap(0)
	if drops == 0 {
		return
	}
	i.mu.Lock()
	release, err := i.acquireMutationLock()
	if err != nil {
		i.workerErr = errors.Join(i.workerErr, err)
		i.pendingDrops.Add(drops)
		i.mu.Unlock()
		return
	}
	defer release()
	if err := i.reloadLocked(); err != nil {
		i.workerErr = errors.Join(i.workerErr, err)
		i.pendingDrops.Add(drops)
		i.mu.Unlock()
		return
	}
	i.state.Dropped += drops
	if err := i.persistLocked(); err != nil {
		i.workerErr = errors.Join(i.workerErr, err)
		i.state.Dropped -= drops
		i.pendingDrops.Add(drops)
	}
	i.mu.Unlock()
}

func (i *DeliveryInbox) persistLocked() error {
	data, err := json.MarshalIndent(i.state, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(i.path, data, 0o600)
}

func (i *DeliveryInbox) acquireMutationLock() (func(), error) {
	pathMu := exemptionStorePathLock(i.path)
	pathMu.Lock()
	lock, err := acquireExemptionStoreFileLock(i.path + ".lock")
	if err != nil {
		pathMu.Unlock()
		return nil, fmt.Errorf("delivery inbox: lock: %w", err)
	}
	return func() {
		_ = lock.Close()
		pathMu.Unlock()
	}, nil
}

func (i *DeliveryInbox) reloadLocked() error {
	data, err := os.ReadFile(i.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delivery inbox: reload: %w", err)
	}
	var state deliveryInboxState
	if err := decodeStrictJSON(data, &state); err != nil || validateDeliveryState(state) != nil {
		return errors.New("delivery inbox: reload invalid persisted state")
	}
	i.state = state
	return nil
}

func (i *DeliveryInbox) DeadLetters() []DeliveryAttempt {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := append([]DeliveryAttempt(nil), i.state.DeadLetters...)
	sort.Slice(out, func(a, b int) bool { return out[a].AttemptedAt.Before(out[b].AttemptedAt) })
	return out
}

func (i *DeliveryInbox) Health() DeliveryHealth {
	i.mu.RLock()
	defer i.mu.RUnlock()
	health := DeliveryHealth{Dropped: i.state.Dropped + i.pendingDrops.Load(), DeadLetters: len(i.state.DeadLetters), UpdatedAt: i.state.UpdatedAt}
	for _, attempt := range i.state.Attempts {
		switch attempt.Status {
		case DeliveryQueued:
			health.Queued++
		case DeliveryDelivered:
			health.Delivered++
		case DeliveryFailed:
			health.Failed++
		}
	}
	return health
}

// Pending returns queued and failed attempts for a future forwarder. The
// returned slice is detached from the store and cannot mutate durable state.
func (i *DeliveryInbox) Pending() []DeliveryAttempt {
	i.mu.RLock()
	defer i.mu.RUnlock()
	var out []DeliveryAttempt
	for _, attempt := range i.state.Attempts {
		if attempt.Status != DeliveryDelivered {
			out = append(out, attempt)
		}
	}
	return out
}

type DeliveryInboxReader interface {
	Pending() []DeliveryAttempt
	DeadLetters() []DeliveryAttempt
	Health() DeliveryHealth
}

func (i *DeliveryInbox) Close(ctx context.Context) error {
	if i == nil {
		return nil
	}
	i.closeOnce.Do(func() {
		i.closed.Store(true)
		for i.activeRecords.Load() != 0 {
			runtime.Gosched()
		}
		close(i.stop)
	})
	select {
	case <-i.done:
		i.mu.RLock()
		defer i.mu.RUnlock()
		return i.workerErr
	case <-ctx.Done():
		return fmt.Errorf("close delivery inbox: %w", ctx.Err())
	}
}
