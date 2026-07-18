//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
)

const (
	deliveryInboxVersion         = 1
	maxDeliveryInboxFileBytes    = 8 << 20
	maxPersistedDeliveryAttempts = 1000
	maxPersistedDeadLetters      = 250
	maxDeliveryIDBytes           = 256
	maxDeliveryAlertIDBytes      = 256
	maxDeliveryErrorBytes        = 2 << 10
)

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
	Totals      *deliveryTotals   `json:"totals,omitempty"`
	Dropped     uint64            `json:"dropped"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type deliveryTotals struct {
	Queued      uint64 `json:"queued"`
	Delivered   uint64 `json:"delivered"`
	Failed      uint64 `json:"failed"`
	DeadLetters uint64 `json:"dead_letters"`
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
	data, err := readBoundedDeliveryInbox(path)
	if err == nil {
		if err := decodeStrictJSON(data, &state); err != nil || normalizeDeliveryState(&state) != nil {
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
	attempt.Error = normalizeDeliveryError(attempt.Error)
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
		saturatingAddAtomicUint64(&i.pendingDrops, 1)
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
	if len(a.ID) > maxDeliveryIDBytes || len(a.AlertID) > maxDeliveryAlertIDBytes || len(a.Error) > maxDeliveryErrorBytes {
		return errors.New("delivery attempt field exceeds persistence limit")
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
	var sampled deliveryTotals
	for _, attempt := range state.Attempts {
		if err := validateDeliveryAttempt(attempt); err != nil {
			return err
		}
		incrementDeliveryTotal(&sampled, attempt.Status)
	}
	for _, attempt := range state.DeadLetters {
		if err := validateDeliveryAttempt(attempt); err != nil || attempt.Status != DeliveryFailed {
			return errors.New("invalid dead-letter attempt")
		}
	}
	if state.Totals != nil {
		maxUint64 := ^uint64(0)
		if state.Totals.Queued < sampled.Queued || state.Totals.Delivered < sampled.Delivered || state.Totals.Failed < sampled.Failed || state.Totals.DeadLetters < uint64(len(state.DeadLetters)) {
			return errors.New("delivery inbox totals are below persisted samples")
		}
		if state.Totals.Queued == maxUint64 || state.Totals.Delivered == maxUint64 || state.Totals.Failed == maxUint64 || state.Totals.DeadLetters == maxUint64 || state.Totals.DeadLetters > uint64(^uint(0)>>1) {
			return errors.New("delivery inbox total exceeds persistence limit")
		}
	}
	return nil
}

func normalizeDeliveryState(state *deliveryInboxState) error {
	if err := validateDeliveryState(*state); err != nil {
		return err
	}
	trimDeliveryRetention(state)
	return nil
}

func trimDeliveryRetention(state *deliveryInboxState) {
	if len(state.Attempts) > maxPersistedDeliveryAttempts {
		state.Attempts = append([]DeliveryAttempt(nil), state.Attempts[len(state.Attempts)-maxPersistedDeliveryAttempts:]...)
	}
	if len(state.DeadLetters) > maxPersistedDeadLetters {
		state.DeadLetters = append([]DeliveryAttempt(nil), state.DeadLetters[len(state.DeadLetters)-maxPersistedDeadLetters:]...)
	}
}

func saturatingAddUint64(value, delta uint64) uint64 {
	if ^uint64(0)-value < delta {
		return ^uint64(0)
	}
	return value + delta
}

func saturatingAddAtomicUint64(value *atomic.Uint64, delta uint64) {
	for {
		current := value.Load()
		next := saturatingAddUint64(current, delta)
		if value.CompareAndSwap(current, next) {
			return
		}
	}
}

func truncateUTF8(value string, maxBytes int) string {
	if len(value) > maxBytes {
		value = value[:maxBytes]
	}
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func normalizeDeliveryError(value string) string {
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return '�'
		}
		return character
	}, value)
	return truncateUTF8(value, maxDeliveryErrorBytes)
}

func initializeDeliveryTotals(state *deliveryInboxState) {
	if state.Totals != nil {
		return
	}
	state.Totals = &deliveryTotals{DeadLetters: uint64(len(state.DeadLetters))}
	for _, attempt := range state.Attempts {
		incrementDeliveryTotal(state.Totals, attempt.Status)
	}
}

func incrementDeliveryTotal(totals *deliveryTotals, status DeliveryStatus) {
	switch status {
	case DeliveryQueued:
		totals.Queued++
	case DeliveryDelivered:
		totals.Delivered++
	case DeliveryFailed:
		totals.Failed++
	}
}

func appendRecentAttempt(attempts []DeliveryAttempt, attempt DeliveryAttempt, limit int) []DeliveryAttempt {
	if len(attempts) == limit {
		copy(attempts, attempts[1:])
		attempts[len(attempts)-1] = attempt
		return attempts
	}
	return append(attempts, attempt)
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
	priorState.Attempts = append([]DeliveryAttempt(nil), i.state.Attempts...)
	priorState.DeadLetters = append([]DeliveryAttempt(nil), i.state.DeadLetters...)
	if i.state.Totals != nil {
		priorTotals := *i.state.Totals
		priorState.Totals = &priorTotals
	}
	initializeDeliveryTotals(&i.state)
	incrementDeliveryTotal(i.state.Totals, attempt.Status)
	i.state.Attempts = appendRecentAttempt(i.state.Attempts, attempt, maxPersistedDeliveryAttempts)
	if attempt.Status == DeliveryFailed {
		i.state.Totals.DeadLetters++
		i.state.DeadLetters = appendRecentAttempt(i.state.DeadLetters, attempt, maxPersistedDeadLetters)
	}
	i.state.UpdatedAt = attempt.AttemptedAt.UTC()
	drops := i.pendingDrops.Swap(0)
	i.state.Dropped = saturatingAddUint64(i.state.Dropped, drops)
	if err := i.persistLocked(); err != nil {
		i.workerErr = errors.Join(i.workerErr, err)
		i.state = priorState
		saturatingAddAtomicUint64(&i.pendingDrops, drops)
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
		saturatingAddAtomicUint64(&i.pendingDrops, drops)
		i.mu.Unlock()
		return
	}
	defer release()
	if err := i.reloadLocked(); err != nil {
		i.workerErr = errors.Join(i.workerErr, err)
		saturatingAddAtomicUint64(&i.pendingDrops, drops)
		i.mu.Unlock()
		return
	}
	priorDropped := i.state.Dropped
	i.state.Dropped = saturatingAddUint64(i.state.Dropped, drops)
	if err := i.persistLocked(); err != nil {
		i.workerErr = errors.Join(i.workerErr, err)
		i.state.Dropped = priorDropped
		saturatingAddAtomicUint64(&i.pendingDrops, drops)
	}
	i.mu.Unlock()
}

func (i *DeliveryInbox) persistLocked() error {
	trimDeliveryRetention(&i.state)
	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(i.state); err != nil {
		return err
	}
	if data.Len() > maxDeliveryInboxFileBytes {
		return errors.New("delivery inbox encoded state exceeds file size limit")
	}
	return atomicfile.Write(i.path, data.Bytes(), 0o600)
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
	data, err := readBoundedDeliveryInbox(i.path)
	if errors.Is(err, os.ErrNotExist) {
		i.state = deliveryInboxState{Version: deliveryInboxVersion}
		return nil
	}
	if err != nil {
		return fmt.Errorf("delivery inbox: reload: %w", err)
	}
	var state deliveryInboxState
	if err := decodeStrictJSON(data, &state); err != nil || normalizeDeliveryState(&state) != nil {
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
	health := deliveryHealthFromState(i.state)
	health.Dropped = saturatingAddUint64(health.Dropped, i.pendingDrops.Load())
	return health
}

func deliveryHealthFromState(state deliveryInboxState) DeliveryHealth {
	health := DeliveryHealth{Dropped: state.Dropped, DeadLetters: len(state.DeadLetters), UpdatedAt: state.UpdatedAt}
	if state.Totals != nil {
		health.Queued = state.Totals.Queued
		health.Delivered = state.Totals.Delivered
		health.Failed = state.Totals.Failed
		if state.Totals.DeadLetters <= uint64(^uint(0)>>1) {
			health.DeadLetters = int(state.Totals.DeadLetters)
		}
		return health
	}
	for _, attempt := range state.Attempts {
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

func readBoundedDeliveryInbox(path string) ([]byte, error) {
	file, _, err := openRegularDashboardFile(path, "delivery inbox")
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxDeliveryInboxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDeliveryInboxFileBytes {
		return nil, errors.New("delivery inbox file too large")
	}
	return data, nil
}

// Pending returns queued and failed attempts for a future forwarder. The
// returned slice is detached from the store and cannot mutate durable state.
// TODO: define the producer acknowledge/retry/archive/purge lifecycle before
// delivery forwarding depends on this retention sample.
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
