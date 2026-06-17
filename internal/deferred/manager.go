// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	StateHeld                = "deferred_held"
	StateResolving           = "resolving"
	StateResolvedAllow       = "resolved_allow"
	StateResolvedBlock       = "resolved_block"
	StateResolvedStepUp      = "resolved_step_up"
	SourceContext            = "context"
	SourceTimeout            = "timeout"
	SourceCancel             = "cancel"
	SourceRestartRecovery    = "restart_recovery"
	SourceKillSwitch         = "kill_switch"
	SourceCapacity           = "capacity"
	SourcePolicyReload       = "policy_reload"
	SourceApproval           = "approval"
	SourceToolInventory      = "tool_inventory"
	DefaultTimeoutSeconds    = 2
	DefaultMaxPending        = 64
	DefaultMaxPendingSession = 8
	DefaultMaxPendingBytes   = 1024 * 1024
)

// Config controls held-action bounds and timers.
type Config struct {
	Enabled              bool
	Timeout              time.Duration
	MaxPending           int
	MaxPendingPerSession int
	MaxPendingBytes      int
	JournalPath          string
}

// ResolutionPolicy is persisted into the defer receipt.
type ResolutionPolicy struct {
	Timeout              time.Duration `json:"timeout"`
	MaxPending           int           `json:"max_pending"`
	MaxPendingPerSession int           `json:"max_pending_per_session"`
	MaxPendingBytes      int           `json:"max_pending_bytes"`
}

func (p ResolutionPolicy) String() string {
	data, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return string(data)
}

type ReceiptPolicy struct {
	Bounds   ResolutionPolicy     `json:"bounds"`
	AllowOn  config.DeferAllowOn  `json:"allow_on,omitempty"`
	StepUpOn config.DeferStepUpOn `json:"step_up_on,omitempty"`
}

func ReceiptPolicyString(bounds ResolutionPolicy, rule config.DeferResolutionPolicy) string {
	data, err := json.Marshal(ReceiptPolicy{
		Bounds:   bounds,
		AllowOn:  rule.AllowOn,
		StepUpOn: rule.StepUpOn,
	})
	if err != nil {
		return ""
	}
	return string(data)
}

// AuthoritySnapshot preserves the original identity through async resolution.
type AuthoritySnapshot struct {
	Principal         string
	Actor             string
	SessionID         string
	SessionIDOriginal string
}

// HeldAction is the immutable action payload stored while awaiting resolution.
type HeldAction struct {
	DeferID    string
	ActionID   string
	Target     string
	Reason     string
	Surface    string
	Method     string
	SizeBytes  int
	Policy     ResolutionPolicy
	RulePolicy config.DeferResolutionPolicy
	Authority  AuthoritySnapshot
	Deadline   time.Time
	Payload    []byte
	ArgDigest  string
	Resolve    func(Resolution)
	timer      *time.Timer
	state      string
	createdAt  time.Time
}

// Resolution is delivered exactly once for a held action.
type Resolution struct {
	DeferID          string
	ParentActionID   string
	FinalDecision    string
	ResolutionSource string
	Authority        AuthoritySnapshot
	Target           string
	Method           string
	Reason           string
}

// Manager tracks per-action holds. It is safe for concurrent use.
type Manager struct {
	mu             sync.Mutex
	cfg            Config
	holds          map[string]*HeldAction
	bySession      map[string]int
	totalBytes     int
	pendingJournal map[string]journalEntry
}

var (
	ErrDisabled = errors.New("defer manager disabled")
	ErrCapacity = errors.New("defer capacity exceeded")
	ErrNotFound = errors.New("defer hold not found")
)

// NewManager constructs a bounded held-action manager.
func NewManager(cfg Config) *Manager {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeoutSeconds * time.Second
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = DefaultMaxPending
	}
	if cfg.MaxPendingPerSession <= 0 {
		cfg.MaxPendingPerSession = DefaultMaxPendingSession
	}
	if cfg.MaxPendingBytes <= 0 {
		cfg.MaxPendingBytes = DefaultMaxPendingBytes
	}
	return &Manager{
		cfg:            cfg,
		holds:          make(map[string]*HeldAction),
		bySession:      make(map[string]int),
		pendingJournal: make(map[string]journalEntry),
	}
}

func (m *Manager) Enabled() bool {
	return m != nil && m.cfg.Enabled
}

func (m *Manager) Policy() ResolutionPolicy {
	if m == nil {
		return ResolutionPolicy{}
	}
	return ResolutionPolicy{
		Timeout:              m.cfg.Timeout,
		MaxPending:           m.cfg.MaxPending,
		MaxPendingPerSession: m.cfg.MaxPendingPerSession,
		MaxPendingBytes:      m.cfg.MaxPendingBytes,
	}
}

func (m *Manager) JournalPath() string {
	if m == nil {
		return ""
	}
	return m.cfg.JournalPath
}

// Hold stores an action and starts its hard timeout. Capacity rejects the new
// action; existing held actions are never evicted open.
func (m *Manager) Hold(action HeldAction) error {
	if !m.Enabled() {
		return ErrDisabled
	}
	if action.DeferID == "" {
		return fmt.Errorf("defer_id is required")
	}
	if action.Resolve == nil {
		return fmt.Errorf("resolve callback is required")
	}
	if action.SizeBytes < 0 {
		action.SizeBytes = 0
	}
	now := time.Now().UTC()
	action.Policy = m.Policy()
	action.Deadline = now.Add(m.cfg.Timeout)
	action.createdAt = now
	action.state = StateHeld

	m.mu.Lock()
	if _, exists := m.holds[action.DeferID]; exists {
		m.mu.Unlock()
		return fmt.Errorf("defer hold %q already exists", action.DeferID)
	}
	if len(m.holds) >= m.cfg.MaxPending ||
		m.bySession[action.Authority.SessionID] >= m.cfg.MaxPendingPerSession ||
		action.SizeBytes > m.cfg.MaxPendingBytes ||
		m.totalBytes > m.cfg.MaxPendingBytes-action.SizeBytes {
		m.mu.Unlock()
		return ErrCapacity
	}
	journalAction := action
	stored := action
	held := &stored
	m.holds[action.DeferID] = held
	m.bySession[action.Authority.SessionID]++
	m.totalBytes += action.SizeBytes
	m.mu.Unlock()

	if err := m.appendJournal(journalEntryFromHeld(journalAction, StateHeld, "")); err != nil {
		_ = m.Resolve(action.DeferID, "block", SourceCancel)
		return fmt.Errorf("journal defer hold: %w", err)
	}
	m.mu.Lock()
	if live := m.holds[action.DeferID]; live != nil && live.state == StateHeld {
		live.timer = time.AfterFunc(m.cfg.Timeout, func() {
			_ = m.Resolve(action.DeferID, "block", SourceTimeout)
		})
	}
	m.mu.Unlock()
	return nil
}

// Resolve atomically transitions a held action and invokes its callback once.
func (m *Manager) Resolve(deferID, finalDecision, source string) error {
	if m == nil {
		return ErrDisabled
	}
	if finalDecision == "" {
		finalDecision = "block"
	}
	if source == "" {
		source = SourceContext
	}

	m.mu.Lock()
	held := m.holds[deferID]
	if held == nil || held.state != StateHeld {
		m.mu.Unlock()
		return ErrNotFound
	}
	held.state = StateResolving
	delete(m.holds, deferID)
	m.bySession[held.Authority.SessionID]--
	if m.bySession[held.Authority.SessionID] <= 0 {
		delete(m.bySession, held.Authority.SessionID)
	}
	m.totalBytes -= held.SizeBytes
	if held.timer != nil {
		held.timer.Stop()
	}
	m.mu.Unlock()

	state := resolvedState(finalDecision)
	if err := m.appendJournal(journalEntryFromHeld(*held, state, source)); err != nil {
		finalDecision = "block"
		source = SourceCancel
		state = resolvedState(finalDecision)
		_ = m.appendJournal(journalEntryFromHeld(*held, state, source))
	}
	held.Resolve(Resolution{
		DeferID:          held.DeferID,
		ParentActionID:   held.ActionID,
		FinalDecision:    finalDecision,
		ResolutionSource: source,
		Authority:        held.Authority,
		Target:           held.Target,
		Method:           held.Method,
		Reason:           held.Reason,
	})
	return nil
}

// ResolveAll resolves every currently held action with the same final decision.
func (m *Manager) ResolveAll(finalDecision, source string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	ids := make([]string, 0, len(m.holds))
	for id := range m.holds {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		_ = m.Resolve(id, finalDecision, source)
	}
}

func (m *Manager) RecordRestartRecovery(held HeldAction) error {
	if m == nil {
		return ErrDisabled
	}
	return m.appendJournal(journalEntryFromHeld(held, StateResolvedBlock, SourceRestartRecovery))
}

func (m *Manager) Snapshot() []HeldAction {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HeldAction, 0, len(m.holds))
	for _, held := range m.holds {
		cp := *held
		cp.timer = nil
		cp.Resolve = nil
		cp.Payload = append([]byte(nil), held.Payload...)
		out = append(out, cp)
	}
	return out
}

func (m *Manager) Held(deferID string) (HeldAction, bool) {
	held, err := m.snapshotOne(deferID)
	if err != nil {
		return HeldAction{}, false
	}
	return held, true
}

func (m *Manager) ResolveToolInventory(sessionID, finalDecision string) {
	if m == nil {
		return
	}
	for _, held := range m.Snapshot() {
		if held.Authority.SessionID == sessionID && held.RulePolicy.AllowOn.ToolInventoryBaseline {
			_ = m.Resolve(held.DeferID, finalDecision, SourceToolInventory)
		}
	}
}

// ResolveApproval resolves a hold from an explicit approval decision. A
// misconfigured positive approval cannot open the action; it resolves closed.
func (m *Manager) ResolveApproval(deferID, finalDecision string) error {
	held, err := m.snapshotOne(deferID)
	if err != nil {
		return err
	}
	switch finalDecision {
	case config.ActionAllow:
		if held.RulePolicy.AllowOn.Approval {
			return m.Resolve(deferID, config.ActionAllow, SourceApproval)
		}
	case config.ActionAsk:
		if held.RulePolicy.StepUpOn.ApprovalRequestsHuman {
			return m.Resolve(deferID, config.ActionAsk, SourceApproval)
		}
	case "step_up":
		if held.RulePolicy.StepUpOn.ApprovalRequestsHuman {
			return m.Resolve(deferID, config.ActionAsk, SourceApproval)
		}
	case config.ActionBlock, "":
		return m.Resolve(deferID, config.ActionBlock, SourceApproval)
	}
	return m.Resolve(deferID, config.ActionBlock, SourceApproval)
}

type ReloadEvaluator func(HeldAction) (string, error)

// ResolvePolicyReload re-evaluates held actions against a caller-supplied fresh
// policy view. Only affirmative policy_permits may allow; block/error resolves
// closed; defer remains held until another resolver or the hard deadline.
func (m *Manager) ResolvePolicyReload(evaluate ReloadEvaluator) {
	if m == nil || evaluate == nil {
		return
	}
	for _, held := range m.Snapshot() {
		decision, err := evaluate(held)
		if err != nil {
			_ = m.Resolve(held.DeferID, config.ActionBlock, SourcePolicyReload)
			continue
		}
		switch decision {
		case config.ActionAllow:
			if held.RulePolicy.AllowOn.PolicyPermits {
				_ = m.Resolve(held.DeferID, config.ActionAllow, SourcePolicyReload)
			}
		case config.ActionBlock:
			_ = m.Resolve(held.DeferID, config.ActionBlock, SourcePolicyReload)
		case config.ActionDefer:
			continue
		default:
			_ = m.Resolve(held.DeferID, config.ActionBlock, SourcePolicyReload)
		}
	}
}

func (m *Manager) snapshotOne(deferID string) (HeldAction, error) {
	if m == nil {
		return HeldAction{}, ErrDisabled
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	held := m.holds[deferID]
	if held == nil || held.state != StateHeld {
		return HeldAction{}, ErrNotFound
	}
	cp := *held
	cp.timer = nil
	cp.Resolve = nil
	cp.Payload = append([]byte(nil), held.Payload...)
	return cp, nil
}

func resolvedState(finalDecision string) string {
	switch finalDecision {
	case "allow":
		return StateResolvedAllow
	case "ask":
		return StateResolvedStepUp
	default:
		return StateResolvedBlock
	}
}

type journalEntry struct {
	DeferID    string                       `json:"defer_id"`
	ActionID   string                       `json:"action_id"`
	State      string                       `json:"state"`
	Source     string                       `json:"source,omitempty"`
	Target     string                       `json:"target,omitempty"`
	Surface    string                       `json:"surface,omitempty"`
	Method     string                       `json:"method,omitempty"`
	Reason     string                       `json:"reason,omitempty"`
	Authority  AuthoritySnapshot            `json:"authority"`
	RulePolicy config.DeferResolutionPolicy `json:"rule_policy,omitempty"`
	Deadline   time.Time                    `json:"deadline,omitempty"`
	Timestamp  time.Time                    `json:"timestamp"`
	SizeBytes  int                          `json:"size_bytes,omitempty"`
}

func journalEntryFromHeld(held HeldAction, state, source string) journalEntry {
	return journalEntry{
		DeferID:    held.DeferID,
		ActionID:   held.ActionID,
		State:      state,
		Source:     source,
		Target:     held.Target,
		Surface:    held.Surface,
		Method:     held.Method,
		Reason:     held.Reason,
		Authority:  held.Authority,
		RulePolicy: held.RulePolicy,
		Deadline:   held.Deadline,
		Timestamp:  time.Now().UTC(),
		SizeBytes:  held.SizeBytes,
	}
}

func (m *Manager) appendJournal(entry journalEntry) error {
	if m == nil || m.cfg.JournalPath == "" {
		return nil
	}
	path := filepath.Clean(m.cfg.JournalPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

// PendingJournal returns held actions from a prior process that lack a terminal
// journal entry. Callers should emit restart_recovery block receipts for each.
func PendingJournal(path string) ([]HeldAction, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	pending := map[string]journalEntry{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var entry journalEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("parse defer journal: %w", err)
		}
		switch entry.State {
		case StateHeld:
			pending[entry.DeferID] = entry
		default:
			delete(pending, entry.DeferID)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan defer journal: %w", err)
	}
	out := make([]HeldAction, 0, len(pending))
	for _, entry := range pending {
		out = append(out, HeldAction{
			DeferID:    entry.DeferID,
			ActionID:   entry.ActionID,
			Target:     entry.Target,
			Reason:     entry.Reason,
			Surface:    entry.Surface,
			Method:     entry.Method,
			SizeBytes:  entry.SizeBytes,
			RulePolicy: entry.RulePolicy,
			Authority:  entry.Authority,
			Deadline:   entry.Deadline,
		})
	}
	return out, nil
}
