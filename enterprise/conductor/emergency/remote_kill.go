//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package emergency applies Conductor emergency control messages on followers.
package emergency

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

var (
	ErrRemoteKillDisabled      = errors.New("conductor remote kill switch disabled")
	ErrRemoteKillSuperseded    = errors.New("conductor remote kill message superseded")
	ErrRemoteKillStateRequired = errors.New("conductor remote kill replay state path required")
)

const (
	RemoteKillStateFileName = "remote-kill-state.json"
	maxRemoteKillStateBytes = 16 * 1024
)

type KillSwitchSetter interface {
	SetConductorRemote(active bool, message string)
}

type remoteKillState struct {
	LastCounter     uint64                    `json:"last_counter"`
	LastMessageHash string                    `json:"last_message_hash"`
	State           conductor.KillSwitchState `json:"state"`
	Reason          string                    `json:"reason"`
	AppliedAt       time.Time                 `json:"applied_at"`
}

type RemoteKillApplier struct {
	OrgID      string
	FleetID    string
	InstanceID string
	Labels     map[string]string
	Resolver   conductor.SignatureKeyResolver
	KillSwitch KillSwitchSetter
	// StatePath stores the last applied counter and message hash so signed
	// remote-kill messages cannot replay after follower restart.
	StatePath string
	// DisableRemoteKill explicitly opts out of applying otherwise valid
	// remote-kill messages. The zero value honors remote kills.
	DisableRemoteKill bool
	Now               func() time.Time
	Logger            *slog.Logger

	mu sync.Mutex
}

func (a *RemoteKillApplier) Apply(msg conductor.RemoteKillMessage) error {
	if a == nil {
		return errors.New("conductor remote kill applier required")
	}
	if a.KillSwitch == nil {
		return errors.New("conductor remote kill applier kill switch required")
	}
	if a.StatePath == "" {
		return ErrRemoteKillStateRequired
	}
	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now().UTC()
	}
	if a.DisableRemoteKill {
		a.logReject("disabled", ErrRemoteKillDisabled)
		return ErrRemoteKillDisabled
	}
	if err := msg.ValidateAtTime(now); err != nil {
		a.logReject("validation", err)
		return err
	}
	if err := msg.VerifySignaturesAt(now, a.Resolver); err != nil {
		a.logReject("signature", err)
		return err
	}
	if err := msg.ValidateForFollower(a.OrgID, a.FleetID, a.InstanceID, a.Labels); err != nil {
		a.logReject("audience", err)
		return err
	}
	hash, err := msg.CanonicalHash()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := readRemoteKillState(a.StatePath)
	if err != nil {
		return err
	}
	if hash == state.LastMessageHash {
		switch state.State {
		case conductor.KillSwitchActive, conductor.KillSwitchInactive:
			return a.applyPersistedDecisionLocked(state)
		default:
			a.KillSwitch.SetConductorRemote(msg.State == conductor.KillSwitchActive, msg.Reason)
			return writeRemoteKillState(a.StatePath, remoteKillState{
				LastCounter:     msg.Counter,
				LastMessageHash: hash,
				State:           msg.State,
				Reason:          msg.Reason,
				AppliedAt:       now,
			})
		}
	}
	if msg.Counter <= state.LastCounter {
		err := fmt.Errorf("%w: counter=%d last=%d", ErrRemoteKillSuperseded, msg.Counter, state.LastCounter)
		a.logReject("stale_counter", err)
		return err
	}
	a.KillSwitch.SetConductorRemote(msg.State == conductor.KillSwitchActive, msg.Reason)
	return writeRemoteKillState(a.StatePath, remoteKillState{
		LastCounter:     msg.Counter,
		LastMessageHash: hash,
		State:           msg.State,
		Reason:          msg.Reason,
		AppliedAt:       now,
	})
}

func (a *RemoteKillApplier) RestorePersistedState() error {
	if a == nil {
		return errors.New("conductor remote kill applier required")
	}
	if a.KillSwitch == nil {
		return errors.New("conductor remote kill applier kill switch required")
	}
	if a.StatePath == "" {
		return ErrRemoteKillStateRequired
	}
	if a.DisableRemoteKill {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := readRemoteKillState(a.StatePath)
	if err != nil {
		return err
	}
	if state.LastMessageHash == "" {
		return nil
	}
	return a.applyPersistedDecisionLocked(state)
}

func (a *RemoteKillApplier) applyPersistedDecisionLocked(state remoteKillState) error {
	switch state.State {
	case conductor.KillSwitchActive, conductor.KillSwitchInactive:
	default:
		return fmt.Errorf("invalid conductor remote kill persisted state %q", state.State)
	}
	if len(state.Reason) > conductor.MaxReasonBytes {
		return fmt.Errorf("invalid conductor remote kill persisted reason: %d bytes > cap %d", len(state.Reason), conductor.MaxReasonBytes)
	}
	a.KillSwitch.SetConductorRemote(state.State == conductor.KillSwitchActive, state.Reason)
	return nil
}

func (a *RemoteKillApplier) logReject(reason string, err error) {
	if a.Logger == nil {
		return
	}
	a.Logger.Warn("conductor_remote_kill_rejected",
		slog.String("event", "conductor_remote_kill_rejected"),
		slog.String("reason", reason),
		slog.String("error", err.Error()),
	)
}

func readRemoteKillState(path string) (remoteKillState, error) {
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return remoteKillState{}, nil
		}
		return remoteKillState{}, fmt.Errorf("read conductor remote kill state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return remoteKillState{}, fmt.Errorf("invalid conductor remote kill state file %s", clean)
	}
	if info.Size() > maxRemoteKillStateBytes {
		return remoteKillState{}, fmt.Errorf("conductor remote kill state too large")
	}
	file, err := os.Open(clean)
	if err != nil {
		return remoteKillState{}, fmt.Errorf("open conductor remote kill state: %w", err)
	}
	defer func() { _ = file.Close() }()
	var state remoteKillState
	decoder := json.NewDecoder(io.LimitReader(file, maxRemoteKillStateBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return remoteKillState{}, fmt.Errorf("decode conductor remote kill state: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return remoteKillState{}, fmt.Errorf("decode conductor remote kill state: trailing JSON document")
	}
	return state, nil
}

func writeRemoteKillState(path string, state remoteKillState) error {
	clean := filepath.Clean(path)
	dir := filepath.Dir(clean)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create conductor remote kill state dir: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal conductor remote kill state: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".remote-kill-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create conductor remote kill state temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write conductor remote kill state temp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod conductor remote kill state temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync conductor remote kill state temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close conductor remote kill state temp: %w", err)
	}
	if err := os.Rename(tmpName, clean); err != nil {
		return fmt.Errorf("rename conductor remote kill state: %w", err)
	}
	dirFile, err := os.Open(dir) //nolint:gosec // dir is derived from the configured local replay-state path and opened only for fsync.
	if err != nil {
		return fmt.Errorf("open conductor remote kill state dir: %w", err)
	}
	defer func() { _ = dirFile.Close() }()
	if err := dirFile.Sync(); err != nil {
		return fmt.Errorf("sync conductor remote kill state dir: %w", err)
	}
	return nil
}
