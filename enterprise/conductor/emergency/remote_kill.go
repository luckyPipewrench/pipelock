//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package emergency applies Conductor emergency control messages on followers.
package emergency

import (
	"crypto/sha256"
	"encoding/hex"
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
	ErrRemoteKillStateMismatch = errors.New("conductor remote kill replay state mismatch")
)

const (
	RemoteKillStateFileName     = "remote-kill-state.json"
	RemoteKillStateAnchorSuffix = ".anchor"
	remoteKillStateContextFile  = "context.json"
	maxRemoteKillStateBytes     = 16 * 1024
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
	Context         string                    `json:"context,omitempty"`
	Digest          string                    `json:"digest,omitempty"`
}

type remoteKillStateContext struct {
	Context string `json:"context"`
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
	state, err := readDurableRemoteKillState(a.StatePath)
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
	state, err := readDurableRemoteKillState(a.StatePath)
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
	state, err := readRemoteKillStateFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return remoteKillState{}, nil
	}
	return state, err
}

func readRemoteKillStateFile(clean string) (remoteKillState, error) {
	clean = filepath.Clean(clean)
	info, err := os.Lstat(clean)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return remoteKillState{}, err
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

func remoteKillStateAnchorPath(path string) string {
	return filepath.Join(remoteKillProtectedDir(path), "secondary.json")
}

func remoteKillStateContextPath(path string) string {
	return filepath.Join(remoteKillProtectedDir(path), remoteKillStateContextFile)
}

func remoteKillProtectedDir(path string) string {
	clean := filepath.Clean(path)
	sum := sha256.Sum256([]byte(clean))
	return filepath.Join(filepath.Dir(clean), ".pipelock-state", "remote-kill-replay", hex.EncodeToString(sum[:16]))
}

func remoteKillContextID(path string) string {
	clean := filepath.Clean(path)
	sum := sha256.Sum256([]byte("remote-kill-replay-v1\n" + clean))
	return hex.EncodeToString(sum[:])
}

func remoteKillDigest(path string, state remoteKillState) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("remote-kill-replay-v1\n%s\n%d\n%s\n%s\n%s\n%s",
		remoteKillContextID(path),
		state.LastCounter,
		state.LastMessageHash,
		state.State,
		state.Reason,
		state.AppliedAt.UTC().Format(time.RFC3339Nano),
	)))
	return hex.EncodeToString(sum[:])
}

func readDurableRemoteKillState(path string) (remoteKillState, error) {
	canonical := filepath.Clean(path)
	primary, primaryFound, err := readOptionalRemoteKillState(canonical, canonical)
	if err != nil {
		return remoteKillState{}, err
	}
	anchor, anchorFound, err := readOptionalRemoteKillState(remoteKillStateAnchorPath(path), canonical)
	if err != nil {
		return remoteKillState{}, err
	}
	switch {
	case primaryFound && anchorFound:
		if !remoteKillStatesEqual(primary, anchor) {
			return remoteKillState{}, fmt.Errorf("%w: primary and anchor differ", ErrRemoteKillStateMismatch)
		}
		return primary, nil
	case primaryFound:
		if err := writeRemoteKillStateFileForContext(remoteKillStateAnchorPath(path), canonical, primary); err != nil {
			return remoteKillState{}, fmt.Errorf("backfill conductor remote kill state anchor: %w", err)
		}
		if err := writeRemoteKillStateContext(path); err != nil {
			return remoteKillState{}, fmt.Errorf("backfill conductor remote kill state context: %w", err)
		}
		return primary, nil
	case anchorFound:
		if err := writeRemoteKillStateFileForContext(canonical, canonical, anchor); err != nil {
			return remoteKillState{}, fmt.Errorf("restore conductor remote kill state primary: %w", err)
		}
		if err := writeRemoteKillStateContext(path); err != nil {
			return remoteKillState{}, fmt.Errorf("backfill conductor remote kill state context: %w", err)
		}
		return anchor, nil
	default:
		contextFound, contextErr := remoteKillReplayContextPresent(path)
		if contextErr != nil {
			return remoteKillState{}, contextErr
		}
		if contextFound {
			return remoteKillState{}, fmt.Errorf("conductor remote kill replay state missing while follower context is present; run an explicit replay-state reset")
		}
		return remoteKillState{}, nil
	}
}

func readOptionalRemoteKillState(path, canonicalPath string) (remoteKillState, bool, error) {
	state, err := readRemoteKillStateFile(path)
	if err == nil {
		if err := validateRemoteKillStateBinding(canonicalPath, state); err != nil {
			return remoteKillState{}, false, err
		}
		return state, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return remoteKillState{}, false, nil
	}
	return remoteKillState{}, false, err
}

func validateRemoteKillStateBinding(path string, state remoteKillState) error {
	if state.Context != "" && state.Context != remoteKillContextID(path) {
		return fmt.Errorf("conductor remote kill state context mismatch")
	}
	if state.Digest != "" && state.Digest != remoteKillDigest(path, state) {
		return fmt.Errorf("conductor remote kill state digest mismatch")
	}
	return nil
}

func remoteKillStatesEqual(a, b remoteKillState) bool {
	return a.LastCounter == b.LastCounter &&
		a.LastMessageHash == b.LastMessageHash &&
		a.State == b.State &&
		a.Reason == b.Reason &&
		a.AppliedAt.Equal(b.AppliedAt)
}

func writeRemoteKillState(path string, state remoteKillState) error {
	canonical := filepath.Clean(path)
	if err := writeRemoteKillStateFileForContext(canonical, canonical, state); err != nil {
		return err
	}
	if err := writeRemoteKillStateFileForContext(remoteKillStateAnchorPath(path), canonical, state); err != nil {
		return err
	}
	if err := writeRemoteKillStateContext(path); err != nil {
		return err
	}
	return nil
}

func writeRemoteKillStateFileForContext(path, canonicalPath string, state remoteKillState) error {
	clean := filepath.Clean(path)
	state.Context = remoteKillContextID(canonicalPath)
	state.Digest = ""
	state.Digest = remoteKillDigest(canonicalPath, state)
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

func remoteKillReplayContextPresent(path string) (bool, error) {
	if found, err := readRemoteKillStateContext(path); err != nil || found {
		return found, err
	}
	info, err := os.Stat(filepath.Join(filepath.Dir(filepath.Clean(path)), "enrolled.json"))
	if err == nil {
		return info.Mode().IsRegular(), nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("stat conductor enrollment marker: %w", err)
}

func readRemoteKillStateContext(path string) (bool, error) {
	data, err := os.ReadFile(filepath.Clean(remoteKillStateContextPath(path))) // #nosec G304 -- path derives from configured local replay-state path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("read conductor remote kill state context: %w", err)
	}
	var ctx remoteKillStateContext
	if err := json.Unmarshal(data, &ctx); err != nil {
		return false, fmt.Errorf("parse conductor remote kill state context: %w", err)
	}
	if ctx.Context != remoteKillContextID(path) {
		return false, fmt.Errorf("conductor remote kill state context mismatch")
	}
	return true, nil
}

func writeRemoteKillStateContext(path string) error {
	contextPath := remoteKillStateContextPath(path)
	if err := os.MkdirAll(filepath.Dir(contextPath), 0o750); err != nil {
		return fmt.Errorf("create conductor remote kill state context dir: %w", err)
	}
	data, err := json.Marshal(remoteKillStateContext{Context: remoteKillContextID(path)})
	if err != nil {
		return fmt.Errorf("marshal conductor remote kill state context: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(contextPath, data, 0o600); err != nil {
		return fmt.Errorf("write conductor remote kill state context: %w", err)
	}
	return nil
}

func ResetRemoteKillReplayState(path string, counter uint64, state conductor.KillSwitchState, reason string, now time.Time) error {
	switch state {
	case conductor.KillSwitchActive, conductor.KillSwitchInactive:
	default:
		return fmt.Errorf("invalid conductor remote kill reset state %q", state)
	}
	if counter == 0 {
		return errors.New("conductor remote kill reset counter must be greater than zero")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return writeRemoteKillState(path, remoteKillState{
		LastCounter:     counter,
		LastMessageHash: fmt.Sprintf("operator-reset:%d", counter),
		State:           state,
		Reason:          reason,
		AppliedAt:       now.UTC(),
	})
}
