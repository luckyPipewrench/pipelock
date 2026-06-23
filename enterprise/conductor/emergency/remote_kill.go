//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package emergency applies Conductor emergency control messages on followers.
package emergency

import (
	"bytes"
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

	remoteKillStateLocks sync.Map
)

const (
	RemoteKillStateFileName     = "remote-kill-state.json"
	RemoteKillStateAnchorSuffix = ".anchor"
	remoteKillStateContextFile  = "context.json"
	maxRemoteKillStateBytes     = 16 * 1024
	remoteKillDigestAlgorithmV1 = "remote-kill-replay-v1"
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
	// SignedMessage is the canonical JSON of the signed Conductor
	// RemoteKillMessage that authorized this decision. It is re-verified against
	// the trust roster on restore, so a persisted decision cannot be forged by an
	// attacker who can write the (non-secret) replay-state binding. Empty only for
	// the no-decision baseline (LastMessageHash == "").
	SignedMessage json.RawMessage `json:"signed_message,omitempty"`
	Context       string          `json:"context,omitempty"`
	Digest        string          `json:"digest,omitempty"`
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
	now := a.nowUTC()
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
	// Persist the just-verified signed message so the decision can be
	// re-verified against the trust roster on restart (anti-forgery).
	signedJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal verified conductor remote kill message: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return withRemoteKillStateLock(a.StatePath, func(canonical string) error {
		state, err := readDurableRemoteKillStateLocked(canonical)
		if err != nil {
			return err
		}
		if hash == state.LastMessageHash {
			// Idempotent re-apply (also backfills legacy/loose persisted state): the
			// incoming message was just signature-verified above, so re-apply it and
			// persist the signed message so a later restart re-verifies it.
			return a.applyAndPersistLocked(canonical, msg, hash, signedJSON, now)
		}
		if msg.Counter <= state.LastCounter {
			err := fmt.Errorf("%w: counter=%d last=%d", ErrRemoteKillSuperseded, msg.Counter, state.LastCounter)
			a.logReject("stale_counter", err)
			return err
		}
		return a.applyAndPersistLocked(canonical, msg, hash, signedJSON, now)
	})
}

// applyAndPersistLocked applies a freshly signature-verified message to the kill
// switch and persists the decision together with its signed message. Callers
// MUST hold a.mu and the per-path remote-kill state lock, and MUST have verified
// msg before calling.
func (a *RemoteKillApplier) applyAndPersistLocked(canonical string, msg conductor.RemoteKillMessage, hash string, signedJSON json.RawMessage, now time.Time) error {
	a.KillSwitch.SetConductorRemote(msg.State == conductor.KillSwitchActive, msg.Reason)
	return writeRemoteKillStateLocked(canonical, remoteKillState{
		LastCounter:     msg.Counter,
		LastMessageHash: hash,
		State:           msg.State,
		Reason:          msg.Reason,
		AppliedAt:       now,
		SignedMessage:   signedJSON,
	})
}

func (a *RemoteKillApplier) nowUTC() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
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
	return withRemoteKillStateLock(a.StatePath, func(canonical string) error {
		state, err := readDurableRemoteKillStateLocked(canonical)
		if err != nil {
			return err
		}
		if state.LastMessageHash == "" {
			return nil
		}
		return a.applyPersistedDecisionLocked(state)
	})
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
	// A persisted decision MUST be backed by a re-verifiable signed Conductor
	// message. The replay-state Context/Digest binding is deterministic and
	// non-secret, so without re-verification an attacker who can write the
	// follower replay-state dir could forge a decision and flip (or pin) the kill
	// switch on restart. Re-verify the signature against the trust roster and fail
	// CLOSED on any mismatch; the operator recovers with
	// `conductor follower reset-replay-state`.
	//
	// Residual (documented, not closed here): an attacker with replay-state write
	// access who also possesses a genuine OLDER signed resume (inactive) message
	// could roll the persisted state back to it; it re-verifies. This is bounded —
	// the live poller re-fetches the authoritative higher-counter state and
	// re-asserts within one poll interval — and write access to pipelock's own
	// state store already implies host compromise. The signature requirement
	// closes the trivial, total, no-message-needed forgery.
	if len(state.SignedMessage) == 0 {
		return errors.New("conductor remote kill persisted decision is not backed by a signed message; refusing to apply unauthenticated kill state (run conductor follower reset-replay-state)")
	}
	if a.Resolver == nil {
		return errors.New("conductor remote kill applier resolver required to verify persisted decision")
	}
	var msg conductor.RemoteKillMessage
	if err := json.Unmarshal(state.SignedMessage, &msg); err != nil {
		return fmt.Errorf("decode persisted conductor remote kill message: %w", err)
	}
	now := a.nowUTC()
	if err := msg.VerifySignaturesAt(now, a.Resolver); err != nil {
		a.logReject("persisted_signature", err)
		return fmt.Errorf("verify persisted conductor remote kill signature: %w", err)
	}
	if err := msg.ValidateForFollower(a.OrgID, a.FleetID, a.InstanceID, a.Labels); err != nil {
		a.logReject("persisted_audience", err)
		return fmt.Errorf("verify persisted conductor remote kill audience: %w", err)
	}
	hash, err := msg.CanonicalHash()
	if err != nil {
		return err
	}
	// The signed message must match the persisted decision it claims to authorize;
	// otherwise an attacker could pair a valid signed message with a different
	// on-disk State/Counter/Reason.
	if hash != state.LastMessageHash || msg.State != state.State || msg.Counter != state.LastCounter || msg.Reason != state.Reason {
		return errors.New("persisted conductor remote kill decision does not match its signed message")
	}
	a.KillSwitch.SetConductorRemote(msg.State == conductor.KillSwitchActive, msg.Reason)
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
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%d\n%s\n%s\n%s\n%s\n%s",
		remoteKillDigestAlgorithmV1,
		remoteKillContextID(path),
		state.LastCounter,
		state.LastMessageHash,
		state.State,
		state.Reason,
		state.AppliedAt.UTC().Format(time.RFC3339Nano),
		signedMessageDigest(state.SignedMessage),
	)))
	return hex.EncodeToString(sum[:])
}

// signedMessageDigest hashes the signed message in a whitespace-invariant way.
// json.MarshalIndent re-indents an embedded json.RawMessage when writing the
// state file, so the bytes differ from the compact form passed in; compacting
// first keeps the digest stable across the write/read round-trip.
func signedMessageDigest(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func legacyRemoteKillDigestV1(path string, state remoteKillState) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%d\n%s\n%s\n%s\n%s",
		remoteKillDigestAlgorithmV1,
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
	var state remoteKillState
	err := withRemoteKillStateLock(path, func(canonical string) error {
		var err error
		state, err = readDurableRemoteKillStateLocked(canonical)
		return err
	})
	return state, err
}

func readDurableRemoteKillStateLocked(canonical string) (remoteKillState, error) {
	primary, primaryFound, primaryRewrite, err := readOptionalRemoteKillState(canonical, canonical)
	if err != nil {
		return remoteKillState{}, err
	}
	anchorPath := remoteKillStateAnchorPath(canonical)
	anchor, anchorFound, anchorRewrite, err := readOptionalRemoteKillState(anchorPath, canonical)
	if err != nil {
		return remoteKillState{}, err
	}
	switch {
	case primaryFound && anchorFound:
		if !remoteKillStatesEqual(primary, anchor) {
			return remoteKillState{}, fmt.Errorf("%w: primary and anchor differ", ErrRemoteKillStateMismatch)
		}
		if primaryRewrite || anchorRewrite {
			if err := writeRemoteKillStateLocked(canonical, primary); err != nil {
				return remoteKillState{}, fmt.Errorf("migrate conductor remote kill state format: %w", err)
			}
		}
		return primary, nil
	case primaryFound:
		if primaryRewrite {
			if err := writeRemoteKillStateFileForContext(canonical, canonical, primary); err != nil {
				return remoteKillState{}, fmt.Errorf("migrate conductor remote kill state primary: %w", err)
			}
		}
		if err := writeRemoteKillStateFileForContext(anchorPath, canonical, primary); err != nil {
			return remoteKillState{}, fmt.Errorf("backfill conductor remote kill state anchor: %w", err)
		}
		if err := writeRemoteKillStateContext(canonical); err != nil {
			return remoteKillState{}, fmt.Errorf("backfill conductor remote kill state context: %w", err)
		}
		return primary, nil
	case anchorFound:
		if anchorRewrite {
			if err := writeRemoteKillStateFileForContext(anchorPath, canonical, anchor); err != nil {
				return remoteKillState{}, fmt.Errorf("migrate conductor remote kill state anchor: %w", err)
			}
		}
		if err := writeRemoteKillStateFileForContext(canonical, canonical, anchor); err != nil {
			return remoteKillState{}, fmt.Errorf("restore conductor remote kill state primary: %w", err)
		}
		if err := writeRemoteKillStateContext(canonical); err != nil {
			return remoteKillState{}, fmt.Errorf("backfill conductor remote kill state context: %w", err)
		}
		return anchor, nil
	default:
		contextFound, contextErr := remoteKillReplayContextPresent(canonical)
		if contextErr != nil {
			return remoteKillState{}, contextErr
		}
		if contextFound {
			return remoteKillState{}, fmt.Errorf("conductor remote kill replay state missing while follower context is present; run: pipelock conductor follower reset-replay-state --state-dir <conductor.bundle_cache_dir> --confirm")
		}
		return remoteKillState{}, nil
	}
}

func readOptionalRemoteKillState(path, canonicalPath string) (remoteKillState, bool, bool, error) {
	state, err := readRemoteKillStateFile(path)
	if err == nil {
		rewrite, err := validateRemoteKillStateBinding(canonicalPath, state)
		if err != nil {
			return remoteKillState{}, false, false, err
		}
		return state, true, rewrite, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return remoteKillState{}, false, false, nil
	}
	return remoteKillState{}, false, false, err
}

func validateRemoteKillStateBinding(path string, state remoteKillState) (bool, error) {
	if state.Context != "" && state.Context != remoteKillContextID(path) {
		return false, fmt.Errorf("conductor remote kill state context mismatch")
	}
	switch {
	case state.Digest == "":
		return false, nil
	case state.Digest == remoteKillDigest(path, state):
		return false, nil
	case state.Digest == legacyRemoteKillDigestV1(path, state):
		return true, nil
	default:
		return false, fmt.Errorf("conductor remote kill state digest mismatch")
	}
}

func remoteKillStatesEqual(a, b remoteKillState) bool {
	return a.LastCounter == b.LastCounter &&
		a.LastMessageHash == b.LastMessageHash &&
		a.State == b.State &&
		a.Reason == b.Reason &&
		a.AppliedAt.Equal(b.AppliedAt) &&
		bytes.Equal(a.SignedMessage, b.SignedMessage)
}

func withRemoteKillStateLock(path string, fn func(canonical string) error) error {
	canonical := filepath.Clean(path)
	value, _ := remoteKillStateLocks.LoadOrStore(canonical, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	return fn(canonical)
}

func writeRemoteKillState(path string, state remoteKillState) error {
	return withRemoteKillStateLock(path, func(canonical string) error {
		return writeRemoteKillStateLocked(canonical, state)
	})
}

func writeRemoteKillStateLocked(canonical string, state remoteKillState) error {
	if err := writeRemoteKillStateFileForContext(canonical, canonical, state); err != nil {
		return err
	}
	if err := writeRemoteKillStateFileForContext(remoteKillStateAnchorPath(canonical), canonical, state); err != nil {
		return err
	}
	if err := writeRemoteKillStateContext(canonical); err != nil {
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

// ResetRemoteKillReplayState writes an unsigned monotonic replay floor.
//
// This is not a boot-recovery path for a persisted kill decision: after signed
// restore hardening, non-empty decisions without SignedMessage intentionally fail
// RestorePersistedState. Use ResetReplayStateToBaseline for the shipped operator
// recovery command that lets a wedged follower boot and re-sync from Conductor.
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

// InitializeReplayBaseline writes an initial, no-decision remote-kill replay
// baseline for a freshly enrolled follower that has never received a kill.
//
// Why this exists: an enrolled follower is treated as "follower context
// present" (the enrollment marker sits next to the replay state). On restart,
// readDurableRemoteKillState refuses to start when that context is present but
// no replay state exists — a deliberate anti-replay guard against someone
// deleting the state file to reset the kill counter. A follower that enrolled
// cleanly but was never killed has no replay state yet, so without this
// baseline it would wedge (fail closed) on its first restart with no shipped
// recovery path. Writing the baseline at enrollment closes that gap.
//
// The baseline carries counter 0 and an empty LastMessageHash, so
// RestorePersistedState treats it as "no decision to apply" (boots clean, kill
// switch untouched) while the first real remote-kill (counter > 0) still
// advances the replay counter normally.
//
// It is replay-safe: if ANY replay state already exists (primary file, anchor,
// or context) the call is a no-op, so it can never overwrite a real kill
// decision and reset the counter. A corrupt/unreadable existing state fails
// loud rather than being silently overwritten.
func InitializeReplayBaseline(path string, now time.Time) error {
	return withRemoteKillStateLock(path, func(canonical string) error {
		if _, found, _, err := readOptionalRemoteKillState(canonical, canonical); err != nil {
			return err
		} else if found {
			return nil
		}
		if _, found, _, err := readOptionalRemoteKillState(remoteKillStateAnchorPath(canonical), canonical); err != nil {
			return err
		} else if found {
			return nil
		}
		if found, err := readRemoteKillStateContext(canonical); err != nil {
			return err
		} else if found {
			return nil
		}
		return writeReplayBaselineLocked(canonical, now)
	})
}

// ResetReplayStateToBaseline force-writes a clean, no-decision replay baseline,
// OVERWRITING any existing remote-kill replay state. It is the explicit operator
// recovery for a follower that cannot start because it is enrolled but its replay
// state is missing or partial ("replay state missing while follower context is
// present") and there is otherwise no shipped way out.
//
// Unlike InitializeReplayBaseline this is intentionally NOT replay-safe on its own:
// it resets the local replay counter to 0. That is acceptable ONLY as a deliberate,
// operator-invoked action because the Conductor remains the source of truth — on the
// next poll the follower re-fetches and re-applies the authoritative kill state
// (whose counter exceeds 0), so a genuinely-active fleet kill is restored. Callers
// MUST gate this behind an explicit operator command, never an automatic path.
func ResetReplayStateToBaseline(path string, now time.Time) error {
	return writeReplayBaseline(filepath.Clean(path), now)
}

// writeReplayBaseline writes the canonical no-decision baseline (counter 0, empty
// message hash, inactive) bound to path. RestorePersistedState treats the empty
// hash as "no decision to apply" so the follower boots clean, and the first real
// remote-kill (counter > 0) still advances normally.
func writeReplayBaseline(canonical string, now time.Time) error {
	return withRemoteKillStateLock(canonical, func(canonical string) error {
		return writeReplayBaselineLocked(canonical, now)
	})
}

func writeReplayBaselineLocked(canonical string, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return writeRemoteKillStateLocked(canonical, remoteKillState{
		LastCounter:     0,
		LastMessageHash: "",
		State:           conductor.KillSwitchInactive,
		Reason:          "",
		AppliedAt:       now.UTC(),
	})
}
