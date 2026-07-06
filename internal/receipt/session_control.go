package receipt

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// SessionControlKind names the three within-run session-lifecycle control
// records. They are signed v1 receipts carried inline on an ActionRecord via
// the SessionControl field, so a verifier can prove offline when a covered
// process window opened, that it kept beating, and how it closed.
type SessionControlKind string

const (
	// SessionControlOpen marks the first receipt of a process run. It replaces
	// the literal "genesis" sentinel on a brand-new chain and, on a restart,
	// binds the new run_nonce window to the prior chain tail.
	SessionControlOpen SessionControlKind = "session_open"
	// SessionControlHeartbeat is a periodic signed liveness+durability snapshot
	// so a crash mid-stream leaves a signed floor, not silence.
	SessionControlHeartbeat SessionControlKind = "heartbeat"
	// SessionControlClose is the signed end-of-run record: final seq, root hash,
	// receipt count, and cumulative durability counters.
	SessionControlClose SessionControlKind = "session_close"
)

// genesisSessionOpenPrefix tags a chain_prev_hash whose value is a bound
// session-open genesis rather than the legacy literal "genesis" sentinel.
// A verifier that sees this prefix MUST recompute ComputeSessionOpenGenesis
// over the receipt's signed SessionControl.Open and require equality.
const genesisSessionOpenPrefix = "g1:"

// sessionOpenGenesisLabel domain-separates the session-open genesis preimage
// from every other hash in the system. Changing this string is a breaking
// verifier change and MUST bump the label version suffix.
const sessionOpenGenesisLabel = "pipelock.receipt.session_open.v1"

// SessionControl is the inline session-lifecycle payload on an ActionRecord.
// Exactly one of Open/Heartbeat/Close is set, matching Kind.
type SessionControl struct {
	Kind SessionControlKind `json:"kind"`

	Open      *SessionOpen      `json:"open,omitempty"`
	Heartbeat *SessionHeartbeat `json:"heartbeat,omitempty"`
	Close     *SessionClose     `json:"close,omitempty"`
}

// SessionOpen is the signed opening record for one process run. Its digest,
// via ComputeSessionOpenGenesis, is the chain_prev_hash of the first receipt
// on a brand-new chain (prefixed with genesisSessionOpenPrefix). On a restart
// that resumes an existing chain, PriorChainHead/PriorChainSeq carry the
// observed tail and the open is an ordinary continuation, not chain genesis.
type SessionOpen struct {
	RunNonce         string `json:"run_nonce"`
	OpenNonce        string `json:"open_nonce"`
	RecorderSession  string `json:"recorder_session"`
	PolicyHash       string `json:"policy_hash"`
	SignerKeyEpoch   string `json:"signer_key_epoch"`
	HeartbeatSeconds int    `json:"heartbeat_seconds"`

	ChainOpenSeq   uint64 `json:"chain_open_seq"`
	PriorChainHead string `json:"prior_chain_head,omitempty"`
	PriorChainSeq  uint64 `json:"prior_chain_seq,omitempty"`

	// GenesisHash is the value the emitter computed for the first-chain case;
	// it MUST equal ComputeSessionOpenGenesis(open) and the receipt's
	// ChainPrevHash. Empty on restart/continuation opens.
	GenesisHash       string `json:"genesis_hash,omitempty"`
	GenesisAnchorHead string `json:"genesis_anchor_head,omitempty"`
	GenesisAnchorLog  string `json:"genesis_anchor_log,omitempty"`

	// Posture/containment binding. Present only when a signed posture capsule
	// binds this run to a contained UID; the containment grade gate consumes it.
	PostureCapsuleSHA256 string `json:"posture_capsule_sha256,omitempty"`
	PostureSignerKeyID   string `json:"posture_signer_key_id,omitempty"`
	ContainmentNonce     string `json:"containment_nonce,omitempty"`
	ContainedUID         string `json:"contained_uid,omitempty"`
}

// SessionHeartbeat is a periodic signed cumulative snapshot. The durability
// counters are the offline-verifiable interface the evidence-health scorecard
// consumes to prove the fsync-gated invariant held.
type SessionHeartbeat struct {
	RunNonce      string `json:"run_nonce"`
	OpenNonce     string `json:"open_nonce"`
	Beat          uint64 `json:"beat"`
	ChainHead     string `json:"chain_head"`
	ChainSeqHead  uint64 `json:"chain_seq_head"`
	HeartbeatTime string `json:"heartbeat_time"`

	FsyncErrorsGated uint64 `json:"fsync_errors_gated"`
	DurabilityBlocks uint64 `json:"durability_blocks"`
}

// SessionClose is the signed end-of-run record. It promotes the existing
// transcript-root fields to a signed receipt and carries the same cumulative
// durability counters as the heartbeat.
type SessionClose struct {
	RunNonce     string `json:"run_nonce"`
	OpenNonce    string `json:"open_nonce"`
	FinalSeq     uint64 `json:"final_seq"`
	RootHash     string `json:"root_hash"`
	ReceiptCount uint64 `json:"receipt_count"`
	CloseReason  string `json:"close_reason"`

	FsyncErrorsGated uint64 `json:"fsync_errors_gated"`
	DurabilityBlocks uint64 `json:"durability_blocks"`
}

// ComputeSessionOpenGenesis returns the bound genesis value for a first-chain
// session_open: genesisSessionOpenPrefix + hex(sha256(length-framed preimage)).
//
// The preimage is LENGTH-FRAMED (each field prefixed with its 8-byte big-endian
// length) so no two distinct field sets can collide by concatenation — the
// classic ("a","bc") vs ("ab","c") ambiguity. Every field is always framed,
// including empty optionals (framed as length 0), so the value is fully
// deterministic and a verifier recomputes it offline. Field order and the
// domain label are frozen; any change is a breaking verifier change.
func ComputeSessionOpenGenesis(o SessionOpen) string {
	h := sha256.New()
	frame := func(b []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(b)))
		_, _ = h.Write(l[:])
		_, _ = h.Write(b)
	}
	frame([]byte(sessionOpenGenesisLabel))
	frame([]byte(o.RunNonce))
	frame([]byte(o.OpenNonce))
	frame([]byte(o.RecorderSession))
	frame([]byte(o.PolicyHash))
	frame([]byte(o.SignerKeyEpoch))

	// A heartbeat interval is never negative; clamp defensively so the
	// conversion is provably in range and the preimage stays deterministic.
	hbSecs := o.HeartbeatSeconds
	if hbSecs < 0 {
		hbSecs = 0
	}
	var hb [8]byte
	binary.BigEndian.PutUint64(hb[:], uint64(hbSecs))
	frame(hb[:])

	frame([]byte(o.GenesisAnchorHead))
	frame([]byte(o.GenesisAnchorLog))
	frame([]byte(o.PostureCapsuleSHA256))
	frame([]byte(o.ContainmentNonce))
	frame([]byte(o.ContainedUID))

	return genesisSessionOpenPrefix + hex.EncodeToString(h.Sum(nil))
}
