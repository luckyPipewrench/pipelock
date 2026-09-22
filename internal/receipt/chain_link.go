// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	// ChainLinkVersion is the current chain_link schema.
	ChainLinkVersion = 1
	// ChainLinkEntryType identifies a continuity link in recorder logs. It is
	// the first entry of a run session that claimed a predecessor chain.
	ChainLinkEntryType = "chain_link"

	chainLinkDomain = "pipelock-chain-link-v1\x00"

	// chainClaimPrefix and chainClaimSuffix name the claim marker for one
	// predecessor session. The name is derived only from the predecessor, so
	// two processes racing to claim the same chain collide on O_EXCL and at
	// most one of them links to it. The marker never starts with "evidence-",
	// so no evidence enumeration mistakes it for a shard.
	chainClaimPrefix = "chain-claim-"
	chainClaimSuffix = ".claim"
)

// ChainLink is a run session's signed statement that it continues exactly one
// earlier chain of the same base: the predecessor's final receipt (sequence and
// hash) and signer key, and the successor's session and signer key. It is
// signed by the SUCCESSOR key, so it proves which tail the successor claims to
// continue. It does not by itself prove the predecessor key authorized a new
// key; a key change is trusted only through the caller's trusted key set or a
// RotationEndorsement signed by the predecessor key (see VerifyBase).
//
// The link lives in the recorder log, never inside a receipt: a run chain
// opens with an ordinary bound genesis session_open, and every existing
// single-chain verifier rejects a genesis session_open that carries a prior
// chain tail.
type ChainLink struct {
	Version              int    `json:"version"`
	PredecessorSession   string `json:"predecessor_session"`
	PredecessorTailSeq   uint64 `json:"predecessor_tail_seq"`
	PredecessorTailHash  string `json:"predecessor_tail_hash"`
	PredecessorSignerKey string `json:"predecessor_signer_key"`
	SuccessorSession     string `json:"successor_session"`
	SuccessorSignerKey   string `json:"successor_signer_key"`
	LinkedAt             string `json:"linked_at"`
	Signature            string `json:"signature"`
}

type chainLinkCanonical struct {
	Version              int    `json:"version"`
	PredecessorSession   string `json:"predecessor_session"`
	PredecessorTailSeq   uint64 `json:"predecessor_tail_seq"`
	PredecessorTailHash  string `json:"predecessor_tail_hash"`
	PredecessorSignerKey string `json:"predecessor_signer_key"`
	SuccessorSession     string `json:"successor_session"`
	SuccessorSignerKey   string `json:"successor_signer_key"`
	LinkedAt             string `json:"linked_at"`
}

// SignChainLink signs a link with the successor private key. The embedded
// successor key is derived from privKey rather than trusted input.
func SignChainLink(l ChainLink, privKey ed25519.PrivateKey) (ChainLink, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return ChainLink{}, fmt.Errorf("invalid successor private key size: got %d, want %d", len(privKey), ed25519.PrivateKeySize)
	}
	l.Version = ChainLinkVersion
	l.SuccessorSignerKey = hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
	l.Signature = ""
	if err := validateChainLinkFields(l, false); err != nil {
		return ChainLink{}, err
	}
	digest, err := chainLinkDigest(l)
	if err != nil {
		return ChainLink{}, err
	}
	l.Signature = signaturePrefix + hex.EncodeToString(ed25519.Sign(privKey, digest))
	return l, nil
}

// VerifyChainLink verifies the link's structure and successor-key signature.
// A caller must additionally match the predecessor fields against the
// predecessor chain and the successor fields against the chain holding the
// link before treating the link as continuity.
func VerifyChainLink(l ChainLink) error {
	if err := validateChainLinkFields(l, true); err != nil {
		return err
	}
	pubBytes, err := hex.DecodeString(l.SuccessorSignerKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("invalid successor_signer_key")
	}
	sigHex, ok := strings.CutPrefix(l.Signature, signaturePrefix)
	if !ok {
		return fmt.Errorf("invalid chain link signature format: missing %s prefix", signaturePrefix)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid chain link signature")
	}
	digest, err := chainLinkDigest(l)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), digest, sig) {
		return errors.New("chain link signature verification failed")
	}
	return nil
}

func validateChainLinkFields(l ChainLink, requireSignature bool) error {
	if l.Version != ChainLinkVersion {
		return fmt.Errorf("unsupported chain link version %d", l.Version)
	}
	if strings.TrimSpace(l.PredecessorSession) == "" || strings.TrimSpace(l.SuccessorSession) == "" {
		return errors.New("chain link sessions must be non-empty")
	}
	if l.PredecessorSession == l.SuccessorSession {
		return errors.New("chain link must not name its own session as predecessor")
	}
	if !validEd25519PublicKeyHex(l.PredecessorSignerKey) {
		return errors.New("chain link predecessor_signer_key is invalid")
	}
	if !validEd25519PublicKeyHex(l.SuccessorSignerKey) {
		return errors.New("chain link successor_signer_key is invalid")
	}
	if !validSHA256Hex(l.PredecessorTailHash) {
		return errors.New("chain link predecessor_tail_hash is invalid")
	}
	linkedAt, err := time.Parse(time.RFC3339Nano, l.LinkedAt)
	if err != nil || linkedAt.IsZero() || l.LinkedAt != linkedAt.UTC().Format(time.RFC3339Nano) {
		return errors.New("chain link linked_at must be canonical UTC RFC3339Nano")
	}
	if requireSignature && l.Signature == "" {
		return errors.New("chain link signature is empty")
	}
	return nil
}

func chainLinkDigest(l ChainLink) ([]byte, error) {
	canonical, err := json.Marshal(chainLinkCanonical{
		Version:              l.Version,
		PredecessorSession:   l.PredecessorSession,
		PredecessorTailSeq:   l.PredecessorTailSeq,
		PredecessorTailHash:  l.PredecessorTailHash,
		PredecessorSignerKey: l.PredecessorSignerKey,
		SuccessorSession:     l.SuccessorSession,
		SuccessorSignerKey:   l.SuccessorSignerKey,
		LinkedAt:             l.LinkedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal chain link: %w", err)
	}
	// Ed25519 signs the domain-separated canonical bytes directly (it hashes
	// internally); the domain prefix keeps a link signature from ever being
	// valid as any other signed Pipelock structure.
	return append([]byte(chainLinkDomain), canonical...), nil
}

// UnmarshalChainLink strictly decodes and verifies one link. Duplicate,
// unknown, and trailing fields are rejected because every accepted field is a
// claim covered by the successor key's signature.
func UnmarshalChainLink(data []byte) (ChainLink, error) {
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return ChainLink{}, fmt.Errorf("unmarshal chain link: %w", err)
	}
	var link ChainLink
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&link); err != nil {
		return ChainLink{}, fmt.Errorf("unmarshal chain link: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return ChainLink{}, errors.New("unmarshal chain link: trailing tokens")
	}
	if err := VerifyChainLink(link); err != nil {
		return ChainLink{}, err
	}
	return link, nil
}

// RunSessionBase returns the base of a run session ("<base>.run.<hex>") and
// true, or "" and false for any other session.
func RunSessionBase(session string) (string, bool) {
	idx := strings.Index(session, evidencename.RunInfix)
	if idx <= 0 {
		return "", false
	}
	return session[:idx], true
}

// isBaseChain reports whether session is a chain of base: the legacy plain
// base session an older binary wrote, or a run session minted from base.
func isBaseChain(session, base string) bool {
	if session == base {
		return true
	}
	b, ok := RunSessionBase(session)
	return ok && b == base
}

// chainClaimMarkerName is the deterministic claim marker for predecessor.
func chainClaimMarkerName(predecessor string) string {
	return chainClaimPrefix + predecessor + chainClaimSuffix
}

// predecessorTail is a claimed predecessor chain and its self-consistent tail.
type predecessorTail struct {
	session  string
	tail     Receipt
	tailHash string
}

// sessionReceiptTail returns the last receipt recorded for session, or nil
// when the session holds no receipt.
func sessionReceiptTail(dir, session string) (*Receipt, error) {
	files, err := recorderFiles(dir, session)
	if err != nil {
		return nil, err
	}
	for i := len(files) - 1; i >= 0; i-- {
		entry, found, readErr := recorder.FindLastEntry(files[i], func(entry recorder.Entry) bool {
			return entry.Type == recorderEntryType
		})
		if readErr != nil {
			return nil, fmt.Errorf("reading evidence file %s: %w", filepath.Base(files[i]), readErr)
		}
		if found {
			return receiptFromEntry(entry)
		}
	}
	return nil, nil
}

// claimPredecessor finds the most recent chain of base whose writer is gone
// and that nobody has claimed yet, and claims it with an O_CREAT|O_EXCL marker.
// It never blocks, never holds the marker open, and visits each candidate at
// most once. Returning (nil, nil) means start unlinked, which is correct when
// nothing is claimable. notice receives one line per candidate skipped for a
// reason an operator should see (a corrupt tail).
//
// The marker is a coordination hint between cooperating Pipelock processes,
// nothing more: verification never reads it, and trust derives only from the
// signed link, the predecessor's verified tail, and the key trust rules.
func claimPredecessor(dir, base, self string, notice io.Writer) (*predecessorTail, error) {
	sessions, err := recorder.ListSessions(dir)
	if err != nil {
		return nil, fmt.Errorf("listing prior chains: %w", err)
	}
	type candidate struct {
		session string
		latest  string
		modTime time.Time
	}
	candidates := make([]candidate, 0, len(sessions))
	for _, s := range sessions {
		if s == self || !isBaseChain(s, base) {
			continue
		}
		files, filesErr := recorderFiles(dir, s)
		if filesErr != nil || len(files) == 0 {
			continue
		}
		latest := files[len(files)-1]
		info, statErr := os.Stat(latest)
		if statErr != nil {
			continue
		}
		candidates = append(candidates, candidate{session: s, latest: latest, modTime: info.ModTime()})
	}
	// Prefer the most recent chain: it is the one a restart most plausibly
	// continues. Break ties on the session name for a total order.
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].modTime.Equal(candidates[j].modTime) {
			return candidates[i].modTime.After(candidates[j].modTime)
		}
		return candidates[i].session > candidates[j].session
	})

	for _, c := range candidates {
		marker := filepath.Join(filepath.Clean(dir), chainClaimMarkerName(c.session))
		if _, statErr := os.Lstat(marker); statErr == nil {
			continue // already has a successor claim
		}
		gone, probeErr := recorder.EvidenceWriterGone(c.latest)
		if probeErr != nil || !gone {
			continue // a live writer, or its absence cannot be proven
		}
		tail, tailErr := sessionReceiptTail(dir, c.session)
		if tailErr != nil {
			_, _ = fmt.Fprintf(notice, "pipelock: receipt chain %s not linked: reading its tail: %v\n", c.session, tailErr)
			continue
		}
		if tail == nil {
			continue // nothing to continue
		}
		// A corrupt predecessor tail is NOT claimed and does NOT stop this
		// run. Before run sessions, a corrupt tail on the shared session
		// bricked receipt emission until an operator intervened, because the
		// new receipts would have extended the damaged chain. A run session
		// owns a fresh chain, so bricking all future evidence over one damaged
		// old file is an availability failure with no integrity benefit. The
		// damaged chain stays on disk untouched and `pipelock evidence doctor`
		// reports it.
		if verifyErr := VerifyInternalConsistencyOnly(*tail); verifyErr != nil {
			_, _ = fmt.Fprintf(notice, "pipelock: WARNING receipt chain %s has a corrupt tail (seq %d): %v; starting this run unlinked, the damaged chain is left on disk for inspection\n",
				c.session, tail.ActionRecord.ChainSeq, verifyErr)
			continue
		}
		hash, hashErr := ReceiptHash(*tail)
		if hashErr != nil {
			continue
		}
		f, createErr := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			continue // EEXIST: another process claimed it first
		}
		body, _ := json.Marshal(struct {
			Predecessor string `json:"predecessor_session"`
			Successor   string `json:"successor_session"`
		}{c.session, self})
		_, _ = f.Write(append(body, '\n'))
		_ = f.Close()
		return &predecessorTail{session: c.session, tail: *tail, tailHash: hash}, nil
	}
	return nil, nil
}
