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
	"io/fs"
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

	chainLinkDomain = "pipelock-chain-link-v1\x00"

	// ChainLinkFilePrefix and ChainLinkFileSuffix name the signed link file
	// for one predecessor session: "chain-link-<predecessor>.json", beside the
	// evidence files. The name derives only from the predecessor, so two
	// processes racing to continue the same chain collide on the same name
	// and at most one link file per predecessor can exist. The name never
	// starts with "evidence-", so no evidence enumeration mistakes it for a
	// shard, and no receipt chain file ever contains a link.
	ChainLinkFilePrefix = "chain-link-"
	ChainLinkFileSuffix = ".json"

	// chainLinkTempPattern names the unpublished temp file. It starts with a
	// dot and ends in .tmp, so a temp file left by a crash never parses as a
	// link file name.
	chainLinkTempPattern = ".chain-link-*.tmp"

	// maxChainLinkFileBytes bounds a link file read. A signed link is well
	// under 1 KiB; anything larger is not a link this code wrote.
	maxChainLinkFileBytes = 64 << 10
)

// ChainLink is a run session's signed statement that it continues exactly one
// earlier chain of the same base: the predecessor's final receipt (sequence and
// hash) and signer key, and the successor's session and signer key. It is
// signed by the SUCCESSOR key, so it proves which tail the successor claims to
// continue. It does not by itself prove the predecessor key authorized a new
// key; a key change is trusted only through the caller's trusted key set or a
// RotationEndorsement signed by the predecessor key (see VerifyBase).
//
// The link lives in its own file beside the chain (see ChainLinkFileName),
// never inside the chain: a run chain holds only entry types every shipped
// verifier already accepts and opens with an ordinary bound genesis
// session_open. The link is OPTIONAL evidence. Deleting a link file makes its
// successor look like an unlinked run, and nothing detects that deletion;
// resisting it needs a signed head commitment, which this format does not
// provide.
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

// ChainLinkFileName is the link file name for predecessor.
func ChainLinkFileName(predecessor string) string {
	return ChainLinkFilePrefix + predecessor + ChainLinkFileSuffix
}

// chainLinkFilePredecessor returns the predecessor a link file name was
// published under, or false when name is not a link file name.
func chainLinkFilePredecessor(name string) (string, bool) {
	pred, ok := strings.CutPrefix(name, ChainLinkFilePrefix)
	if !ok {
		return "", false
	}
	pred, ok = strings.CutSuffix(pred, ChainLinkFileSuffix)
	if !ok || pred == "" {
		return "", false
	}
	return pred, true
}

// predecessorTail is a claimable predecessor chain and its self-consistent tail.
type predecessorTail struct {
	session  string
	tail     Receipt
	tailHash string
}

// sessionReceiptTail returns the last receipt in a session's shard files, or
// nil when the session holds no receipt.
func sessionReceiptTail(files []string) (*Receipt, error) {
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

// linkFile is the publish primitive, a package variable only so a test can
// force the non-EEXIST failure path. Production always uses os.Link.
var linkFile = os.Link

// errLinkNameTaken reports that another process already published a link for
// this predecessor.
var errLinkNameTaken = errors.New("chain link name already published")

// publishChainLinkFile writes body to a unique temp file in dir, fsyncs it,
// and hard-links it to name. os.Link fails with EEXIST when name exists, which
// makes the publish both atomic (the final name only ever points at a
// complete, fsynced file) and create-if-absent (at most one publisher wins).
// The temp file is always removed. The directory is fsynced after a
// successful link so the new name survives a crash.
func publishChainLinkFile(dir, name string, body []byte) error {
	tmp, err := os.CreateTemp(dir, chainLinkTempPattern)
	if err != nil {
		return fmt.Errorf("creating chain link temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := writeSyncClose(tmp, body); err != nil {
		return err
	}
	if err := linkFile(tmpName, filepath.Join(dir, name)); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errLinkNameTaken
		}
		return fmt.Errorf("publishing chain link: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("syncing evidence directory after chain link: %w", err)
	}
	return nil
}

func writeSyncClose(f *os.File, body []byte) error {
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("setting chain link mode: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing chain link: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("syncing chain link: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing chain link: %w", err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// linkRequest carries what publishPredecessorLink needs about the successor.
type linkRequest struct {
	dir     string
	base    string
	self    string
	privKey ed25519.PrivateKey
	now     time.Time
	notice  io.Writer
}

// publishPredecessorLink finds the most recent chain of base whose writer is
// gone and that has no link file yet, signs a link to its exact tail, and
// publishes it as that predecessor's link file. It never blocks and visits
// each candidate at most once. (nil, nil) means start unlinked, which is
// correct when nothing is claimable. A lost publish race (EEXIST) moves on to
// the next candidate; any other publish failure stops and is returned, so the
// caller starts unlinked and says why. notice receives one line per candidate
// skipped for a reason an operator should see (a corrupt tail).
//
// The link file IS the claim: there is no separate marker, and the file that
// wins the name is the signed statement verification reads.
func publishPredecessorLink(req linkRequest) (*ChainLink, error) {
	dir, base, self := req.dir, req.base, req.self
	ix, err := indexRecorderFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("listing prior chains: %w", err)
	}
	type candidate struct {
		session string
		files   []string
		latest  string
		modTime time.Time
	}
	candidates := make([]candidate, 0, len(ix))
	for _, s := range ix.sessions() {
		if s == self || !isBaseChain(s, base) {
			continue
		}
		files, filesErr := ix.files(s)
		if filesErr != nil || len(files) == 0 {
			continue
		}
		latest := files[len(files)-1]
		info, statErr := os.Stat(latest)
		if statErr != nil {
			continue
		}
		candidates = append(candidates, candidate{session: s, files: files, latest: latest, modTime: info.ModTime()})
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
		name := ChainLinkFileName(c.session)
		if _, statErr := os.Lstat(filepath.Join(dir, name)); statErr == nil {
			continue // already continued by another run
		}
		gone, probeErr := recorder.EvidenceRunWriterGone(dir, c.session)
		if !strings.Contains(c.session, ".run.") {
			gone, probeErr = recorder.EvidenceWriterGone(c.latest)
		}
		if probeErr != nil || !gone {
			continue // a live writer, or its absence cannot be proven
		}
		pred, ok := claimableTail(c.files, c.session, req.notice)
		if !ok {
			continue
		}
		link, signErr := SignChainLink(ChainLink{
			PredecessorSession:   pred.session,
			PredecessorTailSeq:   pred.tail.ActionRecord.ChainSeq,
			PredecessorTailHash:  pred.tailHash,
			PredecessorSignerKey: pred.tail.SignerKey,
			SuccessorSession:     self,
			LinkedAt:             req.now.UTC().Format(time.RFC3339Nano),
		}, req.privKey)
		if signErr != nil {
			return nil, fmt.Errorf("signing chain link: %w", signErr)
		}
		body, marshalErr := json.Marshal(link)
		if marshalErr != nil {
			return nil, fmt.Errorf("encoding chain link: %w", marshalErr)
		}
		pubErr := publishChainLinkFile(dir, name, append(body, '\n'))
		if errors.Is(pubErr, errLinkNameTaken) {
			continue // another process continued this chain first
		}
		if pubErr != nil {
			return nil, pubErr
		}
		return &link, nil
	}
	return nil, nil
}

// claimableTail reads session's tail and reports whether it can be linked.
func claimableTail(files []string, session string, notice io.Writer) (predecessorTail, bool) {
	tail, tailErr := sessionReceiptTail(files)
	if tailErr != nil {
		_, _ = fmt.Fprintf(notice, "pipelock: receipt chain %s not linked: reading its tail: %v\n", session, tailErr)
		return predecessorTail{}, false
	}
	if tail == nil {
		return predecessorTail{}, false // nothing to continue
	}
	// A corrupt predecessor tail is NOT linked and does NOT stop this run.
	// Before run sessions, a corrupt tail on the shared session bricked
	// receipt emission until an operator intervened, because the new receipts
	// would have extended the damaged chain. A run session owns a fresh chain,
	// so bricking all future evidence over one damaged old file is an
	// availability failure with no integrity benefit. The damaged chain stays
	// on disk untouched and `pipelock evidence doctor` reports it.
	if verifyErr := VerifyInternalConsistencyOnly(*tail); verifyErr != nil {
		_, _ = fmt.Fprintf(notice, "pipelock: WARNING receipt chain %s has a corrupt tail (seq %d): %v; starting this run unlinked, the damaged chain is left on disk for inspection\n",
			session, tail.ActionRecord.ChainSeq, verifyErr)
		return predecessorTail{}, false
	}
	hash, hashErr := ReceiptHash(*tail)
	if hashErr != nil {
		return predecessorTail{}, false
	}
	return predecessorTail{session: session, tail: *tail, tailHash: hash}, true
}
