// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// The walkers in this file verify a recorder as it is read, one entry or
// receipt at a time, and return exactly what the slice verifiers return for
// the same input: VerifyWholeRecorderEntries, VerifyChainTrusted,
// VerifyChainWithEndorsements and VerifyEvidenceChainTrusted. They hold the
// verification state those functions build while walking (the previous hash,
// the open signing segment, the closed segments, the run lifecycle table)
// and never the entries or receipts themselves, so verifying a long-running
// recorder takes memory in the number of signing segments and process runs,
// not in the number of receipts. Result may be called at any point and
// reports the receipts added so far, which is how a caller verifies a
// transcript_root's prefix without a second pass.

// ChainAccumulator is a receipt chain verifier fed one receipt at a time.
type ChainAccumulator interface {
	Add(r Receipt)
	Result() ChainResult
}

// ChainWalker is VerifyChainTrusted applied one receipt at a time.
type ChainWalker struct {
	normErr error
	strict  *chainVerifier
	// strictFail is the strict walk's first failure. When it is the
	// lifecycle-open kind, VerifyChainTrusted reruns the chain in
	// integrity-only mode; integ is that walk, started from the strict
	// walk's state at the failing receipt.
	strictFail *ChainResult
	integ      *chainVerifier
	integFail  *ChainResult

	count     uint64
	firstSeq  uint64
	firstTime time.Time
	lastSeq   uint64
	lastTime  time.Time

	// chainKeys marks the endorsement base walk, which trusts every signer
	// key the chain names. emptyKey records that a receipt's key normalizes
	// to empty, which fails that whole set.
	chainKeys bool
	emptyKey  bool
}

var _ ChainAccumulator = (*ChainWalker)(nil)

// NewChainWalker starts an empty chain under trustedKeys, with the same
// trust model as VerifyChainTrusted: an empty set is trust-on-first-use.
func NewChainWalker(trustedKeys []string) *ChainWalker {
	w := &ChainWalker{}
	normalized, err := normalizeTrustedKeys(trustedKeys)
	if err != nil {
		w.normErr = err
		return w
	}
	trusted := make(map[string]struct{}, len(normalized))
	for _, k := range normalized {
		trusted[k] = struct{}{}
	}
	w.strict = &chainVerifier{trusted: trusted, runNonces: make(map[string]string), closedRuns: make(map[string]bool)}
	return w
}

// newChainKeysWalker is VerifyChainTrusted(receipts, <every signer key in
// receipts>), the base check of VerifyChainWithEndorsements.
func newChainKeysWalker() *ChainWalker {
	w := &ChainWalker{chainKeys: true}
	w.strict = &chainVerifier{trusted: make(map[string]struct{}), runNonces: make(map[string]string), closedRuns: make(map[string]bool), trustChainKeys: true}
	return w
}

// Add verifies the next receipt. A failure is kept for Result; later
// receipts still count toward the lifecycle fallback walk.
func (w *ChainWalker) Add(r Receipt) {
	index := w.count
	if index == 0 {
		w.firstSeq = r.ActionRecord.ChainSeq
		w.firstTime = r.ActionRecord.Timestamp
	}
	w.count++
	w.lastSeq = r.ActionRecord.ChainSeq
	w.lastTime = r.ActionRecord.Timestamp
	if w.chainKeys && strings.TrimSpace(r.SignerKey) == "" {
		w.emptyKey = true
	}
	if w.normErr != nil || w.emptyKey {
		// The trusted set itself is invalid; nothing more can change the
		// result, so skip the signature work.
		return
	}
	if w.strictFail == nil {
		res, ok := w.strict.add(r, index)
		if ok {
			return
		}
		w.strictFail = &res
		if res.FailureKind != ChainFailureLifecycleOpen {
			return
		}
		// The lifecycle-open failure comes from the session-control check,
		// the last step before the hash advances. Every integrity step for
		// this receipt has already passed and mutated the state exactly as an
		// integrity-only walk would, so that walk continues from a copy of
		// this state with the hash advance.
		w.integ = w.strict.integrityCopy()
		if res, ok := w.integ.advanceReceiptHash(r); !ok {
			w.integFail = &res
		}
		return
	}
	if w.integ != nil && w.integFail == nil {
		if res, ok := w.integ.add(r, index); !ok {
			w.integFail = &res
		}
	}
}

// Result returns VerifyChainTrusted's result for the receipts added so far.
func (w *ChainWalker) Result() ChainResult {
	if w.count == 0 {
		return ChainResult{Valid: true, IntegrityVerified: true}
	}
	normErr := w.normErr
	if w.emptyKey {
		normErr = errors.New("trusted signer key cannot be empty")
	}
	if normErr != nil {
		return ChainResult{
			Valid:         false,
			BrokenAtSeq:   w.firstSeq,
			BrokenAtIndex: 0,
			Error:         fmt.Sprintf("seq %d: trusted key set: %v", w.firstSeq, normErr),
			FailureKind:   ChainFailureTrust,
		}
	}
	if w.strictFail == nil {
		return w.validResult(w.strict)
	}
	if w.strictFail.FailureKind != ChainFailureLifecycleOpen {
		return *w.strictFail
	}
	if w.integFail != nil {
		return *w.integFail
	}
	res := *w.strictFail
	integrity := w.validResult(w.integ)
	res.IntegrityVerified = true
	res.ReceiptCount = integrity.ReceiptCount
	res.FinalSeq = integrity.FinalSeq
	res.RootHash = integrity.RootHash
	res.StartTime = integrity.StartTime
	res.EndTime = integrity.EndTime
	res.SignerKeys = integrity.SignerKeys
	res.Segments = integrity.Segments
	return res
}

// validResult is chainVerifier.run's success result, built without closing
// the open segment so the walk can continue.
func (w *ChainWalker) validResult(v *chainVerifier) ChainResult {
	segments := slices.Clone(v.segments)
	if v.curSeg != nil {
		segments = append(segments, *v.curSeg)
	}
	return ChainResult{
		Valid:             true,
		IntegrityVerified: true,
		ReceiptCount:      w.count,
		FinalSeq:          w.lastSeq,
		RootHash:          v.prevHash,
		StartTime:         w.firstTime,
		EndTime:           w.lastTime,
		SignerKeys:        slices.Clone(v.signerKeys),
		Segments:          segments,
	}
}

// integrityCopy returns an independent integrity-only verifier in v's
// current walking state. Lifecycle tables are not copied: integrity-only
// walks never read them.
func (v *chainVerifier) integrityCopy() *chainVerifier {
	c := *v
	c.integrityOnly = true
	c.trusted = make(map[string]struct{}, len(v.trusted))
	for k := range v.trusted {
		c.trusted[k] = struct{}{}
	}
	c.signerKeys = slices.Clone(v.signerKeys)
	c.segments = slices.Clone(v.segments)
	if v.curSeg != nil {
		seg := *v.curSeg
		c.curSeg = &seg
	}
	if v.signerKeySet != nil {
		c.signerKeySet = make(map[string]struct{}, len(v.signerKeySet))
		for k := range v.signerKeySet {
			c.signerKeySet[k] = struct{}{}
		}
	}
	c.runNonces = make(map[string]string)
	c.closedRuns = make(map[string]bool)
	c.runStore = nil
	return &c
}

// endorsementBoundary is one rotation boundary of an endorsed chain: the
// prior segment's tail and the key that follows it.
type endorsementBoundary struct {
	priorKey  string
	priorSeq  uint64
	priorHash string
	newKey    string
}

// EndorsedChainWalker is VerifyChainWithEndorsements applied one receipt at
// a time. Beyond the base walk it keeps each rotation boundary and the
// positions of the first boundary and session_open receipts.
type EndorsedChainWalker struct {
	sessionID    string
	endorsements []RotationEndorsement
	rootKeys     []string
	base         *ChainWalker

	count    uint64
	firstKey string
	prevKey  string
	prevSeq  uint64

	boundaries []endorsementBoundary
	// firstBoundary is the first index >= 1 carrying a KeyTransition and
	// firstOpen the first session_open index, each valid when its flag is set.
	hasBoundary   bool
	firstBoundary uint64
	hasOpen       bool
	firstOpen     uint64
	// mismatchedSession is the first session_open naming another session.
	mismatch          bool
	mismatchedSession string
}

var _ ChainAccumulator = (*EndorsedChainWalker)(nil)

// NewEndorsedChainWalker starts an empty endorsed chain with the arguments
// VerifyChainWithEndorsements takes.
func NewEndorsedChainWalker(sessionID string, endorsements []RotationEndorsement, rootTrustedKeys []string) *EndorsedChainWalker {
	return &EndorsedChainWalker{
		sessionID:    sessionID,
		endorsements: endorsements,
		rootKeys:     rootTrustedKeys,
		base:         newChainKeysWalker(),
	}
}

// Add verifies the next receipt.
func (w *EndorsedChainWalker) Add(r Receipt) {
	index := w.count
	if index == 0 {
		w.firstKey = r.SignerKey
	} else {
		if !w.hasBoundary && r.ActionRecord.KeyTransition != nil {
			w.hasBoundary, w.firstBoundary = true, index
		}
		// Within a valid chain the signer key changes exactly where a
		// rotated segment starts. The base walk's hash is the prior tail's
		// receipt hash while that walk is intact; when it is not, the base
		// result fails and no boundary is consulted.
		if r.SignerKey != w.prevKey && w.base.strict != nil {
			w.boundaries = append(w.boundaries, endorsementBoundary{
				priorKey: w.prevKey, priorSeq: w.prevSeq, priorHash: w.base.strict.prevHash, newKey: r.SignerKey,
			})
		}
	}
	if open := sessionOpen(r.ActionRecord.SessionControl); open != nil {
		if !w.hasOpen {
			w.hasOpen, w.firstOpen = true, index
		}
		if !w.mismatch && open.RecorderSession != w.sessionID {
			w.mismatch, w.mismatchedSession = true, open.RecorderSession
		}
	}
	w.base.Add(r)
	w.prevKey = r.SignerKey
	w.prevSeq = r.ActionRecord.ChainSeq
	w.count++
}

// Result returns VerifyChainWithEndorsements' result for the receipts added
// so far.
func (w *EndorsedChainWalker) Result() ChainResult {
	if strings.TrimSpace(w.sessionID) == "" {
		return ChainResult{Error: "rotation endorsement verification requires a recorder session ID", FailureKind: ChainFailureTrust}
	}
	if w.count == 0 {
		if len(w.endorsements) != 0 {
			return ChainResult{Error: "rotation endorsements supplied for an empty receipt chain", FailureKind: ChainFailureTrust}
		}
		return ChainResult{Valid: true, IntegrityVerified: true}
	}
	base := w.base.Result()
	if !base.Valid {
		return base
	}
	roots, err := normalizeTrustedKeys(w.rootKeys)
	if err != nil {
		base.Valid = false
		base.FailureKind = ChainFailureTrust
		base.Error = fmt.Sprintf("trusted key set: %v", err)
		return base
	}
	rootSet := make(map[string]struct{}, len(roots))
	for _, key := range roots {
		rootSet[key] = struct{}{}
	}
	if len(rootSet) == 0 {
		return endorsementFailure(base, w.firstKey, errors.New("rotation endorsement verification requires at least one trusted root key"))
	}
	if _, trusted := rootSet[w.firstKey]; !trusted {
		return endorsementFailure(base, w.firstKey, errors.New("genesis signer key is not in the trusted root set"))
	}
	if err := w.signedRecorderSessionErr(); err != nil {
		return endorsementFailure(base, "", err)
	}

	for _, endorsement := range w.endorsements {
		if err := VerifyRotationEndorsement(endorsement); err != nil {
			return endorsementFailure(base, endorsement.NewSignerKey, err)
		}
	}

	base.TrustBasis = make([]string, 0, len(base.Segments))
	base.TrustBasis = append(base.TrustBasis, "root")
	used := make(map[int]struct{}, len(w.endorsements))
	for segmentIndex := 1; segmentIndex < len(base.Segments); segmentIndex++ {
		segment := base.Segments[segmentIndex]
		if segmentIndex-1 >= len(w.boundaries) {
			return endorsementFailure(base, segment.SignerKey, errors.New("cannot locate rotation boundary"))
		}
		boundary := w.boundaries[segmentIndex-1]
		match := -1
		for endorsementIndex, endorsement := range w.endorsements {
			if _, alreadyUsed := used[endorsementIndex]; alreadyUsed {
				continue
			}
			if endorsement.SessionID != w.sessionID ||
				endorsement.PriorSignerKey != boundary.priorKey ||
				endorsement.PriorFinalSeq != boundary.priorSeq ||
				endorsement.PriorTailHash != boundary.priorHash ||
				endorsement.NewSignerKey != boundary.newKey {
				continue
			}
			if match >= 0 {
				return endorsementFailure(base, segment.SignerKey, errors.New("multiple rotation endorsements match one receipt boundary"))
			}
			match = endorsementIndex
		}
		if match < 0 {
			return endorsementFailure(base, segment.SignerKey, errors.New("rotation endorsement does not match receipt boundary"))
		}
		used[match] = struct{}{}
		base.TrustBasis = append(base.TrustBasis, "endorsed")
	}
	if len(used) != len(w.endorsements) {
		return endorsementFailure(base, "", errors.New("unused rotation endorsement does not match a required boundary"))
	}
	return base
}

// signedRecorderSessionErr is verifySignedRecorderSession over the receipts
// added so far.
func (w *EndorsedChainWalker) signedRecorderSessionErr() error {
	if w.mismatch {
		return fmt.Errorf("signed recorder session %q does not match endorsement session %q", w.mismatchedSession, w.sessionID)
	}
	firstBoundary := w.count
	if w.hasBoundary {
		firstBoundary = w.firstBoundary
	}
	if w.hasOpen && w.firstOpen < firstBoundary {
		return nil
	}
	return errors.New("root receipt segment has no signed session_open recorder binding")
}

// EvidenceChainWalker is VerifyEvidenceChainTrusted applied one receipt at a
// time. The pinned key depends only on the first receipt, so it is chosen
// when that receipt arrives.
type EvidenceChainWalker struct {
	trusted []string
	opts    contractreceipt.ChainVerifyOptions
	count   int
	pinErr  error
	walk    *contractreceipt.ChainWalker
}

// NewEvidenceChainWalker starts an empty EvidenceReceipt v2 chain under the
// arguments VerifyEvidenceChainTrusted takes.
func NewEvidenceChainWalker(trusted []string, opts contractreceipt.ChainVerifyOptions) *EvidenceChainWalker {
	return &EvidenceChainWalker{trusted: trusted, opts: opts}
}

// Add verifies the next evidence receipt.
func (w *EvidenceChainWalker) Add(r contractreceipt.EvidenceReceipt) {
	w.count++
	if w.count == 1 {
		var pin ed25519.PublicKey
		if len(w.trusted) == 0 {
			pin, w.pinErr = decodeEd25519Hex(strings.ToLower(strings.TrimSpace(r.Signature.SignerKeyID)))
		} else {
			pin, w.pinErr = EvidenceChainPin([]contractreceipt.EvidenceReceipt{r}, w.trusted)
		}
		if w.pinErr != nil {
			return
		}
		opts := w.opts
		opts.PinnedKey = pin
		w.walk = contractreceipt.NewChainWalker(opts)
	}
	if w.pinErr != nil {
		return
	}
	w.walk.Add(r)
}

// Count reports how many evidence receipts were added.
func (w *EvidenceChainWalker) Count() int { return w.count }

// Result returns VerifyEvidenceChainTrusted's result for the receipts added
// so far.
func (w *EvidenceChainWalker) Result() contractreceipt.ChainResult {
	if w.pinErr != nil {
		return contractreceipt.ChainResult{Valid: false, Error: w.pinErr.Error()}
	}
	var res contractreceipt.ChainResult
	if w.walk == nil {
		res = contractreceipt.VerifyChain(nil, w.opts)
	} else {
		res = w.walk.Result()
	}
	if len(w.trusted) == 0 {
		res.SignaturesVerified = false
	}
	return res
}

// WholeRecorderWalker is VerifyWholeRecorderEntries applied one entry at a
// time. It applies the same three checks in the same precedence: taxonomy
// and single session over every entry, then the recorder hash chain, then
// receipt extraction. Each check keeps its own first failure, so Err reports
// what the slice function would for the entries added so far.
type WholeRecorderWalker struct {
	count      int
	sessionID  string
	entryErr   error
	chain      recorder.ChainWalker
	extractErr error
	groupGate  bool
}

// NewGroupRecorderWalker requires the group gate as the first entry while
// retaining the whole-recorder hash and taxonomy checks. Legacy walkers keep
// rejecting that gate so a single surviving shard cannot verify as legacy.
func NewGroupRecorderWalker() *WholeRecorderWalker {
	return &WholeRecorderWalker{groupGate: true}
}

// Add checks one entry. It returns the entry's action receipt when the entry
// is one and no receipt before it failed to decode; once extraction fails
// the slice function would return no receipts, so none are returned.
func (w *WholeRecorderWalker) Add(e recorder.Entry) (Receipt, bool) {
	i := w.count
	w.count++
	if w.entryErr == nil {
		if w.groupGate && i == 0 && e.Type != recorder.GroupGateEntryType {
			w.entryErr = fmt.Errorf("receipt group gate must be first recorder entry")
		} else if e.Type == recorder.GroupGateEntryType && (!w.groupGate || i != 0) {
			w.entryErr = fmt.Errorf("%w: %q at seq %d", ErrUnexpectedRecorderEntryType, e.Type, e.Sequence)
		} else if !knownRecorderEntryType(e.Type) && (!w.groupGate || i != 0 || e.Type != recorder.GroupGateEntryType) {
			w.entryErr = fmt.Errorf("%w: %q at seq %d", ErrUnexpectedRecorderEntryType, e.Type, e.Sequence)
		} else if i == 0 {
			w.sessionID = e.SessionID
		} else if e.SessionID != w.sessionID {
			w.entryErr = fmt.Errorf("%w: entry at seq %d belongs to session %q, not %q", ErrUnexpectedRecorderEntryType, e.Sequence, e.SessionID, w.sessionID)
		}
	}
	_ = w.chain.Add(e)
	if w.extractErr != nil {
		return Receipt{}, false
	}
	if w.groupGate && i == 0 && e.Type == recorder.GroupGateEntryType {
		return Receipt{}, false
	}
	r, ok, err := actionReceiptFromEntry(e)
	if err != nil {
		w.extractErr = err
		return Receipt{}, false
	}
	return r, ok
}

// Err returns the error VerifyWholeRecorderEntries returns for the entries
// added so far, or nil. A non-nil Err never becomes nil again.
func (w *WholeRecorderWalker) Err() error {
	if w.entryErr != nil {
		return w.entryErr
	}
	if err := w.chain.Err(); err != nil {
		return fmt.Errorf("recorder hash chain: %w", err)
	}
	return w.extractErr
}

// EntryCount reports how many entries were added.
func (w *WholeRecorderWalker) EntryCount() int { return w.count }

// actionReceiptFromEntry is one step of extractReceiptsFromEntries.
func actionReceiptFromEntry(e recorder.Entry) (Receipt, bool, error) {
	if e.Type == recorderEntryType {
		r, err := receiptFromEntry(e)
		if err != nil {
			return Receipt{}, false, fmt.Errorf("receipt at seq %d: %w", e.Sequence, err)
		}
		return *r, true, nil
	}
	if !knownRecorderEntryType(e.Type) {
		return Receipt{}, false, fmt.Errorf("%w: %q at seq %d", ErrUnexpectedRecorderEntryType, e.Type, e.Sequence)
	}
	return Receipt{}, false, nil
}
