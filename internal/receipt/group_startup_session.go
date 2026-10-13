// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

// startupSessionVerification owns one shard's walkers. The primary consumer
// and the inventory run synchronously on each delivered entry; authenticate
// shares that entry's outer-chain and v1 proof, not an unbounded receipt cache.
// Results are never reused by a later verification ceremony.
type startupSessionVerification struct {
	firstReceipt                              *Receipt
	durableOuterSeq                           uint64
	durableOuterHash, durableSigner           string
	dir, session, currentGroup, previousGroup string
	trusted                                   []string
	options                                   verification.Options
	whole                                     *WholeRecorderWalker
	v1                                        *ChainWalker
	v2                                        *EvidenceChainWalker
	seen                                      bool
	currentAuthenticated                      bool
	receipt                                   Receipt
	isReceipt                                 bool
	authErr                                   error
	inventoryErr                              error
	inventoryWholeErr                         error
	inventoryResult                           *ChainResult
	claim                                     startupAELClaim
	aelHead                                   ael.VerifiedHead
	aelErr                                    error
	aelChecked                                bool
	aelClose                                  bool
	aelRun, aelSigner                         string
	observation                               *recorder.HistoryObservation
	prefix                                    bool
	writerGone                                bool
	durableSeq                                uint64
	durableHash                               string
}

type startupAELClaim struct {
	run, session, groupID, signer string
	completed                     bool
}

func newStartupSessionVerification(dir string, open ReceiptGroupOpen, session string, trusted []string, options verification.Options) *startupSessionVerification {
	return &startupSessionVerification{
		dir: dir, session: session, currentGroup: open.GroupID, previousGroup: open.PreviousGroupID,
		trusted: trusted, options: options,
		whole: NewGroupRecorderWalker(), v1: NewChainWalker([]string{open.SignerKey}),
		v2: NewEvidenceChainWalker([]string{open.SignerKey}, contractreceipt.ChainVerifyOptions{}),
	}
}

func (s *startupSessionVerification) authenticate(e recorder.Entry) (Receipt, bool) {
	if s.currentAuthenticated {
		return s.receipt, s.isReceipt
	}
	s.currentAuthenticated = true
	s.seen = true
	s.receipt, s.isReceipt = s.whole.Add(e)
	if s.whole.Err() != nil {
		return s.receipt, s.isReceipt
	}
	if s.isReceipt {
		s.v1.Add(s.receipt)
		if s.firstReceipt == nil {
			r := s.receipt
			s.firstReceipt = &r
		}
	}
	if err := s.options.Report(verification.Progress{Kind: "recorder_record", Session: s.session, Records: 1}); err != nil {
		s.authErr = err
	}
	return s.receipt, s.isReceipt
}

func (s *startupSessionVerification) walkWithInventory(primary func(recorder.Entry) error) error {
	var primaryErr error
	s.inventoryErr = indexAELClaimsForSessionWithWalk(s.dir, s.session, s.currentGroup, s.previousGroup, s.trusted,
		func(run, session, groupID, signer string, completed bool) error {
			s.claim = startupAELClaim{run: run, session: session, groupID: groupID, signer: signer, completed: completed}
			return nil
		}, nil, s, func(inventory func(recorder.Entry) error) error {
			var inventoryErr error
			visit := func(e recorder.Entry) error {
				s.currentAuthenticated = false
				if primaryErr == nil {
					primaryErr = primary(e)
				}
				if primaryErr != nil {
					s.authenticate(e)
				}
				if s.authErr != nil {
					return s.authErr
				}
				s.durableOuterSeq, s.durableOuterHash = e.Sequence, e.Hash
				if s.isReceipt {
					s.durableSigner = s.receipt.SignerKey
				}
				if s.prefix {
					s.durableSeq = s.v1.lastSeq
					s.durableHash = s.v1.strict.prevHash
				}
				if inventoryErr == nil {
					inventoryErr = inventory(e)
				}
				return nil
			}
			var err error
			if s.prefix {
				s.observation, err = recorder.WalkSessionHistoryObserved(s.dir, s.session, s.options, func(e recorder.Entry, complete bool) error {
					if complete {
						return visit(e)
					}
					// Freeze the inventory proof at the last complete record. The
					// recovery-only fragment must not alter its verdict or claims.
					result := s.v1.Result()
					s.inventoryResult, s.inventoryWholeErr = &result, s.whole.Err()
					// Only the recovery verifier consumes a valid unterminated fragment.
					// It cannot become an inventory claim or a durable transition head.
					s.currentAuthenticated = false
					if primaryErr == nil {
						primaryErr = primary(e)
					}
					return s.authErr
				})
			} else {
				err = recorder.WalkSessionHistoryWithOptions(s.dir, s.session, s.options, visit)
			}
			if err != nil {
				if primaryErr == nil {
					primaryErr = err
				}
				return err
			}
			return inventoryErr
		})
	return primaryErr
}

func (s *startupSessionVerification) verifyAEL(run, signer string, closed bool) (ael.VerifiedHead, error) {
	if s.aelChecked {
		if run != s.aelRun || signer != s.aelSigner || closed != s.aelClose {
			return ael.VerifiedHead{}, errors.New("startup native AEL proof binding differs")
		}
		return s.aelHead, s.aelErr
	}
	s.aelChecked, s.aelRun, s.aelSigner, s.aelClose = true, run, signer, closed
	s.aelHead, s.aelErr = ael.VerifyRunWithOptions(s.dir, run, signer, closed, s.options)
	return s.aelHead, s.aelErr
}
