// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	sessionOpenTestPolicy = "policy-hash"
	sessionOpenTestRunA   = "run-a"
	sessionOpenTestRunB   = "run-b"
)

func testSessionOpen(runNonce, openNonce string, seq uint64) SessionOpen {
	return SessionOpen{
		RunNonce:         runNonce,
		OpenNonce:        openNonce,
		RecorderSession:  recorderSessionID,
		PolicyHash:       sessionOpenTestPolicy,
		SignerKeyEpoch:   "signer-epoch",
		HeartbeatSeconds: 0,
		ChainOpenSeq:     seq,
	}
}

func signSessionReceipt(
	t *testing.T,
	priv ed25519.PrivateKey,
	seq uint64,
	prevHash string,
	ts time.Time,
	runNonce string,
	ctrl *SessionControl,
	marker *KeyTransition,
) Receipt {
	t.Helper()
	ar := ActionRecord{
		Version:        ActionRecordVersion,
		ActionID:       NewActionID(),
		ActionType:     ActionUnclassified,
		Timestamp:      ts,
		Target:         sessionOpenTarget,
		PolicyHash:     sessionOpenTestPolicy,
		Verdict:        config.ActionAllow,
		Transport:      sessionControlTransport,
		ChainPrevHash:  prevHash,
		ChainSeq:       seq,
		RunNonce:       runNonce,
		KeyTransition:  marker,
		SessionControl: ctrl,
	}
	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return r
}

func signBoundOpen(t *testing.T, priv ed25519.PrivateKey, ts time.Time) Receipt {
	t.Helper()
	open := testSessionOpen(sessionOpenTestRunA, "open-a", 0)
	genesis := ComputeSessionOpenGenesis(open)
	open.GenesisHash = genesis
	return signSessionReceipt(t, priv, 0, genesis, ts, sessionOpenTestRunA, &SessionControl{
		Kind: SessionControlOpen,
		Open: &open,
	}, nil)
}

func signRestartOpen(
	t *testing.T,
	priv ed25519.PrivateKey,
	seq uint64,
	priorHash string,
	priorSeq uint64,
	runNonce string,
	ts time.Time,
	marker *KeyTransition,
) Receipt {
	t.Helper()
	open := testSessionOpen(runNonce, "open-"+runNonce, seq)
	open.PriorChainHead = priorHash
	open.PriorChainSeq = priorSeq
	return signSessionReceipt(t, priv, seq, priorHash, ts, runNonce, &SessionControl{
		Kind: SessionControlOpen,
		Open: &open,
	}, marker)
}

func signRunReceipt(t *testing.T, priv ed25519.PrivateKey, seq uint64, prevHash, runNonce string, ts time.Time) Receipt {
	t.Helper()
	ar := ActionRecord{
		Version:       ActionRecordVersion,
		ActionID:      NewActionID(),
		ActionType:    ActionRead,
		Timestamp:     ts,
		Target:        chainTestTarget,
		PolicyHash:    sessionOpenTestPolicy,
		Verdict:       config.ActionAllow,
		Transport:     chainTestTransport,
		ChainPrevHash: prevHash,
		ChainSeq:      seq,
		RunNonce:      runNonce,
	}
	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return r
}

func TestVerifyChain_LegacyGenesisWithoutRunNonceStillAccepted(t *testing.T) {
	t.Parallel()
	pub, priv := generateTestKey(t)

	legacy := signChainReceipt(t, priv, 0, GenesisHash, time.Now().UTC())
	res := VerifyChain([]Receipt{legacy}, hex.EncodeToString(pub))
	if !res.Valid {
		t.Fatalf("legacy genesis should verify: %s", res.Error)
	}
}

func TestVerifyChain_BoundSessionOpenGenesisAccepted(t *testing.T) {
	t.Parallel()
	pub, priv := generateTestKey(t)
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	open := signBoundOpen(t, priv, base)
	next := signRunReceipt(t, priv, 1, mustHash(t, open), sessionOpenTestRunA, base.Add(time.Second))

	res := VerifyChain([]Receipt{open, next}, hex.EncodeToString(pub))
	if !res.Valid {
		t.Fatalf("bound session_open chain should verify: %s", res.Error)
	}
}

func TestVerifyChain_RestartSessionOpenAccepted(t *testing.T) {
	t.Parallel()
	pub, priv := generateTestKey(t)
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	firstOpen := signBoundOpen(t, priv, base)
	firstTail := signRunReceipt(t, priv, 1, mustHash(t, firstOpen), sessionOpenTestRunA, base.Add(time.Second))
	priorHash := mustHash(t, firstTail)
	restartOpen := signRestartOpen(t, priv, 2, priorHash, firstTail.ActionRecord.ChainSeq, sessionOpenTestRunB, base.Add(2*time.Second), nil)
	afterRestart := signRunReceipt(t, priv, 3, mustHash(t, restartOpen), sessionOpenTestRunB, base.Add(3*time.Second))

	res := VerifyChain([]Receipt{firstOpen, firstTail, restartOpen, afterRestart}, hex.EncodeToString(pub))
	if !res.Valid {
		t.Fatalf("restart session_open chain should verify: %s", res.Error)
	}
}

func TestVerifyChain_KeyRotationSessionOpenAccepted(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	pubB, privB := generateTestKey(t)
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	firstOpen := signBoundOpen(t, privA, base)
	firstTail := signRunReceipt(t, privA, 1, mustHash(t, firstOpen), sessionOpenTestRunA, base.Add(time.Second))
	priorHash := mustHash(t, firstTail)
	marker := &KeyTransition{
		PriorSignerKey: hex.EncodeToString(pubA),
		PriorChainSeq:  firstTail.ActionRecord.ChainSeq,
		PriorChainHash: priorHash,
	}
	rotatedOpen := signRestartOpen(t, privB, 0, priorHash, firstTail.ActionRecord.ChainSeq, sessionOpenTestRunB, base.Add(time.Hour), marker)

	res := VerifyChainTrusted([]Receipt{firstOpen, firstTail, rotatedOpen}, []string{
		hex.EncodeToString(pubA),
		hex.EncodeToString(pubB),
	})
	if !res.Valid {
		t.Fatalf("key-rotation session_open chain should verify: %s", res.Error)
	}
}

func TestVerifyChain_SessionOpenAdversarialRejections(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		build   func(t *testing.T, priv ed25519.PrivateKey) []Receipt
		wantErr string
	}{
		"forged_g1_without_open": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				return []Receipt{signSessionReceipt(t, priv, 0, genesisSessionOpenPrefix+strings.Repeat("0", 64), time.Now().UTC(), "", nil, nil)}
			},
			wantErr: "requires SessionControl.Open",
		},
		"bound_open_chain_prev_hash_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				open := testSessionOpen(sessionOpenTestRunA, "open-a", 0)
				computed := ComputeSessionOpenGenesis(open)
				open.GenesisHash = computed
				return []Receipt{
					signSessionReceipt(t, priv, 0, genesisSessionOpenPrefix+strings.Repeat("1", 64), time.Now().UTC(), sessionOpenTestRunA, &SessionControl{
						Kind: SessionControlOpen,
						Open: &open,
					}, nil),
				}
			},
			wantErr: "genesis hash mismatch",
		},
		"bound_open_payload_genesis_hash_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				open := testSessionOpen(sessionOpenTestRunA, "open-a", 0)
				computed := ComputeSessionOpenGenesis(open)
				open.GenesisHash = genesisSessionOpenPrefix + strings.Repeat("2", 64)
				return []Receipt{
					signSessionReceipt(t, priv, 0, computed, time.Now().UTC(), sessionOpenTestRunA, &SessionControl{
						Kind: SessionControlOpen,
						Open: &open,
					}, nil),
				}
			},
			wantErr: "genesis_hash mismatch",
		},
		"run_nonce_without_matching_open": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				return []Receipt{signRunReceipt(t, priv, 0, GenesisHash, sessionOpenTestRunA, time.Now().UTC())}
			},
			wantErr: "first receipt is not a matching session_open",
		},
		"open_out_of_position_without_prior_link": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				legacy := signChainReceipt(t, priv, 0, GenesisHash, base)
				open := testSessionOpen(sessionOpenTestRunA, "open-a", 1)
				return []Receipt{
					legacy,
					signSessionReceipt(t, priv, 1, mustHash(t, legacy), base.Add(time.Second), sessionOpenTestRunA, &SessionControl{
						Kind: SessionControlOpen,
						Open: &open,
					}, nil),
				}
			},
			wantErr: "prior_chain_head",
		},
		"restart_open_prior_tail_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				open := signBoundOpen(t, priv, base)
				tail := signRunReceipt(t, priv, 1, mustHash(t, open), sessionOpenTestRunA, base.Add(time.Second))
				bad := testSessionOpen(sessionOpenTestRunB, "open-b", 2)
				bad.PriorChainHead = "wrong-prior-head"
				bad.PriorChainSeq = tail.ActionRecord.ChainSeq
				return []Receipt{
					open,
					tail,
					signSessionReceipt(t, priv, 2, mustHash(t, tail), base.Add(2*time.Second), sessionOpenTestRunB, &SessionControl{
						Kind: SessionControlOpen,
						Open: &bad,
					}, nil),
				}
			},
			wantErr: "prior_chain_head",
		},
		"second_open_same_run_nonce": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				open := signBoundOpen(t, priv, base)
				tail := signRunReceipt(t, priv, 1, mustHash(t, open), sessionOpenTestRunA, base.Add(time.Second))
				priorHash := mustHash(t, tail)
				second := signRestartOpen(t, priv, 2, priorHash, tail.ActionRecord.ChainSeq, sessionOpenTestRunA, base.Add(2*time.Second), nil)
				return []Receipt{open, tail, second}
			},
			wantErr: "duplicate session_open",
		},
		"heartbeat_kind_with_close_payload": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				open := signBoundOpen(t, priv, base)
				return []Receipt{
					open,
					signSessionReceipt(t, priv, 1, mustHash(t, open), base.Add(time.Second), sessionOpenTestRunA, &SessionControl{
						Kind: SessionControlHeartbeat,
						Close: &SessionClose{
							RunNonce:     sessionOpenTestRunA,
							OpenNonce:    "open-a",
							FinalSeq:     0,
							RootHash:     mustHash(t, open),
							ReceiptCount: 1,
							CloseReason:  "forged",
						},
					}, nil),
				}
			},
			wantErr: "heartbeat kind missing heartbeat payload",
		},
		"close_kind_with_heartbeat_payload": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				open := signBoundOpen(t, priv, base)
				return []Receipt{
					open,
					signSessionReceipt(t, priv, 1, mustHash(t, open), base.Add(time.Second), sessionOpenTestRunA, &SessionControl{
						Kind: SessionControlClose,
						Heartbeat: &SessionHeartbeat{
							RunNonce:     sessionOpenTestRunA,
							OpenNonce:    "open-a",
							Beat:         1,
							ChainHead:    mustHash(t, open),
							ChainSeqHead: 1,
						},
					}, nil),
				}
			},
			wantErr: "session_close kind missing close payload",
		},
		"heartbeat_open_nonce_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				open := signBoundOpen(t, priv, base)
				return []Receipt{
					open,
					signSessionReceipt(t, priv, 1, mustHash(t, open), base.Add(time.Second), sessionOpenTestRunA, &SessionControl{
						Kind: SessionControlHeartbeat,
						Heartbeat: &SessionHeartbeat{
							RunNonce:     sessionOpenTestRunA,
							OpenNonce:    "wrong-open",
							Beat:         1,
							ChainHead:    mustHash(t, open),
							ChainSeqHead: 1,
						},
					}, nil),
				}
			},
			wantErr: "heartbeat open_nonce does not match session_open",
		},
		"heartbeat_missing_record_run_nonce": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				open := signBoundOpen(t, priv, base)
				return []Receipt{
					open,
					signSessionReceipt(t, priv, 1, mustHash(t, open), base.Add(time.Second), "", &SessionControl{
						Kind: SessionControlHeartbeat,
						Heartbeat: &SessionHeartbeat{
							RunNonce:     sessionOpenTestRunA,
							OpenNonce:    "open-a",
							Beat:         1,
							ChainHead:    mustHash(t, open),
							ChainSeqHead: 0,
						},
					}, nil),
				}
			},
			wantErr: "session_control receipt missing run_nonce",
		},
		"close_run_nonce_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				open := signBoundOpen(t, priv, base)
				return []Receipt{
					open,
					signSessionReceipt(t, priv, 1, mustHash(t, open), base.Add(time.Second), sessionOpenTestRunA, &SessionControl{
						Kind: SessionControlClose,
						Close: &SessionClose{
							RunNonce:     sessionOpenTestRunB,
							OpenNonce:    "open-a",
							FinalSeq:     0,
							RootHash:     mustHash(t, open),
							ReceiptCount: 1,
							CloseReason:  "forged",
						},
					}, nil),
				}
			},
			wantErr: "session_close run_nonce does not match receipt run_nonce",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pub, priv := generateTestKey(t)
			res := VerifyChain(tc.build(t, priv), hex.EncodeToString(pub))
			if res.Valid {
				t.Fatal("malformed session_open chain verified")
			}
			if !strings.Contains(res.Error, tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", res.Error, tc.wantErr)
			}
		})
	}
}

func TestVerifyChain_SessionControlClaimedValueRejections(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		build   func(t *testing.T, priv ed25519.PrivateKey) []Receipt
		wantErr string
	}{
		"heartbeat_run_nonce_active_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				return buildStaleSessionControlHeartbeatAfterRestart(t, priv)
			},
			wantErr: "heartbeat run_nonce does not match active session_open",
		},
		"heartbeat_run_nonce_receipt_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				chain := buildValidSessionControlChain(t, priv)
				chain[1].ActionRecord.SessionControl.Heartbeat.RunNonce = sessionOpenTestRunB
				chain[1] = resignSessionReceipt(t, priv, chain[1])
				return chain
			},
			wantErr: "heartbeat run_nonce does not match receipt run_nonce",
		},
		"heartbeat_open_nonce_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				chain := buildValidSessionControlChain(t, priv)
				chain[1].ActionRecord.SessionControl.Heartbeat.OpenNonce = "wrong-open"
				chain[1] = resignSessionReceipt(t, priv, chain[1])
				return chain
			},
			wantErr: "heartbeat open_nonce does not match session_open",
		},
		"heartbeat_chain_head_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				chain := buildValidSessionControlChain(t, priv)
				chain[1].ActionRecord.SessionControl.Heartbeat.ChainHead = "wrong-chain-head"
				chain[1] = resignSessionReceipt(t, priv, chain[1])
				return chain
			},
			wantErr: "heartbeat chain_head mismatch",
		},
		"heartbeat_chain_seq_head_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				chain := buildValidSessionControlChain(t, priv)
				chain[1].ActionRecord.SessionControl.Heartbeat.ChainSeqHead = chain[1].ActionRecord.ChainSeq
				chain[1] = resignSessionReceipt(t, priv, chain[1])
				return chain
			},
			wantErr: "heartbeat chain_seq_head mismatch",
		},
		"heartbeat_missing_record_run_nonce": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				chain := buildValidSessionControlChain(t, priv)
				chain[1].ActionRecord.RunNonce = ""
				chain[1] = resignSessionReceipt(t, priv, chain[1])
				return chain
			},
			wantErr: "session_control receipt missing run_nonce",
		},
		"session_close_run_nonce_receipt_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				chain := buildValidSessionControlChain(t, priv)
				chain[2].ActionRecord.SessionControl.Close.RunNonce = sessionOpenTestRunB
				chain[2] = resignSessionReceipt(t, priv, chain[2])
				return chain
			},
			wantErr: "session_close run_nonce does not match receipt run_nonce",
		},
		"session_close_run_nonce_active_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				return buildStaleSessionControlCloseAfterRestart(t, priv)
			},
			wantErr: "session_close run_nonce does not match active session_open",
		},
		"session_close_open_nonce_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				chain := buildValidSessionControlChain(t, priv)
				chain[2].ActionRecord.SessionControl.Close.OpenNonce = "wrong-open"
				chain[2] = resignSessionReceipt(t, priv, chain[2])
				return chain
			},
			wantErr: "session_close open_nonce does not match session_open",
		},
		"session_close_root_hash_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				chain := buildValidSessionControlChain(t, priv)
				chain[2].ActionRecord.SessionControl.Close.RootHash = "wrong-root-hash"
				chain[2] = resignSessionReceipt(t, priv, chain[2])
				return chain
			},
			wantErr: "session_close root_hash mismatch",
		},
		"heartbeat_after_session_close": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				chain := buildValidSessionControlChain(t, priv)
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				afterClose := signHeartbeatReceipt(t, priv, 3, mustHash(t, chain[2]), "open-a", base.Add(3*time.Second))
				return append(chain, afterClose)
			},
			wantErr: "heartbeat has no active session_open",
		},
		"session_close_final_seq_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				chain := buildValidSessionControlChain(t, priv)
				chain[2].ActionRecord.SessionControl.Close.FinalSeq = chain[2].ActionRecord.ChainSeq - 1
				chain[2] = resignSessionReceipt(t, priv, chain[2])
				return chain
			},
			wantErr: "session_close final_seq mismatch",
		},
		"session_close_receipt_count_mismatch": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				chain := buildValidSessionControlChain(t, priv)
				chain[2].ActionRecord.SessionControl.Close.ReceiptCount++
				chain[2] = resignSessionReceipt(t, priv, chain[2])
				return chain
			},
			wantErr: "session_close receipt_count mismatch",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pub, priv := generateTestKey(t)
			res := VerifyChain(tc.build(t, priv), hex.EncodeToString(pub))
			if res.Valid {
				t.Fatal("malformed session_control chain verified")
			}
			if !strings.Contains(res.Error, tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", res.Error, tc.wantErr)
			}
		})
	}
}

func TestValidateSessionControl_ActiveOpenNonceMismatchRejections(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		receipt func(t *testing.T, priv ed25519.PrivateKey, prevHash string) Receipt
		wantErr string
	}{
		"heartbeat": {
			receipt: func(t *testing.T, priv ed25519.PrivateKey, prevHash string) Receipt {
				return signHeartbeatReceipt(t, priv, 1, prevHash, "open-a", time.Now().UTC())
			},
			wantErr: "heartbeat open_nonce does not match active session_open",
		},
		"session_close": {
			receipt: func(t *testing.T, priv ed25519.PrivateKey, prevHash string) Receipt {
				return signCloseReceipt(t, priv, 1, prevHash, sessionOpenTestRunA, "open-a", time.Now().UTC())
			},
			wantErr: "session_close open_nonce does not match active session_open",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, priv := generateTestKey(t)
			prevHash := strings.Repeat("a", 64)
			verifier := &chainVerifier{
				runNonces:  map[string]string{sessionOpenTestRunA: "open-a"},
				activeRun:  sessionOpenTestRunA,
				activeOpen: "open-active",
				prevHash:   prevHash,
			}

			res, ok := verifier.validateSessionControl(tc.receipt(t, priv, prevHash))
			if ok {
				t.Fatal("mismatched active open_nonce was accepted")
			}
			if !strings.Contains(res.Error, tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", res.Error, tc.wantErr)
			}
		})
	}
}

func TestVerifyChain_AllowsSameKeyRestartAfterSessionClose(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	openA := signBoundOpen(t, priv, base)
	closeA := signCloseReceipt(t, priv, 1, mustHash(t, openA), sessionOpenTestRunA, "open-a", base.Add(time.Second))
	openB := signRestartOpen(
		t,
		priv,
		2,
		mustHash(t, closeA),
		closeA.ActionRecord.ChainSeq,
		sessionOpenTestRunB,
		base.Add(2*time.Second),
		nil,
	)
	closeB := signCloseReceipt(
		t,
		priv,
		3,
		mustHash(t, openB),
		sessionOpenTestRunB,
		"open-"+sessionOpenTestRunB,
		base.Add(3*time.Second),
	)

	res := VerifyChain([]Receipt{openA, closeA, openB, closeB}, hex.EncodeToString(pub))
	if !res.Valid {
		t.Fatalf("same-key restart after session_close rejected: %s", res.Error)
	}
}

func buildValidSessionControlChain(t *testing.T, priv ed25519.PrivateKey) []Receipt {
	t.Helper()
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	open := signBoundOpen(t, priv, base)
	heartbeat := signHeartbeatReceipt(t, priv, 1, mustHash(t, open), "open-a", base.Add(time.Second))
	closeReceipt := signCloseReceipt(t, priv, 2, mustHash(t, heartbeat), sessionOpenTestRunA, "open-a", base.Add(2*time.Second))
	return []Receipt{open, heartbeat, closeReceipt}
}

func buildStaleSessionControlHeartbeatAfterRestart(t *testing.T, priv ed25519.PrivateKey) []Receipt {
	t.Helper()
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	open := signBoundOpen(t, priv, base)
	heartbeat := signHeartbeatReceipt(t, priv, 1, mustHash(t, open), "open-a", base.Add(time.Second))
	restart := signRestartOpen(
		t,
		priv,
		2,
		mustHash(t, heartbeat),
		heartbeat.ActionRecord.ChainSeq,
		sessionOpenTestRunB,
		base.Add(2*time.Second),
		nil,
	)
	staleHeartbeat := signHeartbeatReceipt(t, priv, 3, mustHash(t, restart), "open-a", base.Add(3*time.Second))
	return []Receipt{open, heartbeat, restart, staleHeartbeat}
}

func buildStaleSessionControlCloseAfterRestart(t *testing.T, priv ed25519.PrivateKey) []Receipt {
	t.Helper()
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	open := signBoundOpen(t, priv, base)
	heartbeat := signHeartbeatReceipt(t, priv, 1, mustHash(t, open), "open-a", base.Add(time.Second))
	restart := signRestartOpen(
		t,
		priv,
		2,
		mustHash(t, heartbeat),
		heartbeat.ActionRecord.ChainSeq,
		sessionOpenTestRunB,
		base.Add(2*time.Second),
		nil,
	)
	staleClose := signSessionReceipt(t, priv, 3, mustHash(t, restart), base.Add(3*time.Second), sessionOpenTestRunA, &SessionControl{
		Kind: SessionControlClose,
		Close: &SessionClose{
			RunNonce:     sessionOpenTestRunA,
			OpenNonce:    "open-a",
			FinalSeq:     3,
			RootHash:     mustHash(t, restart),
			ReceiptCount: 4,
			CloseReason:  "normal",
		},
	}, nil)
	return []Receipt{open, heartbeat, restart, staleClose}
}

func resignSessionReceipt(t *testing.T, priv ed25519.PrivateKey, r Receipt) Receipt {
	t.Helper()
	signed, err := Sign(r.ActionRecord, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return signed
}

func TestVerifyChain_SessionOpenDeletionAndReorderRejected(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		build   func(t *testing.T, priv ed25519.PrivateKey) []Receipt
		wantErr string
	}{
		"drop_first_session_open": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				open := signBoundOpen(t, priv, base)
				first := signRunReceipt(t, priv, 1, mustHash(t, open), sessionOpenTestRunA, base.Add(time.Second))
				second := signRunReceipt(t, priv, 2, mustHash(t, first), sessionOpenTestRunA, base.Add(2*time.Second))
				return []Receipt{first, second}
			},
			wantErr: "genesis receipt chain_prev_hash",
		},
		"drop_middle_receipt": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				open := signBoundOpen(t, priv, base)
				first := signRunReceipt(t, priv, 1, mustHash(t, open), sessionOpenTestRunA, base.Add(time.Second))
				second := signRunReceipt(t, priv, 2, mustHash(t, first), sessionOpenTestRunA, base.Add(2*time.Second))
				return []Receipt{open, second}
			},
			wantErr: "seq gap",
		},
		"reorder_receipts": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				open := signBoundOpen(t, priv, base)
				first := signRunReceipt(t, priv, 1, mustHash(t, open), sessionOpenTestRunA, base.Add(time.Second))
				second := signRunReceipt(t, priv, 2, mustHash(t, first), sessionOpenTestRunA, base.Add(2*time.Second))
				return []Receipt{open, second, first}
			},
			wantErr: "seq gap",
		},
		"restart_open_prior_tail_missing": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				open := signBoundOpen(t, priv, base)
				first := signRunReceipt(t, priv, 1, mustHash(t, open), sessionOpenTestRunA, base.Add(time.Second))
				priorHash := mustHash(t, first)
				restart := signRestartOpen(t, priv, 2, priorHash, first.ActionRecord.ChainSeq, sessionOpenTestRunB, base.Add(2*time.Second), nil)
				return []Receipt{open, restart}
			},
			wantErr: "prior_chain_head",
		},
		"key_rotation_session_open_prior_tail_missing": {
			build: func(t *testing.T, priv ed25519.PrivateKey) []Receipt {
				_, privB := generateTestKey(t)
				base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				open := signBoundOpen(t, priv, base)
				first := signRunReceipt(t, priv, 1, mustHash(t, open), sessionOpenTestRunA, base.Add(time.Second))
				priorHash := mustHash(t, first)
				marker := &KeyTransition{
					PriorSignerKey: hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
					PriorChainSeq:  first.ActionRecord.ChainSeq,
					PriorChainHash: priorHash,
				}
				rotated := signRestartOpen(t, privB, 0, priorHash, first.ActionRecord.ChainSeq, sessionOpenTestRunB, base.Add(2*time.Second), marker)
				return []Receipt{open, rotated}
			},
			wantErr: "prior_chain_hash",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pub, priv := generateTestKey(t)
			res := VerifyChain(tc.build(t, priv), hex.EncodeToString(pub))
			if res.Valid {
				t.Fatal("tampered session_open chain verified")
			}
			if !strings.Contains(res.Error, tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", res.Error, tc.wantErr)
			}
		})
	}
}

func TestVerifyChain_RunNonceScopeIsPerVerifyCall(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	first := signBoundOpen(t, priv, base)
	second := signBoundOpen(t, priv, base.Add(time.Minute))

	if res := VerifyChain([]Receipt{first}, hex.EncodeToString(pub)); !res.Valid {
		t.Fatalf("first VerifyChain: %s", res.Error)
	}
	if res := VerifyChain([]Receipt{second}, hex.EncodeToString(pub)); !res.Valid {
		t.Fatalf("second VerifyChain with reused run_nonce should not inherit prior call state: %s", res.Error)
	}
}
