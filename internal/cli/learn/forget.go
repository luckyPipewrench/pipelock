// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/activation"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const localErasureTombstone = "local_erasure_tombstone"

type forgetFlags struct {
	candidatePath   string
	ruleID          string
	reason          string
	outPath         string
	tombstoneDir    string
	receiptOut      string
	keystore        string
	compileKeyAgent string
	activationKey   string
	deterministic   bool
}

func forgetCmd() *cobra.Command {
	var flags forgetFlags
	cmd := &cobra.Command{
		Use:   "forget",
		Short: "Remove a rule from a candidate and write signed erasure tombstone evidence",
		Long: `Remove one rule from a candidate contract, re-sign the reduced
candidate, write a signed tombstone for the prior contract hash, and emit a
contract_redaction_request evidence receipt.

The original history blob is not overwritten. This command writes a new
candidate artifact plus tombstone-index evidence for local private erasure.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runForget(cmd, flags)
		},
	}
	cmd.Flags().StringVar(&flags.candidatePath, "candidate", "", "candidate YAML path (required, absolute)")
	cmd.Flags().StringVar(&flags.ruleID, "rule-id", "", "rule_id to forget (required)")
	cmd.Flags().StringVar(&flags.reason, "reason", "", "legal reason or ticket reference (required)")
	cmd.Flags().StringVar(&flags.outPath, "out", "", "forgotten candidate output path")
	cmd.Flags().StringVar(&flags.tombstoneDir, "tombstone-dir", "", "directory for signed tombstone YAML; defaults next to candidate")
	cmd.Flags().StringVar(&flags.receiptOut, "receipt-out", "", "redaction receipt JSONL path")
	cmd.Flags().StringVar(&flags.keystore, "keystore", "", "keystore directory for compile and activation signing")
	cmd.Flags().StringVar(&flags.compileKeyAgent, "compile-key-agent", "", "keystore agent name for contract re-signing; defaults to candidate signer")
	cmd.Flags().StringVar(&flags.activationKey, "activation-key", "", "keystore key id for redaction authorization signing")
	cmd.Flags().BoolVar(&flags.deterministic, "deterministic", false, "use deterministic timestamps, ids, and signing keys for tests")
	_ = cmd.MarkFlagRequired("candidate")
	_ = cmd.MarkFlagRequired("rule-id")
	_ = cmd.MarkFlagRequired("reason")
	return cmd
}

func runForget(cmd *cobra.Command, flags forgetFlags) error {
	if strings.TrimSpace(flags.ruleID) == "" {
		return fmt.Errorf("%w: --rule-id is required", ErrRuleNotFound)
	}
	if strings.TrimSpace(flags.reason) == "" {
		return fmt.Errorf("learn forget: --reason is required")
	}
	clean, env, err := loadCandidateEnvelope(flags.candidatePath)
	if err != nil {
		return err
	}
	priorHash := env.Body.ContractHash
	if priorHash == "" {
		return fmt.Errorf("%w: candidate contract_hash is empty", ErrInvalidCandidate)
	}
	if !removeRule(&env.Body, flags.ruleID) {
		return fmt.Errorf("%w: %q", ErrRuleNotFound, flags.ruleID)
	}
	if len(env.Body.Rules) == 0 {
		return fmt.Errorf("learn forget: refusing to write candidate with no rules")
	}

	compileSigner, err := resolveForgetCompileSigner(flags, env.Body.SignerKeyID)
	if err != nil {
		return err
	}
	activationSigner, err := resolveForgetActivationSigner(flags)
	if err != nil {
		return err
	}
	env.Body.PriorContractHash = priorHash
	if err := signContractEnvelope(&env, compileSigner); err != nil {
		return fmt.Errorf("learn forget: sign reduced candidate: %w", err)
	}

	dest, err := resolveForgetOut(clean, flags.outPath)
	if err != nil {
		return err
	}
	now := ratifyNow(flags.deterministic)
	authID := forgetAuthorizationID(flags.deterministic)
	tombstone := contract.NewTombstone(priorHash, now.Format(timeFormatRFC3339Nano), authID, activationSigner.KeyID())
	tombstoneEnv, tombstoneHash, err := signTombstone(tombstone, activationSigner)
	if err != nil {
		return err
	}
	tombstonePath, err := resolveTombstonePath(flags.tombstoneDir, clean, priorHash)
	if err != nil {
		return err
	}
	receiptOut, err := resolveReceiptOut(flags.receiptOut, dest, "redaction-receipts.jsonl")
	if err != nil {
		return err
	}
	receipt, err := activation.SignReceipt(
		contractreceipt.PayloadContractRedactionRequest,
		contractreceipt.PayloadContractRedactionRequestStruct{
			TargetContractHash: priorHash,
			RequestKind:        localErasureTombstone,
			ReasonClass:        strings.TrimSpace(flags.reason),
			AuthorizationID:    authID,
			TombstoneHash:      tombstoneHash,
		},
		activation.ReceiptContext{
			EventID:      authID,
			Timestamp:    now,
			Principal:    activationSigner.KeyID(),
			Actor:        "learn forget",
			ContractHash: priorHash,
			SelectorID:   env.Body.Selector.SelectorID,
		},
		activationSigner,
		signing.PurposeContractActivationSigning,
	)
	if err != nil {
		return err
	}
	if err := writeTombstoneYAML(tombstonePath, tombstoneEnv); err != nil {
		return err
	}
	stagedCandidate, err := stageContractEnvelopeYAML(dest, env)
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(stagedCandidate)
	}()
	if err := appendLifecycleReceipts(receiptOut, receipt); err != nil {
		return err
	}
	if err := commitStagedContract(stagedCandidate, dest); err != nil {
		return err
	}

	emitAuditEvent(cmd, auditEvent{
		Event:           "learn_forget",
		Candidate:       clean,
		Dest:            dest,
		Rule:            flags.ruleID,
		Output:          receiptOut,
		Tombstone:       tombstonePath,
		SignerKeyID:     activationSigner.KeyID(),
		ReceiptsEmitted: 1,
	})
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "forget: rule %s removed, candidate written to %s, tombstone written to %s\n",
		flags.ruleID, dest, tombstonePath)
	return nil
}

func removeRule(c *contract.Contract, ruleID string) bool {
	oldRules := c.Rules
	oldFieldDataClasses := c.FieldDataClasses
	rules := c.Rules[:0]
	removed := false
	for _, rule := range c.Rules {
		if rule.RuleID == ruleID {
			removed = true
			continue
		}
		rules = append(rules, rule)
	}
	c.Rules = rules
	if removed {
		remapRuleFieldDataClasses(c, oldRules, oldFieldDataClasses)
	}
	return removed
}

func resolveForgetOut(candidate, out string) (string, error) {
	if out == "" {
		out = strings.TrimSuffix(candidate, filepath.Ext(candidate)) + ".forgotten.yaml"
	}
	return resolveOut(candidate, out)
}

func resolveForgetCompileSigner(flags forgetFlags, defaultKey string) (privateKeySigner, error) {
	if flags.deterministic {
		seed := sha256.Sum256([]byte("pipelock deterministic forget compile signer"))
		return privateKeySigner{keyID: "deterministic-contract-compile", key: ed25519.NewKeyFromSeed(seed[:])}, nil
	}
	key := flags.compileKeyAgent
	if key == "" {
		key = defaultKey
	}
	return loadLifecycleSigner(flags.keystore, key)
}

func resolveForgetActivationSigner(flags forgetFlags) (privateKeySigner, error) {
	if flags.deterministic {
		seed := sha256.Sum256([]byte("pipelock deterministic forget activation signer"))
		return privateKeySigner{keyID: "deterministic-contract-activation", key: ed25519.NewKeyFromSeed(seed[:])}, nil
	}
	return loadLifecycleSigner(flags.keystore, flags.activationKey)
}

func forgetAuthorizationID(deterministic bool) string {
	if deterministic {
		return "redaction-deterministic"
	}
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}

func signTombstone(body contract.Tombstone, signer privateKeySigner) (contract.TombstoneEnvelope, string, error) {
	if err := body.Validate(); err != nil {
		return contract.TombstoneEnvelope{}, "", err
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		return contract.TombstoneEnvelope{}, "", err
	}
	sig, err := signer.Sign(preimage)
	if err != nil {
		return contract.TombstoneEnvelope{}, "", err
	}
	env := contract.TombstoneEnvelope{Body: body, Signature: "ed25519:" + hex.EncodeToString(sig)}
	hash, err := tombstoneHash(env)
	if err != nil {
		return contract.TombstoneEnvelope{}, "", err
	}
	return env, hash, nil
}

func tombstoneHash(env contract.TombstoneEnvelope) (string, error) {
	raw, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		return "", err
	}
	canon, err := contract.Canonicalize(tree)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func resolveTombstonePath(dir, candidate, priorHash string) (string, error) {
	if dir == "" {
		dir = filepath.Join(filepath.Dir(candidate), "tombstones")
	}
	cleanDir, err := checkedWriteDir(filepath.Clean(dir))
	if err != nil {
		return "", err
	}
	name := strings.NewReplacer(":", "-", "/", "-").Replace(priorHash) + ".tombstone.yaml"
	return checkedWritePath(filepath.Join(cleanDir, name))
}

func writeTombstoneYAML(path string, env contract.TombstoneEnvelope) error {
	out, err := marshalYAMLWithJSONTags(env)
	if err != nil {
		return fmt.Errorf("learn forget: marshal tombstone: %w", err)
	}
	if err := atomicfile.Write(path, out, 0o600); err != nil {
		return fmt.Errorf("learn forget: write tombstone: %w", err)
	}
	return nil
}

const timeFormatRFC3339Nano = "2006-01-02T15:04:05.999999999Z07:00"
