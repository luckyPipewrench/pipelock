// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
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

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/activation"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	contractstore "github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	ratifyDecisionEnforce = "enforce"
	ratifyDecisionCapture = "capture_only"
	ratifyDecisionReject  = "reject"

	ratifyConfidenceNeverConfirmed = "never_confirmed"
	ratifyConfidenceRefuted        = "refuted"
)

// ErrLowConfidenceRatification is returned when ratify would promote
// low-confidence rules without explicit operator override.
var ErrLowConfidenceRatification = errors.New("learn ratify: low-confidence rules require explicit override")

type ratifyFlags struct {
	candidatePath       string
	outPath             string
	receiptOut          string
	keystore            string
	compileKeyAgent     string
	receiptKey          string
	interactive         bool
	acceptLowConfidence bool
	deterministic       bool
}

type ratifyDecision struct {
	RuleID   string
	Decision string
}

func ratifyCmd() *cobra.Command {
	flags := ratifyFlags{receiptKey: defaultReceiptKeyAgent}
	cmd := &cobra.Command{
		Use:   "ratify",
		Short: "Review and ratify candidate contract rules",
		Long: `Review a candidate contract rule by rule, choose enforce,
capture-only, or reject for each rule, then write a newly signed candidate
and a contract_ratified evidence receipt.

Interactive mode reads one decision per rule from stdin: e=enforce,
c=capture-only, r=reject.

Non-interactive ratification refuses never_confirmed and refuted rules unless
--accept-low-confidence is set. That override can promote rules built from
insufficient or refuted evidence into enforcement, so use it only for deliberate
operator-reviewed dogfood workflows.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRatify(cmd, flags)
		},
	}
	cmd.Flags().StringVar(&flags.candidatePath, "candidate", "", "candidate YAML path (required, absolute)")
	cmd.Flags().StringVar(&flags.outPath, "out", "", "ratified candidate output path; empty rewrites candidate")
	cmd.Flags().StringVar(&flags.receiptOut, "receipt-out", "", "contract_ratified receipt JSONL path")
	cmd.Flags().StringVar(&flags.keystore, "keystore", "", "keystore directory for compile and receipt signing")
	cmd.Flags().StringVar(&flags.compileKeyAgent, "compile-key-agent", "", "keystore agent name for contract re-signing; defaults to candidate signer")
	cmd.Flags().StringVar(&flags.receiptKey, "receipt-key-agent", flags.receiptKey, "keystore agent name for ratification receipt signing")
	cmd.Flags().BoolVar(&flags.interactive, "interactive", false, "prompt for each rule decision")
	cmd.Flags().BoolVar(&flags.acceptLowConfidence, "accept-low-confidence", false, "allow ratifying never_confirmed or refuted rules; dangerous because thin or refuted evidence can become enforce policy")
	cmd.Flags().BoolVar(&flags.deterministic, "deterministic", false, "use deterministic timestamps, ids, and signing keys for tests")
	_ = cmd.MarkFlagRequired("candidate")
	return cmd
}

func runRatify(cmd *cobra.Command, flags ratifyFlags) error {
	clean, env, err := loadCandidateEnvelope(flags.candidatePath)
	if err != nil {
		return err
	}
	if len(env.Body.Rules) == 0 {
		return fmt.Errorf("%w: candidate has no rules", ErrInvalidCandidate)
	}
	if flags.interactive && !flags.acceptLowConfidence && allLowConfidenceRules(env.Body.Rules) {
		return fmt.Errorf("%w: candidate has only low-confidence rules (%s); rerun with --accept-low-confidence only after operator review",
			ErrLowConfidenceRatification, lowConfidenceRuleSummary(env.Body.Rules))
	}
	decisions, err := collectRatifyDecisions(cmd, env.Body, flags.interactive, flags.acceptLowConfidence)
	if err != nil {
		return err
	}
	ratified, decisionMap := applyRatifyDecisions(&env.Body, decisions)
	if len(ratified) == 0 {
		return fmt.Errorf("learn ratify: all rules rejected; refusing to emit empty ratification")
	}

	compileSigner, err := resolveRatifyCompileSigner(flags, env.Body.SignerKeyID)
	if err != nil {
		return err
	}
	receiptSigner, err := resolveRatifyReceiptSigner(flags)
	if err != nil {
		return err
	}
	if err := signContractEnvelope(&env, compileSigner); err != nil {
		return fmt.Errorf("learn ratify: sign candidate: %w", err)
	}

	dest, err := resolveOut(clean, flags.outPath)
	if err != nil {
		return err
	}
	receiptOut, err := resolveReceiptOut(flags.receiptOut, dest, "ratification-receipts.jsonl")
	if err != nil {
		return err
	}
	now := ratifyNow(flags.deterministic)
	eventID := lifecycleID("", flags.deterministic, "contract-ratified")
	receipt, err := activation.SignReceipt(
		contractreceipt.PayloadContractRatified,
		contractreceipt.PayloadContractRatifiedStruct{
			ContractHash:                env.Body.ContractHash,
			RatifierKeyID:               receiptSigner.KeyID(),
			RatifiedRuleIDs:             ratified,
			RatificationDecisionPerRule: decisionMap,
		},
		activation.ReceiptContext{
			EventID:            eventID,
			Timestamp:          now,
			Principal:          receiptSigner.KeyID(),
			Actor:              "learn ratify",
			ContractHash:       env.Body.ContractHash,
			SelectorID:         env.Body.Selector.SelectorID,
			ContractGeneration: env.Body.ObservationWindow.EventCount,
		},
		receiptSigner,
		signing.PurposeReceiptSigning,
	)
	if err != nil {
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
		Event:           "learn_ratify",
		Candidate:       clean,
		Dest:            dest,
		Output:          receiptOut,
		SignerKeyID:     receiptSigner.KeyID(),
		RulesRatified:   len(ratified),
		RulesRejected:   countDecision(decisionMap, ratifyDecisionReject),
		ReceiptsEmitted: 1,
	})
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "ratify: %d rules ratified, %d rejected, written to %s\n",
		len(ratified), countDecision(decisionMap, ratifyDecisionReject), dest)
	return nil
}

func loadCandidateEnvelope(path string) (string, contract.ContractEnvelope, error) {
	clean, doc, err := loadCandidate(path)
	if err != nil {
		return "", contract.ContractEnvelope{}, err
	}
	raw, err := yamlBytes(doc)
	if err != nil {
		return "", contract.ContractEnvelope{}, err
	}
	var env contract.ContractEnvelope
	if err := contract.DecodeStrictYAML(raw, &env); err != nil {
		return "", contract.ContractEnvelope{}, fmt.Errorf("learn: decode candidate envelope: %w", err)
	}
	return clean, env, nil
}

func collectRatifyDecisions(cmd *cobra.Command, c contract.Contract, interactive, acceptLowConfidence bool) ([]ratifyDecision, error) {
	decisions := make([]ratifyDecision, 0, len(c.Rules))
	if !interactive {
		if !acceptLowConfidence {
			if summary := lowConfidenceRuleSummary(c.Rules); summary != "" {
				return nil, fmt.Errorf("%w: refusing non-interactive enforce for %s; rerun with --interactive to review each rule or --accept-low-confidence to override",
					ErrLowConfidenceRatification, summary)
			}
		}
		for _, rule := range c.Rules {
			decisions = append(decisions, ratifyDecision{RuleID: rule.RuleID, Decision: ratifyDecisionEnforce})
		}
		return decisions, nil
	}
	reader := bufio.NewReader(cmd.InOrStdin())
	for i, rule := range c.Rules {
		if err := renderRatifyRule(cmd.OutOrStdout(), c, rule, i); err != nil {
			return nil, err
		}
		choice, err := readRatifyChoice(reader)
		if err != nil {
			return nil, err
		}
		decisions = append(decisions, ratifyDecision{RuleID: rule.RuleID, Decision: choice})
	}
	return decisions, nil
}

func allLowConfidenceRules(rules []contract.Rule) bool {
	if len(rules) == 0 {
		return false
	}
	for _, rule := range rules {
		if !isLowConfidenceRule(rule) {
			return false
		}
	}
	return true
}

func lowConfidenceRuleSummary(rules []contract.Rule) string {
	low := make([]string, 0)
	for _, rule := range rules {
		if isLowConfidenceRule(rule) {
			low = append(low, fmt.Sprintf("%s(confidence=%s)", rule.RuleID, strings.TrimSpace(rule.Confidence)))
		}
	}
	return strings.Join(low, ", ")
}

func isLowConfidenceRule(rule contract.Rule) bool {
	switch strings.ToLower(strings.TrimSpace(rule.Confidence)) {
	case ratifyConfidenceNeverConfirmed, ratifyConfidenceRefuted:
		return true
	default:
		return false
	}
}

func renderRatifyRule(w io.Writer, c contract.Contract, rule contract.Rule, index int) error {
	dataClass := dataClassForRule(c, index)
	_, err := fmt.Fprintf(w, "\nRule %d/%d: %s\nselector: %s\nobservations: %s\nwilson: %s\nconfidence: %s\ndata_class: %s\nfp_risk: %s\nrationale: %s\nsamples: %s\n[e]nforce [c]apture-only [r]eject > ",
		index+1,
		len(c.Rules),
		rule.RuleID,
		summarizeSelector(rule.Selector),
		mapValueString(rule.Observation, "event_count"),
		rule.WilsonLower,
		rule.Confidence,
		dataClass,
		mapValueString(rule.Rationale, "fp_risk_class"),
		summarizeMap(rule.Rationale),
		summarizeSamples(rule.Observation),
	)
	return err
}

func readRatifyChoice(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil && !errorsIsEOF(err) {
		return "", fmt.Errorf("learn ratify: read decision: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "e", "enforce":
		return ratifyDecisionEnforce, nil
	case "c", "capture", "capture_only":
		return ratifyDecisionCapture, nil
	case "r", "reject":
		return ratifyDecisionReject, nil
	default:
		return "", fmt.Errorf("learn ratify: invalid decision %q (want e, c, or r)", strings.TrimSpace(line))
	}
}

func errorsIsEOF(err error) bool {
	return errors.Is(err, io.EOF)
}

func applyRatifyDecisions(c *contract.Contract, decisions []ratifyDecision) ([]string, map[string]string) {
	byRule := map[string]string{}
	for _, d := range decisions {
		byRule[d.RuleID] = d.Decision
	}
	kept := make([]contract.Rule, 0, len(c.Rules))
	ratified := make([]string, 0, len(c.Rules))
	decisionMap := make(map[string]string, len(c.Rules))
	oldRules := c.Rules
	oldFieldDataClasses := c.FieldDataClasses
	for _, rule := range oldRules {
		decision := byRule[rule.RuleID]
		if decision == "" {
			decision = ratifyDecisionEnforce
		}
		decisionMap[rule.RuleID] = decision
		if decision == ratifyDecisionReject {
			continue
		}
		rule.LifecycleState = decision
		kept = append(kept, rule)
		ratified = append(ratified, rule.RuleID)
	}
	sort.Strings(ratified)
	c.Rules = kept
	remapRuleFieldDataClasses(c, oldRules, oldFieldDataClasses)
	return ratified, decisionMap
}

func signContractEnvelope(env *contract.ContractEnvelope, signer privateKeySigner) error {
	env.Body.SignerKeyID = signer.KeyID()
	env.Body.KeyPurpose = signing.PurposeContractCompileSigning.String()
	hash, err := contractstore.ContractHash(env.Body)
	if err != nil {
		return err
	}
	env.Body.ContractHash = hash
	if err := env.Body.Validate(); err != nil {
		return err
	}
	preimage, err := env.Body.SignablePreimage()
	if err != nil {
		return err
	}
	sig, err := signer.Sign(preimage)
	if err != nil {
		return err
	}
	env.Signature = "ed25519:" + hex.EncodeToString(sig)
	return nil
}

func writeContractEnvelopeYAML(dest string, env contract.ContractEnvelope) error {
	out, err := marshalYAMLWithJSONTags(env)
	if err != nil {
		return fmt.Errorf("learn: marshal candidate envelope: %w", err)
	}
	if err := atomicfile.Write(dest, out, 0o600); err != nil {
		return fmt.Errorf("learn: write candidate envelope: %w", err)
	}
	return nil
}

func stageContractEnvelopeYAML(dest string, env contract.ContractEnvelope) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(dest), "."+filepath.Base(dest)+".*.tmp")
	if err != nil {
		return "", fmt.Errorf("learn: create candidate staging file: %w", err)
	}
	staged := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(staged)
		return "", fmt.Errorf("learn: close candidate staging file: %w", err)
	}
	if err := os.Remove(staged); err != nil {
		return "", fmt.Errorf("learn: clear candidate staging file: %w", err)
	}
	if err := writeContractEnvelopeYAML(staged, env); err != nil {
		_ = os.Remove(staged)
		return "", err
	}
	return staged, nil
}

func commitStagedContract(staged, dest string) error {
	if err := os.Rename(staged, dest); err != nil {
		return fmt.Errorf("learn: commit candidate envelope: %w", err)
	}
	return nil
}

func remapRuleFieldDataClasses(c *contract.Contract, oldRules []contract.Rule, oldClasses map[string]string) {
	if len(oldClasses) == 0 {
		return
	}
	byRuleID := map[string]string{}
	for i, rule := range oldRules {
		if class := oldClasses[fmt.Sprintf("/rules/%d", i)]; class != "" {
			byRuleID[rule.RuleID] = class
		}
	}
	for key := range c.FieldDataClasses {
		if strings.HasPrefix(key, "/rules/") {
			delete(c.FieldDataClasses, key)
		}
	}
	for i, rule := range c.Rules {
		if class := byRuleID[rule.RuleID]; class != "" {
			c.FieldDataClasses[fmt.Sprintf("/rules/%d", i)] = class
		}
	}
}

func marshalYAMLWithJSONTags(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return nil, err
	}
	return yaml.Marshal(tree)
}

func resolveRatifyCompileSigner(flags ratifyFlags, defaultKey string) (privateKeySigner, error) {
	if flags.deterministic {
		seed := sha256.Sum256([]byte("pipelock deterministic ratify compile signer"))
		return privateKeySigner{keyID: "deterministic-contract-compile", key: ed25519Key(seed)}, nil
	}
	key := flags.compileKeyAgent
	if key == "" {
		key = defaultKey
	}
	return loadLifecycleSigner(flags.keystore, key)
}

func resolveRatifyReceiptSigner(flags ratifyFlags) (privateKeySigner, error) {
	if flags.deterministic {
		seed := sha256.Sum256([]byte("pipelock deterministic ratify receipt signer"))
		return privateKeySigner{keyID: "deterministic-receipt-signing", key: ed25519Key(seed)}, nil
	}
	return loadLifecycleSigner(flags.keystore, flags.receiptKey)
}

func ed25519Key(seed [32]byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(seed[:])
}

func resolveReceiptOut(path, sibling, name string) (string, error) {
	if path == "" {
		path = filepath.Join(filepath.Dir(sibling), name)
	}
	return checkedWritePath(filepath.Clean(path))
}

func ratifyNow(deterministic bool) time.Time {
	if deterministic {
		return time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	}
	return time.Now().UTC()
}

func dataClassForRule(c contract.Contract, index int) string {
	for _, key := range []string{
		fmt.Sprintf("/rules/%d", index),
		fmt.Sprintf("rules.%d", index),
		"rules",
	} {
		if v := c.FieldDataClasses[key]; v != "" {
			return v
		}
	}
	if c.DataClassRoot != "" {
		return c.DataClassRoot
	}
	return string(c.Defaults.Privacy.DefaultDataClass)
}

func summarizeSelector(m map[string]any) string {
	if len(m) == 0 {
		return "(none)"
	}
	if host := mapValueString(m, "host"); host != "" {
		if path := mapValueString(m, "path"); path != "" {
			return host + path
		}
		return host
	}
	raw, _ := json.Marshal(m)
	if len(raw) > 160 {
		return string(raw[:157]) + "..."
	}
	return string(raw)
}

func summarizeMap(m map[string]any) string {
	if len(m) == 0 {
		return "(none)"
	}
	raw, _ := json.Marshal(m)
	if len(raw) > 180 {
		return string(raw[:177]) + "..."
	}
	return string(raw)
}

func summarizeSamples(m map[string]any) string {
	for _, key := range []string{"redacted_samples", "sample_hashes", "exemplar_ids"} {
		if v := mapValueString(m, key); v != "" {
			return v
		}
	}
	return "(redacted)"
}

func mapValueString(m map[string]any, key string) string {
	if len(m) == 0 {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch typed := v.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	default:
		raw, _ := json.Marshal(typed)
		return string(raw)
	}
}

func countDecision(decisions map[string]string, decision string) int {
	n := 0
	for _, got := range decisions {
		if got == decision {
			n++
		}
	}
	return n
}
