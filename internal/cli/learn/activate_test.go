// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	contractstore "github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestLearnCmdRegistersPromoteAndRollback(t *testing.T) {
	cmd := Cmd()
	for _, name := range []string{"promote", "rollback"} {
		t.Run(name, func(t *testing.T) {
			found := false
			for _, child := range cmd.Commands() {
				if child.Name() == name {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("learn command missing %q", name)
			}
		})
	}
}

func TestBuildManifestSelectorComputesStableIDs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		input     string
		wantAgent string
		wantGlob  string
		wantDef   bool
	}{
		{name: "agent", input: "worker-a", wantAgent: "worker-a"},
		{name: "glob", input: "worker-*", wantGlob: "worker-*"},
		{name: "default", input: "default", wantDef: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selector, err := buildManifestSelector(tc.input, "sha256:contract")
			if err != nil {
				t.Fatalf("buildManifestSelector: %v", err)
			}
			if selector.Agent != tc.wantAgent || selector.AgentGlob != tc.wantGlob || selector.Default != tc.wantDef {
				t.Fatalf("selector = %+v", selector)
			}
			recomputed, err := selector.ComputeSelectorID()
			if err != nil {
				t.Fatalf("ComputeSelectorID: %v", err)
			}
			if selector.SelectorID == "" || selector.SelectorID != recomputed {
				t.Fatalf("selector_id = %q recomputed=%q", selector.SelectorID, recomputed)
			}
		})
	}

	if _, err := buildManifestSelector("", "sha256:contract"); err == nil || !strings.Contains(err.Error(), "--selector") {
		t.Fatalf("empty selector err = %v, want --selector", err)
	}
	if _, err := buildManifestSelector("worker-a", ""); err == nil || !strings.Contains(err.Error(), "--contract") {
		t.Fatalf("empty contract err = %v, want --contract", err)
	}
}

func TestResolveLifecycleEnvironmentInheritsOrRequiresExplicit(t *testing.T) {
	env := contract.Environment{ID: "prod", Tenant: "tenant", DeploymentID: "dep"}
	got, err := resolveLifecycleEnvironment(lifecycleFlags{}, contractstore.State{
		Envelope: contract.ActiveManifestEnvelope{Body: contract.ActiveManifest{Environment: env}},
	}, true)
	if err != nil {
		t.Fatalf("resolve inherited environment: %v", err)
	}
	if got != env {
		t.Fatalf("environment = %+v, want %+v", got, env)
	}

	got, err = resolveLifecycleEnvironment(lifecycleFlags{
		environmentID: "stage",
		tenant:        "tenant",
		deploymentID:  "dep",
	}, contractstore.State{}, false)
	if err != nil {
		t.Fatalf("resolve explicit environment: %v", err)
	}
	if got.ID != "stage" || got.Tenant != "tenant" || got.DeploymentID != "dep" {
		t.Fatalf("explicit environment = %+v", got)
	}

	_, err = resolveLifecycleEnvironment(lifecycleFlags{
		environmentID: "stage",
		tenant:        "tenant",
		deploymentID:  "dep",
	}, contractstore.State{
		Envelope: contract.ActiveManifestEnvelope{Body: contract.ActiveManifest{Environment: env}},
	}, true)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched environment err = %v, want mismatch", err)
	}

	got, err = resolveLifecycleEnvironment(lifecycleFlags{environmentID: "stage"}, contractstore.State{}, false)
	if err != nil {
		t.Fatalf("resolve environment with empty tenant/deployment_id: %v", err)
	}
	if got != (contract.Environment{ID: "stage"}) {
		t.Fatalf("explicit environment with empty tuple scopes = %+v, want id-only stage", got)
	}

	_, err = resolveLifecycleEnvironment(lifecycleFlags{tenant: "tenant"}, contractstore.State{}, false)
	if err == nil || !strings.Contains(err.Error(), "--environment-id") {
		t.Fatalf("missing environment id err = %v, want missing flag error", err)
	}
}

func TestLifecycleIDDeterministicAndExplicit(t *testing.T) {
	if got := lifecycleID("provided", true, "label"); got != "provided" {
		t.Fatalf("explicit id = %q", got)
	}
	if got := lifecycleID("", true, "label"); got != "label-deterministic" {
		t.Fatalf("deterministic id = %q", got)
	}
	if got := lifecycleID("", false, "label"); got == "" {
		t.Fatal("generated lifecycle id is empty")
	}
}

func TestRunPromoteWritesReceiptsAndAcceptedManifest(t *testing.T) {
	fixture := newLifecycleTestFixture(t)
	contractHash := fixture.putContract(t, "agent-a")
	receiptOut := filepath.Join(fixture.root, "promote-receipts.jsonl")
	var stdout, stderr bytes.Buffer
	cmd := lifecycleTestCmd(&stdout, &stderr)

	err := runPromote(cmd, lifecycleFlags{
		storeDir:              fixture.storeDir,
		rosterPath:            fixture.rosterPath,
		rosterRootFingerprint: fixture.rootFingerprint,
		keystore:              fixture.keystoreDir,
		activationKey:         "activation-primary",
		dualControlFrom:       "activation-secondary",
		receiptKey:            defaultReceiptKeyAgent,
		receiptOut:            receiptOut,
		environmentID:         fixture.env.ID,
		tenant:                fixture.env.Tenant,
		deploymentID:          fixture.env.DeploymentID,
		production:            true,
		deterministic:         true,
		contractHash:          contractHash,
		selector:              "agent-a",
	})
	if err != nil {
		t.Fatalf("runPromote: %v", err)
	}
	if !strings.Contains(stdout.String(), "generation 1 active") {
		t.Fatalf("stdout = %q, want generation 1 active", stdout.String())
	}
	if !strings.Contains(stderr.String(), "learn_promote") {
		t.Fatalf("stderr = %q, want audit event", stderr.String())
	}

	latest := fixture.latestAccepted(t)
	receipts := readLifecycleReceipts(t, receiptOut)
	if len(receipts) != 2 {
		t.Fatalf("receipt count = %d, want 2", len(receipts))
	}
	intent := receipts[0]
	if intent.PayloadKind != contractreceipt.PayloadContractPromoteIntent {
		t.Fatalf("intent payload kind = %q", intent.PayloadKind)
	}
	if intent.ActiveManifestHash != latest.ManifestHash || intent.ContractHash != contractHash || intent.SelectorID == "" {
		t.Fatalf("intent receipt hashes = active %q contract %q selector %q, want active %q contract %q selector set",
			intent.ActiveManifestHash, intent.ContractHash, intent.SelectorID, latest.ManifestHash, contractHash)
	}
	var intentPayload contractreceipt.PayloadContractPromoteIntentStruct
	mustUnmarshalPayload(t, intent, &intentPayload)
	if intentPayload.TargetGeneration != 1 || intentPayload.PriorManifestHash != genesisManifestHash || intentPayload.TargetManifestHash != latest.ManifestHash {
		t.Fatalf("intent payload = %+v, latest=%s", intentPayload, latest.ManifestHash)
	}
	committed := receipts[1]
	if committed.PayloadKind != contractreceipt.PayloadContractPromoteCommitted {
		t.Fatalf("committed payload kind = %q", committed.PayloadKind)
	}
	var committedPayload contractreceipt.PayloadContractPromoteCommittedStruct
	mustUnmarshalPayload(t, committed, &committedPayload)
	if committedPayload.ValidationOutcome != lifecycleOutcomeAccepted || committedPayload.TargetManifestHash != latest.ManifestHash {
		t.Fatalf("committed payload = %+v, latest=%s", committedPayload, latest.ManifestHash)
	}
}

func TestRunPromoteManifestLoadsInRuntimeWithEnvironmentTuple(t *testing.T) {
	fixture := newLifecycleTestFixture(t)
	firstContract := fixture.putContract(t, "agent-a")
	if err := runPromote(lifecycleTestCmd(nil, nil), fixture.promoteFlags(firstContract, "agent-a", filepath.Join(fixture.root, "first-receipts.jsonl"))); err != nil {
		t.Fatalf("runPromote first: %v", err)
	}

	loader, err := contractruntime.NewLoader(contractruntime.LoaderOptions{
		StoreDir:              fixture.storeDir,
		RosterPath:            fixture.rosterPath,
		PinnedRootFingerprint: fixture.rootFingerprint,
		Environment:           fixture.env,
		MinSignatures:         1,
		Mode:                  contractruntime.ModeLive,
	}, nil)
	if err != nil {
		t.Fatalf("NewLoader with matching environment tuple: %v", err)
	}
	if loader.Current() == nil || loader.Current().Generation() != 1 {
		t.Fatalf("runtime current = %+v, want generation 1", loader.Current())
	}

	secondContract := fixture.putContract(t, "agent-b")
	if err := runPromote(lifecycleTestCmd(nil, nil), fixture.promoteFlags(secondContract, "agent-b", filepath.Join(fixture.root, "second-receipts.jsonl"))); err != nil {
		t.Fatalf("runPromote second: %v", err)
	}
	if err := loader.Reload(); err != nil {
		t.Fatalf("runtime Reload after second promote: %v", err)
	}
	if loader.Current() == nil || loader.Current().Generation() != 2 {
		t.Fatalf("runtime current after reload = %+v, want generation 2", loader.Current())
	}

	_, err = contractruntime.NewLoader(contractruntime.LoaderOptions{
		StoreDir:              fixture.storeDir,
		RosterPath:            fixture.rosterPath,
		PinnedRootFingerprint: fixture.rootFingerprint,
		Environment:           contract.Environment{ID: fixture.env.ID, Tenant: "wrong", DeploymentID: fixture.env.DeploymentID},
		MinSignatures:         1,
		Mode:                  contractruntime.ModeLive,
	}, nil)
	if err == nil {
		t.Fatal("NewLoader accepted mismatched environment tuple")
	}
	if !strings.Contains(err.Error(), "environment mismatch") {
		t.Fatalf("mismatch err = %v, want environment mismatch", err)
	}
}

func TestRunRollbackWritesNewManifestHashReceipts(t *testing.T) {
	fixture := newLifecycleTestFixture(t)
	firstContract := fixture.putContract(t, "agent-a")
	secondContract := fixture.putContract(t, "agent-b")
	firstReceiptOut := filepath.Join(fixture.root, "first-promote.jsonl")
	secondReceiptOut := filepath.Join(fixture.root, "second-promote.jsonl")
	rollbackReceiptOut := filepath.Join(fixture.root, "rollback-receipts.jsonl")

	if err := runPromote(lifecycleTestCmd(nil, nil), fixture.promoteFlags(firstContract, "agent-a", firstReceiptOut)); err != nil {
		t.Fatalf("first runPromote: %v", err)
	}
	target := fixture.latestAccepted(t)
	if err := runPromote(lifecycleTestCmd(nil, nil), fixture.promoteFlags(secondContract, "agent-b", secondReceiptOut)); err != nil {
		t.Fatalf("second runPromote: %v", err)
	}
	currentBeforeRollback := fixture.latestAccepted(t)
	var stdout, stderr bytes.Buffer
	cmd := lifecycleTestCmd(&stdout, &stderr)

	err := runRollback(cmd, lifecycleFlags{
		storeDir:              fixture.storeDir,
		rosterPath:            fixture.rosterPath,
		rosterRootFingerprint: fixture.rootFingerprint,
		keystore:              fixture.keystoreDir,
		activationKey:         "activation-primary",
		receiptKey:            defaultReceiptKeyAgent,
		receiptOut:            rollbackReceiptOut,
		environmentID:         fixture.env.ID,
		tenant:                fixture.env.Tenant,
		deploymentID:          fixture.env.DeploymentID,
		deterministic:         true,
		rollbackTarget:        target.ManifestHash,
	})
	if err != nil {
		t.Fatalf("runRollback: %v", err)
	}
	if !strings.Contains(stdout.String(), "generation 3") || !strings.Contains(stdout.String(), target.ManifestHash) {
		t.Fatalf("stdout = %q, want target hash and generation 3", stdout.String())
	}
	latest := fixture.latestAccepted(t)
	if latest.ManifestHash == target.ManifestHash || latest.ManifestHash == currentBeforeRollback.ManifestHash {
		t.Fatalf("rollback latest hash = %q, want new rollback manifest hash distinct from target %q and current %q",
			latest.ManifestHash, target.ManifestHash, currentBeforeRollback.ManifestHash)
	}
	if !strings.Contains(stderr.String(), latest.ManifestHash) {
		t.Fatalf("audit stderr = %q, want rollback manifest hash %q", stderr.String(), latest.ManifestHash)
	}

	receipts := readLifecycleReceipts(t, rollbackReceiptOut)
	if len(receipts) != 2 {
		t.Fatalf("receipt count = %d, want 2", len(receipts))
	}
	for _, rcpt := range receipts {
		if rcpt.ActiveManifestHash != latest.ManifestHash {
			t.Fatalf("receipt active_manifest_hash = %q, want rollback manifest %q", rcpt.ActiveManifestHash, latest.ManifestHash)
		}
		if rcpt.ContractHash != "" {
			t.Fatalf("receipt contract_hash = %q, want empty for rollback receipts", rcpt.ContractHash)
		}
		if rcpt.ContractGeneration != 3 {
			t.Fatalf("receipt generation = %d, want 3", rcpt.ContractGeneration)
		}
	}
	var authorizedPayload contractreceipt.PayloadContractRollbackAuthorizedStruct
	mustUnmarshalPayload(t, receipts[0], &authorizedPayload)
	if authorizedPayload.RollbackTargetHash != target.ManifestHash || authorizedPayload.CurrentGeneration != currentBeforeRollback.Envelope.Body.Generation {
		t.Fatalf("authorized payload = %+v, target=%s currentGen=%d",
			authorizedPayload, target.ManifestHash, currentBeforeRollback.Envelope.Body.Generation)
	}
	var committedPayload contractreceipt.PayloadContractRollbackCommittedStruct
	mustUnmarshalPayload(t, receipts[1], &committedPayload)
	if committedPayload.ValidationOutcome != lifecycleOutcomeAccepted || committedPayload.PriorManifestHash != currentBeforeRollback.ManifestHash {
		t.Fatalf("committed payload = %+v, current=%s", committedPayload, currentBeforeRollback.ManifestHash)
	}
}

func TestLifecycleErrorPaths(t *testing.T) {
	fixture := newLifecycleTestFixture(t)
	contractHash := fixture.putContract(t, "agent-a")
	base := fixture.promoteFlags(contractHash, "agent-a", filepath.Join(fixture.root, "receipts.jsonl"))

	missingEnv := base
	missingEnv.environmentID = ""
	missingEnv.tenant = ""
	missingEnv.deploymentID = ""
	if err := runPromote(lifecycleTestCmd(nil, nil), missingEnv); err == nil || !strings.Contains(err.Error(), "--environment-id") {
		t.Fatalf("runPromote missing env err = %v, want environment flag error", err)
	}

	emptyFixture := newLifecycleTestFixture(t)
	emptyContractHash := emptyFixture.putContract(t, "agent-a")
	emptyTupleScopes := emptyFixture.promoteFlags(emptyContractHash, "agent-a", filepath.Join(emptyFixture.root, "empty-scope-receipts.jsonl"))
	emptyTupleScopes.tenant = ""
	emptyTupleScopes.deploymentID = ""
	if err := runPromote(lifecycleTestCmd(nil, nil), emptyTupleScopes); err != nil {
		t.Fatalf("runPromote should accept empty tenant/deployment_id with environment id: %v", err)
	}
	latest, err := contractstore.New(emptyFixture.storeDir).LatestAccepted(contractstore.Options{
		Environment:   contract.Environment{ID: emptyFixture.env.ID},
		Roster:        emptyFixture.roster,
		MinSignatures: 1,
		Now:           lifecycleTestNow,
	})
	if err != nil {
		t.Fatalf("LatestAccepted with id-only environment: %v", err)
	}
	if latest.Envelope.Body.Environment != (contract.Environment{ID: emptyFixture.env.ID}) {
		t.Fatalf("promote environment = %+v, want id-only environment", latest.Envelope.Body.Environment)
	}

	missingSelector := base
	missingSelector.selector = ""
	if err := runPromote(lifecycleTestCmd(nil, nil), missingSelector); err == nil || !strings.Contains(err.Error(), "--selector") {
		t.Fatalf("runPromote missing selector err = %v, want selector error", err)
	}

	badSigner := base
	badSigner.activationKey = ""
	if err := runPromote(lifecycleTestCmd(nil, nil), badSigner); err == nil || !strings.Contains(err.Error(), "signer key id") {
		t.Fatalf("runPromote bad signer err = %v, want signer key error", err)
	}

	noAcceptedRollback := lifecycleFlags{
		storeDir:              fixture.storeDir,
		rosterPath:            fixture.rosterPath,
		rosterRootFingerprint: fixture.rootFingerprint,
		keystore:              fixture.keystoreDir,
		activationKey:         "activation-primary",
		receiptKey:            defaultReceiptKeyAgent,
		environmentID:         fixture.env.ID,
		tenant:                fixture.env.Tenant,
		deploymentID:          fixture.env.DeploymentID,
		rollbackTarget:        "sha256:missing",
	}
	if err := runRollback(lifecycleTestCmd(nil, nil), noAcceptedRollback); err == nil || !strings.Contains(err.Error(), "no accepted manifest") {
		t.Fatalf("runRollback no accepted err = %v, want no accepted manifest", err)
	}

	if err := runPromote(lifecycleTestCmd(nil, nil), base); err != nil {
		t.Fatalf("seed runPromote: %v", err)
	}
	badTargetRollback := noAcceptedRollback
	badTargetRollback.rollbackTarget = "sha256:missing"
	if err := runRollback(lifecycleTestCmd(nil, nil), badTargetRollback); err == nil || !strings.Contains(err.Error(), "load target manifest") {
		t.Fatalf("runRollback bad target err = %v, want target load error", err)
	}

	if err := appendLifecycleReceipts("relative.jsonl"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("appendLifecycleReceipts relative err = %v, want absolute path error", err)
	}
}

type lifecycleTestFixture struct {
	root            string
	storeDir        string
	keystoreDir     string
	rosterPath      string
	rootFingerprint string
	roster          *signing.LoadedRoster
	env             contract.Environment
	compileKey      ed25519.PrivateKey
}

func newLifecycleTestFixture(t *testing.T) lifecycleTestFixture {
	t.Helper()
	root := t.TempDir()
	storeDir := filepath.Join(root, "store")
	keystoreDir := filepath.Join(root, "keys")
	ks := signing.NewKeystore(keystoreDir)
	rootPub := mustGenerateAgent(t, ks, "roster-root")
	activationPub := mustGenerateAgent(t, ks, "activation-primary")
	secondaryActivationPub := mustGenerateAgent(t, ks, "activation-secondary")
	thirdActivationPub := mustGenerateAgent(t, ks, "activation-third")
	compilePub := mustGenerateAgent(t, ks, "compile-primary")
	receiptPub := mustGenerateAgent(t, ks, defaultReceiptKeyAgent)
	rootPriv := mustLoadPrivateKey(t, ks, "roster-root")
	compilePriv := mustLoadPrivateKey(t, ks, "compile-primary")
	rootFingerprint, err := signing.Fingerprint(rootPub)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	body := contract.KeyRoster{
		SchemaVersion:  1,
		RosterSignedBy: "roster-root",
		DataClassRoot:  string(contract.DataClassInternal),
		Keys: []contract.KeyInfo{
			lifecycleTestRosterKey("roster-root", signing.PurposeRosterRoot, rootPub, contract.KeyStatusRoot, "root"),
			lifecycleTestRosterKey("activation-primary", signing.PurposeContractActivationSigning, activationPub, contract.KeyStatusActive, "operator"),
			lifecycleTestRosterKey("activation-secondary", signing.PurposeContractActivationSigning, secondaryActivationPub, contract.KeyStatusActive, "operator-secondary"),
			lifecycleTestRosterKey("activation-third", signing.PurposeContractActivationSigning, thirdActivationPub, contract.KeyStatusActive, "operator-third"),
			lifecycleTestRosterKey("compile-primary", signing.PurposeContractCompileSigning, compilePub, contract.KeyStatusActive, "compiler"),
			lifecycleTestRosterKey(defaultReceiptKeyAgent, signing.PurposeReceiptSigning, receiptPub, contract.KeyStatusActive, "learn"),
		},
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("roster SignablePreimage: %v", err)
	}
	envelope := contract.RosterEnvelope{
		Body:      body,
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(rootPriv, preimage)),
	}
	rosterPath := filepath.Join(root, "roster.json")
	if err := os.WriteFile(rosterPath, mustJSON(t, envelope), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	loaded, err := signing.LoadRoster(rosterPath, rootFingerprint)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}
	return lifecycleTestFixture{
		root:            root,
		storeDir:        storeDir,
		keystoreDir:     keystoreDir,
		rosterPath:      rosterPath,
		rootFingerprint: rootFingerprint,
		roster:          loaded,
		env:             contract.Environment{ID: "prod", Tenant: "tenant-a", DeploymentID: "deploy-a"},
		compileKey:      compilePriv,
	}
}

func (f lifecycleTestFixture) promoteFlags(contractHash, selector, receiptOut string) lifecycleFlags {
	return lifecycleFlags{
		storeDir:              f.storeDir,
		rosterPath:            f.rosterPath,
		rosterRootFingerprint: f.rootFingerprint,
		keystore:              f.keystoreDir,
		activationKey:         "activation-primary",
		receiptKey:            defaultReceiptKeyAgent,
		receiptOut:            receiptOut,
		environmentID:         f.env.ID,
		tenant:                f.env.Tenant,
		deploymentID:          f.env.DeploymentID,
		deterministic:         true,
		contractHash:          contractHash,
		selector:              selector,
	}
}

func (f lifecycleTestFixture) putContract(t *testing.T, agent string) string {
	t.Helper()
	st := contractstore.New(f.storeDir)
	body := contract.Contract{
		SchemaVersion:    contract.SchemaVersionContract,
		ContractKind:     contract.ContractKind,
		SignerKeyID:      "compile-primary",
		KeyPurpose:       signing.PurposeContractCompileSigning.String(),
		DataClassRoot:    string(contract.DataClassInternal),
		FieldDataClasses: map[string]string{},
		Selector:         contract.Selector{Agent: agent, SelectorID: "selector-" + agent},
	}
	hash, err := contractstore.ContractHash(body)
	if err != nil {
		t.Fatalf("ContractHash: %v", err)
	}
	body.ContractHash = hash
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("contract SignablePreimage: %v", err)
	}
	envelope := contract.ContractEnvelope{
		Body:      body,
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(f.compileKey, preimage)),
	}
	got, err := st.PutHistoryContract(mustJSON(t, envelope), contractstore.Options{Roster: f.roster, Now: lifecycleTestNow})
	if err != nil {
		t.Fatalf("PutHistoryContract: %v", err)
	}
	if got != hash {
		t.Fatalf("PutHistoryContract hash = %q, want %q", got, hash)
	}
	return hash
}

func (f lifecycleTestFixture) latestAccepted(t *testing.T) contractstore.State {
	t.Helper()
	state, err := contractstore.New(f.storeDir).LatestAccepted(contractstore.Options{
		Environment:   f.env,
		Roster:        f.roster,
		MinSignatures: 1,
		Now:           lifecycleTestNow,
	})
	if err != nil {
		t.Fatalf("LatestAccepted: %v", err)
	}
	return state
}

func lifecycleTestRosterKey(keyID string, purpose signing.KeyPurpose, pub ed25519.PublicKey, status, principal string) contract.KeyInfo {
	return contract.KeyInfo{
		KeyID:        keyID,
		KeyPurpose:   purpose.String(),
		PublicKeyHex: hex.EncodeToString(pub),
		ValidFrom:    time.Date(2026, 4, 29, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Status:       status,
		Principal:    principal,
	}
}

func lifecycleTestCmd(stdout, stderr *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{}
	if stdout != nil {
		cmd.SetOut(stdout)
	}
	if stderr != nil {
		cmd.SetErr(stderr)
	}
	return cmd
}

func lifecycleTestNow() time.Time {
	return time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
}

func mustGenerateAgent(t *testing.T, ks *signing.Keystore, name string) ed25519.PublicKey {
	t.Helper()
	pub, err := ks.GenerateAgent(name)
	if err != nil {
		t.Fatalf("GenerateAgent(%s): %v", name, err)
	}
	return pub
}

func mustLoadPrivateKey(t *testing.T, ks *signing.Keystore, name string) ed25519.PrivateKey {
	t.Helper()
	priv, err := ks.LoadPrivateKey(name)
	if err != nil {
		t.Fatalf("LoadPrivateKey(%s): %v", name, err)
	}
	return priv
}

func readLifecycleReceipts(t *testing.T, path string) []contractreceipt.EvidenceReceipt {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("open receipts: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("close receipts: %v", err)
		}
	}()
	var receipts []contractreceipt.EvidenceReceipt
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var receipt contractreceipt.EvidenceReceipt
		if err := json.Unmarshal(scanner.Bytes(), &receipt); err != nil {
			t.Fatalf("decode receipt: %v", err)
		}
		if err := receipt.Validate(); err != nil {
			t.Fatalf("receipt Validate: %v", err)
		}
		receipts = append(receipts, receipt)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan receipts: %v", err)
	}
	return receipts
}

func mustUnmarshalPayload(t *testing.T, receipt contractreceipt.EvidenceReceipt, out any) {
	t.Helper()
	if err := json.Unmarshal(receipt.Payload, out); err != nil {
		t.Fatalf("unmarshal payload %s: %v", receipt.PayloadKind, err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return append(raw, '\n')
}
