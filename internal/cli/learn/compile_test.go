// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// captureJSONL returns a minimal recorder envelope JSONL line that passes
// validateCaptureSessionDir's schema + agent-attribution check.
func captureJSONL(agent string) []byte {
	return []byte(`{"v":1,"seq":1,"ts":"2026-05-03T17:00:00Z","session_id":"` + agent + `","type":"capture","transport":"fetch","summary":"x","detail":{"agent":"` + agent + `"},"prev_hash":"","hash":"abc"}` + "\n")
}

func TestResolveCompileInputsRejectsAgentPathSegments(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Learn.CaptureDir = t.TempDir()

	for _, agent := range []string{"", ".", "..", "team/a", `team\a`} {
		t.Run(agent, func(t *testing.T) {
			_, err := resolveCompileInputs(cfg, compileFlags{agent: agent, since: time.Hour})
			if err == nil || !strings.Contains(err.Error(), "--agent") {
				t.Fatalf("resolveCompileInputs(%q) error = %v, want --agent validation", agent, err)
			}
		})
	}
}

func TestResolveCompileInputsAcceptsSingleSegmentAgent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	agentDir := filepath.Join(dir, "agent-a")
	if err := os.MkdirAll(agentDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	input := filepath.Join(agentDir, "capture.jsonl")
	if err := os.WriteFile(input, captureJSONL("agent-a"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg := config.Defaults()
	cfg.Learn.CaptureDir = dir

	got, err := resolveCompileInputs(cfg, compileFlags{agent: "agent-a", since: time.Hour})
	if err != nil {
		t.Fatalf("resolveCompileInputs: %v", err)
	}
	if len(got) != 1 || got[0] != input {
		t.Fatalf("paths = %#v, want [%q]", got, input)
	}
}

func TestResolveCompileInputsAcceptsAgentSessionKeyDirs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, sessionDir := range []string{"agent-a", "agent-a|10.0.0.1"} {
		fullDir := filepath.Join(dir, sessionDir)
		if err := os.MkdirAll(fullDir, 0o750); err != nil {
			t.Fatalf("MkdirAll %s: %v", sessionDir, err)
		}
		if err := os.WriteFile(filepath.Join(fullDir, "capture.jsonl"), captureJSONL("agent-a"), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", sessionDir, err)
		}
	}
	otherDir := filepath.Join(dir, "agent-ab|10.0.0.2")
	if err := os.MkdirAll(otherDir, 0o750); err != nil {
		t.Fatalf("MkdirAll other: %v", err)
	}
	if err := os.WriteFile(filepath.Join(otherDir, "capture.jsonl"), captureJSONL("agent-ab"), 0o600); err != nil {
		t.Fatalf("WriteFile other: %v", err)
	}
	cfg := config.Defaults()
	cfg.Learn.CaptureDir = dir

	got, err := resolveCompileInputs(cfg, compileFlags{agent: "agent-a", since: time.Hour})
	if err != nil {
		t.Fatalf("resolveCompileInputs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("paths = %#v, want 2 agent-a captures", got)
	}
	for _, path := range got {
		sessionDir := filepath.Base(filepath.Dir(path))
		if sessionDir != "agent-a" && !strings.HasPrefix(sessionDir, "agent-a|") {
			t.Fatalf("unexpected session dir %q in %#v", sessionDir, got)
		}
		if sessionDir == "agent-ab" || strings.HasPrefix(sessionDir, "agent-ab|") {
			t.Fatalf("unexpected path %q in %#v", path, got)
		}
	}
}

func TestResolveCompileInputsRejectsPoisonedSiblingSession(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Legitimate agent-a session with matching attribution.
	goodDir := filepath.Join(dir, "agent-a|10.0.0.1")
	if err := os.MkdirAll(goodDir, 0o750); err != nil {
		t.Fatalf("MkdirAll good: %v", err)
	}
	good := filepath.Join(goodDir, "capture.jsonl")
	if err := os.WriteFile(good, captureJSONL("agent-a"), 0o600); err != nil {
		t.Fatalf("WriteFile good: %v", err)
	}

	// Planted sibling whose name passes the agent-a prefix match but whose
	// content attributes the traffic to a different agent. Must be skipped:
	// otherwise an attacker who can write to the capture root could silently
	// poison agent-a's compile inputs simply by naming a directory with the
	// agent prefix.
	poisonDir := filepath.Join(dir, "agent-a|poison")
	if err := os.MkdirAll(poisonDir, 0o750); err != nil {
		t.Fatalf("MkdirAll poison: %v", err)
	}
	poison := filepath.Join(poisonDir, "capture.jsonl")
	if err := os.WriteFile(poison, captureJSONL("evil-agent"), 0o600); err != nil {
		t.Fatalf("WriteFile poison: %v", err)
	}

	cfg := config.Defaults()
	cfg.Learn.CaptureDir = dir
	got, err := resolveCompileInputs(cfg, compileFlags{agent: "agent-a", since: time.Hour})
	if err != nil {
		t.Fatalf("resolveCompileInputs: %v", err)
	}
	if len(got) != 1 || got[0] != good {
		t.Fatalf("paths = %#v, want only [%q] (poison must be filtered)", got, good)
	}
}

func TestResolveCompileInputsRejectsSymlinkInput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target.jsonl")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	cfg := config.Defaults()

	_, err := resolveCompileInputs(cfg, compileFlags{agent: "agent-a", inputGlob: link, since: time.Hour})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("resolveCompileInputs symlink error = %v, want symlink rejection", err)
	}
}

func TestResolveCompileInputsRejectsSymlinkedCaptureRootEscape(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	captureRoot := filepath.Join(dir, "captures")
	if err := os.MkdirAll(captureRoot, 0o750); err != nil {
		t.Fatalf("MkdirAll captureRoot: %v", err)
	}
	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatalf("MkdirAll outside: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "capture.jsonl"), captureJSONL("agent-a"), 0o600); err != nil {
		t.Fatalf("WriteFile outside capture: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(captureRoot, "agent-a")); err != nil {
		t.Fatalf("Symlink agent dir: %v", err)
	}
	cfg := config.Defaults()
	cfg.Learn.CaptureDir = captureRoot

	_, err := resolveCompileInputs(cfg, compileFlags{agent: "agent-a", since: time.Hour})
	if err == nil || !strings.Contains(err.Error(), "escapes learn.capture_dir") {
		t.Fatalf("resolveCompileInputs error = %v, want capture root escape rejection", err)
	}
}

func TestReadCompileInputsCountsAppendedNewline(t *testing.T) {
	t.Parallel()
	input := filepath.Join(t.TempDir(), "capture.jsonl")
	if err := os.WriteFile(input, []byte("{}\n{}"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	stream, refs, err := readCompileInputs([]string{input})
	if err != nil {
		t.Fatalf("readCompileInputs: %v", err)
	}
	data, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(data) != "{}\n{}\n" {
		t.Fatalf("stream = %q, want appended newline", data)
	}
	if len(refs) != 1 || refs[0].EventCount != 2 {
		t.Fatalf("refs = %#v, want event_count 2", refs)
	}
}

func TestRunCompileWritesArtifactsAndAudit(t *testing.T) {
	t.Setenv("TZ", "")
	t.Setenv("LC_ALL", "")

	dir := t.TempDir()
	input := filepath.Join(dir, "capture.jsonl")
	if err := os.WriteFile(input, []byte(compileFixtureJSONL(t)), 0o600); err != nil {
		t.Fatalf("WriteFile input: %v", err)
	}
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
learn:
  inference:
    floors:
      min_sessions: 1
      min_events: 1
      min_windows: 1
`), 0o600); err != nil {
		t.Fatalf("WriteFile config: %v", err)
	}
	output := filepath.Join(dir, "candidate.yaml")
	review := filepath.Join(dir, "candidate.review.md")
	manifest := filepath.Join(dir, "candidate.manifest.json")
	var stdout, stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := runCompile(cmd, compileFlags{
		agent:         "agent-a",
		inputGlob:     input,
		output:        output,
		review:        review,
		manifest:      manifest,
		configPath:    cfgPath,
		deterministic: true,
	})
	if err != nil {
		t.Fatalf("runCompile: %v\nstderr:\n%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "compile: 3 events") {
		t.Fatalf("stdout = %q, want compile summary", stdout.String())
	}
	if !strings.Contains(stderr.String(), `"event":"learn_compile"`) ||
		!strings.Contains(stderr.String(), `"signer_key_id":"deterministic-contract-compile"`) {
		t.Fatalf("stderr audit event missing expected fields:\n%s", stderr.String())
	}
	for _, check := range []struct {
		path string
		want string
	}{
		{path: output, want: "agent-a"},
		{path: review, want: "Capture Fidelity"},
		{path: manifest, want: "deterministic-contract-compile"},
	} {
		data, err := os.ReadFile(check.path)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", check.path, err)
		}
		if !strings.Contains(string(data), check.want) {
			t.Fatalf("%s missing %q:\n%s", check.path, check.want, string(data))
		}
	}
}

func TestResolveCompileOutputsRejectsOverlappingPaths(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	output := filepath.Join(dir, "candidate.yaml")
	manifest := filepath.Join(dir, "manifest.json")

	_, _, _, err := resolveCompileOutputs(compileFlags{
		agent:    "agent-a",
		output:   output,
		review:   output,
		manifest: manifest,
	})
	if err == nil || !strings.Contains(err.Error(), "overlaps output") {
		t.Fatalf("resolveCompileOutputs error = %v, want overlap rejection", err)
	}
}

func TestResolveCompileOutputsDefaultPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PIPELOCK_HOME", home)

	output, review, manifest, err := resolveCompileOutputs(compileFlags{agent: "agent-a"})
	if err != nil {
		t.Fatalf("resolveCompileOutputs: %v", err)
	}
	wantBase := filepath.Join(home, "contracts", "candidates")
	if output != filepath.Join(wantBase, "agent-a.candidate.yaml") {
		t.Fatalf("output = %q, want default candidate under %q", output, wantBase)
	}
	if review != filepath.Join(wantBase, "agent-a.candidate.review.md") {
		t.Fatalf("review = %q, want default review sibling", review)
	}
	if manifest != filepath.Join(wantBase, "agent-a.candidate.manifest.json") {
		t.Fatalf("manifest = %q, want default manifest sibling", manifest)
	}
	if info, err := os.Stat(wantBase); err != nil || !info.IsDir() {
		t.Fatalf("default candidate dir stat = %v, info=%v", err, info)
	}
}

func TestResolveCompileOutputsRejectsManifestReviewOverlap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	output := filepath.Join(dir, "candidate.yaml")
	reviewAndManifest := filepath.Join(dir, "same.json")

	_, _, _, err := resolveCompileOutputs(compileFlags{
		agent:    "agent-a",
		output:   output,
		review:   reviewAndManifest,
		manifest: reviewAndManifest,
	})
	if err == nil || !strings.Contains(err.Error(), "overlaps review") {
		t.Fatalf("resolveCompileOutputs error = %v, want review/manifest overlap rejection", err)
	}
}

func TestContractsCandidateDirUsesResolvedHome(t *testing.T) {
	home := t.TempDir()
	oldHomeFlag := cliutil.PipelockHome
	cliutil.PipelockHome = filepath.Join(home, "flag-home")
	t.Cleanup(func() { cliutil.PipelockHome = oldHomeFlag })
	t.Setenv("PIPELOCK_HOME", filepath.Join(home, "env-home"))

	got, err := contractsCandidateDir()
	if err != nil {
		t.Fatalf("contractsCandidateDir: %v", err)
	}
	want := filepath.Join(home, "flag-home", "contracts", "candidates")
	if got != want {
		t.Fatalf("contractsCandidateDir = %q, want %q", got, want)
	}
}

func TestCompileConfigMapsResolvedInferenceSettings(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Learn.Inference.Floors.MinSessions = 7
	cfg.Learn.Inference.Floors.MinEvents = 51
	cfg.Learn.Inference.Floors.MinWindows = 4
	cfg.Learn.Inference.Normalization.MinEvents = 11
	cfg.Learn.Inference.Normalization.MinDistinctValues = 6
	cfg.Learn.Inference.Normalization.EntropyThresholdBits = 4.25
	cfg.Learn.Inference.Normalization.ReservedSegmentsExtra = []string{"tenant"}
	cfg.Learn.Inference.Normalization.CardinalityCapPerHost = 222
	cfg.Learn.Inference.Normalization.TailPromotionBlockPct = 8.5
	refs := []contract.InputRef{{Path: "/tmp/capture.jsonl", SHA256: "sha256:abc", EventCount: 3}}

	got := compileConfig("agent-a", cfg, refs)
	if got.Agent != "agent-a" {
		t.Fatalf("Agent = %q, want agent-a", got.Agent)
	}
	if got.Floors.MinSessions != 7 || got.Floors.MinEvents != 51 || got.Floors.MinWindows != 4 {
		t.Fatalf("Floors = %#v, want configured values", got.Floors)
	}
	if got.Normalization.MinEvents != 11 ||
		got.Normalization.MinDistinctValues != 6 ||
		got.Normalization.EntropyThresholdBits != 4.25 ||
		len(got.Normalization.ReservedExtras) != 1 ||
		got.Normalization.ReservedExtras[0] != "tenant" {
		t.Fatalf("Normalization = %#v, want configured values", got.Normalization)
	}
	if got.Cardinality.CardinalityCapPerHost != 222 || got.Cardinality.TailPromotionBlockPct != 8.5 {
		t.Fatalf("Cardinality = %#v, want configured values", got.Cardinality)
	}
	if len(got.InputRefs) != 1 || got.InputRefs[0] != refs[0] {
		t.Fatalf("InputRefs = %#v, want %#v", got.InputRefs, refs)
	}
	if got.CompileConfigHash == "" {
		t.Fatal("CompileConfigHash is empty")
	}
	normalization, ok := got.Settings["normalization"].(map[string]any)
	if !ok || normalization["algorithm"] != config.LearnNormalizationAlgorithmV1 {
		t.Fatalf("normalization settings = %#v, want algorithm %q", got.Settings["normalization"], config.LearnNormalizationAlgorithmV1)
	}
}

func TestDecodeOptionalHex(t *testing.T) {
	t.Parallel()
	valid := strings.Repeat("0a", 32)
	got, err := decodeOptionalHex(" " + valid + " ")
	if err != nil {
		t.Fatalf("decodeOptionalHex valid: %v", err)
	}
	if len(got) != 32 || got[0] != 0x0a || got[31] != 0x0a {
		t.Fatalf("decoded = %x, want 32 bytes of 0a", got)
	}

	if got, err := decodeOptionalHex(" \t "); err != nil || got != nil {
		t.Fatalf("decodeOptionalHex blank = %x, %v; want nil, nil", got, err)
	}
	for _, value := range []string{"zz", strings.Repeat("01", 31)} {
		if _, err := decodeOptionalHex(value); err == nil {
			t.Fatalf("decodeOptionalHex(%q) error = nil, want validation error", value)
		}
	}
}

func TestResolveCompileSignerDeterministic(t *testing.T) {
	t.Parallel()
	signer, err := resolveCompileSigner(compileFlags{agent: "agent-a", deterministic: true})
	if err != nil {
		t.Fatalf("resolveCompileSigner deterministic: %v", err)
	}
	if signer.KeyID() != "deterministic-contract-compile" {
		t.Fatalf("KeyID = %q, want deterministic-contract-compile", signer.KeyID())
	}
	msg := []byte("contract payload")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	seed := sha256.Sum256([]byte("pipelock deterministic compile signer"))
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("deterministic signer signature did not verify")
	}
}

func TestResolveCompileSignerLoadsKeystoreAgent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := signing.NewKeystore(dir).ForceGenerateAgent("compile-alpha"); err != nil {
		t.Fatalf("ForceGenerateAgent: %v", err)
	}
	signer, err := resolveCompileSigner(compileFlags{
		agent:           "runtime-agent",
		compileKeyAgent: "compile-alpha",
		keystore:        dir,
	})
	if err != nil {
		t.Fatalf("resolveCompileSigner keystore: %v", err)
	}
	if signer.KeyID() != "compile-alpha" {
		t.Fatalf("KeyID = %q, want compile-alpha", signer.KeyID())
	}
	pub, err := signing.NewKeystore(dir).LoadPublicKey("compile-alpha")
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	msg := []byte("manifest")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("keystore signer signature did not verify")
	}
}

func TestResolveCompileSignerDefaultsKeyAgentAndErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := signing.NewKeystore(dir).ForceGenerateAgent("runtime-agent"); err != nil {
		t.Fatalf("ForceGenerateAgent: %v", err)
	}
	signer, err := resolveCompileSigner(compileFlags{agent: "runtime-agent", keystore: dir})
	if err != nil {
		t.Fatalf("resolveCompileSigner default agent: %v", err)
	}
	if signer.KeyID() != "runtime-agent" {
		t.Fatalf("KeyID = %q, want runtime-agent", signer.KeyID())
	}
	if _, err := resolveCompileSigner(compileFlags{agent: "missing-agent", keystore: dir}); err == nil {
		t.Fatal("resolveCompileSigner missing key error = nil, want error")
	}
}

func TestEnsureEnvDefault(t *testing.T) {
	key := "PIPELOCK_TEST_ENSURE_ENV_DEFAULT"
	t.Setenv(key, "")
	ensureEnvDefault(key, "fallback")
	if got := os.Getenv(key); got != "fallback" {
		t.Fatalf("env after default = %q, want fallback", got)
	}
	t.Setenv(key, "explicit")
	ensureEnvDefault(key, "fallback")
	if got := os.Getenv(key); got != "explicit" {
		t.Fatalf("env after explicit = %q, want explicit", got)
	}
}

func compileFixtureJSONL(t *testing.T) string {
	t.Helper()
	first := compileRecorderEntry(t, 1, recorder.GenesisHash, "https://api.vendor.example/v1/users")
	second := compileRecorderEntry(t, 2, first.Hash, "https://api.vendor.example/v1/repos")
	third := compileRecorderEntry(t, 3, second.Hash, "https://api.vendor.example/v1/users")
	return compileJSONLines(t, first, second, third)
}

func compileRecorderEntry(t *testing.T, seq int, prevHash, rawURL string) recorder.Entry {
	t.Helper()
	var sequence uint64
	switch seq {
	case 1:
		sequence = 1
	case 2:
		sequence = 2
	case 3:
		sequence = 3
	default:
		t.Fatalf("unexpected fixture sequence %d", seq)
	}
	rec := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  sequence,
		Timestamp: time.Date(2026, 4, 29, 12, 0, seq, 0, time.UTC),
		SessionID: fmt.Sprintf("session-%d", seq),
		Type:      capture.EntryTypeCapture,
		EventKind: "read",
		Transport: "fetch",
		Summary:   "captured",
		Detail: capture.CaptureSummary{
			CaptureSchemaVersion: capture.CaptureSchemaV1,
			Surface:              capture.SurfaceURL,
			ActionClass:          "read",
			PayloadBytes:         seq * 10,
			ScannerBytes:         seq * 100,
			EffectiveAction:      config.ActionAllow,
			Request: capture.CaptureRequest{
				Method: "GET",
				URL:    rawURL,
			},
		},
		PrevHash: prevHash,
	}
	rec.Hash = recorder.ComputeHash(rec)
	return rec
}

func compileJSONLines(t *testing.T, entries ...recorder.Entry) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, entry := range entries {
		if err := enc.Encode(entry); err != nil {
			t.Fatalf("encode entry: %v", err)
		}
	}
	return buf.String()
}
