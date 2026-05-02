// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference"
	contractcompile "github.com/luckyPipewrench/pipelock/internal/contract/inference/compile"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// -update regenerates every harness golden file. Refresh procedure:
//
//	go test ./internal/capture -run TestReplayHarness -update
//
// Inspect the resulting diff manually before committing. Goldens are the
// regression-detection contract for the learn-and-lock pipeline; an
// unintentional drift here means a compile / scanner / contract-eval logic
// change altered the byte output.
var updateHarnessGoldens = flag.Bool("update", false, "regenerate replay-harness golden files")

const (
	harnessGoldenDir         = "testdata/replay-corpus/golden"
	harnessAgent             = "harness-agent"
	harnessOriginalHash      = "sha256:harness-original-config"
	harnessCandidateHash     = "sha256:harness-candidate-config"
	harnessBuildVersion      = "harness"
	harnessBuildSHA          = "harness"
	harnessGoldenContract    = "contract.yaml"
	harnessGoldenManifest    = "contract.manifest.json"
	harnessGoldenReview      = "review.md"
	harnessGoldenReplayDiff  = "replay-diff.json"
	harnessGoldenCorpusJSONL = "corpus.jsonl"
)

// harnessBaseTime fixes the deterministic timestamp floor for harness
// recorder entries. Each entry's timestamp is harnessBaseTime + sequence
// seconds, so adding records changes only the new entries' hashes.
var harnessBaseTime = time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)

// harnessSigner is a deterministic ed25519 signer used by the compile path
// during golden generation. The seed is the SHA-256 of a fixed phrase, so
// signatures are stable across runs without needing on-disk keystores.
type harnessSigner struct {
	priv ed25519.PrivateKey
}

func newHarnessSigner() harnessSigner {
	seed := sha256.Sum256([]byte("replay-harness-deterministic-signer"))
	return harnessSigner{priv: ed25519.NewKeyFromSeed(seed[:])}
}

func (s harnessSigner) KeyID() string { return "harness-contract-compile" }

func (s harnessSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

// recordSpec is one capture entry in the synthetic corpus.
type recordSpec struct {
	surface         string
	subsurface      string
	transport       string
	actionClass     string
	request         capture.CaptureRequest
	rawFindings     []capture.Finding
	effectiveAction string
	outcome         string
	transformKind   string
}

// sessionSpec is one session's deterministic record list.
type sessionSpec struct {
	sessionID string
	records   []recordSpec
}

// harnessCorpus returns the canonical synthetic corpus. The shape is locked
// for v2.4: 3 sessions, ~12 records each, mix of URL / DLP / response /
// tool_policy surfaces, mix of allow / block / warn original outcomes. Adding
// records means appending sessions or appending to the tail of an existing
// session — never rewriting earlier records, since that would mask whether a
// regression caused a golden drift.
func harnessCorpus() []sessionSpec {
	return []sessionSpec{
		{
			sessionID: "session-001",
			records: []recordSpec{
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/users"),
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/repos"),
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/users"),
				allowedURLSpec("forward", http.MethodPost, "https://api.example.com/v1/repos"),
				allowedURLSpec("forward", http.MethodGet, "https://docs.example.com/guide"),
				blockedURLSpec(http.MethodGet, "https://exfil.example.net/sink"),
				dlpSpec("forward", http.MethodPost, "https://api.example.com/v1/users"),
				toolPolicyAllowSpec("read_file", `{"path":"/tmp/notes.md"}`),
				toolPolicyBlockSpec("write_file", `{"path":"/etc/hosts","content":"x"}`),
				responseSpec("forward", http.MethodGet, "https://docs.example.com/guide"),
				warnedURLSpec("forward", http.MethodPost, "https://api.example.com/v1/repos"),
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/users"),
			},
		},
		{
			sessionID: "session-002",
			records: []recordSpec{
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/users"),
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/orgs"),
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/users"),
				allowedURLSpec("forward", http.MethodPost, "https://api.example.com/v1/repos"),
				allowedURLSpec("intercept", http.MethodGet, "https://docs.example.com/guide"),
				dlpSpec("intercept", http.MethodPost, "https://api.example.com/v1/users"),
				blockedURLSpec(http.MethodGet, "https://exfil.example.net/sink"),
				blockedURLSpec(http.MethodPost, "https://exfil.example.net/upload"),
				toolPolicyAllowSpec("read_file", `{"path":"/var/log/app.log"}`),
				responseSpec("intercept", http.MethodGet, "https://docs.example.com/guide"),
				warnedURLSpec("forward", http.MethodPost, "https://api.example.com/v1/repos"),
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/users"),
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/repos"),
			},
		},
		{
			sessionID: "session-003",
			records: []recordSpec{
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/users"),
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/users"),
				allowedURLSpec("forward", http.MethodPost, "https://api.example.com/v1/repos"),
				allowedURLSpec("forward", http.MethodGet, "https://docs.example.com/guide"),
				warnedURLSpec("forward", http.MethodPost, "https://api.example.com/v1/repos"),
				blockedURLSpec(http.MethodGet, "https://exfil.example.net/sink"),
				dlpSpec("forward", http.MethodPost, "https://api.example.com/v1/users"),
				toolPolicyAllowSpec("read_file", `{"path":"/tmp/notes.md"}`),
				responseSpec("forward", http.MethodGet, "https://docs.example.com/guide"),
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/users"),
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/orgs"),
				allowedURLSpec("forward", http.MethodGet, "https://api.example.com/v1/users"),
			},
		},
	}
}

// allowedURLSpec, blockedURLSpec, warnedURLSpec each fix a specific
// (action, outcome, surface) tuple so the corpus stays explicit. Per-record
// callers vary only the transport, method, URL, and (for blocked/warned) the
// finding pattern. unparam flagged earlier signatures because the variable
// fields are constants in practice — we keep the constants out of the
// signature to make the corpus declaration easier to read at the call site.
func allowedURLSpec(transport, method, url string) recordSpec {
	return recordSpec{
		surface:         capture.SurfaceURL,
		subsurface:      transport,
		transport:       transport,
		actionClass:     "read",
		request:         capture.CaptureRequest{Method: method, URL: url},
		effectiveAction: config.ActionAllow,
		outcome:         capture.OutcomeClean,
	}
}

func blockedURLSpec(method, url string) recordSpec {
	const transport = "forward"
	const pattern = "test_blocklist"
	finding := capture.Finding{
		Kind:        capture.KindDLP,
		Action:      config.ActionBlock,
		PatternName: pattern,
	}
	return recordSpec{
		surface:         capture.SurfaceURL,
		subsurface:      transport,
		transport:       transport,
		actionClass:     "network",
		request:         capture.CaptureRequest{Method: method, URL: url},
		rawFindings:     []capture.Finding{finding},
		effectiveAction: config.ActionBlock,
		outcome:         capture.OutcomeBlocked,
	}
}

func warnedURLSpec(transport, method, url string) recordSpec {
	const pattern = "soft_signal"
	finding := capture.Finding{
		Kind:        capture.KindInjection,
		Action:      config.ActionWarn,
		PatternName: pattern,
	}
	return recordSpec{
		surface:         capture.SurfaceURL,
		subsurface:      transport,
		transport:       transport,
		actionClass:     "write",
		request:         capture.CaptureRequest{Method: method, URL: url},
		rawFindings:     []capture.Finding{finding},
		effectiveAction: config.ActionWarn,
		outcome:         capture.OutcomeWarned,
	}
}

func dlpSpec(transport, method, url string) recordSpec {
	return recordSpec{
		surface:         capture.SurfaceDLP,
		subsurface:      transport,
		transport:       transport,
		actionClass:     "write",
		request:         capture.CaptureRequest{Method: method, URL: url},
		effectiveAction: config.ActionAllow,
		outcome:         capture.OutcomeClean,
		transformKind:   capture.TransformRaw,
	}
}

func responseSpec(transport, method, url string) recordSpec {
	return recordSpec{
		surface:         capture.SurfaceResponse,
		subsurface:      transport,
		transport:       transport,
		actionClass:     "read",
		request:         capture.CaptureRequest{Method: method, URL: url},
		effectiveAction: config.ActionAllow,
		outcome:         capture.OutcomeClean,
		transformKind:   capture.TransformReadability,
	}
}

// toolPolicyBaseSpec is the common shape for an MCP tool_policy capture.
// allow and block variants below set effective_action / outcome / findings
// appropriately and stay simple at the call site so unparam doesn't flag
// always-the-same parameters.
func toolPolicyBaseSpec(toolName, argsJSON string) recordSpec {
	return recordSpec{
		surface:    capture.SurfaceToolPolicy,
		subsurface: "mcp_stdio",
		transport:  "mcp_stdio",
		// Tool calls map to the "exec" action class — they trigger a
		// side-effecting tool invocation regardless of the underlying verb.
		actionClass: "exec",
		request: capture.CaptureRequest{
			ToolName:     toolName,
			ToolArgsJSON: argsJSON,
			MCPMethod:    "tools/call",
		},
	}
}

func toolPolicyAllowSpec(toolName, argsJSON string) recordSpec {
	spec := toolPolicyBaseSpec(toolName, argsJSON)
	spec.effectiveAction = config.ActionAllow
	spec.outcome = capture.OutcomeClean
	return spec
}

func toolPolicyBlockSpec(toolName, argsJSON string) recordSpec {
	spec := toolPolicyBaseSpec(toolName, argsJSON)
	spec.effectiveAction = config.ActionBlock
	spec.outcome = capture.OutcomeBlocked
	spec.rawFindings = []capture.Finding{{
		Kind:       capture.KindToolPolicy,
		Action:     config.ActionBlock,
		PolicyRule: "system_file_deny",
	}}
	return spec
}

// harnessSeq is a positive monotonic sequence number used for both the
// global timestamp stride and the per-session entry sequence. Using a
// signed int (instead of uint64) lets time.Duration cast cleanly without
// gosec G115 firing on the uint64->int64 conversion.
type harnessSeq int

// makeEntry constructs a recorder.Entry with the given chain coordinates.
// Caller computes Hash via recorder.ComputeHash after the entry is fully
// populated. Timestamp is harnessBaseTime + globalSeq seconds so timestamps
// are stable across both chain renderings. perSessionSeq is converted to
// the recorder's uint64 Sequence field via the same negative-clamping
// pattern as compile.IntToUint64 so gosec recognizes the non-negative
// guard.
func makeEntry(spec recordSpec, sessionID string, globalSeq, perSessionSeq harnessSeq, prevHash string) recorder.Entry {
	entry := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  contractcompile.IntToUint64(int(perSessionSeq)),
		Timestamp: harnessBaseTime.Add(time.Duration(globalSeq) * time.Second),
		SessionID: sessionID,
		Type:      capture.EntryTypeCapture,
		EventKind: spec.surface,
		Transport: spec.transport,
		Summary:   "captured",
		PrevHash:  prevHash,
		Detail: capture.CaptureSummary{
			CaptureSchemaVersion: capture.CaptureSchemaV1,
			Surface:              spec.surface,
			Subsurface:           spec.subsurface,
			ConfigHash:           harnessOriginalHash,
			BuildVersion:         harnessBuildVersion,
			BuildSHA:             harnessBuildSHA,
			Agent:                harnessAgent,
			Profile:              "harness",
			ActionClass:          spec.actionClass,
			TransformKind:        spec.transformKind,
			Request:              spec.request,
			RawFindings:          spec.rawFindings,
			EffectiveFindings:    spec.rawFindings,
			EffectiveAction:      spec.effectiveAction,
			Outcome:              spec.outcome,
		},
	}
	entry.Hash = recorder.ComputeHash(entry)
	return entry
}

// buildContinuousEntries renders the corpus as ONE continuous hash-chain
// across every session, in declaration order. This is the format compile
// ingests, since the inference Stream verifies a single PrevHash/Hash chain
// across the whole input. SessionID varies across the chain (compile counts
// distinct sessions via the SessionID field, not via chain resets).
func buildContinuousEntries(t *testing.T) []recorder.Entry {
	t.Helper()
	var entries []recorder.Entry
	prev := recorder.GenesisHash
	var globalSeq harnessSeq
	for _, sess := range harnessCorpus() {
		for _, spec := range sess.records {
			globalSeq++
			entry := makeEntry(spec, sess.sessionID, globalSeq, globalSeq, prev)
			entries = append(entries, entry)
			prev = entry.Hash
		}
	}
	return entries
}

// buildPerSessionEntries renders the corpus as one independent hash-chain
// per session (each starting at recorder.GenesisHash). This is the format
// the replay path expects, since LoadAndReplay loads each session's
// evidence file separately and downstream readers may verify the
// per-session chain. Entry timestamps still stride globally so corpus
// ordering remains explicit.
func buildPerSessionEntries(t *testing.T) map[string][]recorder.Entry {
	t.Helper()
	out := make(map[string][]recorder.Entry, 3)
	var globalSeq harnessSeq
	for _, sess := range harnessCorpus() {
		entries := make([]recorder.Entry, 0, len(sess.records))
		prev := recorder.GenesisHash
		var perSessionSeq harnessSeq
		for _, spec := range sess.records {
			globalSeq++
			perSessionSeq++
			entry := makeEntry(spec, sess.sessionID, globalSeq, perSessionSeq, prev)
			entries = append(entries, entry)
			prev = entry.Hash
		}
		out[sess.sessionID] = entries
	}
	return out
}

// harnessCorpusJSONL serializes one session's hash-chained entries to JSONL
// bytes using the recorder's canonical newline-terminated encoding.
func harnessCorpusJSONL(t *testing.T, entries []recorder.Entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, entry := range entries {
		if err := enc.Encode(entry); err != nil {
			t.Fatalf("encode entry: %v", err)
		}
	}
	return buf.Bytes()
}

// continuousCorpusJSONL renders every entry in the continuous chain to a
// single JSONL stream and returns the deterministic InputRef set compile
// uses for manifest pinning. The InputRef path string is a stable virtual
// path (not the on-disk testdata location), so the manifest does not depend
// on tempdir randomness.
func continuousCorpusJSONL(t *testing.T, entries []recorder.Entry) ([]byte, []contract.InputRef) {
	t.Helper()
	jsonl := harnessCorpusJSONL(t, entries)
	sum := sha256.Sum256(jsonl)
	refs := []contract.InputRef{{
		Path:       "testdata/replay-corpus/observations/corpus.jsonl",
		SHA256:     "sha256:" + hex.EncodeToString(sum[:]),
		EventCount: uint64(len(entries)),
	}}
	return jsonl, refs
}

// writeHarnessSessions writes each session's JSONL into the directory layout
// that capture.LoadAndReplay enumerates: <root>/<session_id>/evidence-<session_id>-1.jsonl.
func writeHarnessSessions(t *testing.T, root string, sessions map[string][]recorder.Entry) {
	t.Helper()
	for sid, entries := range sessions {
		sessionDir := filepath.Join(root, sid)
		if err := os.MkdirAll(sessionDir, 0o750); err != nil {
			t.Fatalf("mkdir session dir: %v", err)
		}
		path := filepath.Join(sessionDir, fmt.Sprintf("evidence-%s-1.jsonl", sid))
		jsonl := harnessCorpusJSONL(t, entries)
		if err := os.WriteFile(path, jsonl, 0o600); err != nil {
			t.Fatalf("write evidence file: %v", err)
		}
	}
}

// harnessCompileConfig returns the deterministic compile config used by every
// harness golden invocation. Floors are tuned so the small corpus actually
// emits rules; in production these live in pipelock config.
//
// Provenance fields (PipelockVersion, PipelockBuildSHA, GoVersion,
// ModuleDigestRoot) are pinned to synthetic constants here to keep the
// goldens byte-stable across the Go-version CI matrix and across developer
// machines. Without pinning, the emit layer would auto-fill GoVersion from
// runtime.Version() and ModuleDigestRoot from debug.ReadBuildInfo(),
// breaking the Go 1.26 CI leg the moment it ran.
func harnessCompileConfig(refs []contract.InputRef) contractcompile.CompileConfig {
	return contractcompile.CompileConfig{
		Agent:             harnessAgent,
		Floors:            inference.Floors{MinSessions: 1, MinEvents: 1, MinWindows: 1},
		CompileConfigHash: harnessOriginalHash,
		InputRefs:         refs,
		PipelockVersion:   "harness-pipelock-version",
		PipelockBuildSHA:  "harness-pipelock-sha",
		GoVersion:         "harness-go-version",
		ModuleDigestRoot:  "sha256:harness-module-digest-root",
		Settings: map[string]any{
			"confidence":    map[string]any{"min_events": 1},
			"normalization": map[string]any{},
		},
	}
}

// harnessCandidateConfig returns the candidate pipelock config that the
// replay harness scans against. It blocks `exfil.example.net` (matching
// blocked URL records) and `docs.example.com` (matching previously-allowed
// records, so the replay diff produces new_block deltas the golden snapshot
// can prove are stable).
//
// CRITICAL — tool policy invariant. The candidate MUST configure a
// tool-policy deny rule for system-file writes (matching the corpus's
// `write_file` to `/etc/hosts` record). Without it the original block
// becomes a `new_allow` in the replay diff, which would bake a privilege-
// boundary weakening into the regression corpus and let future tool-policy
// bypasses look like expected behavior. See the GPT review on PR #468 (high
// severity) for the original finding.
func harnessCandidateConfig() *config.Config {
	cfg := config.Defaults()
	// SSRF off: tests don't have DNS access in CI, and the harness is
	// proving compile / replay determinism, not network behavior.
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.Blocklist = []string{
		"exfil.example.net",
		"docs.example.com",
	}
	cfg.MCPToolPolicy = config.MCPToolPolicy{
		Enabled: true,
		Action:  config.ActionBlock,
		Rules: []config.ToolPolicyRule{
			{
				Name:        "system_file_deny",
				ToolPattern: `^write_file$`,
				ArgKey:      `^path$`,
				ArgPattern:  `^/etc/`,
				Action:      config.ActionBlock,
			},
		},
	}
	return cfg
}

// readGolden reads a golden file. If -update was passed the file may not
// exist on the first run; the caller writes it via writeGolden.
func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join(harnessGoldenDir, name)))
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to create)", name, err)
	}
	return data
}

// writeGolden writes a golden file under the testdata directory. Used only
// when -update is passed.
func writeGolden(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(harnessGoldenDir, 0o750); err != nil {
		t.Fatalf("mkdir golden dir: %v", err)
	}
	path := filepath.Join(harnessGoldenDir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write golden %s: %v", name, err)
	}
}

// assertGolden compares got against the named golden file. With -update it
// writes the golden first so subsequent runs assert against the new bytes.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	if *updateHarnessGoldens {
		writeGolden(t, name, got)
		return
	}
	want := readGolden(t, name)
	if !bytes.Equal(got, want) {
		t.Fatalf("golden %s drifted; rerun with -update after reviewing the diff.\n--- want first 200 bytes:\n%s\n--- got first 200 bytes:\n%s",
			name, truncate(want, 200), truncate(got, 200))
	}
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

// stableManifestPlaceholder replaces the module_digest_root field in the
// manifest before golden comparison. The emit layer's buildManifest() always
// recomputes ModuleDigestRoot from debug.ReadBuildInfo() regardless of the
// pinned CompileConfig.ModuleDigestRoot, so a raw byte-comparison would fail
// across Go-version CI legs and across developer machines whose go.sum
// resolves a different stdlib build info hash. The contract YAML is the
// load-bearing signed artifact and stays byte-stable; the manifest is a
// human-readable provenance sidecar where this single field can vary.
const stableManifestPlaceholder = "sha256:HARNESS-PLACEHOLDER"

// stableManifestModuleDigests is the redacted module_digests value the
// stabilized manifest carries instead of the build-info-derived map.
var stableManifestModuleDigestsValue = map[string]string{
	"harness-stable-placeholder": stableManifestPlaceholder,
}

// stabilizeManifest validates the build-info-derived fields of a compile
// manifest STRUCTURALLY (presence + shape), then replaces them with
// placeholders so the rest of the manifest can be byte-compared against a
// golden. This is stricter than wholesale replacement: provenance
// regressions where the fields disappear, become malformed, or carry the
// wrong shape still fail CI. See the GPT review on PR #468 (medium
// severity) for the original finding.
func stabilizeManifest(t *testing.T, raw []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	body, ok := doc["body"].(map[string]any)
	if !ok {
		t.Fatalf("manifest body is not a map: %T", doc["body"])
	}

	// module_digest_root must exist and be a non-empty sha256:<hex> string.
	root, present := body["module_digest_root"]
	if !present {
		t.Fatal("manifest missing module_digest_root: provenance regression")
	}
	rootStr, ok := root.(string)
	if !ok {
		t.Fatalf("manifest module_digest_root is not a string: %T", root)
	}
	if !strings.HasPrefix(rootStr, "sha256:") || len(rootStr) <= len("sha256:") {
		t.Fatalf("manifest module_digest_root malformed: %q (want sha256:<hex>)", rootStr)
	}
	body["module_digest_root"] = stableManifestPlaceholder

	// module_digests must exist, be a non-empty map, and every value must be
	// a sha256:<hex> string. The map's keys are module paths from
	// debug.ReadBuildInfo; we don't constrain the keys themselves because
	// they're environment-derived (which is the whole reason we stabilize).
	digests, present := body["module_digests"]
	if !present {
		t.Fatal("manifest missing module_digests: provenance regression")
	}
	digestsMap, ok := digests.(map[string]any)
	if !ok {
		t.Fatalf("manifest module_digests is not a map: %T", digests)
	}
	if len(digestsMap) == 0 {
		t.Fatal("manifest module_digests is empty: provenance regression")
	}
	for k, v := range digestsMap {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("manifest module_digests[%q] is not a string: %T", k, v)
		}
		if !strings.HasPrefix(s, "sha256:") || len(s) <= len("sha256:") {
			t.Fatalf("manifest module_digests[%q] malformed: %q", k, s)
		}
	}
	stable := make(map[string]any, len(stableManifestModuleDigestsValue))
	for k, v := range stableManifestModuleDigestsValue {
		stable[k] = v
	}
	body["module_digests"] = stable

	// Re-marshal with the same indentation Compile.Emit uses (two spaces) so
	// the rest of the bytes match the original encoder output exactly.
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	out = append(out, '\n')
	return out
}

// runHarnessCompile compiles the synthetic corpus deterministically and
// returns the contract YAML, manifest JSON, review markdown.
func runHarnessCompile(t *testing.T, entries []recorder.Entry) (contractcompile.CompileResult, []byte) {
	t.Helper()
	combined, refs := continuousCorpusJSONL(t, entries)
	cfg := harnessCompileConfig(refs)
	result, err := contractcompile.Compile(
		contractcompile.CompileInput{
			Stream: bytes.NewReader(combined),
			Config: cfg,
		},
		contractcompile.CompileOptions{
			Deterministic: true,
			Signer:        newHarnessSigner(),
		},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return result, combined
}

// TestReplayHarness_CorpusJSONLMatchesGolden snapshots the rendered
// continuous-chain corpus JSONL. If the corpus-builder helper drifts (e.g.
// a new CaptureSummary field), this test fails before the downstream
// goldens drift, which makes regressions easier to localize.
func TestReplayHarness_CorpusJSONLMatchesGolden(t *testing.T) {
	t.Parallel()
	entries := buildContinuousEntries(t)
	combined, _ := continuousCorpusJSONL(t, entries)
	assertGolden(t, harnessGoldenCorpusJSONL, combined)
}

// TestReplayHarness_CompileDeterministic compiles the corpus twice and
// asserts byte-identical artifacts. Catches non-determinism in compile (
// random salt, unsorted iteration, time.Now misuse) at the harness level.
func TestReplayHarness_CompileDeterministic(t *testing.T) {
	t.Parallel()
	entries := buildContinuousEntries(t)
	first, _ := runHarnessCompile(t, entries)
	second, _ := runHarnessCompile(t, entries)

	if !bytes.Equal(first.YAML, second.YAML) {
		t.Fatal("contract YAML differs across two compile runs")
	}
	if !bytes.Equal(first.ManifestJSON, second.ManifestJSON) {
		t.Fatal("compile manifest JSON differs across two compile runs")
	}
	if first.Review != second.Review {
		t.Fatal("review markdown differs across two compile runs")
	}
}

// TestReplayHarness_CompileMatchesGolden snapshots the compile output —
// signed contract YAML, compile manifest JSON, and operator review.md.
//
// The manifest's module_digest_root and module_digests fields are
// stabilized before comparison: the emit layer recomputes them from
// debug.ReadBuildInfo() at every compile, so they drift across Go-version
// CI legs and across developer machines. Stabilizing isolates the
// regression signal to compile / inference / signing logic, which is what
// this harness is built to detect.
func TestReplayHarness_CompileMatchesGolden(t *testing.T) {
	t.Parallel()
	entries := buildContinuousEntries(t)
	result, _ := runHarnessCompile(t, entries)

	assertGolden(t, harnessGoldenContract, result.YAML)
	assertGolden(t, harnessGoldenManifest, stabilizeManifest(t, result.ManifestJSON))
	assertGolden(t, harnessGoldenReview, []byte(result.Review))
}

// TestReplayHarness_ReplayDiffMatchesGolden writes the corpus to a temp
// directory, runs LoadAndReplay against the candidate config, and snapshots
// the rendered diff JSON. Validates that the replay engine + diff emitter
// stay byte-stable across versions.
func TestReplayHarness_ReplayDiffMatchesGolden(t *testing.T) {
	t.Parallel()
	sessions := buildPerSessionEntries(t)
	root := t.TempDir()
	writeHarnessSessions(t, root, sessions)

	cfg := harnessCandidateConfig()
	records, dropped, skipped, originalHash, err := capture.LoadAndReplay(cfg, root)
	if err != nil {
		t.Fatalf("LoadAndReplay: %v", err)
	}
	if originalHash != harnessOriginalHash {
		t.Fatalf("originalHash = %q, want %q", originalHash, harnessOriginalHash)
	}

	// Strip the tempdir-dependent ReplayedRecord.Timestamp field
	// transitively populated by the recorder envelope. Our entries' inner
	// CaptureSummary already pins deterministic content; the envelope
	// timestamp is ours too via Entry.Timestamp, so this should already be
	// stable. Verified below.
	diff := capture.ComputeDiff(records, dropped, skipped, originalHash, harnessCandidateHash)

	var buf bytes.Buffer
	if err := capture.RenderDiffJSON(&buf, diff); err != nil {
		t.Fatalf("RenderDiffJSON: %v", err)
	}
	got := buf.Bytes()

	// Sanity checks before snapshotting: confirms the corpus actually
	// exercises the new_block / unchanged paths the harness is meant to
	// regression-test.
	if diff.NewBlocks == 0 {
		t.Fatalf("diff.NewBlocks = 0; corpus is supposed to exercise new_block path")
	}
	if diff.Unchanged == 0 {
		t.Fatalf("diff.Unchanged = 0; corpus is supposed to exercise unchanged path")
	}
	if !strings.Contains(buf.String(), "exfil.example.net") {
		t.Fatalf("rendered diff missing expected exfil.example.net reference")
	}

	// SECURITY INVARIANT — privilege-boundary preservation.
	// A tool-policy record going from block to allow is a privilege-
	// expansion regression. The harness is here to catch exactly that;
	// snapshotting it as expected would defeat the purpose. If a future
	// scenario legitimately needs to test tool-policy-allow drift, it must
	// land in a new test function with its own golden, not silently flip
	// this one. See GPT review on PR #468 (medium severity).
	for _, entry := range diff.AllRecords {
		if entry.Summary.Surface != capture.SurfaceToolPolicy {
			continue
		}
		if entry.OriginalAction == config.ActionBlock && entry.CandidateAction != config.ActionBlock {
			t.Fatalf("privilege-boundary regression: tool_policy record %q (tool=%q) went from %q to %q",
				entry.Summary.Request.URL, entry.Summary.Request.ToolName,
				entry.OriginalAction, entry.CandidateAction)
		}
	}

	assertGolden(t, harnessGoldenReplayDiff, got)
}
