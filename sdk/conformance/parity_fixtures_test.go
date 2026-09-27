// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// Parity fixtures are tampered copies of the real run-chain evidence, one
// directory per tamper class. Each expect.json states the verdict every
// verifier must reach under the shared parity contract, in directory mode, for
// each named run, and for each file, with the findings and error kinds it must
// name. "Rehash" recomputes the unkeyed recorder entry hash chain with
// internal/recorder, which models an attacker who can write the evidence
// directory and holds no signing key. The fixtures are derived here, so the
// tamper is reproducible and checked, never hand-edited. Regenerate with
// PIPELOCK_PARITY_FIXTURES=1.
//
// The expectations below are the contract, stated per class; they are not
// derived from any verifier's output.
const parityDir = "testdata/parity"

// Error kinds a chain report must name. The README maps each to the phrase a
// verifier's error text carries.
const (
	errOuterChain    = "outer_chain_broken"
	errActionChain   = "action_receipt_chain"
	errEvidenceChain = "evidence_receipt_chain"
	errSessionMatch  = "session_mismatch"
	errSymlink       = "symlink_refused"
)

// Recorder hash chain state of a class's evidence.
const (
	chainIntact   = "intact"
	chainBroken   = "broken"
	chainRehashed = "rehashed"
)

// findingDuplicateRunNonce is the contract's finding for two chains of one
// base that carry the same signed run_nonce. The Go reference does not define
// it yet, so it is spelled here.
const findingDuplicateRunNonce = "duplicate_run_nonce"

const (
	keyFile         = "signer-key.hex"
	rotatedKeyFile  = "rotated-signer-key.hex"
	endorsementFile = "rotation-endorsement.json"
	replaySession   = "proxy.run.00000000000000000000000000000000"
	renamedSession  = "proxy.run.11111111111111111111111111111111"
	legacySession   = "proxy"
)

type parityFinding struct {
	Kind    string `json:"kind"`
	Session string `json:"session"`
}

type parityError struct {
	Session string `json:"session,omitempty"`
	Kind    string `json:"kind"`
}

type paritySymlink struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}

type parityCell struct {
	Mode         string   `json:"mode"`
	Target       string   `json:"target"`
	Keys         []string `json:"keys"`
	Endorsements []string `json:"endorsements"`
	// AllowUnpinned runs the cell with no key and --allow-unpinned. Every
	// signature is still checked against the chain's declared signer, so a
	// forged receipt fails; only the signer's identity goes unchecked.
	AllowUnpinned bool            `json:"allow_unpinned,omitempty"`
	Valid         bool            `json:"valid"`
	Findings      []parityFinding `json:"findings"`
	Errors        []parityError   `json:"errors"`
}

type parityExpect struct {
	Description   string          `json:"description"`
	RecorderChain string          `json:"recorder_chain"`
	Symlinks      []paritySymlink `json:"symlinks"`
	Cells         []parityCell    `json:"cells"`
}

// paritySource names the real runs the classes are built from.
type paritySource struct {
	a, b, d  string // run A, run B (links A), run D (links A across a key change)
	validDir string
	rotDir   string
}

func loadParitySource(t *testing.T) paritySource {
	t.Helper()
	read := func(p string) runChainExpect {
		var e runChainExpect
		raw, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		if len(e.Unlinked) != 1 || len(e.Linked) != 1 {
			t.Fatalf("%s: want one unlinked and one linked run", p)
		}
		return e
	}
	valid := read(filepath.Join(runChainsDir, "valid", runChainExpectFile))
	rot := read(filepath.Join(runChainsDir, "key-rotated", "expect-endorsed.json"))
	return paritySource{
		a:        valid.Unlinked[0],
		b:        valid.Linked[0].Session,
		d:        rot.Linked[0].Session,
		validDir: filepath.Join(runChainsDir, "valid"),
		rotDir:   filepath.Join(runChainsDir, "key-rotated"),
	}
}

func evidenceName(session string, seq int) string {
	return fmt.Sprintf("evidence-%s-%d.jsonl", session, seq)
}

func linkName(pred string) string { return receipt.ChainLinkFileName(pred) }

func readLines(t *testing.T, p string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(p))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

func joinLines(lines []string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

var recorderTail = regexp.MustCompile(`,"prev_hash":"([^"]*)","hash":"([^"]*)"}$`)

// rehash recomputes the recorder entry hash chain of lines with Go's
// recorder.ComputeHash, keeping every other byte.
func rehash(t *testing.T, lines []string) []string {
	t.Helper()
	out := make([]string, len(lines))
	prev := recorder.GenesisHash
	for i, line := range lines {
		if !recorderTail.MatchString(line) {
			t.Fatalf("line %d has no recorder hash tail", i)
		}
		sealed := recorderTail.ReplaceAllLiteralString(line, `,"prev_hash":"`+prev+`","hash":"__HASH__"}`)
		e, err := recorder.ParseEntryLine([]byte(sealed))
		if err != nil {
			t.Fatalf("parse line %d: %v", i, err)
		}
		h := recorder.ComputeHash(e)
		out[i] = strings.Replace(sealed, "__HASH__", h, 1)
		prev = h
	}
	return out
}

// entryType returns the recorder entry type of a line.
func entryType(t *testing.T, line string) string {
	t.Helper()
	e, err := recorder.ParseEntryLine([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	return e.Type
}

func lastIndexOfType(t *testing.T, lines []string, typ string) int {
	t.Helper()
	for i := len(lines) - 1; i >= 0; i-- {
		if entryType(t, lines[i]) == typ {
			return i
		}
	}
	t.Fatalf("no %s entry", typ)
	return -1
}

// replaceOnce replaces the single occurrence of old in s, failing when old is
// absent or ambiguous so a changed source cannot turn a tamper into a no-op.
func replaceOnce(t *testing.T, s, old, repl string) string {
	t.Helper()
	if n := strings.Count(s, old); n != 1 {
		t.Fatalf("anchor %q occurs %d times", old, n)
	}
	return strings.Replace(s, old, repl, 1)
}

type parityFiles map[string][]byte

type parityClass struct {
	name   string
	build  func(t *testing.T, src paritySource) parityFiles
	expect func(src paritySource) parityExpect
	// check asserts the tamper is present in the built files.
	check func(t *testing.T, src paritySource, files parityFiles)
}

func baseFiles(t *testing.T, src paritySource) parityFiles {
	t.Helper()
	files := parityFiles{}
	for _, name := range []string{evidenceName(src.a, 0), evidenceName(src.b, 0), linkName(src.a), keyFile} {
		p := filepath.Join(src.validDir, name)
		if name == keyFile {
			p = filepath.Join(runChainsDir, keyFile)
		}
		raw, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = raw
	}
	return files
}

func linesOf(files parityFiles, name string) []string {
	return strings.Split(strings.TrimRight(string(files[name]), "\n"), "\n")
}

var keyOnly = []string{keyFile}

// withUnpinned repeats cells with no key and --allow-unpinned. The verdict is
// unchanged: a missing pin changes whose key is trusted, never whether a
// signature must verify.
func withUnpinned(cells []parityCell) []parityCell {
	out := append([]parityCell{}, cells...)
	for _, c := range cells {
		c.Keys = []string{}
		c.Endorsements = []string{}
		c.AllowUnpinned = true
		out = append(out, c)
	}
	return out
}

func cellsFor(dir parityCell, sessions []parityCell, files []parityCell) []parityCell {
	cells := append([]parityCell{dir}, sessions...)
	return append(cells, files...)
}

func cell(mode, target string, keys []string, valid bool, findings []parityFinding, errs ...parityError) parityCell {
	if findings == nil {
		findings = []parityFinding{}
	}
	if errs == nil {
		errs = []parityError{}
	}
	return parityCell{Mode: mode, Target: target, Keys: keys, Endorsements: []string{}, Valid: valid, Findings: findings, Errors: errs}
}

func fileCell(target string, keys []string, errs ...parityError) parityCell {
	return cell("file", target, keys, len(errs) == 0, nil, errs...)
}

// twoRunCells states the verdict for a directory holding runs A and B when
// base findings f are present and chain c fails with errs.
func twoRunCells(src paritySource, f []parityFinding, c string, errs []string, fileErrs map[string][]string) []parityCell {
	chainErrs := func(session string) []parityError {
		var out []parityError
		if session == "" || session == c {
			for _, k := range errs {
				out = append(out, parityError{Session: c, Kind: k})
			}
		}
		return out
	}
	healthy := len(f) == 0
	dir := cell("dir", ".", keyOnly, healthy && len(errs) == 0, f, chainErrs("")...)
	var sess []parityCell
	for _, s := range []string{src.a, src.b} {
		sess = append(sess, cell("session", s, keyOnly, healthy && (s != c || len(errs) == 0), f, chainErrs(s)...))
	}
	var fc []parityCell
	for _, s := range []string{src.a, src.b} {
		var pe []parityError
		for _, k := range fileErrs[s] {
			pe = append(pe, parityError{Kind: k})
		}
		fc = append(fc, fileCell(evidenceName(s, 0), keyOnly, pe...))
	}
	return cellsFor(dir, sess, fc)
}

func parityClasses() []parityClass {
	editB := func(edit func(t *testing.T, src paritySource, lines []string) []string, rehashed bool) func(t *testing.T, src paritySource) parityFiles {
		return func(t *testing.T, src paritySource) parityFiles {
			files := baseFiles(t, src)
			name := evidenceName(src.b, 0)
			lines := edit(t, src, linesOf(files, name))
			if rehashed {
				lines = rehash(t, lines)
			}
			files[name] = joinLines(lines)
			return files
		}
	}
	forgeV2 := func(t *testing.T, _ paritySource, lines []string) []string {
		i := lastIndexOfType(t, lines, "evidence_receipt")
		lines[i] = replaceOnce(t, lines[i], `"verdict":"block"`, `"verdict":"allow"`)
		return lines
	}
	stripV2 := func(t *testing.T, _ paritySource, lines []string) []string {
		var out []string
		for _, l := range lines {
			if entryType(t, l) != "evidence_receipt" {
				out = append(out, l)
			}
		}
		return out
	}
	dropV2Tail := func(t *testing.T, _ paritySource, lines []string) []string {
		i := lastIndexOfType(t, lines, "evidence_receipt")
		return append(append([]string{}, lines[:i]...), lines[i+1:]...)
	}
	editEnvelope := func(t *testing.T, _ paritySource, lines []string) []string {
		i := lastIndexOfType(t, lines, "action_receipt") - 2
		if entryType(t, lines[i]) != "action_receipt" || !strings.Contains(lines[i], `"summary":"receipt: block`) {
			t.Fatalf("line %d is not the blocked action receipt", i)
		}
		lines[i] = replaceOnce(t, lines[i], `"summary":"receipt: block`, `"summary":"receipt: allow`)
		return lines
	}
	outerB := func(src paritySource) []parityFinding {
		return []parityFinding{{Kind: receipt.FindingOuterChainBroken, Session: src.b}}
	}
	corruptB := func(src paritySource) []parityFinding {
		return []parityFinding{{Kind: receipt.FindingCorruptChain, Session: src.b}}
	}
	allValid := func(src paritySource) []parityCell {
		return twoRunCells(src, nil, "", nil, nil)
	}

	return []parityClass{
		{
			name:  "v2-forge-norehash",
			build: editB(forgeV2, false),
			expect: func(src paritySource) parityExpect {
				return parityExpect{
					Description:   "Run B's last EvidenceReceipt v2 verdict edited from block to allow; its signature no longer verifies. The recorder hash chain was not recomputed. The base check verifies B's v2 chain, so every mode that reads the base reports it.",
					RecorderChain: chainBroken,
					Cells: twoRunCells(src, append(outerB(src), corruptB(src)...), src.b, []string{errEvidenceChain},
						map[string][]string{src.b: {errOuterChain, errEvidenceChain}}),
				}
			},
			check: checkEditedLine(`"verdict":"allow"`, "evidence_receipt"),
		},
		{
			name:  "v2-forge-rehash",
			build: editB(forgeV2, true),
			expect: func(src paritySource) parityExpect {
				return parityExpect{
					Description:   "Run B's last EvidenceReceipt v2 verdict edited from block to allow, and the recorder hash chain recomputed. Only the v2 signature catches it. The base check verifies every run's v2 chain, so a named run A fails too: a named run fails on any finding in its base.",
					RecorderChain: chainRehashed,
					Cells: withUnpinned(twoRunCells(src, corruptB(src), src.b, []string{errEvidenceChain},
						map[string][]string{src.b: {errEvidenceChain}})),
				}
			},
			check: checkEditedLine(`"verdict":"allow"`, "evidence_receipt"),
		},
		{
			name:  "v2-strip-norehash",
			build: editB(stripV2, false),
			expect: func(src paritySource) parityExpect {
				return parityExpect{
					Description:   "Every EvidenceReceipt v2 entry of run B deleted. The recorder hash chain was not recomputed.",
					RecorderChain: chainBroken,
					Cells:         twoRunCells(src, outerB(src), "", nil, map[string][]string{src.b: {errOuterChain}}),
				}
			},
			check: checkEvidenceCount(0),
		},
		{
			name:  "v2-strip-rehash",
			build: editB(stripV2, true),
			expect: func(src paritySource) parityExpect {
				return parityExpect{
					Description:   "Every EvidenceReceipt v2 entry of run B deleted and the recorder hash chain recomputed. A v2 chain carries no count or seal, so no verifier here detects its removal; only a signed checkpoint does. Valid is the contract verdict.",
					RecorderChain: chainRehashed,
					Cells:         allValid(src),
				}
			},
			check: checkEvidenceCount(0),
		},
		{
			name:  "v2-drop-norehash",
			build: editB(dropV2Tail, false),
			expect: func(src paritySource) parityExpect {
				return parityExpect{
					Description:   "Run B's last EvidenceReceipt v2 entry deleted. The recorder hash chain was not recomputed.",
					RecorderChain: chainBroken,
					Cells:         twoRunCells(src, outerB(src), "", nil, map[string][]string{src.b: {errOuterChain}}),
				}
			},
			check: checkEvidenceCount(1),
		},
		{
			name:  "v2-drop-rehash",
			build: editB(dropV2Tail, true),
			expect: func(src paritySource) parityExpect {
				return parityExpect{
					Description:   "Run B's last EvidenceReceipt v2 entry deleted and the recorder hash chain recomputed. Truncating a v2 chain's tail leaves a valid chain; only a signed checkpoint detects it. Valid is the contract verdict.",
					RecorderChain: chainRehashed,
					Cells:         withUnpinned(allValid(src)),
				}
			},
			check: checkEvidenceCount(1),
		},
		{
			name:  "envelope-edit-norehash",
			build: editB(editEnvelope, false),
			expect: func(src paritySource) parityExpect {
				return parityExpect{
					Description:   "The unsigned recorder summary of run B's second blocked action receipt edited to say allow. The recorder hash chain was not recomputed.",
					RecorderChain: chainBroken,
					Cells:         twoRunCells(src, outerB(src), "", nil, map[string][]string{src.b: {errOuterChain}}),
				}
			},
			check: checkEditedLine(`"summary":"receipt: allow`, "action_receipt"),
		},
		{
			name:  "envelope-edit-rehash",
			build: editB(editEnvelope, true),
			expect: func(src paritySource) parityExpect {
				return parityExpect{
					Description:   "The unsigned recorder summary of run B's second blocked action receipt edited to say allow, and the recorder hash chain recomputed. The signed receipt is unchanged; only a signed checkpoint detects the envelope edit. Valid is the contract verdict.",
					RecorderChain: chainRehashed,
					Cells:         allValid(src),
				}
			},
			check: checkEditedLine(`"summary":"receipt: allow`, "action_receipt"),
		},
		{
			name: "dup-run",
			build: func(t *testing.T, src paritySource) parityFiles {
				files := baseFiles(t, src)
				files[evidenceName(replaySession, 0)] = files[evidenceName(src.a, 0)]
				return files
			},
			expect: func(src paritySource) parityExpect {
				f := []parityFinding{{Kind: receipt.FindingCorruptChain, Session: replaySession}}
				e := parityError{Session: replaySession, Kind: errSessionMatch}
				return parityExpect{
					Description:   "Run A's file copied verbatim under a new run name. Its entries still name run A, so the copy is refused as the new run's evidence, in its directory and read alone.",
					RecorderChain: chainIntact,
					Cells: cellsFor(
						cell("dir", ".", keyOnly, false, f, e),
						[]parityCell{
							cell("session", replaySession, keyOnly, false, f, e),
							cell("session", src.a, keyOnly, false, f),
							cell("session", src.b, keyOnly, false, f),
						},
						[]parityCell{
							fileCell(evidenceName(replaySession, 0), keyOnly, parityError{Kind: errSessionMatch}),
							fileCell(evidenceName(src.a, 0), keyOnly),
							fileCell(evidenceName(src.b, 0), keyOnly),
						}),
				}
			},
			check: func(t *testing.T, src paritySource, files parityFiles) {
				if !bytes.Equal(files[evidenceName(replaySession, 0)], files[evidenceName(src.a, 0)]) {
					t.Fatal("replayed file differs from run A's")
				}
			},
		},
		{
			name: "rename-run",
			build: func(t *testing.T, src paritySource) parityFiles {
				files := baseFiles(t, src)
				files[evidenceName(renamedSession, 0)] = files[evidenceName(src.b, 0)]
				delete(files, evidenceName(src.b, 0))
				return files
			},
			expect: func(src paritySource) parityExpect {
				f := []parityFinding{
					{Kind: receipt.FindingCorruptChain, Session: renamedSession},
					{Kind: receipt.FindingDanglingLink, Session: src.b},
				}
				e := parityError{Session: renamedSession, Kind: errSessionMatch}
				return parityExpect{
					Description:   "Run B's file moved to a new run name. Its entries still name run B, so it is refused, read alone too, and A's link now names a successor that is not present.",
					RecorderChain: chainIntact,
					Cells: cellsFor(
						cell("dir", ".", keyOnly, false, f, e),
						[]parityCell{
							cell("session", src.a, keyOnly, false, f),
							cell("session", renamedSession, keyOnly, false, f, e),
						},
						[]parityCell{
							fileCell(evidenceName(src.a, 0), keyOnly),
							fileCell(evidenceName(renamedSession, 0), keyOnly, parityError{Kind: errSessionMatch}),
						}),
				}
			},
			check: func(t *testing.T, src paritySource, files parityFiles) {
				if _, ok := files[evidenceName(src.b, 0)]; ok {
					t.Fatal("run B's file still present")
				}
			},
		},
		{
			name: "run-as-legacy",
			build: func(t *testing.T, src paritySource) parityFiles {
				files := baseFiles(t, src)
				files[evidenceName(legacySession, 0)] = files[evidenceName(src.a, 0)]
				delete(files, evidenceName(src.a, 0))
				return files
			},
			expect: func(src paritySource) parityExpect {
				f := []parityFinding{
					{Kind: receipt.FindingCorruptChain, Session: legacySession},
					{Kind: receipt.FindingDanglingLink, Session: src.b},
				}
				e := parityError{Session: legacySession, Kind: errSessionMatch}
				return parityExpect{
					Description:   "Run A's file renamed to the legacy base session name. Its entries still name run A, so it is refused, read alone too, and B's link now names a predecessor that is not present.",
					RecorderChain: chainIntact,
					Cells: cellsFor(
						cell("dir", ".", keyOnly, false, f, e),
						[]parityCell{
							cell("session", legacySession, keyOnly, false, f, e),
							cell("session", src.b, keyOnly, false, f),
						},
						[]parityCell{
							fileCell(evidenceName(legacySession, 0), keyOnly, parityError{Kind: errSessionMatch}),
							fileCell(evidenceName(src.b, 0), keyOnly),
						}),
				}
			},
			check: func(t *testing.T, src paritySource, files parityFiles) {
				if _, ok := files[evidenceName(src.a, 0)]; ok {
					t.Fatal("run A's file still present")
				}
			},
		},
		{
			name: "symlink-run",
			build: func(t *testing.T, src paritySource) parityFiles {
				files := baseFiles(t, src)
				files["target/"+evidenceName(src.b, 0)] = files[evidenceName(src.b, 0)]
				delete(files, evidenceName(src.b, 0))
				return files
			},
			expect: func(src paritySource) parityExpect {
				f := []parityFinding{{Kind: receipt.FindingCorruptChain, Session: src.b}}
				e := parityError{Session: src.b, Kind: errSymlink}
				return parityExpect{
					Description:   "Run B's evidence file is a symlink to an identical copy in a subdirectory. A verifier creates the link at test time from \"symlinks\". Inside a directory root a symlinked evidence file is refused; a file path named on the command line is read as given.",
					RecorderChain: chainIntact,
					Symlinks:      []paritySymlink{{Name: evidenceName(src.b, 0), Target: "target/" + evidenceName(src.b, 0)}},
					Cells: cellsFor(
						cell("dir", ".", keyOnly, false, f, e),
						[]parityCell{
							cell("session", src.a, keyOnly, false, f),
							cell("session", src.b, keyOnly, false, f, e),
						},
						[]parityCell{
							fileCell(evidenceName(src.a, 0), keyOnly),
							fileCell(evidenceName(src.b, 0), keyOnly),
						}),
				}
			},
			check: func(t *testing.T, src paritySource, files parityFiles) {
				if _, ok := files[evidenceName(src.b, 0)]; ok {
					t.Fatal("run B's file is committed instead of linked")
				}
			},
		},
		{
			name: "dup-run-nonce",
			build: func(t *testing.T, src paritySource) parityFiles {
				files := baseFiles(t, src)
				lines := linesOf(files, evidenceName(src.a, 0))
				for i := range lines {
					lines[i] = replaceOnce(t, lines[i], `"session_id":"`+src.a+`","type"`, `"session_id":"`+replaySession+`","type"`)
				}
				files[evidenceName(replaySession, 0)] = joinLines(rehash(t, lines))
				return files
			},
			expect: func(src paritySource) parityExpect {
				f := []parityFinding{
					{Kind: findingDuplicateRunNonce, Session: replaySession},
					{Kind: findingDuplicateRunNonce, Session: src.a},
				}
				return parityExpect{
					Description:   "Run A's evidence replayed as a new run: every entry's unsigned session_id rewritten and the recorder hash chain recomputed. Each chain verifies on its own, but both carry run A's signed run_nonce, and a process run writes one chain.",
					RecorderChain: chainRehashed,
					Cells: cellsFor(
						cell("dir", ".", keyOnly, false, f),
						[]parityCell{
							cell("session", replaySession, keyOnly, false, f),
							cell("session", src.a, keyOnly, false, f),
							cell("session", src.b, keyOnly, false, f),
						},
						[]parityCell{
							fileCell(evidenceName(replaySession, 0), keyOnly),
							fileCell(evidenceName(src.a, 0), keyOnly),
							fileCell(evidenceName(src.b, 0), keyOnly),
						}),
				}
			},
			check: func(t *testing.T, src paritySource, files parityFiles) {
				a := runNonces(t, linesOf(files, evidenceName(src.a, 0)))
				r := runNonces(t, linesOf(files, evidenceName(replaySession, 0)))
				if len(a) != 1 || strings.Join(a, ",") != strings.Join(r, ",") {
					t.Fatalf("replay does not share run A's nonce: %v %v", a, r)
				}
				for _, l := range linesOf(files, evidenceName(replaySession, 0)) {
					e, err := recorder.ParseEntryLine([]byte(l))
					if err != nil || e.SessionID != replaySession {
						t.Fatalf("replayed entry session %q: %v", e.SessionID, err)
					}
				}
			},
		},
		{
			name: "rotated",
			build: func(t *testing.T, src paritySource) parityFiles {
				files := parityFiles{}
				for _, name := range []string{evidenceName(src.a, 0), evidenceName(src.d, 0), linkName(src.a), endorsementFile} {
					raw, err := os.ReadFile(filepath.Clean(filepath.Join(src.rotDir, name)))
					if err != nil {
						t.Fatal(err)
					}
					files[name] = raw
				}
				for _, name := range []string{keyFile, rotatedKeyFile} {
					raw, err := os.ReadFile(filepath.Clean(filepath.Join(runChainsDir, name)))
					if err != nil {
						t.Fatal(err)
					}
					files[name] = raw
				}
				return files
			},
			expect: func(src paritySource) parityExpect {
				endorsed := func(c parityCell) parityCell {
					c.Endorsements = []string{endorsementFile}
					return c
				}
				both := []string{keyFile, rotatedKeyFile}
				untrusted := []parityFinding{
					{Kind: receipt.FindingCorruptChain, Session: src.d},
					{Kind: receipt.FindingUntrustedSuccessorKey, Session: src.d},
				}
				return parityExpect{
					Description:   "Honest evidence across a signing key rotation: run D restarts after run A under a new key, with a signed link and the rotation endorsement the documented ceremony produces. It verifies with the first key and the endorsement, or with both keys pinned; with the first key alone run D is untrusted.",
					RecorderChain: chainIntact,
					Cells: cellsFor(
						endorsed(cell("dir", ".", keyOnly, true, nil)),
						[]parityCell{
							endorsed(cell("session", src.a, keyOnly, true, nil)),
							endorsed(cell("session", src.d, keyOnly, true, nil)),
							cell("dir", ".", both, true, nil),
							cell("dir", ".", keyOnly, false, untrusted, parityError{Session: src.d, Kind: errActionChain}),
						},
						[]parityCell{
							fileCell(evidenceName(src.a, 0), keyOnly),
							fileCell(evidenceName(src.d, 0), []string{rotatedKeyFile}),
						}),
				}
			},
			check: func(t *testing.T, _ paritySource, files parityFiles) {
				var e receipt.RotationEndorsement
				if err := json.Unmarshal(files[endorsementFile], &e); err != nil {
					t.Fatal(err)
				}
				if err := receipt.VerifyRotationEndorsement(e); err != nil {
					t.Fatalf("endorsement does not verify: %v", err)
				}
			},
		},
		{
			name: "v2-only-shard",
			build: func(t *testing.T, src paritySource) parityFiles {
				files := baseFiles(t, src)
				name := evidenceName(src.b, 0)
				lines := linesOf(files, name)
				first := lastIndexOfType(t, lines[:5], "evidence_receipt")
				files[evidenceName(src.b, 0)] = joinLines(lines[:first])
				files[evidenceName(src.b, first)] = joinLines(lines[first : first+1])
				files[evidenceName(src.b, first+1)] = joinLines(lines[first+1:])
				return files
			},
			expect: func(src paritySource) parityExpect {
				shard := func(seq int) string { return evidenceName(src.b, seq) }
				return parityExpect{
					Description:   "Run B's honest file split into three shards at entry boundaries; the middle shard holds only one EvidenceReceipt v2. The run verifies as one chain across its shards. Read alone, the v2-only shard is verified as a v2 chain, never reported as holding no receipts; it and the last shard fail file mode because their first entry does not start the recorder hash chain.",
					RecorderChain: chainIntact,
					Cells: cellsFor(
						cell("dir", ".", keyOnly, true, nil),
						[]parityCell{
							cell("session", src.a, keyOnly, true, nil),
							cell("session", src.b, keyOnly, true, nil),
						},
						[]parityCell{
							fileCell(evidenceName(src.a, 0), keyOnly),
							fileCell(shard(0), keyOnly),
							fileCell(shard(4), keyOnly, parityError{Kind: errOuterChain}),
							fileCell(shard(5), keyOnly, parityError{Kind: errOuterChain}, parityError{Kind: errActionChain}, parityError{Kind: errEvidenceChain}),
						}),
				}
			},
			check: func(t *testing.T, src paritySource, files parityFiles) {
				mid := linesOf(files, evidenceName(src.b, 4))
				if len(mid) != 1 || entryType(t, mid[0]) != "evidence_receipt" {
					t.Fatalf("middle shard is not one v2 entry: %v", mid)
				}
			},
		},
	}
}

// checkEditedLine asserts run B holds exactly one more typ line carrying
// marker than the untampered source does.
func checkEditedLine(marker, typ string) func(t *testing.T, src paritySource, files parityFiles) {
	return func(t *testing.T, src paritySource, files parityFiles) {
		t.Helper()
		count := func(lines []string) int {
			n := 0
			for _, l := range lines {
				if strings.Contains(l, marker) && entryType(t, l) == typ {
					n++
				}
			}
			return n
		}
		before := count(readLines(t, filepath.Join(src.validDir, evidenceName(src.b, 0))))
		after := count(linesOf(files, evidenceName(src.b, 0)))
		if after != before+1 {
			t.Fatalf("want one more %s line carrying %s than the source (%d), got %d", typ, marker, before, after)
		}
	}
}

func checkEvidenceCount(want int) func(t *testing.T, src paritySource, files parityFiles) {
	return func(t *testing.T, src paritySource, files parityFiles) {
		t.Helper()
		got := 0
		for _, l := range linesOf(files, evidenceName(src.b, 0)) {
			if entryType(t, l) == "evidence_receipt" {
				got++
			}
		}
		if got != want {
			t.Fatalf("run B holds %d evidence receipts, want %d", got, want)
		}
	}
}

func runNonces(t *testing.T, lines []string) []string {
	t.Helper()
	set := map[string]bool{}
	for _, l := range lines {
		e, err := recorder.ParseEntryLine([]byte(l))
		if err != nil {
			t.Fatal(err)
		}
		if e.Type != "action_receipt" {
			continue
		}
		var d struct {
			ActionRecord struct {
				RunNonce string `json:"run_nonce"`
			} `json:"action_record"`
		}
		if err := json.Unmarshal(e.RawDetail, &d); err != nil {
			t.Fatal(err)
		}
		set[d.ActionRecord.RunNonce] = true
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func sortedExpect(e parityExpect) parityExpect {
	if e.Symlinks == nil {
		e.Symlinks = []paritySymlink{}
	}
	for i := range e.Cells {
		f := e.Cells[i].Findings
		sort.Slice(f, func(a, b int) bool {
			if f[a].Kind != f[b].Kind {
				return f[a].Kind < f[b].Kind
			}
			return f[a].Session < f[b].Session
		})
	}
	return e
}

// buildParityClass returns every file of a class's directory, expect.json
// included.
func buildParityClass(t *testing.T, src paritySource, c parityClass) parityFiles {
	t.Helper()
	files := c.build(t, src)
	body, err := json.MarshalIndent(sortedExpect(c.expect(src)), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files["expect.json"] = append(body, '\n')
	return files
}

func committedParityFiles(t *testing.T, dir string) parityFiles {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open %s: %v (regenerate with PIPELOCK_PARITY_FIXTURES=1)", dir, err)
	}
	defer func() { _ = root.Close() }()
	files := parityFiles{}
	err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		raw, readErr := fs.ReadFile(root.FS(), p)
		if readErr != nil {
			return readErr
		}
		files[p] = raw
		return nil
	})
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	return files
}

// TestParityFixturesMatchGenerator fails when a committed parity fixture is
// not exactly what the generator derives from the run-chain evidence, and
// writes them when PIPELOCK_PARITY_FIXTURES=1.
func TestParityFixturesMatchGenerator(t *testing.T) {
	src := loadParitySource(t)
	regen := os.Getenv("PIPELOCK_PARITY_FIXTURES") == "1"
	var names []string
	for _, c := range parityClasses() {
		names = append(names, c.name)
		want := buildParityClass(t, src, c)
		dir := filepath.Join(parityDir, c.name)
		if regen {
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			for name, body := range want {
				p := filepath.Join(dir, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		got := committedParityFiles(t, dir)
		if len(got) != len(want) {
			t.Errorf("%s: %d files committed, generator writes %d", c.name, len(got), len(want))
		}
		for name, body := range want {
			if !bytes.Equal(got[name], body) {
				t.Errorf("%s/%s is stale; regenerate with PIPELOCK_PARITY_FIXTURES=1", c.name, name)
			}
		}
	}
	entries, err := os.ReadDir(parityDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() && !containsString(names, e.Name()) {
			t.Errorf("%s/%s is not a generated class", parityDir, e.Name())
		}
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// TestParityFixturesAreConsistent checks each class's tamper is present and
// its recorder hash chain is in the state expect.json claims. It does not ask
// any verifier for a verdict.
func TestParityFixturesAreConsistent(t *testing.T) {
	src := loadParitySource(t)
	for _, c := range parityClasses() {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join(parityDir, c.name)
			files := committedParityFiles(t, dir)
			c.check(t, src, files)
			var exp parityExpect
			if err := json.Unmarshal(files["expect.json"], &exp); err != nil {
				t.Fatal(err)
			}
			for _, l := range exp.Symlinks {
				if _, ok := files[l.Target]; !ok {
					t.Fatalf("symlink target %s missing", l.Target)
				}
			}
			checkRecorderChains(t, files, exp)
			checkCells(t, files, exp)
		})
	}
}

// checkRecorderChains verifies the recorder hash chain of every session in
// the class, reading shards in order and symlinks through their targets.
func checkRecorderChains(t *testing.T, files parityFiles, exp parityExpect) {
	t.Helper()
	target := map[string]string{}
	for _, l := range exp.Symlinks {
		target[l.Name] = l.Target
	}
	sessions := map[string][]string{}
	add := func(name string) {
		if strings.Contains(name, "/") || !strings.HasPrefix(name, "evidence-") || !strings.HasSuffix(name, ".jsonl") {
			return
		}
		// The session is everything between "evidence-" and the last dash.
		rest := strings.TrimSuffix(strings.TrimPrefix(name, "evidence-"), ".jsonl")
		sess := rest[:strings.LastIndex(rest, "-")]
		sessions[sess] = append(sessions[sess], name)
	}
	for name := range files {
		add(name)
	}
	for name := range target {
		add(name)
	}
	broken := 0
	for sess, names := range sessions {
		sort.Slice(names, func(i, j int) bool { return shardSeq(names[i]) < shardSeq(names[j]) })
		var entries []recorder.Entry
		for _, n := range names {
			body := files[n]
			if tgt, ok := target[n]; ok {
				body = files[tgt]
			}
			es, err := recorder.ReadEntriesFromReader(bytes.NewReader(body))
			if err != nil {
				t.Fatalf("%s: %v", n, err)
			}
			entries = append(entries, es...)
		}
		if err := recorder.VerifyChain(entries); err != nil {
			broken++
			if exp.RecorderChain != chainBroken {
				t.Fatalf("session %s recorder chain broken (%v), expect.json says %s", sess, err, exp.RecorderChain)
			}
		}
	}
	if exp.RecorderChain == chainBroken && broken == 0 {
		t.Fatal("expect.json says the recorder chain is broken, but every session's chain holds")
	}
}

func shardSeq(name string) int {
	rest := strings.TrimSuffix(name, ".jsonl")
	var n int
	_, _ = fmt.Sscanf(rest[strings.LastIndex(rest, "-")+1:], "%d", &n)
	return n
}

// checkCells keeps every cell well formed: a named file or session exists, a
// valid cell names no finding or error, and every error kind is known.
func checkCells(t *testing.T, files parityFiles, exp parityExpect) {
	t.Helper()
	known := map[string]bool{errOuterChain: true, errActionChain: true, errEvidenceChain: true, errSessionMatch: true, errSymlink: true}
	linked := map[string]bool{}
	for _, l := range exp.Symlinks {
		linked[l.Name] = true
	}
	modes := map[string]int{}
	for _, c := range exp.Cells {
		modes[c.Mode]++
		if c.Valid != (len(c.Findings) == 0 && len(c.Errors) == 0) {
			t.Fatalf("cell %s %s: valid=%v with findings %v errors %v", c.Mode, c.Target, c.Valid, c.Findings, c.Errors)
		}
		for _, e := range c.Errors {
			if !known[e.Kind] {
				t.Fatalf("unknown error kind %q", e.Kind)
			}
		}
		for _, k := range append(append([]string{}, c.Keys...), c.Endorsements...) {
			if _, ok := files[k]; !ok {
				t.Fatalf("cell names missing trust file %s", k)
			}
		}
		switch c.Mode {
		case "file":
			if _, ok := files[c.Target]; !ok && !linked[c.Target] {
				t.Fatalf("file cell names missing %s", c.Target)
			}
		case "session", "dir":
		default:
			t.Fatalf("unknown mode %q", c.Mode)
		}
	}
	if modes["dir"] == 0 || modes["session"] == 0 || modes["file"] == 0 {
		t.Fatalf("want every mode covered, got %v", modes)
	}
}
