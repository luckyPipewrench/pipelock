// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// Regenerate with UPDATE_ROTATION_MATRIX=1 go test ./internal/receipt -run '^TestGenerateReceiptGroupRotationMatrix$',
// then python3 sdk/verifiers/compact_group_matrix.py to copy the same bounded
// archive into all three verifier suites.
// MaxEntriesPerFile drives the production recorder's rotation path with small
// files; the evidence is never split or renamed by this generator.
func TestRecoveryObserverRejectsTornNonFinalSegment(t *testing.T) {
	dir, _, signer, predecessor := writeRotatedRecoverySource(t)
	path := filepath.Join(dir, "evidence-"+predecessor+"-0.jsonl")
	raw, err := os.ReadFile(path) // #nosec G304 -- writer-produced private fixture.
	if err != nil || len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatalf("earlier writer segment: %v", err)
	}
	opts := recoveryObservationOptions{trusted: []string{signer}, maxBytes: recorder.MaxEvidenceReadFileBytes}
	if _, err := observeRecoveryWithOptions(dir, predecessor, signer, opts); err != nil {
		t.Fatalf("intact recovery predecessor: %v", err)
	}
	if err := os.WriteFile(path, raw[:len(raw)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := observeRecoveryWithOptions(dir, predecessor, signer, opts); err == nil || !strings.Contains(err.Error(), "torn non-final segment") {
		t.Fatalf("bounded recovery observer accepted torn earlier segment: %v", err)
	}
}

func TestReceiptGroupRejectsBadHashUnterminatedRecoveryTail(t *testing.T) {
	dir, groupID, signer, predecessor := writeRotatedRecoverySource(t)
	if result := VerifyReceiptGroup(dir, groupID, []string{signer}); result.Verdict != GroupValid {
		t.Fatalf("positive control: %+v", result)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+predecessor+"-*.jsonl"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("predecessor shards=%v err=%v", paths, err)
	}
	last := paths[len(paths)-1]
	raw, err := os.ReadFile(filepath.Clean(last))
	if err != nil {
		t.Fatal(err)
	}
	boundary := bytes.LastIndexByte(raw, '\n') + 1
	if boundary == 0 || boundary == len(raw) {
		t.Fatal("expected a complete prefix and crash fragment")
	}
	previous := raw[:boundary-1]
	start := bytes.LastIndexByte(previous, '\n') + 1
	var entry recorder.Entry
	if err := json.Unmarshal(previous[start:], &entry); err != nil {
		t.Fatal(err)
	}
	entry.Hash = strings.Repeat("0", len(entry.Hash))
	badHash, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	damaged := append(bytes.Clone(raw[:boundary]), badHash...)
	if err := os.WriteFile(last, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := observeRecoveryWithOptions(dir, predecessor, signer, recoveryObservationOptions{trusted: []string{signer}, maxBytes: recorder.MaxEvidenceReadFileBytes}); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("recovery classified bad hash as torn: %v", err)
	}
	if result := VerifyReceiptGroup(dir, groupID, []string{signer}); result.Verdict == GroupValid {
		t.Fatalf("group authenticated damaged predecessor: %+v", result)
	}
	after, err := os.ReadFile(filepath.Clean(last))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, damaged) {
		t.Fatal("recovery or verifier changed damaged shard")
	}
}

func TestGenerateReceiptGroupRotationMatrix(t *testing.T) {
	if os.Getenv("UPDATE_ROTATION_MATRIX") != "1" {
		t.Skip("fixture regeneration only")
	}
	const fixture = "../../sdk/verifiers/python/tests/fixtures/receipt-groups-matrix.zip.gz"
	old, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(old))
	if err != nil {
		t.Fatal(err)
	}
	inner, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	_ = gz.Close()
	zr, err := zip.NewReader(bytes.NewReader(inner), int64(len(inner)))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte)
	for _, file := range zr.File {
		if strings.HasPrefix(file.Name, "cases/rotation__") ||
			strings.HasPrefix(file.Name, "cases/shard__leading-") ||
			strings.HasPrefix(file.Name, "cases/shard__trailing-") ||
			strings.HasPrefix(file.Name, "cases/ael__leading-") ||
			strings.HasPrefix(file.Name, "cases/ael__blank-line-") ||
			strings.HasPrefix(file.Name, "cases/shard__torn-receipt__absent/") ||
			strings.HasPrefix(file.Name, "cases/non-shard-legacy__torn-receipt__absent/") ||
			strings.HasPrefix(file.Name, "cases/shard__evidence-directory__present/") ||
			file.Name == "matrix.json" || file.FileInfo().IsDir() {
			continue
		}
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		files[file.Name], err = io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	type matrixCase struct {
		Name        string              `json:"name"`
		GroupID     string              `json:"group_id"`
		TrustedKeys []string            `json:"trusted_keys"`
		Expected    ReceiptGroupVerdict `json:"expected"`
	}
	var cases []matrixCase
	for _, file := range zr.File {
		if file.Name != "matrix.json" {
			continue
		}
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		err = json.NewDecoder(r).Decode(&cases)
		_ = r.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	baseCases := make([]matrixCase, 0, len(cases))
	for _, item := range cases {
		if !strings.HasPrefix(item.Name, "rotation__") &&
			!strings.HasPrefix(item.Name, "shard__leading-") &&
			!strings.HasPrefix(item.Name, "shard__trailing-") &&
			!strings.HasPrefix(item.Name, "ael__leading-") &&
			!strings.HasPrefix(item.Name, "ael__blank-line-") &&
			!strings.HasPrefix(item.Name, "shard__blank-line-") &&
			!strings.HasPrefix(item.Name, "shard__unsafe-number-line__") &&
			item.Name != "shard__torn-receipt__absent" &&
			item.Name != "non-shard-legacy__torn-receipt__absent" &&
			item.Name != "predecessor__signed-close-head-disagrees" &&
			item.Name != "shard__torn-gate-missing-open" &&
			item.Name != "opening__untrusted-signer" &&
			item.Name != "shard__evidence-directory__present" {
			baseCases = append(baseCases, item)
		}
	}
	cases = baseCases
	base, groupID, signer, predecessor := writeRotatedRecoverySource(t)
	for _, variant := range []string{"intact", "torn-earlier", "empty-line-earlier", "whitespace-line-earlier", "control-001c-earlier", "control-001d-earlier", "control-001e-earlier", "control-001f-earlier"} {
		name := "rotation__recovery__" + variant
		want := GroupValid
		if variant == "torn-earlier" || strings.HasPrefix(variant, "control-") {
			want = GroupInvalid
		}
		caseDir := filepath.Join(t.TempDir(), name)
		copyRotationTree(t, base, caseDir)
		if variant != "intact" {
			first := filepath.Join(caseDir, "evidence-"+predecessor+"-0.jsonl")
			raw, readErr := os.ReadFile(first) // #nosec G304 -- writer-produced private fixture.
			if readErr != nil || len(raw) == 0 || raw[len(raw)-1] != '\n' {
				t.Fatalf("earlier writer segment: %v", readErr)
			}
			if variant == "torn-earlier" {
				raw = raw[:len(raw)-1]
			} else {
				insertion := []byte("\n")
				if variant == "whitespace-line-earlier" {
					insertion = []byte("   \u2003\n")
				} else if strings.HasPrefix(variant, "control-") {
					insertion = []byte(map[string]string{
						"control-001c-earlier": "\u001c\n",
						"control-001d-earlier": "\u001d\n",
						"control-001e-earlier": "\u001e\n",
						"control-001f-earlier": "\u001f\n",
					}[variant])
				}
				at := bytes.IndexByte(raw, '\n') + 1
				if at == 0 {
					t.Fatal("earlier writer segment has no complete entry")
				}
				raw = bytes.Join([][]byte{raw[:at], insertion, raw[at:]}, nil)
			}
			if err := os.WriteFile(first, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := observeRecoveryWithOptions(caseDir, predecessor, signer, recoveryObservationOptions{trusted: []string{signer}, maxBytes: recorder.MaxEvidenceReadFileBytes}); variant == "torn-earlier" && err == nil {
				t.Fatal("bounded recovery observer accepted a torn earlier segment")
			}
		}
		if got := VerifyReceiptGroup(caseDir, groupID, []string{signer}); got.Verdict != want {
			t.Fatalf("%s: got %s, want %s: %s", name, got.Verdict, want, got.Error)
		}
		cases = append(cases, matrixCase{name, groupID, []string{signer}, want})
		err := filepath.WalkDir(caseDir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return walkErr
			}
			rel, err := filepath.Rel(caseDir, path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(filepath.Join("cases", name, rel))], err = os.ReadFile(path) // #nosec G304 G122 -- private fixture tree.
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, scope := range []string{"shard", "legacy", "predecessor"} {
		for _, mode := range []string{"close-later", "span-rotation"} {
			base, groupID, signer, run, _, _ := writeRotationSource(t, scope, mode)
			for _, flipped := range []bool{false, true} {
				for _, present := range []bool{false, true} {
					name := fmt.Sprintf("rotation__%s__%s__%s__%s", scope, mode, map[bool]string{false: "intact", true: "flipped"}[flipped], map[bool]string{false: "absent", true: "present"}[present])
					caseDir := filepath.Join(t.TempDir(), name)
					copyRotationTree(t, base, caseDir)
					if flipped {
						path := filepath.Join(caseDir, "ael", run, "recorders", "pipelock.jsonl")
						raw, err := os.ReadFile(path) // #nosec G304 -- path is a fixed child of this test's temporary fixture directory.
						if err != nil || len(raw) == 0 {
							t.Fatalf("read native run: %v", err)
						}
						raw[0] ^= 1
						if err := os.WriteFile(path, raw, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					if !present {
						closeName, _ := ReceiptGroupFileName(groupID, "close")
						if err := os.Remove(filepath.Join(caseDir, closeName)); err != nil {
							t.Fatal(err)
						}
					}
					want := GroupValid
					if !present {
						want = GroupIncomplete
					}
					if flipped {
						want = GroupInvalid
					}
					got := VerifyReceiptGroup(caseDir, groupID, []string{signer})
					if got.Verdict != want {
						t.Fatalf("%s: got %s want %s: %s", name, got.Verdict, want, got.Error)
					}
					cases = append(cases, matrixCase{name, groupID, []string{signer}, want})
					err := filepath.WalkDir(caseDir, func(path string, entry os.DirEntry, walkErr error) error {
						if walkErr != nil || entry.IsDir() {
							return walkErr
						}
						rel, err := filepath.Rel(caseDir, path)
						if err != nil {
							return err
						}
						files[filepath.ToSlash(filepath.Join("cases", name, rel))], err = os.ReadFile(path) // #nosec G304 G122 -- WalkDir visits this test's private fixture tree.
						return err
					})
					if err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
	for _, scope := range []string{"shard", "legacy", "predecessor"} {
		base, groupID, signer, _, session, _ := writeRotationSource(t, scope, "span-rotation")
		for _, present := range []bool{false, true} {
			for _, damage := range []string{"torn-early", "torn-early-forged", "bad-middle-json"} {
				name := fmt.Sprintf("rotation__%s__%s__%s", scope, damage, map[bool]string{false: "absent", true: "present"}[present])
				caseDir := filepath.Join(t.TempDir(), name)
				copyRotationTree(t, base, caseDir)
				segments, err := filepath.Glob(filepath.Join(caseDir, "evidence-"+session+"-*.jsonl"))
				if err != nil || len(segments) < 3 {
					t.Fatalf("%s needs three writer segments: %v %v", name, segments, err)
				}
				sort.Slice(segments, func(i, j int) bool {
					_, left, _ := evidencename.Parse(filepath.Base(segments[i]))
					_, right, _ := evidencename.Parse(filepath.Base(segments[j]))
					return left < right
				})
				if damage != "bad-middle-json" {
					first, readErr := os.ReadFile(segments[0]) // #nosec G304 -- writer-produced private fixture.
					if readErr != nil || len(first) == 0 || first[len(first)-1] != '\n' {
						t.Fatalf("%s first segment: %v", name, readErr)
					}
					if err := os.WriteFile(segments[0], append(first, []byte(`{"partial":`)...), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if damage != "torn-early" {
					middle, readErr := os.ReadFile(segments[1]) // #nosec G304 -- writer-produced private fixture.
					if readErr != nil || len(middle) == 0 {
						t.Fatalf("%s middle segment: %v", name, readErr)
					}
					if damage == "bad-middle-json" {
						middle[0] = 'z'
					} else {
						marker := []byte(`"prev_hash":"`)
						at := bytes.Index(middle, marker)
						if at < 0 {
							t.Fatal("middle segment lacks previous hash")
						}
						at += len(marker)
						if middle[at] == '0' {
							middle[at] = '1'
						} else {
							middle[at] = '0'
						}
					}
					if err := os.WriteFile(segments[1], middle, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if !present {
					closeName, _ := ReceiptGroupFileName(groupID, "close")
					if err := os.Remove(filepath.Join(caseDir, closeName)); err != nil {
						t.Fatal(err)
					}
				}
				got := VerifyReceiptGroup(caseDir, groupID, []string{signer})
				if got.Verdict != GroupInvalid {
					t.Fatalf("%s: got %s, want %s: %s", name, got.Verdict, GroupInvalid, got.Error)
				}
				cases = append(cases, matrixCase{name, groupID, []string{signer}, GroupInvalid})
				err = filepath.WalkDir(caseDir, func(path string, entry os.DirEntry, walkErr error) error {
					if walkErr != nil || entry.IsDir() {
						return walkErr
					}
					rel, err := filepath.Rel(caseDir, path)
					if err != nil {
						return err
					}
					files[filepath.ToSlash(filepath.Join("cases", name, rel))], err = os.ReadFile(path) // #nosec G304 G122 -- private fixture tree.
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	for _, damage := range []string{"broken-link", "missing-segment"} {
		base, groupID, signer, _, _, _ := writeRotationSource(t, "shard", "span-rotation")
		name := "rotation__shard__" + damage
		caseDir := filepath.Join(t.TempDir(), name)
		copyRotationTree(t, base, caseDir)
		segments, err := filepath.Glob(filepath.Join(caseDir, "evidence-*-*.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(segments)
		later := ""
		for _, segment := range segments {
			if !strings.HasSuffix(segment, "-0.jsonl") {
				later = segment
				break
			}
		}
		if later == "" {
			t.Fatal("writer produced no later segment")
		}
		if damage == "missing-segment" {
			if err := os.Remove(later); err != nil {
				t.Fatal(err)
			}
		} else {
			raw, err := os.ReadFile(later) // #nosec G304 -- later is a file in this test's private fixture tree.
			if err != nil {
				t.Fatal(err)
			}
			marker := []byte(`"prev_hash":"`)
			at := bytes.Index(raw, marker)
			if at < 0 {
				t.Fatal("later segment has no previous hash")
			}
			at += len(marker)
			if raw[at] == '0' {
				raw[at] = '1'
			} else {
				raw[at] = '0'
			}
			if err := os.WriteFile(later, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		got := VerifyReceiptGroup(caseDir, groupID, []string{signer})
		if got.Verdict != GroupInvalid {
			t.Fatalf("%s: got %s, want invalid: %s", name, got.Verdict, got.Error)
		}
		cases = append(cases, matrixCase{name, groupID, []string{signer}, GroupInvalid})
		err = filepath.WalkDir(caseDir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return walkErr
			}
			rel, err := filepath.Rel(caseDir, path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(filepath.Join("cases", name, rel))], err = os.ReadFile(path) // #nosec G304 G122 -- WalkDir visits this test's private fixture tree.
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, variant := range []string{"suffix-intact", "suffix-flipped", "duplicate-seq", "prefix-collision", "deleted-intact", "deleted-flipped", "deleted-partial-ael", "deleted-bad-complete-ael", "deleted-no-newline-ael"} {
		base, groupID, signer, run, session, _ := writeRotationSource(t, "legacy", "span-rotation")
		name := "rotation__legacy__" + variant
		caseDir := filepath.Join(t.TempDir(), name)
		copyRotationTree(t, base, caseDir)
		segments, globErr := filepath.Glob(filepath.Join(caseDir, "evidence-"+session+"-*.jsonl"))
		if globErr != nil || len(segments) < 2 {
			t.Fatalf("legacy rotation segments: %v %v", segments, globErr)
		}
		sort.Strings(segments)
		first := filepath.Join(caseDir, "evidence-"+session+"-0.jsonl")
		later := segments[len(segments)-1]
		switch variant {
		case "suffix-intact", "suffix-flipped":
			if err := os.Rename(later, filepath.Join(caseDir, "evidence-"+session+"-tail.jsonl")); err != nil {
				t.Fatal(err)
			}
		case "duplicate-seq":
			raw, err := os.ReadFile(first) // #nosec G304 -- writer-produced test tree.
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(caseDir, "evidence-"+session+"-00.jsonl"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		case "prefix-collision":
			raw, err := os.ReadFile(first) // #nosec G304 -- writer-produced test tree.
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(caseDir, "evidence-"+session+"-evil-0.jsonl"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		case "deleted-intact", "deleted-flipped", "deleted-partial-ael", "deleted-bad-complete-ael", "deleted-no-newline-ael":
			for _, segment := range segments {
				if segment != first {
					if err := os.Remove(segment); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		if strings.HasSuffix(variant, "flipped") {
			path := filepath.Join(caseDir, "ael", run, "recorders", "pipelock.jsonl")
			raw, err := os.ReadFile(path) // #nosec G304 -- writer-produced test tree.
			if err != nil || len(raw) == 0 {
				t.Fatalf("read native run: %v", err)
			}
			raw[0] ^= 1
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if variant == "deleted-partial-ael" || variant == "deleted-bad-complete-ael" {
			path := filepath.Join(caseDir, "ael", run, "recorders", "pipelock.jsonl")
			raw, err := os.ReadFile(path) // #nosec G304 -- writer-produced test tree.
			if err != nil || len(raw) < 2 {
				t.Fatalf("read native run: %v", err)
			}
			closeStart := bytes.LastIndexByte(raw[:len(raw)-1], '\n')
			if closeStart < 0 {
				t.Fatal("native run has no complete prefix")
			}
			raw = raw[:closeStart+1]
			if variant == "deleted-partial-ael" {
				raw = append(raw, []byte("partial")...)
			} else {
				raw = append(raw, []byte("bad-complete\n")...)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if variant == "deleted-no-newline-ael" {
			path := filepath.Join(caseDir, "ael", run, "recorders", "pipelock.jsonl")
			if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want := GroupInvalid
		if variant == "deleted-intact" || variant == "deleted-partial-ael" || variant == "deleted-no-newline-ael" {
			want = GroupValid // The intact neighbor is visibly reported as open.
		}
		if got := VerifyReceiptGroup(caseDir, groupID, []string{signer}); got.Verdict != want {
			t.Fatalf("%s: got %s, want %s: %s", name, got.Verdict, want, got.Error)
		}
		cases = append(cases, matrixCase{name, groupID, []string{signer}, want})
		err = filepath.WalkDir(caseDir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return walkErr
			}
			rel, err := filepath.Rel(caseDir, path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(filepath.Join("cases", name, rel))], err = os.ReadFile(path) // #nosec G304 G122 -- private fixture tree.
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	cloneCase := func(source, name string, want ReceiptGroupVerdict) {
		t.Helper()
		found := false
		for _, item := range cases {
			if item.Name == source {
				cases = append(cases, matrixCase{name, item.GroupID, item.TrustedKeys, want})
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing matrix source %q", source)
		}
		prefix := "cases/" + source + "/"
		for path, data := range files {
			if strings.HasPrefix(path, prefix) {
				files["cases/"+name+"/"+strings.TrimPrefix(path, prefix)] = bytes.Clone(data)
			}
		}
	}
	cloneCase("shard__intact__absent", "shard__torn-gate-missing-open", GroupInvalid)
	{
		prefix := "cases/shard__torn-gate-missing-open/"
		for name, data := range files {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			if strings.HasSuffix(name, "-open.json") {
				delete(files, name)
			} else if strings.HasPrefix(strings.TrimPrefix(name, prefix), "evidence-") && strings.HasSuffix(name, "-0.jsonl") {
				files[name] = append(data, []byte(`{"torn":`)...)
			}
		}
	}
	cloneCase("shard__intact__present", "opening__untrusted-signer", GroupInvalid)
	cases[len(cases)-1].TrustedKeys = []string{strings.Repeat("0", 64)}
	// A signed predecessor close can lie about a shard head while a signed
	// transition still names the real head. The two signed claims must agree.
	{
		base, groupID, signer, _, _, key := writeRotationSource(t, "predecessor", "span-rotation")
		name := "predecessor__signed-close-head-disagrees"
		caseDir := filepath.Join(t.TempDir(), name)
		copyRotationTree(t, base, caseDir)
		readOpen := func(id string) (ReceiptGroupOpen, string) {
			t.Helper()
			file, _ := ReceiptGroupFileName(id, "open")
			raw, readErr := os.ReadFile(filepath.Join(caseDir, file)) // #nosec G304 -- writer-produced fixture.
			if readErr != nil {
				t.Fatal(readErr)
			}
			opening, decodeErr := UnmarshalReceiptGroupOpen(raw, []string{signer})
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			sum := sha256.Sum256(raw)
			return opening, hex.EncodeToString(sum[:])
		}
		successor, successorHash := readOpen(groupID)
		predecessor, predecessorHash := readOpen(successor.PreviousGroupID)
		closeName, _ := ReceiptGroupFileName(predecessor.GroupID, "close")
		closePath := filepath.Join(caseDir, closeName)
		closeBytes, readErr := os.ReadFile(closePath) // #nosec G304 -- writer-produced fixture.
		if readErr != nil {
			t.Fatal(readErr)
		}
		closed, decodeErr := UnmarshalReceiptGroupClose(closeBytes, predecessor, predecessorHash, []string{signer})
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		closed.Shards[0].FinalChainHash = strings.Repeat("0", 64)
		closed, signErr := SignReceiptGroupClose(closed, predecessor, predecessorHash, key)
		if signErr != nil {
			t.Fatal(signErr)
		}
		closeBytes, err = json.Marshal(closed)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(closePath, closeBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		closeSum := sha256.Sum256(closeBytes)
		transitionName, _ := ReceiptGroupFileName(successor.GroupID, "transition")
		transitionPath := filepath.Join(caseDir, transitionName)
		transitionBytes, readErr := os.ReadFile(transitionPath) // #nosec G304 -- writer-produced fixture.
		if readErr != nil {
			t.Fatal(readErr)
		}
		var transition ReceiptGroupTransition
		if err := json.Unmarshal(transitionBytes, &transition); err != nil {
			t.Fatal(err)
		}
		transition.PreviousCloseManifestSHA256 = hex.EncodeToString(closeSum[:])
		transition, signErr = SignReceiptGroupTransition(transition, successor, predecessor, successorHash, predecessorHash, transition.PreviousCloseManifestSHA256, key)
		if signErr != nil {
			t.Fatal(signErr)
		}
		transitionBytes, err = json.Marshal(transition)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(transitionPath, transitionBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := VerifyReceiptGroup(caseDir, groupID, []string{signer}); got.Verdict != GroupInvalid || !strings.Contains(got.Error, "signed close") {
			t.Fatalf("signed-close mismatch vector = %+v", got)
		}
		cases = append(cases, matrixCase{name, groupID, []string{signer}, GroupInvalid})
		if err := filepath.WalkDir(caseDir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return walkErr
			}
			rel, relErr := filepath.Rel(caseDir, path)
			if relErr != nil {
				return relErr
			}
			files[filepath.ToSlash(filepath.Join("cases", name, rel))], relErr = os.ReadFile(path) // #nosec G304 G122 -- private fixture tree.
			return relErr
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, variant := range []struct {
		name, line string
		want       ReceiptGroupVerdict
	}{
		{"shard__blank-line-feff__present", "\ufeff\n", GroupInvalid},
		{"shard__blank-line-0085__present", "\u0085\n", GroupValid},
		{"shard__unsafe-number-line__present", "{\"v\":9007199254740993}\n", GroupInvalid},
	} {
		cloneCase("shard__intact__present", variant.name, variant.want)
		prefix := "cases/" + variant.name + "/evidence-"
		var paths []string
		for path := range files {
			if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, "-0.jsonl") {
				paths = append(paths, path)
			}
		}
		sort.Strings(paths)
		if len(paths) == 0 {
			t.Fatalf("%s has no evidence segment", variant.name)
		}
		raw := files[paths[0]]
		at := bytes.IndexByte(raw, '\n') + 1
		if at == 0 {
			t.Fatalf("%s has no complete evidence line", paths[0])
		}
		files[paths[0]] = bytes.Join([][]byte{raw[:at], []byte(variant.line), raw[at:]}, nil)
	}
	for _, variant := range []struct {
		name, space string
		leading     bool
		want        ReceiptGroupVerdict
	}{
		{"shard__leading-0085__present", "\u0085", true, GroupValid},
		{"shard__trailing-00a0__present", "\u00a0", false, GroupValid},
		{"shard__leading-001c__present", "\u001c", true, GroupInvalid},
		{"shard__trailing-feff__present", "\ufeff", false, GroupInvalid},
		{"shard__leading-200b__present", "\u200b", true, GroupInvalid},
	} {
		cloneCase("shard__intact__present", variant.name, variant.want)
		prefix := "cases/" + variant.name + "/evidence-"
		var paths []string
		for path := range files {
			if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, "-0.jsonl") {
				paths = append(paths, path)
			}
		}
		sort.Strings(paths)
		if len(paths) == 0 {
			t.Fatalf("%s has no evidence segment", variant.name)
		}
		raw := files[paths[0]]
		at := bytes.IndexByte(raw, '\n')
		if at < 0 {
			t.Fatalf("%s has no complete evidence line", paths[0])
		}
		if variant.leading {
			files[paths[0]] = append([]byte(variant.space), raw...)
		} else {
			files[paths[0]] = bytes.Join([][]byte{raw[:at], []byte(variant.space), raw[at:]}, nil)
		}
	}
	for _, variant := range []struct {
		name, space string
		blank       bool
		want        ReceiptGroupVerdict
	}{
		{"ael__leading-0085__present", "\u0085", false, GroupValid},
		{"ael__leading-001c__present", "\u001c", false, GroupInvalid},
		{"ael__blank-line-0085__present", "\u0085", true, GroupValid},
		{"ael__blank-line-feff__present", "\ufeff", true, GroupInvalid},
	} {
		cloneCase("shard__intact__present", variant.name, variant.want)
		prefix := "cases/" + variant.name + "/ael/"
		var paths []string
		for path := range files {
			if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, "/recorders/pipelock.jsonl") {
				paths = append(paths, path)
			}
		}
		sort.Strings(paths)
		if len(paths) == 0 {
			t.Fatalf("%s has no native AEL recorder", variant.name)
		}
		raw := files[paths[0]]
		if variant.blank {
			at := bytes.IndexByte(raw, '\n') + 1
			if at == 0 {
				t.Fatalf("%s has no complete native AEL line", paths[0])
			}
			files[paths[0]] = bytes.Join([][]byte{raw[:at], []byte(variant.space + "\n"), raw[at:]}, nil)
		} else {
			files[paths[0]] = append([]byte(variant.space), raw...)
		}
	}
	for _, item := range []struct{ source, name string }{
		{"shard__intact__absent", "shard__torn-receipt__absent"},
		{"non-shard-legacy__intact__absent", "non-shard-legacy__torn-receipt__absent"},
	} {
		cloneCase(item.source, item.name, GroupIncomplete)
		prefix := "cases/" + item.name + "/evidence-"
		var paths []string
		for path := range files {
			if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, ".jsonl") {
				paths = append(paths, path)
			}
		}
		sort.Strings(paths)
		if len(paths) == 0 {
			t.Fatalf("%s has no evidence file", item.name)
		}
		path := paths[0]
		raw := files[path]
		if len(raw) < 10 || raw[len(raw)-1] != '\n' {
			t.Fatalf("%s has no complete writer line", path)
		}
		files[path] = raw[:len(raw)-10]
	}
	cloneCase("shard__intact__present", "shard__evidence-directory__present", GroupInvalid)
	var paths []string
	for path := range files {
		if strings.HasPrefix(path, "cases/shard__evidence-directory__present/evidence-") && strings.HasSuffix(path, "-0.jsonl") {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("directory-name matrix source has no evidence segment")
	}
	files[strings.TrimSuffix(paths[0], "-0.jsonl")+"-tail.jsonl/"] = nil
	files["matrix.json"], err = json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	var zipped bytes.Buffer
	zw := zip.NewWriter(&zipped)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := files[name]
		h := &zip.FileHeader{Name: name, Method: zip.Store}
		if strings.HasSuffix(name, "/") {
			h.SetMode(os.ModeDir | 0o750)
		}
		h.CRC32 = crc32.ChecksumIEEE(data)
		h.UncompressedSize64 = uint64(len(data))
		h.CompressedSize64 = uint64(len(data))
		w, err := zw.CreateRaw(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gw, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Write(zipped.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d matrix cells from production recorder rotation", len(cases))
}

func copyRotationTree(t *testing.T, source, target string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		out := filepath.Join(target, rel)
		if entry.IsDir() {
			return os.MkdirAll(out, 0o750)
		}
		raw, err := os.ReadFile(path) // #nosec G304 G122 -- WalkDir visits this test's private fixture tree.
		if err != nil {
			return err
		}
		return os.WriteFile(out, raw, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func writeRotatedRecoverySource(t *testing.T) (string, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	_, key := generateTestKey(t)
	openRecorder := func(maxEntries int) *recorder.Recorder {
		t.Helper()
		r, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true, MaxEntriesPerFile: maxEntries}, nil, key)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	emitterConfig := func(r *recorder.Recorder) EmitterConfig {
		return EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
	}
	firstRecorder := openRecorder(2)
	first, err := OpenInitialReceiptShardSet(emitterConfig(firstRecorder), "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	firstOpen, _ := first.Opening()
	for range 2 {
		if err := first.Emitters()[0].EmitDurable(EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := firstRecorder.Close(); err != nil {
		t.Fatal(err)
	}
	predecessor := firstOpen.Shards[0].SessionID
	segments, err := filepath.Glob(filepath.Join(dir, "evidence-"+predecessor+"-*.jsonl"))
	if err != nil || len(segments) < 2 {
		t.Fatalf("recovery predecessor did not rotate: %v %v", segments, err)
	}
	sort.Slice(segments, func(i, j int) bool {
		_, left, _ := evidencename.Parse(filepath.Base(segments[i]))
		_, right, _ := evidencename.Parse(filepath.Base(segments[j]))
		return left < right
	})
	last := segments[len(segments)-1]
	f, err := os.OpenFile(last, os.O_WRONLY|os.O_APPEND, 0) // #nosec G304 -- last is a writer-produced file in this test's private fixture tree.
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"torn":`); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	successorRecorder := openRecorder(0)
	successor, err := OpenSuccessorReceiptShardSet(emitterConfig(successorRecorder), "proxy", 2, 0, firstOpen.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	for _, emitter := range successor.Emitters() {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := successor.PublishClose(); err != nil {
		t.Fatal(err)
	}
	if err := successorRecorder.Close(); err != nil {
		t.Fatal(err)
	}
	open, _ := successor.Opening()
	return dir, open.GroupID, firstOpen.SignerKey, predecessor
}

func writeRotationSource(t *testing.T, scope, mode string) (string, string, string, string, string, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	_, key := generateTestKey(t)
	newRecorder := func(maxEntries int) *recorder.Recorder {
		t.Helper()
		r, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true, MaxEntriesPerFile: maxEntries}, nil, key)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	seal := func(set *ReceiptShardSet) {
		t.Helper()
		for _, emitter := range set.Emitters() {
			if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
				t.Fatal(err)
			}
			if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := set.PublishClose(); err != nil {
			t.Fatal(err)
		}
	}
	emitActions := func(emitter *Emitter) {
		t.Helper()
		if mode == "span-rotation" {
			for range 2 {
				if err := emitter.EmitDurable(EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data"}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	maxEntries := 3
	if mode == "span-rotation" {
		maxEntries = 2
	}
	firstRec := newRecorder(maxEntries)
	first, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: firstRec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	firstOpen, _ := first.Opening()
	target := first.Emitters()[0]
	if scope == "shard" || scope == "predecessor" {
		emitActions(target)
	}
	seal(first)
	if err := firstRec.Close(); err != nil {
		t.Fatal(err)
	}
	groupID := firstOpen.GroupID
	if scope == "legacy" {
		legacyRec := newRecorder(1)
		session, err := recorder.AcquireRunSession(legacyRec, "proxy")
		if err != nil {
			t.Fatal(err)
		}
		legacy := NewEmitter(EmitterConfig{Recorder: legacyRec, PrivKey: key, Session: session, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
		if err := legacy.EmitSessionOpen(); err != nil {
			t.Fatal(err)
		}
		target = legacy
		emitActions(target)
		if err := legacy.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := legacy.EmitTranscriptRoot(legacy.Session()); err != nil {
			t.Fatal(err)
		}
		if err := legacyRec.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if scope == "predecessor" {
		successorRec := newRecorder(0)
		successor, err := OpenSuccessorReceiptShardSet(EmitterConfig{Recorder: successorRec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0, firstOpen.GroupID)
		if err != nil {
			t.Fatal(err)
		}
		seal(successor)
		if err := successorRec.Close(); err != nil {
			t.Fatal(err)
		}
		open, _ := successor.Opening()
		groupID = open.GroupID
	}
	health, ok := target.HealthSnapshot()
	if !ok || health.RunNonce == "" {
		t.Fatal("native run nonce missing")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+target.Session()+"-*.jsonl"))
	if err != nil || len(paths) < 2 {
		t.Fatalf("writer did not rotate %s: %v %v", scope, paths, err)
	}
	return dir, groupID, firstOpen.SignerKey, health.RunNonce, target.Session(), key
}
