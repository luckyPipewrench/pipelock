// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// Regenerate the shared production-shape group corpus with
//
//	UPDATE_RECEIPT_V2_CORPUS=1 go test ./internal/cli/runtime -run '^TestGenerateReceiptGroupV2Corpus$'
//
// The groups come from the real server emitter path (buildServerReceiptShardGroup
// plus the proxy decision v2 emitter), so every shard carries v1 action
// receipts and v2 evidence receipts. The tamper cases recompute the recorder
// hash chain (and re-sign checkpoints, the recovery seal and the transition
// where the tamper sits under their digests), so only the signed content is
// wrong and a byte-level recorder check cannot catch them. Every expected
// verdict is Go's own verdict on the final directory.
var v2CorpusEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	v2CorpusRoot = "../../../sdk/verifiers"
	v2CorpusName = "receipt-groups-v2.zip"
)

type v2CorpusCase struct {
	Name        string   `json:"name"`
	GroupID     string   `json:"group_id"`
	TrustedKeys []string `json:"trusted_keys"`
	Expected    string   `json:"expected"`
	Note        string   `json:"note"`
	dir         string
	want        receipt.ReceiptGroupVerdict
}

type v2CorpusKeys struct {
	pub  string
	priv ed25519.PrivateKey
}

func newV2CorpusKey(t *testing.T) v2CorpusKeys {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return v2CorpusKeys{pub: hex.EncodeToString(pub), priv: priv}
}

type v2Run struct {
	open receipt.ReceiptGroupOpen
	dir  string
}

// runV2Process starts one server process group in dir: v1 action and v2
// decision receipts on every shard, optionally the graceful shutdown path.
func runV2Process(t *testing.T, dir string, key v2CorpusKeys, graceful bool) v2Run {
	t.Helper()
	return runV2ProcessN(t, dir, key, graceful, nil, 2)
}

// runV2ProcessN starts one server process group of n shards. A non-empty prior
// lists the signer keys of an earlier process, which the new signer endorses.
func runV2ProcessN(t *testing.T, dir string, key v2CorpusKeys, graceful bool, prior []string, n int) v2Run {
	t.Helper()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key.priv)
	if err != nil {
		t.Fatal(err)
	}
	template := receipt.EmitterConfig{Recorder: rec, PrivKey: key.priv, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock", PriorSignerKeys: prior}
	shards, _, err := buildServerReceiptShardGroup(template, n, filepath.Join(dir, "signer.key"), false)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := shards.Opening()
	for _, emitter := range shards.Emitters() {
		if err := emitter.EmitDurable(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data"}); err != nil {
			t.Fatal(err)
		}
		v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{
			Recorder: rec, Signer: proxydecision.NewKeyedSigner(key.priv),
			Sanitize:  proxydecision.SanitizeFromRedactor(rec.ReceiptRedactor()),
			Principal: "local", Actor: "pipelock", Session: emitter.Session(),
		})
		if err := v2.Emit(proxydecision.Decision{
			ActionType: "http_request", Transport: "forward", Target: "https://x.example/a", Verdict: "allow",
			WinningSource: proxydecision.SourceScanner, PolicySources: []string{proxydecision.SourceScanner},
			PolicyHash: strings.Repeat("b", 64),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if graceful {
		(&Server{receiptShardSet: shards}).sealTranscriptRoot()
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	return v2Run{open: open, dir: dir}
}

// runLegacySession adds a signed legacy (non-group) session to dir.
func runLegacySession(t *testing.T, dir string, key v2CorpusKeys, withOpen bool) string {
	t.Helper()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key.priv)
	if err != nil {
		t.Fatal(err)
	}
	session, err := recorder.AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: key.priv, Session: session, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock"})
	if withOpen {
		if err := emitter.EmitSessionOpen(); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := emitter.EmitDurable(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/legacy"}); err != nil {
			t.Fatal(err)
		}
	}
	if withOpen {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	return session
}

// runV2OnlySession adds a legacy session that holds only a v2 decision receipt
// and no v1 action receipt, which Go's inventory accepts as an empty v1 chain.
func runV2OnlySession(t *testing.T, dir string, key v2CorpusKeys) {
	t.Helper()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key.priv)
	if err != nil {
		t.Fatal(err)
	}
	session, err := recorder.AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{
		Recorder: rec, Signer: proxydecision.NewKeyedSigner(key.priv),
		Sanitize:  proxydecision.SanitizeFromRedactor(rec.ReceiptRedactor()),
		Principal: "local", Actor: "pipelock", Session: session,
	})
	if err := v2.Emit(proxydecision.Decision{
		ActionType: "http_request", Transport: "forward", Target: "https://x.example/a", Verdict: "allow",
		WinningSource: proxydecision.SourceScanner, PolicySources: []string{proxydecision.SourceScanner},
		PolicyHash: strings.Repeat("b", 64),
	}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
}

// tearV2Shard appends an unterminated fragment to a crashed shard, the torn
// tail a recovery seal exists to cover.
func tearV2Shard(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"torn":`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// v2HandStep is one receipt of a hand-signed legacy chain.
type v2HandStep struct {
	key v2CorpusKeys
	rot bool   // restart the sequence under key, naming the previous head
	ext string // unsigned ext bag recorded with the receipt, if any
}

// recordHandSignedChain writes a legacy receipt chain with no native AEL run,
// one signed receipt per step, into dir under its own session. A rotating step
// restarts the sequence under its key with a transition from the previous head.
func recordHandSignedChain(t *testing.T, dir, session string, recorderKey v2CorpusKeys, steps []v2HandStep) {
	t.Helper()
	src := t.TempDir()
	srcRec, err := recorder.New(recorder.Config{Enabled: true, Dir: src, SignCheckpoints: true}, nil, recorderKey.priv)
	if err != nil {
		t.Fatal(err)
	}
	srcEmitter := receipt.NewEmitter(receipt.EmitterConfig{Recorder: srcRec, PrivKey: recorderKey.priv, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock"})
	if err := srcEmitter.EmitDurable(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/s"}); err != nil {
		t.Fatal(err)
	}
	if err := srcRec.Close(); err != nil {
		t.Fatal(err)
	}
	tmpl, err := receipt.ExtractReceiptsFromSessionDir(src, "proxy")
	if err != nil || len(tmpl) == 0 {
		t.Fatalf("receipt template: %v", err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, recorderKey.priv)
	if err != nil {
		t.Fatal(err)
	}
	prev := receipt.GenesisHash
	var seq, lastSeq uint64
	var lastKey, lastHash string
	for i, step := range steps {
		ar := tmpl[0].ActionRecord
		ar.RunNonce = ""
		ar.ActionID = receipt.NewActionID()
		ar.Target = "https://api.vendor.example/legacy" + string(rune('a'+i))
		ar.KeyTransition = nil
		if step.rot {
			seq = 0
			ar.KeyTransition = &receipt.KeyTransition{PriorSignerKey: lastKey, PriorChainSeq: lastSeq, PriorChainHash: lastHash}
		}
		ar.ChainSeq, ar.ChainPrevHash = seq, prev
		r, err := receipt.Sign(ar, step.key.priv)
		if err != nil {
			t.Fatal(err)
		}
		if step.ext != "" {
			r.Ext = json.RawMessage(step.ext)
		}
		hash, err := receipt.ReceiptHash(r)
		if err != nil {
			t.Fatal(err)
		}
		body, err := receipt.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := rec.Record(recorder.Entry{SessionID: session, Type: "action_receipt", EventKind: string(ar.ActionType), Transport: "fetch", Summary: "x", Detail: json.RawMessage(body)}); err != nil {
			t.Fatal(err)
		}
		prev, lastHash, lastKey, lastSeq = hash, hash, r.SignerKey, seq
		seq++
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
}

func copyV2Tree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		raw, err := os.ReadFile(filepath.Clean(path)) // #nosec G122 -- generator walks its own private temp tree
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

type v2OutLine struct {
	text    string
	keepSig bool
}

// rewriteV2Shard edits a shard's complete lines, then recomputes the recorder
// hash chain and re-signs every checkpoint except those marked keepSig. A
// trailing unterminated fragment is preserved byte for byte.
func rewriteV2Shard(t *testing.T, path string, key v2CorpusKeys, edit func(lines []string) []v2OutLine) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	boundary := bytes.LastIndexByte(raw, '\n') + 1
	tail := raw[boundary:]
	lines := strings.Split(strings.TrimSuffix(string(raw[:boundary]), "\n"), "\n")
	outs := edit(lines)
	prev := recorder.GenesisHash
	var buf bytes.Buffer
	for i, ol := range outs {
		line := ol.text
		entry, err := recorder.ParseEntryLine([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		if want := uint64(i); entry.Sequence != want {
			line = strings.Replace(line, `"seq":`+strconv.FormatUint(entry.Sequence, 10), `"seq":`+strconv.FormatUint(want, 10), 1)
			entry.Sequence = want
		}
		line = strings.Replace(line, `"prev_hash":"`+entry.PrevHash+`"`, `"prev_hash":"`+prev+`"`, 1)
		if entry.Type == "checkpoint" && !ol.keepSig {
			var detail recorder.CheckpointDetail
			rawDetail, err := json.Marshal(entry.Detail)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(rawDetail, &detail); err != nil {
				t.Fatal(err)
			}
			fresh := hex.EncodeToString(ed25519.Sign(key.priv, []byte(prev)))
			line = strings.Replace(line, `"signature":"`+detail.Signature+`"`, `"signature":"`+fresh+`"`, 1)
		}
		entry, err = recorder.ParseEntryLine([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		oldHash := entry.Hash
		entry.Hash = recorder.ComputeHash(entry)
		line = strings.Replace(line, `"hash":"`+oldHash+`"`, `"hash":"`+entry.Hash+`"`, 1)
		prev = entry.Hash
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	buf.Write(tail)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func passthroughV2(lines []string) []v2OutLine {
	out := make([]v2OutLine, len(lines))
	for i, l := range lines {
		out[i] = v2OutLine{text: l}
	}
	return out
}

func flipHexAfter(t *testing.T, line, marker string) string {
	t.Helper()
	at := strings.Index(line, marker)
	if at < 0 {
		t.Fatalf("marker %q missing in %.120s", marker, line)
	}
	at += len(marker)
	flipped := byte('0')
	if line[at] == '0' {
		flipped = '1'
	}
	return line[:at] + string(flipped) + line[at+1:]
}

func lastCheckpointIndex(t *testing.T, lines []string) int {
	t.Helper()
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], `"type":"checkpoint"`) {
			return i
		}
	}
	t.Fatal("no checkpoint line")
	return -1
}

func shardPath(dir, session string) string {
	return filepath.Join(dir, "evidence-"+session+"-0.jsonl")
}

// resignClosedShardHead rebinds a group's signed close to a shard whose
// recorder chain was recomputed. The close commits the recorder hashes of the
// transcript root and of the final checkpoint, so after a rewrite it must be
// signed again; only then is a single wrong checkpoint signature left for the
// verifier to find, instead of a head that merely differs from the close.
func resignClosedShardHead(t *testing.T, dir string, open receipt.ReceiptGroupOpen, index int, key v2CorpusKeys) {
	t.Helper()
	closeName := "receipt-group-" + open.GroupID + "-close.json"
	rawClose, err := os.ReadFile(filepath.Clean(filepath.Join(dir, closeName)))
	if err != nil {
		t.Fatal(err)
	}
	var closeManifest receipt.ReceiptGroupClose
	if err := json.Unmarshal(rawClose, &closeManifest); err != nil {
		t.Fatal(err)
	}
	rawShard, err := os.ReadFile(filepath.Clean(shardPath(dir, open.Shards[index].SessionID)))
	if err != nil {
		t.Fatal(err)
	}
	head := &closeManifest.Shards[index]
	lines := bytes.Split(bytes.TrimSuffix(rawShard, []byte("\n")), []byte("\n"))
	for _, line := range lines {
		entry, err := recorder.ParseEntryLine(line)
		if err != nil {
			t.Fatal(err)
		}
		if entry.Type == "transcript_root" {
			head.TranscriptRootHash = entry.Hash
		}
		head.CheckpointHash = entry.Hash
	}
	rawOpen, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "receipt-group-"+open.GroupID+"-open.json")))
	if err != nil {
		t.Fatal(err)
	}
	openSum := sha256.Sum256(rawOpen)
	closeManifest, err = receipt.SignReceiptGroupClose(closeManifest, open, hex.EncodeToString(openSum[:]), key.priv)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(closeManifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, closeName), jsonscan.NormalizeReplacementEscapes(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rehashSealedPredecessor(t *testing.T, dir string, pred, succ receipt.ReceiptGroupOpen, key v2CorpusKeys) {
	t.Helper()
	// The recovery seal binds the damaged shard digest and the last good head,
	// and the transition binds the seal digest. Rebind both after a tamper so
	// the signed content, not a stale digest, is what the verifier must reject.
	session := pred.Shards[0].SessionID
	sealName := "chain-link-" + session + ".json"
	rawSeal, err := os.ReadFile(filepath.Clean(filepath.Join(dir, sealName)))
	if err != nil {
		t.Fatal(err)
	}
	seal, err := receipt.UnmarshalRecoverySeal(rawSeal)
	if err != nil {
		t.Fatal(err)
	}
	shard, err := os.ReadFile(filepath.Clean(filepath.Join(dir, seal.Shard)))
	if err != nil {
		t.Fatal(err)
	}
	prefix := shard[:bytes.LastIndexByte(shard, '\n')+1]
	prefixLines := bytes.Split(bytes.TrimSuffix(prefix, []byte("\n")), []byte("\n"))
	last, err := recorder.ParseEntryLine(prefixLines[len(prefixLines)-1])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(shard)
	seal.ShardSize, seal.ShardSHA256, seal.DamageOffset = uint64(len(shard)), hex.EncodeToString(sum[:]), uint64(len(prefix))
	seal.LastGoodSeq, seal.LastGoodHash = last.Sequence, last.Hash
	seal, err = receipt.SignRecoverySeal(seal, key.priv)
	if err != nil {
		t.Fatal(err)
	}
	sealBody, err := json.Marshal(seal)
	if err != nil {
		t.Fatal(err)
	}
	sealBody = append(sealBody, '\n')
	if err := os.WriteFile(filepath.Join(dir, sealName), sealBody, 0o600); err != nil {
		t.Fatal(err)
	}
	sealSum := sha256.Sum256(sealBody)

	trName := "receipt-group-" + succ.GroupID + "-transition.json"
	rawTr, err := os.ReadFile(filepath.Clean(filepath.Join(dir, trName)))
	if err != nil {
		t.Fatal(err)
	}
	var tr receipt.ReceiptGroupTransition
	if err := json.Unmarshal(rawTr, &tr); err != nil {
		t.Fatal(err)
	}
	tr.Predecessors[0].RecoverySealSHA256 = hex.EncodeToString(sealSum[:])
	rawPred, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "receipt-group-"+pred.GroupID+"-open.json")))
	if err != nil {
		t.Fatal(err)
	}
	rawSucc, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "receipt-group-"+succ.GroupID+"-open.json")))
	if err != nil {
		t.Fatal(err)
	}
	predSum, succSum := sha256.Sum256(rawPred), sha256.Sum256(rawSucc)
	tr, err = receipt.SignReceiptGroupTransition(tr, succ, pred, hex.EncodeToString(succSum[:]), hex.EncodeToString(predSum[:]), "", key.priv)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, trName), jsonscan.NormalizeReplacementEscapes(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateReceiptGroupV2Corpus(t *testing.T) {
	if os.Getenv("UPDATE_RECEIPT_V2_CORPUS") != "1" {
		t.Skip("fixture regeneration only")
	}
	work := t.TempDir()
	key := newV2CorpusKey(t)
	trusted := []string{key.pub}
	var cases []*v2CorpusCase
	add := func(name, dir, groupID, note string, want receipt.ReceiptGroupVerdict, keys []string) {
		cases = append(cases, &v2CorpusCase{Name: name, GroupID: groupID, TrustedKeys: keys, Note: note, dir: dir, want: want})
	}
	mkdir := func(name string) string {
		dir := filepath.Join(work, name)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	clone := func(from, name string) string {
		dir := mkdir(name)
		copyV2Tree(t, from, dir)
		return dir
	}

	// 1. A closed two-shard group with v2 evidence receipts on both shards.
	closedDir := mkdir("v2-n2-closed")
	closed := runV2Process(t, closedDir, key, true)
	add("v2-n2-closed", closedDir, closed.open.GroupID, "closed group, v1 and v2 receipts on both shards", receipt.GroupValid, trusted)

	// 2. A closed predecessor followed by a closed successor.
	chainDir := mkdir("v2-successor-closed-predecessor")
	firstClosed := runV2Process(t, chainDir, key, true)
	secondClosed := runV2Process(t, chainDir, key, true)
	if secondClosed.open.PreviousGroupID != firstClosed.open.GroupID {
		t.Fatalf("successor did not bind the predecessor: %+v", secondClosed.open)
	}
	add("v2-successor-closed-predecessor", chainDir, secondClosed.open.GroupID, "closed successor with a transition from a closed v2 predecessor", receipt.GroupValid, trusted)

	// 3. A crashed predecessor with no close, then a closed successor.
	unsealedDir := mkdir("v2-successor-unsealed-predecessor")
	crashed := runV2Process(t, unsealedDir, key, false)
	crashedRuns, err := os.ReadDir(filepath.Join(unsealedDir, "ael"))
	if err != nil {
		t.Fatal(err)
	}
	unsealed := runV2Process(t, unsealedDir, key, true)
	if unsealed.open.PreviousGroupID != crashed.open.GroupID {
		t.Fatalf("successor did not bind the crashed predecessor: %+v", unsealed.open)
	}
	add("v2-successor-unsealed-predecessor", unsealedDir, unsealed.open.GroupID, "successor of a crashed predecessor whose shards end on complete lines", receipt.GroupValid, trusted)

	// 4. A crashed predecessor whose first shard has a torn tail (recovery seal).
	sealedDir := mkdir("v2-successor-sealed-predecessor")
	crashedTorn := runV2Process(t, sealedDir, key, false)
	f, err := os.OpenFile(shardPath(sealedDir, crashedTorn.open.Shards[0].SessionID), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"torn":`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	sealedSucc := runV2Process(t, sealedDir, key, true)
	add("v2-successor-sealed-predecessor", sealedDir, sealedSucc.open.GroupID, "successor of a crashed predecessor whose first shard is torn and sealed", receipt.GroupValid, trusted)

	// Tamper cases on the unsealed predecessor.
	pred0 := shardPath("", crashed.open.Shards[0].SessionID)
	pred1 := shardPath("", crashed.open.Shards[1].SessionID)
	dir := clone(unsealedDir, "unsealed-predecessor-checkpoint-signature-flip")
	rewriteV2Shard(t, filepath.Join(dir, pred0), key, func(lines []string) []v2OutLine {
		out := passthroughV2(lines)
		i := lastCheckpointIndex(t, lines)
		out[i] = v2OutLine{text: flipHexAfter(t, lines[i], `"signature":"`), keepSig: true}
		return out
	})
	add("unsealed-predecessor-checkpoint-signature-flip", dir, unsealed.open.GroupID, "last predecessor checkpoint signature flipped, recorder chain recomputed", receipt.GroupInvalid, trusted)

	dir = clone(unsealedDir, "unsealed-predecessor-garbage-evidence-after-checkpoint")
	rewriteV2Shard(t, filepath.Join(dir, pred1), key, func(lines []string) []v2OutLine {
		out := passthroughV2(lines)
		last, err := recorder.ParseEntryLine([]byte(lines[len(lines)-1]))
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &fields); err != nil {
			t.Fatal(err)
		}
		fields["seq"], _ = json.Marshal(last.Sequence + 1)
		fields["type"], _ = json.Marshal("evidence_receipt")
		fields["detail"] = json.RawMessage(`{"garbage":true}`)
		body, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return append(out, v2OutLine{text: string(body)})
	})
	add("unsealed-predecessor-garbage-evidence-after-checkpoint", dir, unsealed.open.GroupID, "garbage evidence_receipt appended after the last predecessor checkpoint", receipt.GroupInvalid, trusted)

	dir = clone(unsealedDir, "unsealed-predecessor-v2-body-edit")
	rewriteV2Shard(t, filepath.Join(dir, pred0), key, func(lines []string) []v2OutLine {
		out := passthroughV2(lines)
		edited := false
		for i, l := range lines {
			if strings.Contains(l, `"type":"evidence_receipt"`) && strings.Contains(l, "x.example") {
				out[i] = v2OutLine{text: strings.Replace(l, "x.example", "y.example", 1)}
				edited = true
				break
			}
		}
		if !edited {
			t.Fatal("no v2 evidence receipt to edit")
		}
		return out
	})
	add("unsealed-predecessor-v2-body-edit", dir, unsealed.open.GroupID, "signed v2 receipt body edited in the predecessor, recorder chain recomputed", receipt.GroupInvalid, trusted)

	// Tamper cases on the sealed predecessor (shard 0 is torn and sealed).
	predOpenSealed, succOpenSealed := crashedTorn.open, sealedSucc.open
	sealedPath := shardPath("", predOpenSealed.Shards[0].SessionID)
	dir = clone(sealedDir, "sealed-predecessor-checkpoint-signature-flip")
	rewriteV2Shard(t, filepath.Join(dir, sealedPath), key, func(lines []string) []v2OutLine {
		out := passthroughV2(lines)
		i := lastCheckpointIndex(t, lines)
		out[i] = v2OutLine{text: flipHexAfter(t, lines[i], `"signature":"`), keepSig: true}
		return out
	})
	rehashSealedPredecessor(t, dir, predOpenSealed, succOpenSealed, key)
	add("sealed-predecessor-checkpoint-signature-flip", dir, sealedSucc.open.GroupID, "sealed predecessor checkpoint signature flipped; recorder chain, seal and transition re-signed", receipt.GroupInvalid, trusted)

	dir = clone(sealedDir, "sealed-predecessor-v2-body-edit")
	rewriteV2Shard(t, filepath.Join(dir, sealedPath), key, func(lines []string) []v2OutLine {
		out := passthroughV2(lines)
		edited := false
		for i, l := range lines {
			if strings.Contains(l, `"type":"evidence_receipt"`) && strings.Contains(l, "x.example") {
				out[i] = v2OutLine{text: strings.Replace(l, "x.example", "y.example", 1)}
				edited = true
				break
			}
		}
		if !edited {
			t.Fatal("no v2 evidence receipt to edit")
		}
		return out
	})
	rehashSealedPredecessor(t, dir, predOpenSealed, succOpenSealed, key)
	add("sealed-predecessor-v2-body-edit", dir, sealedSucc.open.GroupID, "sealed predecessor v2 receipt body edited; recorder chain, seal and transition re-signed", receipt.GroupInvalid, trusted)

	// A predecessor shard's gate must be covered by the very next checkpoint.
	// Swapping the first checkpoint behind the signed session_open leaves a
	// recorder chain that still verifies but a gate nothing signs over.
	dir = clone(unsealedDir, "unsealed-predecessor-gate-not-covered")
	rewriteV2Shard(t, filepath.Join(dir, pred0), key, func(lines []string) []v2OutLine {
		out := passthroughV2(lines)
		out[1], out[2] = out[2], out[1]
		return out
	})
	add("unsealed-predecessor-gate-not-covered", dir, unsealed.open.GroupID, "first checkpoint moved behind the signed session open, so no checkpoint covers the gate", receipt.GroupInvalid, trusted)

	dir = clone(sealedDir, "sealed-predecessor-gate-not-covered")
	rewriteV2Shard(t, filepath.Join(dir, sealedPath), key, func(lines []string) []v2OutLine {
		out := passthroughV2(lines)
		out[1], out[2] = out[2], out[1]
		return out
	})
	rehashSealedPredecessor(t, dir, predOpenSealed, succOpenSealed, key)
	add("sealed-predecessor-gate-not-covered", dir, sealedSucc.open.GroupID, "sealed predecessor with its first checkpoint behind the signed session open; seal and transition re-signed", receipt.GroupInvalid, trusted)

	// A closed shard's checkpoints are signed too: flip one signature and
	// recompute the recorder chain so only the signature is wrong.
	for _, which := range []string{"first", "last"} {
		dir = clone(closedDir, "closed-shard-checkpoint-signature-flip-"+which)
		rewriteV2Shard(t, shardPath(dir, closed.open.Shards[0].SessionID), key, func(lines []string) []v2OutLine {
			out := passthroughV2(lines)
			idx := lastCheckpointIndex(t, lines)
			if which == "first" {
				for i, l := range lines {
					if strings.Contains(l, `"type":"checkpoint"`) {
						idx = i
						break
					}
				}
			}
			out[idx] = v2OutLine{text: flipHexAfter(t, lines[idx], `"signature":"`), keepSig: true}
			return out
		})
		resignClosedShardHead(t, dir, closed.open, 0, key)
		add("closed-shard-checkpoint-signature-flip-"+which, dir, closed.open.GroupID, which+" checkpoint signature of a closed shard flipped; recorder chain recomputed and signed close rebound", receipt.GroupInvalid, trusted)
	}

	// An unterminated fragment at the end of a crashed predecessor's native AEL
	// stream counts toward the 1 MiB record bound: one byte under is a torn
	// write Go tolerates, a full megabyte is refused.
	for _, spec := range []struct {
		name string
		pad  int
		want receipt.ReceiptGroupVerdict
		note string
	}{
		{"unsealed-predecessor-ael-fragment-below-bound", 1<<20 - 1, receipt.GroupValid, "predecessor native AEL stream ends in an unterminated fragment one byte under 1 MiB"},
		{"unsealed-predecessor-ael-fragment-at-bound", 1 << 20, receipt.GroupInvalid, "predecessor native AEL stream ends in an unterminated fragment of exactly 1 MiB"},
	} {
		dir = clone(unsealedDir, spec.name)
		for _, run := range crashedRuns {
			af, err := os.OpenFile(filepath.Clean(filepath.Join(dir, "ael", run.Name(), "recorders", "pipelock.jsonl")), os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := af.WriteString(strings.Repeat(" ", spec.pad)); err != nil {
				t.Fatal(err)
			}
			if err := af.Close(); err != nil {
				t.Fatal(err)
			}
		}
		add(spec.name, dir, unsealed.open.GroupID, spec.note, spec.want, trusted)
	}

	// A crashed predecessor is only linked once its run's lifetime lock proves
	// the writer is gone. With the lock file missing the exit cannot be proven,
	// so Go refuses the link for unsealed and sealed predecessors alike.
	dir = clone(unsealedDir, "unsealed-predecessor-writer-lock-missing")
	if err := os.Remove(filepath.Join(dir, "writer-"+crashed.open.Shards[0].SessionID+".lock")); err != nil {
		t.Fatal(err)
	}
	add("unsealed-predecessor-writer-lock-missing", dir, unsealed.open.GroupID, "crashed predecessor whose shard-0 writer lock file is gone, so its exit cannot be proven", receipt.GroupInvalid, trusted)

	dir = clone(sealedDir, "sealed-predecessor-writer-lock-missing")
	if err := os.Remove(filepath.Join(dir, "writer-"+predOpenSealed.Shards[0].SessionID+".lock")); err != nil {
		t.Fatal(err)
	}
	add("sealed-predecessor-writer-lock-missing", dir, sealedSucc.open.GroupID, "sealed predecessor whose shard-0 writer lock file is gone, so its exit cannot be proven", receipt.GroupInvalid, trusted)

	// Signer rotation across processes: the successor is signed by a second key
	// that endorses the first, and a crashed predecessor keeps its own key.
	keyB := newV2CorpusKey(t)
	both := []string{key.pub, keyB.pub}
	mixedDir := mkdir("mixed-key-successor-unsealed-predecessor")
	mixedCrashed := runV2Process(t, mixedDir, key, false)
	mixedSucc := runV2ProcessN(t, mixedDir, keyB, true, []string{key.pub}, 2)
	if mixedSucc.open.PreviousGroupID != mixedCrashed.open.GroupID {
		t.Fatalf("mixed-key successor did not bind the predecessor: %+v", mixedSucc.open)
	}
	add("mixed-key-successor-unsealed-predecessor", mixedDir, mixedSucc.open.GroupID, "successor signed by a second trusted key after a crashed predecessor signed by the first", receipt.GroupValid, both)
	add("mixed-key-successor-predecessor-key-untrusted", mixedDir, mixedSucc.open.GroupID, "same directory with only the successor key trusted, so the predecessor key is not", receipt.GroupInvalid, []string{keyB.pub})

	// A legacy chain with no native AEL run that rotates its signer key. Go
	// walks the whole chain against the full trusted set, so both keys trusted
	// is valid and a second key outside the set is not.
	rotation := []v2HandStep{{key: key}, {key: key}, {key: keyB, rot: true}, {key: keyB}}
	dir = clone(closedDir, "legacy-hand-signed-rotation-both-keys-trusted")
	recordHandSignedChain(t, dir, "legacy-old", key, rotation)
	add("legacy-hand-signed-rotation-both-keys-trusted", dir, closed.open.GroupID, "legacy session whose signer rotates between two trusted keys", receipt.GroupValid, both)
	add("legacy-hand-signed-rotation-new-key-untrusted", dir, closed.open.GroupID, "same legacy session with the rotated-to key outside the trusted set", receipt.GroupInvalid, trusted)

	// The unsigned ext bag of a receipt takes part in the chain link hash with
	// the bytes Go marshals, so a verifier must keep the recorded source text.
	dir = clone(closedDir, "legacy-hand-signed-ext-bag")
	recordHandSignedChain(t, dir, "legacy-ext", key, []v2HandStep{{key: key, ext: `{"n":1e2,"s":"<&>"}`}, {key: key}, {key: key}})
	add("legacy-hand-signed-ext-bag", dir, closed.open.GroupID, "legacy session whose first receipt carries an unsigned ext bag that only its recorded bytes hash correctly", receipt.GroupValid, trusted)

	// 32 shards, one of them torn and sealed: every other shard of the same
	// crashed predecessor is unsealed, so both claim shapes meet in one group.
	n32Dir := mkdir("n32-successor-sealed-predecessor")
	n32Crashed := runV2ProcessN(t, n32Dir, key, false, nil, 32)
	tearV2Shard(t, shardPath(n32Dir, n32Crashed.open.Shards[17].SessionID))
	n32Succ := runV2ProcessN(t, n32Dir, key, true, nil, 32)
	add("n32-successor-sealed-predecessor", n32Dir, n32Succ.open.GroupID, "32-shard successor of a 32-shard crashed predecessor with one torn, sealed shard", receipt.GroupValid, trusted)

	// Legacy neighbor sessions in the directory of a closed v2 group.
	legacyDir := clone(closedDir, "v2-n2-legacy-neighbor")
	legacySession := runLegacySession(t, legacyDir, key, true)
	add("v2-n2-legacy-neighbor", legacyDir, closed.open.GroupID, "closed v2 group next to a valid legacy session", receipt.GroupValid, trusted)

	// A legacy neighbor that opened a native AEL run is walked against the whole
	// trusted set, and its run is verified under the key that signed its open.
	add("v2-n2-legacy-neighbor-two-trusted-keys", legacyDir, closed.open.GroupID, "closed v2 group next to a valid legacy session, with a second unrelated key in the trusted set", receipt.GroupValid, both)

	dir = clone(legacyDir, "legacy-neighbor-close-body-edit")
	rewriteV2Shard(t, shardPath(dir, legacySession), key, func(lines []string) []v2OutLine {
		out := passthroughV2(lines)
		edited := false
		for i, l := range lines {
			if strings.Contains(l, `"session_close"`) && strings.Contains(l, "graceful_shutdown") {
				out[i] = v2OutLine{text: strings.Replace(l, "graceful_shutdown", "graceful_shutdowx", 1)}
				edited = true
			}
		}
		if !edited {
			t.Fatal("no session close to edit")
		}
		return out
	})
	add("legacy-neighbor-close-body-edit", dir, closed.open.GroupID, "legacy neighbor session_close body edited, recorder chain recomputed", receipt.GroupInvalid, trusted)

	dir = clone(legacyDir, "legacy-neighbor-close-signature-corruption")
	rewriteV2Shard(t, shardPath(dir, legacySession), key, func(lines []string) []v2OutLine {
		out := passthroughV2(lines)
		edited := false
		for i, l := range lines {
			if strings.Contains(l, `"session_close"`) && strings.Contains(l, `"signature":"ed25519:`) {
				out[i] = v2OutLine{text: flipHexAfter(t, l, `"signature":"ed25519:`)}
				edited = true
			}
		}
		if !edited {
			t.Fatal("no session close signature to corrupt")
		}
		return out
	})
	add("legacy-neighbor-close-signature-corruption", dir, closed.open.GroupID, "legacy neighbor session_close signature corrupted, recorder chain recomputed", receipt.GroupInvalid, trusted)

	// Go counts an entry as a v1 receipt by its entry type, never by the
	// record_type its detail claims.
	dir = clone(legacyDir, "legacy-neighbor-action-entry-claims-v2-record-type")
	rewriteV2Shard(t, shardPath(dir, legacySession), key, func(lines []string) []v2OutLine {
		out := passthroughV2(lines)
		// Edit the last receipt (the session_close): leaving it out of the v1
		// chain keeps the rest of that chain valid, so only classifying the
		// entry by its type catches the claim.
		last := -1
		for i, l := range lines {
			if strings.Contains(l, `"type":"action_receipt"`) {
				last = i
			}
		}
		if last >= 0 {
			out[last] = v2OutLine{text: strings.Replace(lines[last], `"detail":{`, `"detail":{"record_type":"evidence_receipt_v2",`, 1)}
			return out
		}
		t.Fatal("no action receipt to edit")
		return nil
	})
	add("legacy-neighbor-action-entry-claims-v2-record-type", dir, closed.open.GroupID, "legacy neighbor action_receipt entry whose detail claims the v2 record_type, recorder chain recomputed", receipt.GroupInvalid, trusted)

	// A second gate inside a neighbor group's shard is an unknown entry type
	// to Go's group recorder walker, which accepts the gate only first.
	dir = clone(chainDir, "neighbor-group-duplicate-gate")
	rewriteV2Shard(t, shardPath(dir, secondClosed.open.Shards[0].SessionID), key, func(lines []string) []v2OutLine {
		out := passthroughV2(lines)
		return append(out[:1], append([]v2OutLine{{text: lines[0]}}, out[1:]...)...)
	})
	add("neighbor-group-duplicate-gate", dir, firstClosed.open.GroupID, "successor group's first shard repeats its gate; verified as the predecessor's neighbor, recorder chain recomputed", receipt.GroupInvalid, trusted)

	// A decision entry is not a receipt: Go ignores its detail, however odd.
	dir = clone(legacyDir, "legacy-neighbor-decision-entry-odd-detail")
	rewriteV2Shard(t, shardPath(dir, legacySession), key, func(lines []string) []v2OutLine {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(lines[0]), &fields); err != nil {
			t.Fatal(err)
		}
		fields["type"], _ = json.Marshal("decision")
		// One decision whose action_record is a list, and one shaped like a
		// session_open receipt with no signer: neither is a receipt.
		var inserted []v2OutLine
		for _, detail := range []string{
			`{"action_record":[],"decision":{"session_control":"x"}}`,
			`{"action_record":{"session_control":{"kind":"session_open","open":{"run_nonce":"` + strings.Repeat("c", 32) + `"}}}}`,
		} {
			fields["detail"] = json.RawMessage(detail)
			body, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			inserted = append(inserted, v2OutLine{text: string(body)})
		}
		out := passthroughV2(lines)
		return append(out[:1], append(inserted, out[1:]...)...)
	})
	add("legacy-neighbor-decision-entry-odd-detail", dir, closed.open.GroupID, "legacy neighbor holds a decision entry whose detail.action_record is a list", receipt.GroupValid, trusted)

	dir = clone(closedDir, "untrusted-extra-session")
	other := newV2CorpusKey(t)
	knownRuns := map[string]bool{}
	before, err := os.ReadDir(filepath.Join(dir, "ael"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range before {
		knownRuns[e.Name()] = true
	}
	runLegacySession(t, dir, other, false)
	// The session has no signed session_open, so it claims no native AEL run.
	// Drop the run directory the recorder created for it; what remains is a
	// session whose receipts nothing but the inventory chain walk ever checks.
	after, err := os.ReadDir(filepath.Join(dir, "ael"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range after {
		if !knownRuns[e.Name()] {
			if err := os.RemoveAll(filepath.Join(dir, "ael", e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	add("untrusted-extra-session", dir, closed.open.GroupID, "extra legacy session signed by a key outside the trusted set, with no session_open", receipt.GroupInvalid, trusted)

	dir = clone(closedDir, "v2-only-legacy-session")
	runV2OnlySession(t, dir, key)
	add("v2-only-legacy-session", dir, closed.open.GroupID, "extra legacy session with only a v2 decision receipt (an empty v1 chain)", receipt.GroupValid, trusted)

	// A group whose close never landed, with v2 evidence on every shard, is
	// incomplete, not invalid.
	dir = clone(closedDir, "v2-n2-open-group")
	if err := os.Remove(filepath.Join(dir, "receipt-group-"+closed.open.GroupID+"-close.json")); err != nil {
		t.Fatal(err)
	}
	add("v2-n2-open-group", dir, closed.open.GroupID, "v2 group whose signed close is missing", receipt.GroupIncomplete, trusted)

	// Go reads each native AEL record through a 1 MiB buffer, blank lines
	// included: a line at the limit is accepted and one byte over is refused.
	for _, spec := range []struct {
		name string
		pad  int
		want receipt.ReceiptGroupVerdict
		note string
	}{
		{"ael-blank-line-at-record-limit", 1<<20 - 1, receipt.GroupValid, "a blank native AEL line of exactly 1 MiB including its newline"},
		{"ael-blank-line-over-record-limit", 1 << 20, receipt.GroupInvalid, "a blank native AEL line one byte over 1 MiB including its newline"},
	} {
		dir = clone(closedDir, spec.name)
		streams, err := filepath.Glob(filepath.Join(dir, "ael", "*", "recorders", "pipelock.jsonl"))
		if err != nil || len(streams) == 0 {
			t.Fatalf("native AEL streams: %v %v", streams, err)
		}
		sort.Strings(streams)
		af, err := os.OpenFile(filepath.Clean(streams[0]), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := af.WriteString(strings.Repeat(" ", spec.pad) + "\n"); err != nil {
			t.Fatal(err)
		}
		if err := af.Close(); err != nil {
			t.Fatal(err)
		}
		add(spec.name, dir, closed.open.GroupID, spec.note, spec.want, trusted)
	}

	// Go decides every verdict, and each tamper must actually be rejected.
	for _, c := range cases {
		result := receipt.VerifyReceiptGroup(c.dir, c.GroupID, c.TrustedKeys)
		c.Expected = string(result.Verdict)
		if result.Verdict != c.want {
			t.Fatalf("%s: Go verdict %s (%s), want %s", c.Name, result.Verdict, result.Error, c.want)
		}
		t.Logf("%s: %s %s", c.Name, result.Verdict, result.Error)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	sort.Slice(cases, func(i, j int) bool { return cases[i].Name < cases[j].Name })
	for _, c := range cases {
		err := filepath.WalkDir(c.dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(c.dir, path)
			if rel == "signer.key" {
				return nil
			}
			raw, err := os.ReadFile(filepath.Clean(path)) // #nosec G122 -- generator walks its own private temp tree
			if err != nil {
				return err
			}
			w, err := zw.CreateHeader(&zip.FileHeader{Name: "cases/" + c.Name + "/" + filepath.ToSlash(rel), Method: zip.Deflate, Modified: v2CorpusEpoch})
			if err != nil {
				return err
			}
			_, err = w.Write(raw)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := json.MarshalIndent(cases, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "cases.json", Method: zip.Deflate, Modified: v2CorpusEpoch})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	// Go reads only the Python copy; the identity test in every suite keeps the
	// other directories byte-identical to it.
	for _, language := range []string{"python", "ts", "rust"} {
		target := filepath.Join(v2CorpusRoot, language, "tests", "fixtures", v2CorpusName)
		if err := os.WriteFile(target, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
