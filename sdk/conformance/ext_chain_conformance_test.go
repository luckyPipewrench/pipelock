// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// The unsigned top-level ext bag is a json.RawMessage, so ReceiptHash (the
// chain link preimage, json.Marshal of the receipt) carries the ext SOURCE
// bytes compacted and HTML-escaped, with key order, number spelling, and
// string escape spelling verbatim. A default `pipelock run` writes an ext bag
// on the first receipt of every run. These vectors pin that link-hash
// contract for every verifier, including source text that a parse and
// re-serialize cannot reproduce.
const (
	goldenG1ExtChain    = "g1-ext-chain.jsonl"
	goldenG1ExtTampered = "g1-ext-tampered-invalid.jsonl"

	g1ExtRunNonce  = "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
	g1ExtOpenNonce = "open-nonce-g1-ext"
	g1ExtChainLen  = 5

	// g1ExtChainRootHash is the chain root every verifier must report for
	// goldenG1ExtChain. The TypeScript, Rust, and Python suites pin the same
	// value.
	g1ExtChainRootHash = "19805bc704923ef6a602abdfa3dc4982134997a69e3fff7a627b3f1805511d1b"
)

// unicodeEscape spells a JSON \uXXXX escape without writing one literally in
// this source file.
func unicodeEscape(hex4 string) string {
	return "\\" + "u" + hex4
}

// g1HostileExtSource is ext source text that only a byte-faithful encoder
// reproduces: insignificant whitespace (spaces and a tab), integer-like keys
// that JavaScript would reorder, number spellings that parse to the same
// value as simpler ones (1.0, 2.50, -0, 1e2, 1E+2), characters Go
// HTML-escapes (<, >, &, raw U+2028), a raw U+0085 that Go leaves raw, and
// pre-escaped sequences Go copies verbatim.
func g1HostileExtSource() string {
	lineSep := string(rune(0x2028))
	nextLine := string(rune(0x85))
	eAcute := string(rune(0xe9))
	return `{ "posture_proof_availability" : "unreadable",` + "\t" +
		`"10" : { "2" : [ 1.0 , 2.50 , -0 , 1e2 , 1E+2 , true , null , { } , [ ] ] , "1" : "<a&b>" } , ` +
		`"0" : "` + unicodeEscape("0041") + `\/` + unicodeEscape("00e9") + ` ` + eAcute + ` ` + lineSep + ` ` + nextLine + ` ` +
		unicodeEscape("d83d") + unicodeEscape("de00") + ` ` + unicodeEscape("003c") + `" , "a\"b" : "" }`
}

// g1ExtSources is the ext source text written on each receipt of the ext
// chain. An empty string means the receipt carries no ext member.
func g1ExtSources() []string {
	return []string{
		g1HostileExtSource(),
		"",
		"null",
		" 1E+2 ",
		`{"posture_proof_availability":"unreadable"}`,
	}
}

// buildG1ExtChain signs a g1 run (open, three actions, close) whose receipts
// carry the given ext source text. Each chain_prev_hash, the close root_hash,
// and the final root come from receipt.ReceiptHash over the receipt with its
// ext attached, exactly as the production emitter links them.
func buildG1ExtChain(t *testing.T, priv ed25519.PrivateKey, sources []string) []receipt.Receipt {
	t.Helper()
	if len(sources) != g1ExtChainLen {
		t.Fatalf("ext sources = %d, want %d", len(sources), g1ExtChainLen)
	}
	policyHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	open := receipt.SessionOpen{
		RunNonce:         g1ExtRunNonce,
		OpenNonce:        g1ExtOpenNonce,
		RecorderSession:  recorderSessionID,
		PolicyHash:       policyHash,
		SignerKeyEpoch:   "epoch-2026-04",
		HeartbeatSeconds: 60,
		ChainOpenSeq:     0,
	}
	genesis := receipt.ComputeSessionOpenGenesis(open)
	open.GenesisHash = genesis

	attach := func(r receipt.Receipt, i int) receipt.Receipt {
		if sources[i] != "" {
			r.Ext = json.RawMessage(sources[i])
		}
		return r
	}

	chain := make([]receipt.Receipt, 0, g1ExtChainLen)
	openAR := fixedActionRecord(0, genesis)
	openAR.ActionID = "g1-ext-session-open"
	openAR.ActionType = receipt.ActionUnclassified
	openAR.Target = "receipt-session:open"
	openAR.PolicyHash = policyHash
	openAR.Transport = "receipt_session"
	openAR.Method = ""
	openAR.Layer = "session_control"
	openAR.RunNonce = g1ExtRunNonce
	openAR.SessionControl = &receipt.SessionControl{Kind: receipt.SessionControlOpen, Open: &open}
	chain = append(chain, attach(signReceipt(t, openAR, priv), 0))
	prevHash := mustReceiptHash(t, chain[0])

	for seq := uint64(1); seq <= 3; seq++ {
		ar := fixedActionRecord(seq, prevHash)
		ar.ActionID = "g1-ext-action-" + string(rune('0'+seq))
		ar.PolicyHash = policyHash
		ar.RunNonce = g1ExtRunNonce
		chain = append(chain, attach(signReceipt(t, ar, priv), len(chain)))
		prevHash = mustReceiptHash(t, chain[seq])
	}

	closeAR := fixedActionRecord(4, prevHash)
	closeAR.ActionID = "g1-ext-session-close"
	closeAR.ActionType = receipt.ActionUnclassified
	closeAR.Target = "receipt-session:close"
	closeAR.PolicyHash = policyHash
	closeAR.Transport = "receipt_session"
	closeAR.Method = ""
	closeAR.Layer = "session_control"
	closeAR.RunNonce = g1ExtRunNonce
	closeAR.SessionControl = &receipt.SessionControl{
		Kind: receipt.SessionControlClose,
		Close: &receipt.SessionClose{
			RunNonce:     g1ExtRunNonce,
			OpenNonce:    g1ExtOpenNonce,
			FinalSeq:     4,
			RootHash:     prevHash,
			ReceiptCount: g1ExtChainLen,
			CloseReason:  "normal",
		},
	}
	chain = append(chain, attach(signReceipt(t, closeAR, priv), 4))
	return chain
}

// writeExtChainJSONL writes recorder entries whose detail carries each ext
// member as the given SOURCE text rather than Go's compacted re-encoding, so
// the file exercises the verifier's ext byte handling. Entry hashes are
// computed over those exact detail bytes, as the recorder does on read.
func writeExtChainJSONL(t *testing.T, path string, receipts []receipt.Receipt, sources []string) {
	t.Helper()
	var buf strings.Builder
	prevHash := recorder.GenesisHash
	var entrySeq uint64
	for i, r := range receipts {
		bare := r
		bare.Ext = nil
		compact, err := receipt.Marshal(bare)
		if err != nil {
			t.Fatalf("marshal receipt %d: %v", i, err)
		}
		rawDetail := string(compact)
		if sources[i] != "" {
			rawDetail = strings.TrimSuffix(rawDetail, "}") + `, "ext" : ` + sources[i] + ` }`
		}
		e := wrapInFlightRecorderEntries(t, []receipt.Receipt{bare})[0]
		e.Sequence = entrySeq
		entrySeq++
		e.PrevHash = prevHash
		e.Detail = json.RawMessage(rawDetail)
		e.RawDetail = json.RawMessage(rawDetail)
		e.Hash = recorder.ComputeHash(e)
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal entry %d: %v", i, err)
		}
		marshaledDetail, err := json.Marshal(json.RawMessage(rawDetail))
		if err != nil {
			t.Fatalf("marshal detail %d: %v", i, err)
		}
		if strings.Count(string(line), string(marshaledDetail)) != 1 {
			t.Fatalf("entry %d: detail bytes not found exactly once", i)
		}
		buf.WriteString(strings.Replace(string(line), string(marshaledDetail), rawDetail, 1))
		buf.WriteByte('\n')
		prevHash = e.Hash
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

// g1TamperedExtSources edits one value inside receipt 0's ext after receipt
// 1 has already linked the original bytes.
func g1TamperedExtSources(t *testing.T) []string {
	t.Helper()
	sources := g1ExtSources()
	edited := strings.Replace(sources[0], `"unreadable"`, `"unreadablE"`, 1)
	if edited == sources[0] {
		t.Fatal("tamper did not change ext source")
	}
	sources[0] = edited
	return sources
}

// TestGenerateExtChainGoldenFiles regenerates the ext chain vectors. Run
// with -update. Normal test runs skip this.
func TestGenerateExtChainGoldenFiles(t *testing.T) {
	if !*update {
		t.Skip("pass -update to regenerate golden files")
	}
	_, priv := testKeyPair(t)
	chain := buildG1ExtChain(t, priv, g1ExtSources())
	writeExtChainJSONL(t, filepath.Join(testdataDir, goldenG1ExtChain), chain, g1ExtSources())
	writeExtChainJSONL(t, filepath.Join(testdataDir, goldenG1ExtTampered), chain, g1TamperedExtSources(t))
}

// TestConformance_G1ExtChainValid proves the production read path accepts the
// ext chain and that the link bytes really are the compacted source: the
// stored file keeps whitespace and escapes that ReceiptHash must reduce.
func TestConformance_G1ExtChainValid(t *testing.T) {
	t.Parallel()
	path := filepath.Join(testdataDir, goldenG1ExtChain)
	receipts, err := receipt.ExtractReceipts(path)
	if err != nil {
		t.Fatalf("ExtractReceipts: %v", err)
	}
	if len(receipts) != g1ExtChainLen {
		t.Fatalf("receipt count = %d, want %d", len(receipts), g1ExtChainLen)
	}
	pub, _ := testKeyPair(t)
	result := receipt.VerifyChain(receipts, hex.EncodeToString(pub))
	if !result.Valid {
		t.Fatalf("VerifyChain: %s", result.Error)
	}
	if result.RootHash != g1ExtChainRootHash {
		t.Fatalf("root hash = %s, want %s", result.RootHash, g1ExtChainRootHash)
	}
	if string(receipts[0].Ext) != g1HostileExtSource() {
		t.Fatalf("receipt 0 ext was not read verbatim: %q", receipts[0].Ext)
	}
	if string(receipts[2].Ext) != "null" {
		t.Fatalf("receipt 2 ext = %q, want null", receipts[2].Ext)
	}
	if len(receipts[1].Ext) != 0 {
		t.Fatalf("receipt 1 ext = %q, want absent", receipts[1].Ext)
	}

	// The same chain regenerated from the Go builder must link identically,
	// so the file cannot drift from the producer contract.
	_, priv := testKeyPair(t)
	built := buildG1ExtChain(t, priv, g1ExtSources())
	for i := range built {
		if got, want := mustReceiptHash(t, receipts[i]), mustReceiptHash(t, built[i]); got != want {
			t.Fatalf("receipt %d hash = %s, want %s", i, got, want)
		}
	}

	// Removing ext from receipt 0 must break the link, proving the link hash
	// covers ext.
	withoutExt := append([]receipt.Receipt(nil), receipts...)
	withoutExt[0].Ext = nil
	if res := receipt.VerifyChain(withoutExt, hex.EncodeToString(pub)); res.Valid {
		t.Fatal("chain still verified with receipt 0 ext removed")
	}
}

// TestConformance_G1ExtTamperedRejected proves an ext edit made after the
// next receipt linked the original bytes breaks the chain at seq 1.
func TestConformance_G1ExtTamperedRejected(t *testing.T) {
	t.Parallel()
	receipts, err := receipt.ExtractReceipts(filepath.Join(testdataDir, goldenG1ExtTampered))
	if err != nil {
		t.Fatalf("ExtractReceipts: %v", err)
	}
	pub, _ := testKeyPair(t)
	result := receipt.VerifyChain(receipts, hex.EncodeToString(pub))
	if result.Valid {
		t.Fatal("VerifyChain accepted a chain whose linked ext bytes were edited")
	}
	if result.BrokenAtSeq != 1 || !strings.Contains(result.Error, "chain_prev_hash") {
		t.Fatalf("result = %+v, want chain_prev_hash break at seq 1", result)
	}
}
