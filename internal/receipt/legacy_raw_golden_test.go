// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// The fixture is the exact signed N=1 session_open bytes produced by
// 57df3d7de. A nil group binding must preserve the released wire format.
func TestLegacySessionOpenRawBytesMatchBase(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	open := testSessionOpen(sessionOpenTestRunA, "open-a", 0)
	genesis := ComputeSessionOpenGenesis(open)
	open.GenesisHash = genesis
	ar := ActionRecord{
		Version: ActionRecordVersion, ActionID: "act-fixed", ActionType: ActionUnclassified,
		Timestamp: time.Unix(0, 0).UTC(), Target: sessionOpenTarget,
		PolicyHash: sessionOpenTestPolicy, Verdict: config.ActionAllow,
		Transport: sessionControlTransport, ChainPrevHash: genesis,
		ChainSeq: 0, RunNonce: sessionOpenTestRunA,
		SessionControl: &SessionControl{Kind: SessionControlOpen, Open: &open},
	}
	signed, err := Sign(ar, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.OpenReader("testdata/n1-session-open-57df3d7de.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = archive.Close() }()
	if len(archive.File) != 1 || archive.File[0].Name != "n1-session-open.json" {
		t.Fatal("N=1 golden archive has unexpected entries")
	}
	f, err := archive.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	want, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		gotHash, wantHash := sha256.Sum256(got), sha256.Sum256(want)
		t.Fatalf("N=1 raw bytes changed: got %x want %x", gotHash, wantHash)
	}
}
