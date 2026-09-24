// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// An EXISTING file in the receipt directory is already protected: the command
// passes every regular file there to the output-alias check before writing.
// These tests cover what that check cannot see, a recorder-owned name that does
// not exist yet. Writing the bundle under such a name would squat on it, so the
// recorder's later exclusive publish fails and, for a continuity link, the
// successor is left permanently unlinked.

const ownedDecoySession = "proxy.run.ffffffffffffffffffffffffffffffff"

func anchorReceiptsCmdOut(t *testing.T, receiptsPath, keyHex, out string) error {
	t.Helper()
	cmd := receiptsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		receiptsPath,
		"--key", keyHex,
		"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
		"--out", out,
	})
	return cmd.Execute()
}

// TestReceiptsCmdAcceptsUnownedOutput is the positive control. If the command
// failed here for an unrelated reason, the refusal test below would pass
// without exercising the guard.
func TestReceiptsCmdAcceptsUnownedOutput(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T13:00:00Z")
	receiptsPath, keyHex := cliReceiptJSONL(t)
	if err := anchorReceiptsCmdOut(t, receiptsPath, keyHex, "bundle.json"); err != nil {
		t.Fatalf("an unowned --out must succeed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(receiptsPath), "bundle.json")); err != nil {
		t.Fatalf("bundle not written: %v", err)
	}
}

func TestReceiptsCmdRefusesRecorderOwnedOutputName(t *testing.T) {
	for _, owned := range []string{
		"chain-link-" + ownedDecoySession + ".json",
		"writer-" + ownedDecoySession + ".lock",
		"evidence-" + ownedDecoySession + "-0-raw-00112233445566778899aabbccddeeff.raw.enc",
		"anchor-state.json",
		"evidence-" + ownedDecoySession + "-0.jsonl",
	} {
		t.Run(owned, func(t *testing.T) {
			t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T13:00:00Z")
			receiptsPath, keyHex := cliReceiptJSONL(t)
			target := filepath.Join(filepath.Dir(receiptsPath), owned)
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatalf("precondition: %s must not exist yet: %v", owned, err)
			}
			if err := anchorReceiptsCmdOut(t, receiptsPath, keyHex, owned); err == nil {
				t.Fatalf("--out %s must be refused", owned)
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatalf("--out %s squatted on a recorder-owned name: %v", owned, err)
			}
		})
	}
}
