// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRunArtifacts lays down a synthetic but layout-faithful run dir: the
// top-level witnesses/manifest and a packet/ subtree. ArchiveRunForDownload only
// reads bytes, so the contents are arbitrary; the layout is what matters.
func writeRunArtifacts(t *testing.T, dir string, withContainment bool) {
	t.Helper()
	files := map[string]string{
		launchManifestFile: `{"run_nonce":"n1"}`,
		witnessFile:        `{"observed_count":0}`,
		redWitnessFile:     `{"red":true}`,
		filepath.Join(packetSubdir, "packet.json"):    `{"receipt_count":1}`,
		filepath.Join(packetSubdir, "evidence.jsonl"): `{"seq":0}` + "\n",
		filepath.Join(packetSubdir, "manifest.json"):  `{"v":1}`,
	}
	if withContainment {
		files[hostContainmentWitnessFile] = `{"contained":true}`
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
}

// readArchive gunzips + untars the bundle into name->content.
func readArchive(t *testing.T, gzipped []byte) map[string]string {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = gr.Close() }()
	tr := tar.NewReader(gr)
	out := map[string]string{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read %s: %v", hdr.Name, err)
		}
		out[hdr.Name] = string(b)
	}
	return out
}

func TestArchiveRunForDownload_IncludesVerifiableArtifacts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRunArtifacts(t, dir, false)

	const pubHex = "abc123def456"
	arc, err := ArchiveRunForDownload(dir, pubHex)
	if err != nil {
		t.Fatalf("ArchiveRunForDownload: %v", err)
	}
	files := readArchive(t, arc)

	wantPresent := []string{
		downloadArchivePrefix + "/VERIFY.txt",
		downloadArchivePrefix + "/" + launchManifestFile,
		downloadArchivePrefix + "/" + witnessFile,
		downloadArchivePrefix + "/" + redWitnessFile,
		downloadArchivePrefix + "/" + packetSubdir + "/packet.json",
		downloadArchivePrefix + "/" + packetSubdir + "/evidence.jsonl",
		downloadArchivePrefix + "/" + packetSubdir + "/manifest.json",
	}
	for _, name := range wantPresent {
		if _, ok := files[name]; !ok {
			t.Errorf("archive missing %q (have %v)", name, keysOf(files))
		}
	}
	// Uncontained run: no host-containment witness.
	if _, ok := files[downloadArchivePrefix+"/"+hostContainmentWitnessFile]; ok {
		t.Error("uncontained run must not include the host-containment witness")
	}
	// VERIFY.txt names the session trust-root key and the exact verify command.
	verify := files[downloadArchivePrefix+"/VERIFY.txt"]
	for _, want := range []string{pubHex, "pipelock-playground-demo verify " + downloadArchivePrefix, "--orchestrator-key"} {
		if !strings.Contains(verify, want) {
			t.Errorf("VERIFY.txt missing %q:\n%s", want, verify)
		}
	}
}

func TestArchiveRunForDownload_IncludesContainmentWitnessWhenPresent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRunArtifacts(t, dir, true)

	arc, err := ArchiveRunForDownload(dir, "deadbeef")
	if err != nil {
		t.Fatalf("ArchiveRunForDownload: %v", err)
	}
	files := readArchive(t, arc)
	if _, ok := files[downloadArchivePrefix+"/"+hostContainmentWitnessFile]; !ok {
		t.Error("contained run must include the host-containment witness")
	}
}

func TestArchiveRunForDownload_FailsClosedOnMissingRequiredArtifact(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRunArtifacts(t, dir, false)
	// Remove a required artifact: the archive must fail rather than ship a
	// partial bundle that cannot verify.
	if err := os.Remove(filepath.Join(dir, witnessFile)); err != nil {
		t.Fatalf("remove witness: %v", err)
	}
	if _, err := ArchiveRunForDownload(dir, "abc"); err == nil {
		t.Fatal("want error when a required artifact is missing, got nil")
	}
}

func TestArchiveRunForDownload_IsDeterministic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRunArtifacts(t, dir, false)
	a, err := ArchiveRunForDownload(dir, "k")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	b, err := ArchiveRunForDownload(dir, "k")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Error("archive is not byte-deterministic across runs of the same dir")
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
