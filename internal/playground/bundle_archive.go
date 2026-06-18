// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// downloadArchivePrefix is the single top-level directory inside the downloaded
// bundle. Every artifact the shipped verifier needs lives under it, so the
// visitor runs one verify command against one predictably-named directory.
const downloadArchivePrefix = "pipelock-session"

// Audit-packet artifact filenames (the documented packet/ layout: see VerifyRun).
const (
	packetJSONFile     = "packet.json"
	packetEvidenceFile = "evidence.jsonl"
	packetManifestFile = "manifest.json"
)

// archiveArtifacts are the run-dir paths (relative to the run dir) added to the
// downloadable bundle, enumerated explicitly so only known artifacts are ever
// read -- no directory walk, no path input, no traversal surface. The
// host-containment witness exists only for contained runs and is skipped when
// absent; every other entry is required and fails closed if missing.
var archiveArtifacts = []struct {
	name     string
	required bool
}{
	{launchManifestFile, true},
	{witnessFile, true},
	{redWitnessFile, true},
	{hostContainmentWitnessFile, false},
	{filepath.Join(packetSubdir, packetJSONFile), true},
	{filepath.Join(packetSubdir, packetEvidenceFile), true},
	{filepath.Join(packetSubdir, packetManifestFile), true},
}

// ArchiveRunForDownload packages a SEALED run directory's offline-verifiable
// artifacts into a gzip-compressed tar the visitor downloads and re-verifies
// with the shipped verifier. It includes the audit packet (packet/), the launch
// manifest, and the witnesses, plus a VERIFY.txt naming the trust-root key used
// for this run and the exact verify command.
//
// Only known artifact paths under runDir are read -- there is no arbitrary path
// input, so a malicious session cannot smuggle a host file into the download.
// It must be called after AssembleAndVerify has written the artifacts; a missing
// required artifact fails closed with an error rather than a partial bundle.
func ArchiveRunForDownload(runDir, orchestratorPubHex string) ([]byte, error) {
	cleanRun := filepath.Clean(runDir)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	// The verify instructions go first so a visitor who opens the tar sees them.
	verifyTxt := buildVerifyInstructions(orchestratorPubHex)
	if err := writeTarFile(tw, downloadArchivePrefix+"/VERIFY.txt", []byte(verifyTxt)); err != nil {
		return nil, err
	}

	for _, f := range archiveArtifacts {
		if err := addRunFile(tw, cleanRun, f.name, f.required); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("close gzip: %w", err)
	}
	return buf.Bytes(), nil
}

// addRunFile reads one top-level run-dir artifact and writes it into the tar at
// the archive prefix. A missing optional file is skipped; a missing required
// file fails closed.
func addRunFile(tw *tar.Writer, cleanRun, name string, required bool) error {
	data, err := os.ReadFile(filepath.Clean(filepath.Join(cleanRun, name)))
	if err != nil {
		if os.IsNotExist(err) && !required {
			return nil
		}
		return fmt.Errorf("read artifact %s: %w", name, err)
	}
	return writeTarFile(tw, downloadArchivePrefix+"/"+filepath.ToSlash(name), data)
}

// writeTarFile writes one file entry with a fixed mode and a zero mod time so the
// archive is deterministic (the same run always produces byte-identical output).
func writeTarFile(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    int64(len(data)),
		ModTime: time.Unix(0, 0).UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("tar header %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("tar write %s: %w", name, err)
	}
	return nil
}

// buildVerifyInstructions renders the VERIFY.txt shipped inside the bundle. It
// names the trust-root key used for this run and the exact offline verify
// command, so the proof stands on its own: no server, no account, just the key
// the verifier is told to trust. In the public demo this key must match the
// separately published demo key.
func buildVerifyInstructions(orchestratorPubHex string) string {
	return fmt.Sprintf(`Pipelock playground -- verify this session yourself, offline
============================================================

This bundle is a signed record of your live session. You can verify it with the
trust-root key below -- no server, no account, no network. In the public demo,
that key must match the separately published Pipelock demo key. If Pipelab
vanished tomorrow, the proof still stands on its own math.

1. Extract:
     tar xzf pipelock-session.tar.gz

2. Verify (using the SAME binary any customer downloads):
     pipelock-playground-demo verify %s --orchestrator-key %s

A passing run prints OK and the list of checks it ran: receipt-chain
completeness, sequence gaps, canonical JSON, collector-witness binding, and the
session nonce. A model's claim of success in chat is just narration -- this
signed trace is the truth.

Session trust-root (orchestrator) key:
  %s
`, downloadArchivePrefix, orchestratorPubHex, orchestratorPubHex)
}
