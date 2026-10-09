// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// doctorCorpusInventory binds both location discovery and the files consumed
// by the structural and continuity scans. A final comparison is required even
// when a consumer reports damage or returns an error. Unrelated files are not
// evidence; their arrival must not make an otherwise stable audit unavailable.
func doctorCorpusInventory(locations []recorder.EvidenceLocation) ([32]byte, error) {
	h := sha256.New()
	for _, location := range locations {
		_, _ = fmt.Fprintf(h, "%q\n", location.ID)
		entries, err := recorder.ReadEvidenceLocationEntries(location)
		if err != nil {
			return [32]byte{}, err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			name := entry.Name()
			if !isDoctorEvidenceJSONL(name) && !isDoctorRawSidecar(name) &&
				!strings.HasPrefix(name, "chain-link-") && !strings.HasPrefix(name, "receipt-group-") && name != "ael" {
				continue
			}
			path := filepath.Join(location.Dir, name)
			info, err := os.Lstat(path)
			if err != nil {
				return [32]byte{}, err
			}
			identity, err := recorder.EvidenceMetadataIdentity(path, info)
			if err != nil {
				return [32]byte{}, err
			}
			_, _ = fmt.Fprintf(h, "%q %q %d %d %d\n", name, identity, info.Mode(), info.Size(), info.ModTime().UnixNano())
		}
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func inconclusiveDoctorReport(dir string, err error) evidenceDoctorReport {
	return evidenceDoctorReport{
		Dir: dir, ReadIncomplete: true,
		Findings: []evidenceDoctorFinding{{Kind: "directory_read_error", Message: "evidence audit incomplete: " + err.Error()}},
	}
}
