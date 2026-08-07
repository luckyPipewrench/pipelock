// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build (!unix && !windows) || aix

package recorder

import (
	"errors"
	"os"
)

func openEvidenceLocationDirectory(_ EvidenceLocation) (*os.File, error) {
	return nil, errors.New("secure evidence-location reads are unsupported on this platform")
}

func openEvidenceLocationFile(_ EvidenceLocation, _ string) (*os.File, os.FileInfo, error) {
	return nil, nil, errors.New("secure evidence-location reads are unsupported on this platform")
}
