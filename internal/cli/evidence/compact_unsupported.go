// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package evidence

import "errors"

var errCompactUnsupported = errors.New("offline evidence compaction requires Linux RENAME_EXCHANGE")

func exchangeEvidenceDirectories(_, _ string) error {
	return errCompactUnsupported
}

func prepareCompactStage(_, _ string) error {
	return errCompactUnsupported
}

func preserveCompactFileMetadata(_, _ string) error {
	return errCompactUnsupported
}

func syncCompactFile(_ string) error {
	return errCompactUnsupported
}

func syncCompactDirectory(_ string) error {
	return errCompactUnsupported
}
