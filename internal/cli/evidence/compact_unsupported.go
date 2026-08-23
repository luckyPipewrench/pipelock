// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package evidence

import "errors"

func exchangeEvidenceDirectories(_, _ string) error {
	return errors.New("offline evidence compaction requires Linux RENAME_EXCHANGE")
}

func prepareCompactStage(_, _ string) error {
	return errors.New("offline evidence compaction requires Linux RENAME_EXCHANGE")
}

func preserveCompactFileMetadata(_, _ string) error {
	return errors.New("offline evidence compaction requires Linux RENAME_EXCHANGE")
}

func syncCompactFile(_ string) error {
	return errors.New("offline evidence compaction requires Linux RENAME_EXCHANGE")
}

func syncCompactDirectory(_ string) error {
	return errors.New("offline evidence compaction requires Linux RENAME_EXCHANGE")
}
