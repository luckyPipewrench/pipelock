// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package recorder

import (
	"errors"
	"os"
	"syscall/js"
)

var errEvidenceFileAccessUnsupported = errors.New("evidence file access unsupported on this platform")

const (
	evidenceReadNoFollowFlag = 0
	evidenceReadNonblockFlag = 0
)

func supportsEvidenceCeremonyLock() bool { return false }

func tryLockEvidenceFileForCeremonyWrite(_ *os.File) error {
	return errEvidenceFileAccessUnsupported
}

// Browser verification installs the private receipt filesystem before mounting
// a bounded archive. A bare JS runtime, including Node's host filesystem,
// must not gain evidence-file access merely because this target is js/wasm.
func validateEvidenceFileAccess() error {
	if js.Global().Get("pipelockMountReceiptGroup").Type() != js.TypeFunction {
		return errEvidenceFileAccessUnsupported
	}
	return nil
}

func lockEvidenceFileForWrite(_ *os.File) error { return errEvidenceFileAccessUnsupported }

func lockEvidenceAppend(_ *os.File) error { return errEvidenceFileAccessUnsupported }

func unlockEvidenceAppend(_ *os.File) error { return errEvidenceFileAccessUnsupported }

func unlockEvidenceFile(_ *os.File) error { return errEvidenceFileAccessUnsupported }

// tryLockEvidenceFileForExpiry refuses exclusive ownership: this target has no
// platform lock, so expiry and ceremony callers must not proceed.
func tryLockEvidenceFileForExpiry(_ *os.File) (bool, error) {
	return false, errEvidenceFileAccessUnsupported
}

// snapshotWriterGone answers the writer-presence probe for a mounted browser
// archive. An archive snapshot cannot have an attached recorder process, so a
// required lock marker proves the captured run was closed before packaging;
// missing markers still fail in the caller before this probe. Without the
// browser mount the probe fails closed.
func snapshotWriterGone(f *os.File) (bool, bool, error) {
	if err := validateEvidenceFileAccess(); err != nil {
		return false, true, err
	}
	if _, err := f.Stat(); err != nil {
		return false, true, err
	}
	return true, true, nil
}
