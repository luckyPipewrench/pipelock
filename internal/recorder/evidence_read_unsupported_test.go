//go:build aix || (js && wasm) || (wasip1 && wasm)

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"testing"
)

func TestEvidenceFileOperationsFailClosedOnUnsupportedPlatform(t *testing.T) {
	accessErr := validateEvidenceFileAccess()
	if !errors.Is(accessErr, errEvidenceFileAccessUnsupported) {
		t.Fatalf("access error = %v, want %v", accessErr, errEvidenceFileAccessUnsupported)
	}

	file, info, err := openRegularEvidenceFile("unused", "evidence file", accessErr)
	if file != nil || info != nil {
		t.Fatalf("open result = (%v, %v), want nil handles", file, info)
	}
	if !errors.Is(err, errEvidenceFileAccessUnsupported) {
		t.Fatalf("open error = %v, want %v", err, errEvidenceFileAccessUnsupported)
	}

	for name, lockErr := range map[string]error{
		"lock":   lockEvidenceFileForWrite(nil),
		"unlock": unlockEvidenceFile(nil),
	} {
		if !errors.Is(lockErr, errEvidenceFileAccessUnsupported) {
			t.Errorf("%s error = %v, want %v", name, lockErr, errEvidenceFileAccessUnsupported)
		}
	}

	locked, err := tryLockEvidenceFileForExpiry(nil)
	if locked {
		t.Error("expiry lock reported acquired on unsupported platform")
	}
	if !errors.Is(err, errEvidenceFileAccessUnsupported) {
		t.Fatalf("expiry lock error = %v, want %v", err, errEvidenceFileAccessUnsupported)
	}
}
