// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strconv"
	"testing"
)

func TestReviewR2CPUUnavailable(t *testing.T) {
	oldReadProcessAuxv := readProcessAuxv
	readProcessAuxv = func() ([]byte, error) { return nil, os.ErrPermission }
	t.Cleanup(func() { readProcessAuxv = oldReadProcessAuxv })
	res, err := runMode(context.Background(), smallOptions(t, newFakePipelock(t, "clean")), modeOff)
	if err != nil {
		t.Fatal(err)
	}
	if res.Integrity.Verdict != verdictPass {
		t.Fatal("positive control integrity failed")
	}
	if res.Performance.Verdict != perfInvalid {
		t.Fatal("unavailable CPU accounting reported a usable zero")
	}
}

func TestReadClockTicksFromAuxv(t *testing.T) {
	wordSize := strconv.IntSize / 8
	entry := make([]byte, 2*wordSize)
	if wordSize == 8 {
		binary.NativeEndian.PutUint64(entry[:wordSize], atClockTicks)
		binary.NativeEndian.PutUint64(entry[wordSize:], 100)
	} else {
		binary.NativeEndian.PutUint32(entry[:wordSize], atClockTicks)
		binary.NativeEndian.PutUint32(entry[wordSize:], 100)
	}
	oldReadProcessAuxv := readProcessAuxv
	readProcessAuxv = func() ([]byte, error) { return entry, nil }
	t.Cleanup(func() { readProcessAuxv = oldReadProcessAuxv })
	ticks, err := readClockTicks()
	if err != nil || ticks != 100 {
		t.Fatalf("readClockTicks() = %v, %v; want 100, nil", ticks, err)
	}
}

func TestReadClockTicksRejectsUnavailableAuxv(t *testing.T) {
	wantErr := errors.New("auxv unavailable")
	oldReadProcessAuxv := readProcessAuxv
	readProcessAuxv = func() ([]byte, error) { return nil, wantErr }
	t.Cleanup(func() { readProcessAuxv = oldReadProcessAuxv })
	if ticks, err := readClockTicks(); ticks != 0 || !errors.Is(err, wantErr) {
		t.Fatalf("readClockTicks() = %v, %v; want zero and unavailable error", ticks, err)
	}
}

func TestReadClockTicksRejectsMalformedAuxv(t *testing.T) {
	oldReadProcessAuxv := readProcessAuxv
	readProcessAuxv = func() ([]byte, error) { return []byte{1}, nil }
	t.Cleanup(func() { readProcessAuxv = oldReadProcessAuxv })
	if ticks, err := readClockTicks(); ticks != 0 || err == nil {
		t.Fatalf("readClockTicks() = %v, %v; want malformed input error", ticks, err)
	}
}
