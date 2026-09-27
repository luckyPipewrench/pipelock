// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"os"
	"strconv"
)

// testOwnerID converts a process uid or gid to the uint32 a fake Stat_t
// carries. ParseUint with a 32-bit size bounds the value, so a negative id
// (Windows reports -1) or an oversized one panics instead of wrapping.
func testOwnerID(id int) uint32 {
	v, err := strconv.ParseUint(strconv.Itoa(id), 10, 32)
	if err != nil {
		panic("process id does not fit a uint32 owner: " + err.Error())
	}
	return uint32(v)
}

func testGID() uint32 { return testOwnerID(os.Getgid()) }

func testUID() uint32 { return testOwnerID(os.Getuid()) }
