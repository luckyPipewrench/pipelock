// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cliutil

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func configPathOwnerUID(info os.FileInfo) (int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

func currentEUID() int {
	return os.Geteuid()
}

func configPathOwnerTrusted(ownerUID int) bool {
	u, err := user.LookupId(strconv.Itoa(ownerUID))
	if err != nil {
		return false
	}
	return u.Username == "pipelock-proxy"
}
