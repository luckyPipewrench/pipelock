// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package signing

func publishAgentDirectory(targetDir, stageDir, backupDir string) error {
	return publishAgentDirectoryPortable(targetDir, stageDir, backupDir)
}
