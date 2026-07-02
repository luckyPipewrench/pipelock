// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"strings"
)

func isGeneratedPipelockHookCommand(command, tool string) bool {
	fields, ok := splitHookCommandFields(command)
	if !ok || len(fields) != 3 && len(fields) != 5 {
		return false
	}
	if !isPipelockHookBinary(fields[0]) || fields[1] != tool || fields[2] != "hook" {
		return false
	}
	if len(fields) == 3 {
		return true
	}
	return fields[3] == "--config" && fields[4] != "" && !strings.HasPrefix(fields[4], "-")
}

func isPipelockHookBinary(binary string) bool {
	base := filepath.Base(binary)
	if base == "pipelock" || base == "pipelock.exe" {
		return true
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return base == filepath.Base(exe)
}

func splitHookCommandFields(command string) ([]string, bool) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, true
	}

	var fields []string
	var b strings.Builder
	inSingle := false
	inField := false
	for i := 0; i < len(command); i++ {
		c := command[i]
		switch {
		case inSingle && c == '\'':
			inSingle = false
		case !inSingle && c == '\'':
			inSingle = true
			inField = true
		case !inSingle && c == '\\' && i+1 < len(command):
			i++
			b.WriteByte(command[i])
			inField = true
		case !inSingle && (c == ' ' || c == '\t' || c == '\n' || c == '\r'):
			if inField {
				fields = append(fields, b.String())
				b.Reset()
				inField = false
			}
		default:
			b.WriteByte(c)
			inField = true
		}
	}
	if inSingle {
		return nil, false
	}
	if inField {
		fields = append(fields, b.String())
	}
	return fields, true
}
