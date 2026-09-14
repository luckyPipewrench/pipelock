// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	gort "runtime"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/mcp"
)

const (
	windowsOS             = "windows"
	vscodeCarrierPrefix   = "PIPELOCK_VSCODE_"
	maxVSCodeEnvFileBytes = 1 << 20
)

func resolveHeaderCarriers(mappings []string) ([]string, error) {
	lines := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		header, carrier, err := parseCarrierMapping("--header-carrier", mapping)
		if err != nil {
			return nil, err
		}
		value, ok := os.LookupEnv(carrier)
		if !ok {
			return nil, fmt.Errorf("--header-carrier %q: required carrier %s is unset", mapping, carrier)
		}
		lines = append(lines, header+": "+value)
	}
	return lines, nil
}

func resolveChildEnvironment(envFileCarrier string, mappings, unset []string) ([]string, error) {
	return resolveChildEnvironmentForOS(envFileCarrier, mappings, unset, gort.GOOS)
}

func resolveChildEnvironmentForOS(envFileCarrier string, mappings, unset []string, goos string) ([]string, error) {
	values := make(map[string]string)
	removed := make(map[string]bool)
	if envFileCarrier != "" {
		if err := validateCarrierName("--env-file-carrier", envFileCarrier); err != nil {
			return nil, err
		}
		path, ok := os.LookupEnv(envFileCarrier)
		if !ok {
			return nil, fmt.Errorf("--env-file-carrier: required carrier %s is unset", envFileCarrier)
		}
		parsed, err := readVSCodeEnvFile(path)
		if err != nil {
			return nil, err
		}
		for key, value := range parsed {
			values[environmentKey(key, goos)] = value
		}
	}
	for _, key := range unset {
		key = environmentKey(key, goos)
		if err := validateChildEnvTarget("--env-unset", key); err != nil {
			return nil, err
		}
		delete(values, key)
		removed[key] = true
	}
	for _, mapping := range mappings {
		key, carrier, err := parseCarrierMapping("--env-carrier", mapping)
		if err != nil {
			return nil, err
		}
		if err := validateChildEnvTarget("--env-carrier", key); err != nil {
			return nil, err
		}
		key = environmentKey(key, goos)
		value, ok := os.LookupEnv(carrier)
		if !ok {
			return nil, fmt.Errorf("--env-carrier %q: required carrier %s is unset", mapping, carrier)
		}
		if key == "PATH" {
			base, found := values[key]
			if !found {
				base, found = os.LookupEnv(key)
			}
			if found && base != "" {
				separator := string(os.PathListSeparator)
				if goos == windowsOS {
					separator = ";"
				}
				value = base + separator + value
			}
		}
		values[environmentKey(key, goos)] = value
		delete(removed, key)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	removedKeys := make([]string, 0, len(removed))
	for key := range removed {
		removedKeys = append(removedKeys, key)
	}
	sort.Strings(removedKeys)
	result = append(result, removedKeys...)
	return result, nil
}

func environmentKey(key, goos string) string {
	if goos == windowsOS {
		return strings.ToUpper(key)
	}
	return key
}

func parseCarrierMapping(flag, mapping string) (string, string, error) {
	target, carrier, ok := strings.Cut(mapping, "=")
	if !ok || target == "" || carrier == "" || strings.Contains(carrier, "=") {
		return "", "", fmt.Errorf("%s %q: expected TARGET=CARRIER", flag, mapping)
	}
	if err := validateCarrierName(flag, carrier); err != nil {
		return "", "", fmt.Errorf("%s %q: %w", flag, mapping, err)
	}
	return target, carrier, nil
}

func validateCarrierName(flag, carrier string) error {
	if !validEnvName(carrier) {
		return fmt.Errorf("%s: invalid carrier name", flag)
	}
	if !strings.HasPrefix(carrier, vscodeCarrierPrefix) {
		return fmt.Errorf("%s: carrier must use the %s namespace", flag, vscodeCarrierPrefix)
	}
	return nil
}

func validateChildEnvTarget(flag, key string) error {
	if key == "" || strings.ContainsAny(key, "=\x00") {
		return fmt.Errorf("%s %q: invalid environment variable name", flag, key)
	}
	if mcp.IsDangerousEnvKey(key) {
		return fmt.Errorf("%s %s is blocked: this variable can inject code or redirect traffic in the child process", flag, key)
	}
	return nil
}

func validEnvName(name string) bool {
	if name == "" || (name[0] != '_' && (name[0] < 'A' || name[0] > 'Z') && (name[0] < 'a' || name[0] > 'z')) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func readVSCodeEnvFile(path string) (map[string]string, error) {
	clean := filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return nil, fmt.Errorf("reading VS Code envFile %q: %w", path, err)
	}
	defer func() { _ = root.Close() }()
	base := filepath.Base(clean)
	info, err := root.Stat(base)
	if err != nil {
		return nil, fmt.Errorf("reading VS Code envFile %q metadata: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("reading VS Code envFile %q: file must be regular", path)
	}
	if info.Size() > maxVSCodeEnvFileBytes {
		return nil, fmt.Errorf("reading VS Code envFile %q: file exceeds %d bytes", path, maxVSCodeEnvFileBytes)
	}
	file, err := root.Open(base)
	if err != nil {
		return nil, fmt.Errorf("reading VS Code envFile %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxVSCodeEnvFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading VS Code envFile %q: %w", path, err)
	}
	if len(data) > maxVSCodeEnvFileBytes {
		return nil, fmt.Errorf("reading VS Code envFile %q: file exceeds %d bytes", path, maxVSCodeEnvFileBytes)
	}
	values := make(map[string]string)
	normalized := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	for lineNo, raw := range strings.Split(normalized, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		separator := indexOutsideQuotes(line, "=:")
		if separator < 0 {
			continue
		}
		key, value := strings.TrimSpace(line[:separator]), strings.TrimSpace(line[separator+1:])
		if comment := indexOutsideQuotes(value, "#"); comment >= 0 {
			value = strings.TrimSpace(value[:comment])
		}
		if err := validateChildEnvTarget("envFile", key); err != nil {
			return nil, fmt.Errorf("reading VS Code envFile %q line %d: %w", path, lineNo+1, err)
		}
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '`' && value[len(value)-1] == '`')) {
			quote := value[0]
			value = value[1 : len(value)-1]
			if quote == '"' {
				value = strings.ReplaceAll(value, `\n`, "\n")
				value = strings.ReplaceAll(value, `\r`, "\r")
			}
		}
		values[key] = value
	}
	return values, nil
}

func indexOutsideQuotes(value, targets string) int {
	var quote byte
	for i := 0; i < len(value); i++ {
		c := value[i]
		if quote != 0 {
			if c == quote && (i == 0 || value[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			quote = c
			continue
		}
		if strings.ContainsRune(targets, rune(c)) {
			return i
		}
	}
	return -1
}
