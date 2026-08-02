// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	developerEnvironmentMaxPayload = 1 << 20
	developerEnvironmentVersion    = uint32(1)
	developerEnvironmentFD         = 3
	developerEnvironmentControlEnv = "__PIPELOCK_SANDBOX_DEVELOPER_ENV_FD"
)

var developerEnvironmentMagic = [4]byte{'P', 'L', 'K', 'E'}

// DeveloperEnv builds the environment for the final contained command from a
// caller-supplied developer environment. It intentionally preserves developer
// credentials and toolchain settings, including loader/runtime variables: the
// sandbox init process never receives those variables, and this function is
// called only after containment is established for the final command.
//
// Pipelock control and proxy variables are removed. The bridge proxy settings
// are then forced so the final command cannot inherit a caller-controlled
// proxy or NO_PROXY bypass.
func DeveloperEnv(developerEnvironment []string, bridgeAddr string) ([]string, error) {
	if bridgeAddr == "" {
		return nil, errors.New("sandbox: bridge address is required for developer environment")
	}

	env := make([]string, 0, len(developerEnvironment)+6)
	seen := make(map[string]struct{}, len(developerEnvironment))
	for _, entry := range developerEnvironment {
		key, err := validateDeveloperEnvironmentEntry(entry)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("sandbox: duplicate developer environment key %q", key)
		}
		seen[key] = struct{}{}

		if isPipelockControlEnvKey(key) || isProxyEnvKey(key) {
			continue
		}
		if IsDangerousEnvKey(key) {
			// Loader/runtime injection is deliberately final-command-only. The
			// re-exec control environment never contains developer entries.
			env = append(env, entry)
			continue
		}
		env = append(env, entry)
	}

	proxyURL := "http://" + bridgeAddr
	return append(env,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"NO_PROXY=",
		"no_proxy=",
	), nil
}

func isPipelockControlEnvKey(key string) bool {
	return strings.HasPrefix(strings.ToUpper(key), "__PIPELOCK_")
}

func isProxyEnvKey(key string) bool {
	return strings.HasSuffix(strings.ToUpper(key), "_PROXY")
}

func validateDeveloperEnvironmentEntry(entry string) (string, error) {
	key, _, ok := strings.Cut(entry, "=")
	if !ok || key == "" {
		return "", errors.New("sandbox: malformed developer environment entry")
	}
	if strings.IndexByte(entry, 0) >= 0 {
		return "", fmt.Errorf("sandbox: developer environment entry %q contains NUL", key)
	}
	return key, nil
}

// encodeDeveloperEnvironment serializes a complete environment using a
// length-prefixed binary format. It never uses environment delimiters, because
// values may legitimately contain newlines, equals signs, and unit separators.
func encodeDeveloperEnvironment(environment []string) ([]byte, error) {
	if len(environment) > developerEnvironmentMaxPayload/4 {
		return nil, errors.New("sandbox: developer environment has too many entries")
	}

	payload := make([]byte, 12)
	copy(payload, developerEnvironmentMagic[:])
	binary.BigEndian.PutUint32(payload[4:8], developerEnvironmentVersion)
	count := uint32(0)
	for range environment {
		count++
	}
	binary.BigEndian.PutUint32(payload[8:12], count)

	seen := make(map[string]struct{}, len(environment))
	for _, entry := range environment {
		key, err := validateDeveloperEnvironmentEntry(entry)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("sandbox: duplicate developer environment key %q", key)
		}
		seen[key] = struct{}{}
		if len(entry) > developerEnvironmentMaxPayload || len(payload) > developerEnvironmentMaxPayload-4-len(entry) {
			return nil, errors.New("sandbox: developer environment payload exceeds 1 MiB")
		}

		entryLength := uint32(0)
		for range len(entry) {
			entryLength++
		}
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], entryLength)
		payload = append(payload, length[:]...)
		payload = append(payload, entry...)
	}

	return payload, nil
}

func decodeDeveloperEnvironment(payload []byte) ([]string, error) {
	if len(payload) > developerEnvironmentMaxPayload {
		return nil, errors.New("sandbox: developer environment payload exceeds 1 MiB")
	}
	if len(payload) < 12 || string(payload[:4]) != string(developerEnvironmentMagic[:]) {
		return nil, errors.New("sandbox: malformed developer environment payload")
	}
	if binary.BigEndian.Uint32(payload[4:8]) != developerEnvironmentVersion {
		return nil, errors.New("sandbox: unsupported developer environment payload version")
	}

	count := binary.BigEndian.Uint32(payload[8:12])
	if int64(count) > int64((len(payload)-12)/4) {
		return nil, errors.New("sandbox: malformed developer environment entry count")
	}

	environment := make([]string, 0, count)
	seen := make(map[string]struct{}, count)
	offset := 12
	for range count {
		if len(payload)-offset < 4 {
			return nil, errors.New("sandbox: truncated developer environment payload")
		}
		entryLength := binary.BigEndian.Uint32(payload[offset : offset+4])
		offset += 4
		if int64(entryLength) > int64(len(payload)-offset) {
			return nil, errors.New("sandbox: truncated developer environment payload")
		}
		entry := string(payload[offset : offset+int(entryLength)])
		offset += int(entryLength)
		key, err := validateDeveloperEnvironmentEntry(entry)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("sandbox: duplicate developer environment key %q", key)
		}
		seen[key] = struct{}{}
		environment = append(environment, entry)
	}
	if offset != len(payload) {
		return nil, errors.New("sandbox: malformed trailing developer environment payload")
	}
	return environment, nil
}

func readDeveloperEnvironment(fd int) ([]string, error) {
	if fd != developerEnvironmentFD {
		return nil, fmt.Errorf("sandbox: unexpected developer environment descriptor %d", fd)
	}
	file := os.NewFile(uintptr(fd), "developer-environment")
	if file == nil {
		return nil, errors.New("sandbox: invalid developer environment descriptor")
	}
	defer func() { _ = file.Close() }()

	payload, err := io.ReadAll(io.LimitReader(file, developerEnvironmentMaxPayload+1))
	if err != nil {
		return nil, fmt.Errorf("reading developer environment: %w", err)
	}
	return decodeDeveloperEnvironment(payload)
}

func developerEnvironmentFDFromControl(value string) (int, error) {
	if value == "" {
		return -1, errors.New("sandbox: missing developer environment descriptor")
	}
	fd, err := strconv.Atoi(value)
	if err != nil || fd != developerEnvironmentFD {
		return -1, fmt.Errorf("sandbox: invalid developer environment descriptor %q", value)
	}
	return fd, nil
}
