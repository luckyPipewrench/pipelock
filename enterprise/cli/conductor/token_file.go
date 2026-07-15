//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/securefile"
)

const conductorTokenFileMaxBytes = 64 << 10

// readSecureTokenFile is the single credential-file boundary for Conductor
// server and client bearer tokens. It permits Kubernetes-style symlinks only
// when they resolve within the mounted secret directory, then rejects
// non-regular files, group-writable or other-accessible files, file replacement
// during open, and unbounded input before returning any credential bytes.
func readSecureTokenFile(flag, path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%s is required", flag)
	}
	data, err := securefile.Read(path, securefile.Options{MaxBytes: conductorTokenFileMaxBytes, DisallowedPerms: 0o027})
	if err != nil {
		return "", fmt.Errorf("read %s: %w", flag, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("%s is empty", flag)
	}
	return token, nil
}
