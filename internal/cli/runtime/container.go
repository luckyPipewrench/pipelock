// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import "github.com/luckyPipewrench/pipelock/internal/cliutil"

// IsContainerized checks whether the process is running inside a container.
// It shares the diagnostic command's runtime detection so startup warnings
// and verification reports agree about Docker, Podman, and Kubernetes.
func IsContainerized() bool {
	return cliutil.DetectRunContext() != cliutil.RunContextHost
}
