// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cliutil

import "time"

// ServiceStartTimeout is the existing contain-install startup budget, matching
// systemd's stock DefaultTimeoutStartSec (systemd-system.conf(5)). Both the unit
// and genuine verification-progress extensions derive from this duration.
const ServiceStartTimeout = 90 * time.Second
