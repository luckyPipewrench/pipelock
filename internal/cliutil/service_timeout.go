// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cliutil

import "time"

// ServiceStartTimeout is the existing contain-install startup budget, matching
// systemd's stock DefaultTimeoutStartSec (systemd-system.conf(5)). Both the unit
// and genuine verification-progress extensions derive from this duration.
const ServiceStartTimeout = 90 * time.Second

// ServiceStopTimeout is the stop budget every shipped proxy deployment states
// instead of inheriting its manager's default. Closing a receipt group at
// shutdown drains unverified segments and rehashes earlier evidence, so its
// cost grows with recorded history and shrinks with available CPU. Stock
// budgets are 90 s for systemd (systemd-system.conf(5)), 30 s for Kubernetes
// pods and 10 s for Compose and Linux docker stop; a measured 300,000-request,
// 8-chain close on two CPUs took 109 s. Ten minutes is a chosen policy that
// clears that measurement with room, not a proven upper bound: a manager that
// kills the close leaves durable receipts verifiable but the group unsealed,
// which verification reports as GROUP_INCOMPLETE.
const ServiceStopTimeout = 10 * time.Minute
