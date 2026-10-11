// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package contain

import "context"

func probeDoctorRuntimeSockets(_ context.Context, _ *doctorEnv) doctorResult {
	return skip("managed runtime socket isolation requires Linux systemd", "run `pipelock contain doctor` on the Linux containment host")
}
