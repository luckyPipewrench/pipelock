//go:build enterprise && windows

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package siemforward

// Windows has no os.OpenFile equivalent of O_NOFOLLOW. Lstat rejection and
// post-open regular-file verification still apply.
const noFollowFlag = 0
