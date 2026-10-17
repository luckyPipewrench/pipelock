// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cardtest

import "strings"

// Number assembles the synthetic issuer/Luhn fixture at runtime.
func Number() string { return "4111" + strings.Repeat("1", 12) }
