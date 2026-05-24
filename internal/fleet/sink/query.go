// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"fmt"
	"strconv"
	"strings"
)

func parseLimit(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return defaultQueryLimit, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid limit", ErrInvalidRequestBody)
	}
	return normalizeLimit(limit), nil
}
