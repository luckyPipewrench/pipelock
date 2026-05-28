//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

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
