// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

func unmarshalStrictArtifact(name string, data []byte, dst any) error {
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		if errors.Is(err, jsonscan.ErrDuplicateKey) {
			return fmt.Errorf("%s contains duplicate JSON key: %w", name, err)
		}
		return fmt.Errorf("%s is invalid JSON: %w", name, err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return err
	}
	return nil
}
