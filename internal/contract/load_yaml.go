// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"encoding/json"
	"fmt"
)

// DecodeStrictYAML decodes raw YAML into target with the same strictness as
// DecodeStrictJSON. The pipeline is YAML -> generic tree -> JSON -> typed struct,
// intentionally reusing DecodeStrictJSON so that JSON and YAML transports share
// one typed-boundary bug surface.
//
// YAML-layer rejections come from [ParseYAMLStrict]:
//   - [ErrYAMLDuplicateKey]: duplicate mapping keys
//   - [ErrYAMLAliasOrAnchor]: anchors or aliases
//   - [ErrYAMLMergeKey]: merge keys (<<:)
//   - [ErrYAMLCustomTag]: non-core tags
//   - [ErrYAMLMultiDoc]: multi-document streams
//
// Typed-layer rejections come from [DecodeStrictJSON]:
//   - [ErrUnknownField]: fields not in the target struct
//   - [ErrEmptyPayload]: empty or null input
//   - [ErrTrailingTokens]: trailing tokens after the JSON value (should not
//     occur through this pipeline since json.Marshal produces clean output,
//     but the check is inherited from DecodeStrictJSON for defense in depth)
func DecodeStrictYAML(raw []byte, target any) error {
	if len(raw) == 0 {
		return ErrEmptyPayload
	}

	tree, err := ParseYAMLStrict(raw)
	if err != nil {
		return fmt.Errorf("yaml strict decode: %w", err)
	}
	if tree == nil {
		return ErrEmptyPayload
	}

	jsonBytes, err := json.Marshal(tree)
	if err != nil {
		return fmt.Errorf("yaml strict decode: marshal to JSON: %w", err)
	}

	if err := DecodeStrictJSON(jsonBytes, target); err != nil {
		return fmt.Errorf("yaml strict decode: %w", err)
	}
	return nil
}

// LoadContractYAML parses raw YAML into a Contract using DecodeStrictYAML.
// Unknown fields, YAML-layer violations, and empty/null payloads reject.
func LoadContractYAML(raw []byte) (Contract, error) {
	var c Contract
	if err := DecodeStrictYAML(raw, &c); err != nil {
		return Contract{}, fmt.Errorf("load contract yaml: %w", err)
	}
	return c, nil
}

// LoadKeyRosterYAML parses raw YAML into a KeyRoster using DecodeStrictYAML.
// Unknown fields, YAML-layer violations, and empty/null payloads reject.
func LoadKeyRosterYAML(raw []byte) (KeyRoster, error) {
	var r KeyRoster
	if err := DecodeStrictYAML(raw, &r); err != nil {
		return KeyRoster{}, fmt.Errorf("load key_roster yaml: %w", err)
	}
	return r, nil
}

// LoadTombstoneYAML parses raw YAML into a Tombstone using DecodeStrictYAML.
// Unknown fields, YAML-layer violations, and empty/null payloads reject.
func LoadTombstoneYAML(raw []byte) (Tombstone, error) {
	var t Tombstone
	if err := DecodeStrictYAML(raw, &t); err != nil {
		return Tombstone{}, fmt.Errorf("load tombstone yaml: %w", err)
	}
	return t, nil
}
