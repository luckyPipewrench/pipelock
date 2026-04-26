// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"fmt"
)

// DataClass labels a signed field's privacy treatment.
type DataClass string

const (
	DataClassPublic    DataClass = "public"
	DataClassInternal  DataClass = "internal"
	DataClassSensitive DataClass = "sensitive"
	DataClassRegulated DataClass = "regulated"
)

var (
	// ErrInvalidDataClass indicates a value that is not one of the four enumerated DataClass strings.
	ErrInvalidDataClass = errors.New("invalid data_class")
	// ErrRegulatedField indicates a signed field carries data_class=regulated,
	// which is forbidden in v2.4 contracts.
	ErrRegulatedField = errors.New("regulated data_class is forbidden in signed artifacts")
	// ErrMissingDataClass indicates a leaf body field has no class entry and no
	// data_class_root to inherit from.
	ErrMissingDataClass = errors.New("field has no data_class coverage")
)

// Validate reports whether this data class is one of the four enumerated values.
func (c DataClass) Validate() error {
	switch c {
	case DataClassPublic, DataClassInternal, DataClassSensitive, DataClassRegulated:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidDataClass, string(c))
	}
}

func validateDataClassRoot(root any) (bool, error) {
	rs, ok := root.(string)
	if !ok {
		return false, fmt.Errorf("%w: data_class_root has non-string class value", ErrInvalidDataClass)
	}
	if rs == "" {
		return false, nil
	}
	rootClass := DataClass(rs)
	if err := rootClass.Validate(); err != nil {
		return false, fmt.Errorf("data_class_root: %w", err)
	}
	if rootClass == DataClassRegulated {
		return false, fmt.Errorf("%w at path %q", ErrRegulatedField, "data_class_root")
	}
	return true, nil
}

// ValidateDataClassCoverage walks the body recursively and verifies that:
//   - every entry in fieldClasses maps to a value in the enum (rejects unknown classes)
//   - no entry is "regulated" (forbidden in v2.4 signed artifacts)
//   - every leaf body path has either an explicit fieldClasses entry OR a data_class_root
//     to inherit from. Body without root + unclassified leaf => ErrMissingDataClass.
//
// Path notation: dot-separated keys (e.g. "selector.agent"). Arrays use "[]" as a wildcard
// segment (e.g. "rules[].selector.host"). The walker skips envelope keys
// (data_class_root, field_data_classes, signature) so they do not require coverage entries.
func ValidateDataClassCoverage(body any, fieldClasses map[string]any) error {
	// First pass: validate all declared classes (enum check + regulated rejection).
	for path, v := range fieldClasses {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("%w: path %q has non-string class value", ErrInvalidDataClass, path)
		}
		dc := DataClass(s)
		if err := dc.Validate(); err != nil {
			return fmt.Errorf("path %q: %w", path, err)
		}
		if dc == DataClassRegulated {
			return fmt.Errorf("%w at path %q", ErrRegulatedField, path)
		}
	}

	// Determine whether the body provides a root class for lenient inheritance.
	hasRoot := false
	if m, ok := body.(map[string]any); ok {
		if root, present := m["data_class_root"]; present {
			ok, err := validateDataClassRoot(root)
			if err != nil {
				return err
			}
			hasRoot = ok
		}
	}

	// Second pass: walk body tree and check coverage.
	return walkAndCheckCoverage(body, "", fieldClasses, hasRoot)
}

func walkAndCheckCoverage(node any, path string, fieldClasses map[string]any, hasRoot bool) error {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if isEnvelopeKey(k) {
				continue
			}
			next := k
			if path != "" {
				next = path + "." + k
			}
			if isLeaf(v) {
				if _, ok := fieldClasses[next]; !ok && !hasRoot {
					return fmt.Errorf("%w at path %q", ErrMissingDataClass, next)
				}
				continue
			}
			if err := walkAndCheckCoverage(v, next, fieldClasses, hasRoot); err != nil {
				return err
			}
		}
	case []any:
		// Array segments use "[]" as a wildcard path component.
		next := path + "[]"
		for _, item := range n {
			if isLeaf(item) {
				// Array of scalars: covered by the [] path entry. Same lenient treatment.
				if _, ok := fieldClasses[next]; !ok && !hasRoot {
					return fmt.Errorf("%w at path %q", ErrMissingDataClass, next)
				}
				continue
			}
			if err := walkAndCheckCoverage(item, next, fieldClasses, hasRoot); err != nil {
				return err
			}
		}
	}
	return nil
}

func isEnvelopeKey(k string) bool {
	switch k {
	case "data_class_root", "field_data_classes", "signature":
		return true
	default:
		return false
	}
}

func isLeaf(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return false
	default:
		return true
	}
}
