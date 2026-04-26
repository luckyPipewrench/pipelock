// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"testing"
)

func TestDataClass_Validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   DataClass
		ok   bool
	}{
		{"public", DataClassPublic, true},
		{"internal", DataClassInternal, true},
		{"sensitive", DataClassSensitive, true},
		{"regulated", DataClassRegulated, true},
		{"unknown", DataClass("private"), false},
		{"empty", DataClass(""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.in.Validate()
			if tc.ok && err != nil {
				t.Errorf("got %v, want nil", err)
			}
			if !tc.ok && err == nil {
				t.Errorf("got nil, want error for %q", tc.in)
			}
		})
	}
}

func TestDataClassCoverage_RegulatedRejects(t *testing.T) {
	t.Parallel()
	body := map[string]any{
		"data_class_root": "internal",
		"field_data_classes": map[string]any{
			"selector.agent":                 "internal",
			"observation_window.event_count": "public",
			"rationale.summary":              "regulated",
		},
		"selector": map[string]any{"agent": "buster"},
	}
	err := ValidateDataClassCoverage(body, body["field_data_classes"].(map[string]any))
	if !errors.Is(err, ErrRegulatedField) {
		t.Errorf("got %v, want ErrRegulatedField", err)
	}
}

func TestDataClassCoverage_MissingClassRejectsWhenNoRoot(t *testing.T) {
	t.Parallel()
	// No data_class_root set; an unclassified leaf must trigger ErrMissingDataClass.
	body := map[string]any{
		"field_data_classes": map[string]any{
			// selector.agent is unclassified, no root to fall back to
		},
		"selector": map[string]any{"agent": "buster"},
	}
	err := ValidateDataClassCoverage(body, body["field_data_classes"].(map[string]any))
	if !errors.Is(err, ErrMissingDataClass) {
		t.Errorf("got %v, want ErrMissingDataClass", err)
	}
}

func TestDataClassCoverage_LenientWithRoot(t *testing.T) {
	t.Parallel()
	// data_class_root present; unclassified leaves inherit it; no error.
	body := map[string]any{
		"data_class_root":    "internal",
		"field_data_classes": map[string]any{
			// selector.agent intentionally absent; lenient inherits root
		},
		"selector": map[string]any{"agent": "buster"},
	}
	err := ValidateDataClassCoverage(body, body["field_data_classes"].(map[string]any))
	if err != nil {
		t.Errorf("expected nil (lenient with root), got %v", err)
	}
}

func TestDataClassCoverage_InvalidClassValueRejects(t *testing.T) {
	t.Parallel()
	body := map[string]any{
		"data_class_root": "internal",
		"field_data_classes": map[string]any{
			"selector.agent": "private", // not in enum
		},
		"selector": map[string]any{"agent": "buster"},
	}
	err := ValidateDataClassCoverage(body, body["field_data_classes"].(map[string]any))
	if !errors.Is(err, ErrInvalidDataClass) {
		t.Errorf("got %v, want ErrInvalidDataClass", err)
	}
}

func TestDataClassCoverage_NonStringClassValueRejects(t *testing.T) {
	t.Parallel()
	// fieldClasses entry is an int rather than a string; must reject with ErrInvalidDataClass.
	body := map[string]any{
		"data_class_root": "internal",
		"selector":        map[string]any{"agent": "buster"},
	}
	fieldClasses := map[string]any{
		"selector.agent": 42, // non-string class value
	}
	err := ValidateDataClassCoverage(body, fieldClasses)
	if !errors.Is(err, ErrInvalidDataClass) {
		t.Errorf("got %v, want ErrInvalidDataClass", err)
	}
}

func TestDataClassCoverage_ArrayOfScalarsWithRoot(t *testing.T) {
	t.Parallel()
	// Body with an array of scalars; no root needed when fieldClasses has the [] entry.
	body := map[string]any{
		"data_class_root": "public",
		"tags":            []any{"alpha", "beta"},
	}
	fieldClasses := map[string]any{}
	err := ValidateDataClassCoverage(body, fieldClasses)
	if err != nil {
		t.Errorf("expected nil (root covers array scalars), got %v", err)
	}
}

func TestDataClassCoverage_ArrayOfScalarsMissingClass(t *testing.T) {
	t.Parallel()
	// Array of scalars with no root and no [] entry triggers ErrMissingDataClass.
	body := map[string]any{
		"tags": []any{"alpha", "beta"},
	}
	fieldClasses := map[string]any{}
	err := ValidateDataClassCoverage(body, fieldClasses)
	if !errors.Is(err, ErrMissingDataClass) {
		t.Errorf("got %v, want ErrMissingDataClass", err)
	}
}

func TestDataClassCoverage_ArrayOfMapsRecursion(t *testing.T) {
	t.Parallel()
	// Array of maps exercises the sequence-of-maps recursion branch.
	// With a root, leaf fields inside each map entry are covered by inheritance.
	body := map[string]any{
		"data_class_root": "internal",
		"rules": []any{
			map[string]any{"host": "example.com", "action": "block"},
			map[string]any{"host": "safe.com", "action": "allow"},
		},
	}
	fieldClasses := map[string]any{}
	err := ValidateDataClassCoverage(body, fieldClasses)
	if err != nil {
		t.Errorf("expected nil (root covers nested array-of-maps leaves), got %v", err)
	}
}

func TestDataClassCoverage_DeeplyNestedWithExplicitClass(t *testing.T) {
	t.Parallel()
	// Deeply nested body where a leaf at depth 3 has an explicit class entry.
	body := map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"leaf": "value",
			},
		},
	}
	fieldClasses := map[string]any{
		"level1.level2.leaf": "public",
	}
	err := ValidateDataClassCoverage(body, fieldClasses)
	if err != nil {
		t.Errorf("expected nil for explicitly classified deep leaf, got %v", err)
	}
}

func TestDataClassCoverage_ArrayOfMapsMissingLeafClass(t *testing.T) {
	t.Parallel()
	// Array of maps where a leaf is unclassified with no root triggers ErrMissingDataClass.
	body := map[string]any{
		"rules": []any{
			map[string]any{"host": "example.com"},
		},
	}
	fieldClasses := map[string]any{}
	err := ValidateDataClassCoverage(body, fieldClasses)
	if !errors.Is(err, ErrMissingDataClass) {
		t.Errorf("got %v, want ErrMissingDataClass", err)
	}
}
