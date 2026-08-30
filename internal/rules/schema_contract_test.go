// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestBuildRuleSchemaContractUsesReaderDeclarations(t *testing.T) {
	contract, err := BuildRuleSchemaContract("3.5.0", "abcdef0123456789")
	if err != nil {
		t.Fatalf("BuildRuleSchemaContract: %v", err)
	}

	if contract.SchemaVersion != RuleSchemaContractVersion {
		t.Fatalf("schema_version = %d, want %d", contract.SchemaVersion, RuleSchemaContractVersion)
	}
	if contract.Producer.Version != "3.5.0" || contract.Producer.SourceRevision != "abcdef0123456789" {
		t.Fatalf("producer = %+v", contract.Producer)
	}
	if !reflect.DeepEqual(contract.Bundle.AcceptedFormatVersions, []int{1, 2}) {
		t.Fatalf("accepted format versions = %v", contract.Bundle.AcceptedFormatVersions)
	}
	if !reflect.DeepEqual(contract.Bundle.AllowedFields, yamlFields(reflect.TypeOf(Bundle{}))) {
		t.Fatal("bundle allowed fields did not come from Bundle YAML tags")
	}
	if !reflect.DeepEqual(contract.Rule.AllowedFields, yamlFields(reflect.TypeOf(Rule{}))) {
		t.Fatal("rule allowed fields did not come from Rule YAML tags")
	}
	if contract.Bundle.UnknownFields != "reject" || contract.Semantics.UnknownTypes != "reject" {
		t.Fatalf("unknown input semantics = %+v", contract.Semantics)
	}
	if contract.Semantics.BundleExemptionsAllowed {
		t.Fatal("contract says bundles can add exemptions")
	}

	for _, definition := range ruleTypeDefinitions {
		index := slices.IndexFunc(contract.Rule.Types, func(schema RuleTypeSchema) bool {
			return schema.ID == definition.ID
		})
		if index < 0 {
			t.Fatalf("contract omitted reader rule type %q", definition.ID)
		}
		schema := contract.Rule.Types[index]
		if schema.MergeTarget != definition.MergeTarget ||
			!reflect.DeepEqual(schema.ScanFieldValues, definition.ScanFieldValues) ||
			!reflect.DeepEqual(schema.ValidatorValues, definition.ValidatorValues) {
			t.Fatalf("contract type %q = %+v, definition = %+v", definition.ID, schema, definition)
		}
	}
}

func TestSchemaRequiredFieldsMatchValidation(t *testing.T) {
	contract, err := BuildRuleSchemaContract("3.5.0", "abcdef0123456789")
	if err != nil {
		t.Fatalf("BuildRuleSchemaContract: %v", err)
	}

	for _, format := range contract.Bundle.Formats {
		t.Run("bundle-format-"+strconv.Itoa(format.FormatVersion), func(t *testing.T) {
			var bundle *Bundle
			if format.FormatVersion == 1 {
				bundle = testBundle("schema-bundle", nil)
			} else {
				bundle = testBundleV2("schema-bundle", TierCommunity, 1, nil)
			}
			zeroYAMLFieldsExcept(bundle, format.RequiredFields)
			if err := bundle.Validate(); err != nil {
				t.Fatalf("declared minimal format %d bundle rejected: %v", format.FormatVersion, err)
			}
			for _, field := range format.RequiredFields {
				candidate := *bundle
				zeroYAMLField(&candidate, field)
				if err := candidate.Validate(); err == nil {
					t.Fatalf("format %d field %q is declared required but validation accepted its zero value", format.FormatVersion, field)
				}
			}
		})
	}

	rule := testDLPRule("schema-rule", confidenceHigh, StatusStable)
	zeroYAMLFieldsExcept(&rule, contract.Rule.CommonRequiredFields)
	if err := validateRule(&rule, make(map[string]bool)); err != nil {
		t.Fatalf("declared minimal rule rejected: %v", err)
	}
	for _, field := range contract.Rule.CommonRequiredFields {
		candidate := rule
		zeroYAMLField(&candidate, field)
		if err := validateRule(&candidate, make(map[string]bool)); err == nil {
			t.Fatalf("rule field %q is declared required but validation accepted its zero value", field)
		}
	}
}

func TestBuildRuleSchemaContractSyntheticTypeCannotDisappear(t *testing.T) {
	definitions := append([]ruleTypeDefinition(nil), ruleTypeDefinitions...)
	definitions = append(definitions, ruleTypeDefinition{
		ID:                    "synthetic-fourth",
		MergeTarget:           "synthetic.target",
		OptionalPatternFields: []string{"synthetic_field"},
		Load: func(_ *bundleExecCtx, _ *Bundle, _ *Rule, _, _ string, _ *LoadedBundle) error {
			return nil
		},
	})

	contract, err := buildRuleSchemaContract("3.5.0", "abcdef0123456789", definitions)
	if err != nil {
		t.Fatalf("buildRuleSchemaContract: %v", err)
	}
	if !slices.ContainsFunc(contract.Rule.Types, func(schema RuleTypeSchema) bool {
		return schema.ID == "synthetic-fourth" && slices.Contains(schema.OptionalPatternFields, "synthetic_field")
	}) {
		t.Fatal("synthetic reader type disappeared from the exported contract")
	}
}

func TestBuildRuleSchemaContractRequiresProducerIdentity(t *testing.T) {
	for _, test := range []struct {
		name     string
		version  string
		revision string
	}{
		{name: "missing version", revision: "abcdef"},
		{name: "unknown version", version: "unknown", revision: "abcdef"},
		{name: "whitespace unknown version", version: " unknown ", revision: "abcdef"},
		{name: "missing revision", version: "3.5.0"},
		{name: "unknown revision", version: "3.5.0", revision: "unknown"},
		{name: "whitespace unknown revision", version: "3.5.0", revision: " unknown "},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildRuleSchemaContract(test.version, test.revision); err == nil {
				t.Fatal("BuildRuleSchemaContract succeeded without exact producer identity")
			}
		})
	}
}

func TestBuildRuleSchemaContractRejectsAmbiguousTypeRegistry(t *testing.T) {
	duplicate := append([]ruleTypeDefinition(nil), ruleTypeDefinitions...)
	duplicate = append(duplicate, ruleTypeDefinitions[0])
	for _, test := range []struct {
		name        string
		definitions []ruleTypeDefinition
	}{
		{name: "duplicate ID", definitions: duplicate},
		{name: "missing ID", definitions: []ruleTypeDefinition{{MergeTarget: "new.target", Load: loadDLPRule}}},
		{name: "missing merge target", definitions: []ruleTypeDefinition{{ID: "new-type", Load: loadDLPRule}}},
		{name: "missing loader", definitions: []ruleTypeDefinition{{ID: "new-type", MergeTarget: "new.target"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := buildRuleSchemaContract("3.5.0", "abcdef", test.definitions); err == nil {
				t.Fatal("malformed rule type registry produced a contract")
			}
		})
	}
}

func TestBuildRuleSchemaContractJSONIsDeterministic(t *testing.T) {
	first, err := BuildRuleSchemaContract("3.5.0", "abcdef0123456789")
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildRuleSchemaContract("3.5.0", "abcdef0123456789")
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstJSON, secondJSON) {
		t.Fatal("contract JSON changed between identical builds")
	}
}

func zeroYAMLFieldsExcept(value any, keep []string) {
	kept := make(map[string]struct{}, len(keep))
	for _, name := range keep {
		kept[name] = struct{}{}
	}
	structValue := reflect.ValueOf(value).Elem()
	structType := structValue.Type()
	for i := 0; i < structValue.NumField(); i++ {
		name := strings.Split(structType.Field(i).Tag.Get("yaml"), ",")[0]
		if _, ok := kept[name]; !ok {
			structValue.Field(i).Set(reflect.Zero(structValue.Field(i).Type()))
		}
	}
}

func zeroYAMLField(value any, name string) {
	structValue := reflect.ValueOf(value).Elem()
	structType := structValue.Type()
	for i := 0; i < structValue.NumField(); i++ {
		if strings.Split(structType.Field(i).Tag.Get("yaml"), ",")[0] == name {
			structValue.Field(i).Set(reflect.Zero(structValue.Field(i).Type()))
			return
		}
	}
}
