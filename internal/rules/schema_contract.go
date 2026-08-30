// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const RuleSchemaContractVersion = 1

const (
	mergeTargetDLP        = "dlp.patterns"
	mergeTargetInjection  = "response_scanning.patterns"
	mergeTargetToolPoison = "mcp_tool_scanning.descriptions"
)

type ruleTypeDefinition struct {
	ID                    string
	MergeTarget           string
	OptionalPatternFields []string
	ScanFieldValues       []string
	DefaultScanField      string
	ValidatorValues       []string
	Load                  loadRuleFunc
}

var ruleTypeDefinitions = []ruleTypeDefinition{
	{
		ID:                    RuleTypeDLP,
		MergeTarget:           mergeTargetDLP,
		OptionalPatternFields: []string{"exempt_domains", "validator"},
		ValidatorValues:       []string{config.ValidatorABA, config.ValidatorLuhn, config.ValidatorMod97, config.ValidatorWIF},
		Load:                  loadDLPRule,
	},
	{ID: RuleTypeInjection, MergeTarget: mergeTargetInjection, OptionalPatternFields: []string{"exempt_domains"}, Load: loadInjectionRule},
	{
		ID:                    RuleTypeToolPoison,
		MergeTarget:           mergeTargetToolPoison,
		OptionalPatternFields: []string{"exempt_domains", "scan_field"},
		ScanFieldValues:       []string{scanFieldDescription, scanFieldName},
		DefaultScanField:      scanFieldDescription,
		Load:                  loadToolPoisonRule,
	},
}

// RuleSchemaContract is the machine-readable contract exported by the rule
// bundle reader. Consumers can pin this output instead of copying the reader's
// accepted formats, fields, enums, and rule types by hand.
type RuleSchemaContract struct {
	SchemaVersion int                  `json:"schema_version"`
	Producer      RuleSchemaProducer   `json:"producer"`
	Bundle        BundleSchemaContract `json:"bundle"`
	Rule          RuleSchema           `json:"rule"`
	Semantics     RuleSchemaSemantics  `json:"semantics"`
}

type RuleSchemaProducer struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	SourceRevision string `json:"source_revision"`
}

type BundleSchemaContract struct {
	AcceptedFormatVersions []int                `json:"accepted_format_versions"`
	AllowedFields          []string             `json:"allowed_fields"`
	Formats                []BundleFormatSchema `json:"formats"`
	UnknownFields          string               `json:"unknown_fields"`
	KnownFeatures          []string             `json:"known_features"`
	Tiers                  []string             `json:"tiers"`
}

type BundleFormatSchema struct {
	FormatVersion  int      `json:"format_version"`
	RequiredFields []string `json:"required_fields"`
}

type RuleSchema struct {
	AllowedFields        []string         `json:"allowed_fields"`
	CommonRequiredFields []string         `json:"common_required_fields"`
	Statuses             []string         `json:"statuses"`
	Severities           []string         `json:"severities"`
	Confidences          []string         `json:"confidences"`
	Types                []RuleTypeSchema `json:"types"`
}

type RuleTypeSchema struct {
	ID                    string   `json:"id"`
	MergeTarget           string   `json:"merge_target"`
	RequiredPatternFields []string `json:"required_pattern_fields"`
	OptionalPatternFields []string `json:"optional_pattern_fields"`
	IgnoredPatternFields  []string `json:"ignored_pattern_fields"`
	ScanFieldValues       []string `json:"scan_field_values,omitempty"`
	DefaultScanField      string   `json:"default_scan_field,omitempty"`
	ValidatorValues       []string `json:"validator_values,omitempty"`
}

type RuleSchemaSemantics struct {
	Composition             string `json:"composition"`
	ActionAuthority         string `json:"action_authority"`
	BundleExemptionsAllowed bool   `json:"bundle_exemptions_allowed"`
	UnknownTypes            string `json:"unknown_types"`
}

// BuildRuleSchemaContract builds a deterministic contract from the same
// declarations used by YAML decoding and rule validation.
func BuildRuleSchemaContract(version, sourceRevision string) (RuleSchemaContract, error) {
	return buildRuleSchemaContract(version, sourceRevision, ruleTypeDefinitions)
}

func buildRuleSchemaContract(version, sourceRevision string, definitions []ruleTypeDefinition) (RuleSchemaContract, error) {
	version = strings.TrimSpace(version)
	sourceRevision = strings.TrimSpace(sourceRevision)
	if version == "" || version == "unknown" {
		return RuleSchemaContract{}, fmt.Errorf("rule schema contract: exact pipelock version is unavailable")
	}
	if sourceRevision == "" || sourceRevision == "unknown" {
		return RuleSchemaContract{}, fmt.Errorf("rule schema contract: exact source revision is unavailable")
	}

	formats := make([]BundleFormatSchema, 0, MaxFormatVersion)
	acceptedFormats := make([]int, 0, MaxFormatVersion)
	for formatVersion := 1; formatVersion <= MaxFormatVersion; formatVersion++ {
		required := []string{"author", "description", "format_version", "name", "version"}
		if formatVersion >= 2 {
			required = append(required, "expires_at", "key_id", "monotonic_version", "published_at", "tier")
			sort.Strings(required)
		}
		acceptedFormats = append(acceptedFormats, formatVersion)
		formats = append(formats, BundleFormatSchema{FormatVersion: formatVersion, RequiredFields: required})
	}

	types := make([]RuleTypeSchema, 0, len(definitions))
	seenTypes := make(map[string]struct{}, len(definitions))
	for _, definition := range definitions {
		if definition.ID == "" || definition.MergeTarget == "" || definition.Load == nil {
			return RuleSchemaContract{}, fmt.Errorf("rule schema contract: rule type id, merge target, and loader must be declared")
		}
		if _, exists := seenTypes[definition.ID]; exists {
			return RuleSchemaContract{}, fmt.Errorf("rule schema contract: duplicate rule type %q", definition.ID)
		}
		seenTypes[definition.ID] = struct{}{}
		optional := append([]string(nil), definition.OptionalPatternFields...)
		sort.Strings(optional)
		types = append(types, RuleTypeSchema{
			ID:                    definition.ID,
			MergeTarget:           definition.MergeTarget,
			RequiredPatternFields: []string{"regex"},
			OptionalPatternFields: optional,
			IgnoredPatternFields:  []string{"exempt_domains"},
			ScanFieldValues:       append([]string(nil), definition.ScanFieldValues...),
			DefaultScanField:      definition.DefaultScanField,
			ValidatorValues:       append([]string(nil), definition.ValidatorValues...),
		})
	}
	sort.Slice(types, func(i, j int) bool { return types[i].ID < types[j].ID })

	return RuleSchemaContract{
		SchemaVersion: RuleSchemaContractVersion,
		Producer:      RuleSchemaProducer{Name: "pipelock", Version: version, SourceRevision: sourceRevision},
		Bundle: BundleSchemaContract{
			AcceptedFormatVersions: acceptedFormats,
			AllowedFields:          yamlFields(reflect.TypeOf(Bundle{})),
			Formats:                formats,
			UnknownFields:          "reject",
			KnownFeatures:          sortedTrueKeys(KnownFeatures),
			Tiers:                  sortedTrueKeys(validTiers),
		},
		Rule: RuleSchema{
			AllowedFields:        yamlFields(reflect.TypeOf(Rule{})),
			CommonRequiredFields: []string{"confidence", "description", "id", "name", "pattern", "severity", "status", "type"},
			Statuses:             sortedTrueKeys(validStatuses),
			Severities:           sortedTrueKeys(validSeverities),
			Confidences:          sortedTrueKeys(validConfidences),
			Types:                types,
		},
		Semantics: RuleSchemaSemantics{
			Composition:             "additive",
			ActionAuthority:         "local_pipelock_config",
			BundleExemptionsAllowed: false,
			UnknownTypes:            "reject",
		},
	}, nil
}

func ruleTypeDefinitionFor(ruleType string) (ruleTypeDefinition, bool) {
	for _, definition := range ruleTypeDefinitions {
		if definition.ID == ruleType {
			return definition, true
		}
	}
	return ruleTypeDefinition{}, false
}

func yamlFields(t reflect.Type) []string {
	fields := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name := strings.Split(t.Field(i).Tag.Get("yaml"), ",")[0]
		if name != "" && name != "-" {
			fields = append(fields, name)
		}
	}
	sort.Strings(fields)
	return fields
}

func sortedTrueKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for value, enabled := range values {
		if enabled {
			keys = append(keys, value)
		}
	}
	sort.Strings(keys)
	return keys
}
