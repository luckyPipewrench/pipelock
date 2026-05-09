// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// LearnLockEnvironment binds a live-lock runtime to one deployment
// environment. Tenant and DeploymentID may be explicit empty strings for
// single-tenant deployments, but the YAML keys must still be present so
// operators do not silently lose scoping by omission.
//
// All three fields are opaque-string identifiers compared by exact
// byte-equality at manifest load time. They carry no path or URL
// semantics, so values like "../staging" are accepted as-is and produce
// no path-traversal effect; they just become a tuple component the
// runtime mismatches against. There is no length cap at the schema
// layer; YAML loading caps the input upstream.
type LearnLockEnvironment struct {
	ID           string `yaml:"id"`
	Tenant       string `yaml:"tenant"`
	DeploymentID string `yaml:"deployment_id"`
}

func (e *LearnLockEnvironment) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("learn_lock.environment must be a mapping with id, tenant, and deployment_id; migrate string form to environment: {id: <env>, tenant: \"\", deployment_id: \"\"}")
	}

	*e = LearnLockEnvironment{}
	seen := map[string]bool{}
	for i := 0; i < len(value.Content); i += 2 {
		key := value.Content[i]
		val := value.Content[i+1]
		if seen[key.Value] {
			return fmt.Errorf("learn_lock.environment.%s is duplicated", key.Value)
		}
		seen[key.Value] = true

		var target *string
		switch key.Value {
		case "id":
			target = &e.ID
		case "tenant":
			target = &e.Tenant
		case "deployment_id":
			target = &e.DeploymentID
		default:
			return fmt.Errorf("learn_lock.environment.%s is not supported", key.Value)
		}
		if val.Kind != yaml.ScalarNode || val.Tag != "!!str" {
			return fmt.Errorf("learn_lock.environment.%s must be a string", key.Value)
		}
		*target = val.Value
	}

	for _, field := range []string{"id", "tenant", "deployment_id"} {
		if !seen[field] {
			return fmt.Errorf("learn_lock.environment.%s required; use an explicit empty string if intentionally unscoped", field)
		}
	}
	return nil
}
