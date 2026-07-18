// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !subprocess_coverage

package sandbox

import (
	"reflect"
	"testing"
)

func TestPrepareSubprocessCoverageDisabled(t *testing.T) {
	t.Setenv("GOCOVERDIR", "/tmp/should-not-be-authorized")
	policy := Policy{AllowRWDirs: []string{"/workspace"}}
	env := []string{"EXISTING=value"}

	gotPolicy, gotEnv := prepareSubprocessCoverage(policy, env)

	if !reflect.DeepEqual(gotPolicy, policy) {
		t.Fatalf("policy changed in a release build: got %#v, want %#v", gotPolicy, policy)
	}
	if !reflect.DeepEqual(gotEnv, env) {
		t.Fatalf("environment changed in a release build: got %#v, want %#v", gotEnv, env)
	}
	if err := flushSubprocessCoverage(); err != nil {
		t.Fatalf("flushSubprocessCoverage() in a release build: %v", err)
	}
}
