// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestLifecyclePreparedJSONSurvivesContainmentMigration(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.configDir = defaultConfigDir
	env.readFile = func(path string) ([]byte, error) { t.Fatalf("migration unexpectedly read %s", path); return nil, nil }
	env.stat = func(path string) (os.FileInfo, error) {
		t.Fatalf("migration unexpectedly statted %s", path)
		return nil, nil
	}
	env.writeFile = func(path string, _ []byte, _ os.FileMode) error {
		t.Fatalf("migration unexpectedly wrote %s", path)
		return nil
	}
	data := []byte(`{"api_allowlist": ["browser.fixture.example"], "canary_tokens": {"enabled": true, "tokens": [{"name": "browser-repro", "value": "PIPELOCK_BROWSER_REPRO_SYNTHETIC_CANARY"}]}, "dns": {"host_overrides": {"browser.fixture.example": ["127.0.0.1"], "forbidden.fixture.example": ["127.0.0.1"]}}, "fetch_proxy": {"listen": "127.0.0.1:8888"}, "flight_recorder": {"signing_key_path": "/etc/pipelock/keys/flight-recorder-signing.key"}, "forward_proxy": {"enabled": true}, "logging": {"format": "json", "include_allowed": true, "include_blocked": true, "output": "stdout"}, "metrics_listen": "127.0.0.1:9091", "mode": "strict", "response_scanning": {"action": "block", "enabled": true}, "trusted_domains": ["browser.fixture.example"]}`)
	out, artifacts, err := migratePipelockConfigForContain(env, "/etc/pipelock/pipelock.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("unexpected migration artifacts: %v", artifacts)
	}
	var before, after map[string]any
	if err := json.Unmarshal(data, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &after); err != nil {
		t.Fatalf("migration stopped producing JSON: %v; output=%s", err, out)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("migration changed prepared policy: before=%v after=%v", before, after)
	}
}
