//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/convergence"
)

func TestReadReceiptProducerInventory_FixtureStates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt-producers.json")
	fixture := `{
  "schema": "pipelock-receipt-producer-inventory-v1",
  "org_id": "org-example",
  "fleet_id": "production",
  "producers": [
    {"instance_id": "current", "desired_replicas": 1},
    {"instance_id": "stale", "desired_replicas": 1},
    {"instance_id": "missing", "desired_replicas": 1},
    {"instance_id": "local-only", "desired_replicas": 1, "excluded": true, "excluded_owner": "platform", "excluded_reason": "local development proxy"},
    {"instance_id": "scaled-zero", "desired_replicas": 0}
  ]
}`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	inventory, err := readReceiptProducerInventory(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if got, want := len(inventory.Producers), 5; got != want {
		t.Fatalf("producer count = %d, want %d", got, want)
	}
	localOnly := inventory.Producers[3]
	if !localOnly.Excluded || localOnly.ExcludedOwner != "platform" || localOnly.ExcludedReason == "" {
		t.Fatalf("local-only fixture was not preserved: %+v", localOnly)
	}
}

func TestReceiptProducerInventoryExample(t *testing.T) {
	path := filepath.Join("..", "..", "..", "examples", "conductor", "receipt-producer-inventory.json")
	inventory, err := readReceiptProducerInventory(path)
	if err != nil {
		t.Fatalf("read shipped inventory example: %v", err)
	}
	if got, want := len(inventory.Producers), 3; got != want {
		t.Fatalf("producer count = %d, want %d", got, want)
	}
}

func TestReadReceiptProducerInventory_RejectsInvalidExceptions(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name: "local-only needs accountable owner and reason",
			content: `{
  "schema": "pipelock-receipt-producer-inventory-v1",
  "org_id": "org-example", "fleet_id": "production",
  "producers": [{"instance_id": "local-only", "desired_replicas": 1, "excluded": true}]
}`,
			want: "requires excluded_owner and excluded_reason",
		},
		{
			name: "local-only cannot hide scaled zero",
			content: `{
  "schema": "pipelock-receipt-producer-inventory-v1",
  "org_id": "org-example", "fleet_id": "production",
  "producers": [{"instance_id": "local-only", "desired_replicas": 0, "excluded": true, "excluded_owner": "platform", "excluded_reason": "local development proxy"}]
}`,
			want: "cannot be both excluded and scaled to zero",
		},
		{
			name: "unknown inventory field is rejected",
			content: `{
  "schema": "pipelock-receipt-producer-inventory-v1",
  "org_id": "org-example", "fleet_id": "production",
  "producers": [{"instance_id": "current", "desired_replicas": 1}],
  "skip_missing": true
}`,
			want: "unknown field",
		},
		{
			name: "missing desired replicas cannot become scaled zero",
			content: `{
  "schema": "pipelock-receipt-producer-inventory-v1",
  "org_id": "org-example", "fleet_id": "production",
  "producers": [{"instance_id": "current"}]
}`,
			want: "desired_replicas is required",
		},
		{
			name: "org and fleet are required",
			content: `{
  "schema": "pipelock-receipt-producer-inventory-v1",
  "producers": [{"instance_id": "current", "desired_replicas": 1}]
}`,
			want: "org_id and fleet_id are required",
		},
		{
			name: "producers cannot be empty",
			content: `{
  "schema": "pipelock-receipt-producer-inventory-v1",
  "org_id": "org-example", "fleet_id": "production", "producers": []
}`,
			want: "producers must not be empty",
		},
		{
			name: "producer ID is required",
			content: `{
  "schema": "pipelock-receipt-producer-inventory-v1",
  "org_id": "org-example", "fleet_id": "production",
  "producers": [{"instance_id": " ", "desired_replicas": 1}]
}`,
			want: "instance_id is required",
		},
		{
			name: "negative replica count is rejected",
			content: `{
  "schema": "pipelock-receipt-producer-inventory-v1",
  "org_id": "org-example", "fleet_id": "production",
  "producers": [{"instance_id": "current", "desired_replicas": -1}]
}`,
			want: "must not be negative",
		},
		{
			name: "duplicate producer IDs are rejected",
			content: `{
  "schema": "pipelock-receipt-producer-inventory-v1",
  "org_id": "org-example", "fleet_id": "production",
  "producers": [{"instance_id": "current", "desired_replicas": 1}, {"instance_id": "current", "desired_replicas": 1}]
}`,
			want: "duplicate producer",
		},
		{
			name: "duplicate root producers key is rejected",
			content: `{
  "schema": "pipelock-receipt-producer-inventory-v1",
  "org_id": "org-example", "fleet_id": "production",
  "producers": [{"instance_id": "current", "desired_replicas": 1}],
  "producers": [{"instance_id": "scaled-zero", "desired_replicas": 0}]
}`,
			want: "duplicate JSON key \"producers\"",
		},
		{
			name: "duplicate desired replicas key is rejected",
			content: `{
  "schema": "pipelock-receipt-producer-inventory-v1",
  "org_id": "org-example", "fleet_id": "production",
  "producers": [{"instance_id": "current", "desired_replicas": 1, "desired_replicas": 0}]
}`,
			want: "duplicate JSON key \"desired_replicas\"",
		},
		{
			name: "duplicate excluded key is rejected",
			content: `{
  "schema": "pipelock-receipt-producer-inventory-v1",
  "org_id": "org-example", "fleet_id": "production",
  "producers": [{"instance_id": "current", "desired_replicas": 1, "excluded": false, "excluded": true}]
}`,
			want: "duplicate JSON key \"excluded\"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "receipt-producers.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			_, err := readReceiptProducerInventory(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("read error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestReadReceiptProducerInventory_RejectsMalformedTrailingAndOversize(t *testing.T) {
	dir := t.TempDir()
	valid := `{"schema":"pipelock-receipt-producer-inventory-v1","org_id":"org-example","fleet_id":"production","producers":[{"instance_id":"current","desired_replicas":1}]}`
	tests := []struct {
		name    string
		content []byte
		want    string
	}{
		{name: "malformed JSON", content: []byte(`{"schema":`), want: "decode --inventory"},
		{name: "trailing JSON", content: []byte(valid + `{}`), want: "trailing JSON"},
		{name: "wrong schema", content: []byte(`{"schema":"unknown","org_id":"org-example","fleet_id":"production","producers":[{"instance_id":"current","desired_replicas":1}]}`), want: "schema must be"},
		{name: "oversize", content: []byte(strings.Repeat("x", maxReceiptInventoryBytes+1)), want: "exceeds"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".json")
			if err := os.WriteFile(path, tc.content, 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			_, err := readReceiptProducerInventory(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("read error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestReadReceiptProducerInventory_RejectsMissingAndNonRegularPaths(t *testing.T) {
	if _, err := readReceiptProducerInventory(""); err == nil || !strings.Contains(err.Error(), "--inventory is required") {
		t.Fatalf("empty inventory error = %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing.json")
	if _, err := readReceiptProducerInventory(missing); err == nil || !strings.Contains(err.Error(), "read --inventory") {
		t.Fatalf("missing inventory error = %v", err)
	}
	dir := t.TempDir()
	if _, err := readReceiptProducerInventory(dir); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory inventory error = %v", err)
	}
}

func TestRequireCurrentDelivery_AlertsAndExits(t *testing.T) {
	err := requireCurrentDelivery(convergence.DeliveryHealth{
		Expected: 3,
		Current:  1,
		Alerting: []string{"missing", "stale"},
	})
	if !errors.Is(err, ErrReceiptDeliveryUnhealthy) {
		t.Fatalf("error = %v, want ErrReceiptDeliveryUnhealthy", err)
	}
	for _, want := range []string{"1 of 3 expected", "missing", "stale"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want %q", err, want)
		}
	}
	if err := requireCurrentDelivery(convergence.DeliveryHealth{Expected: 2, Current: 2}); err != nil {
		t.Fatalf("healthy delivery error = %v, want nil", err)
	}
}
