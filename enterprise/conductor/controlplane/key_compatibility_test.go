//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// The committed record is published by the base revision's file store.
func TestCaseDistinctLabelsStoreUpgrade(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{"Team": "red", "team": "blue"}
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id: "case-distinct-labels", version: 1,
		audience: conductor.Audience{Labels: labels},
	})
	record, _, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	if output := os.Getenv("PIPELOCK_JSON_UPGRADE_FIXTURE"); output != "" {
		raw, err := os.ReadFile(filepath.Join(store.bundlesDir, record.BundleHash+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Clean(output), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, fromBase := range []bool{false, true} {
		dir := store.dir
		if fromBase {
			baseStore, err := OpenFileBundleStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile("testdata/case-distinct-labels.json")
			if err != nil {
				t.Fatal(err)
			}
			var base PublishedBundle
			if err := json.Unmarshal(raw, &base); err != nil {
				t.Fatal(err)
			}
			writeRawBundleRecordForTest(t, baseStore.bundlesDir, base)
			dir = baseStore.dir
		}
		reopened, err := OpenFileBundleStore(dir)
		if err != nil {
			t.Fatalf("reopen store (base=%v): %v", fromBase, err)
		}
		latest, err := reopened.Latest(t.Context(), FollowerIdentity{
			OrgID: "org-main", FleetID: "prod", InstanceID: "test-instance", Environment: "prod", Labels: labels,
		}, testNow)
		if err != nil {
			t.Fatal(err)
		}
		if latest.Bundle.Audience.Labels["Team"] != "red" || latest.Bundle.Audience.Labels["team"] != "blue" {
			t.Fatalf("labels did not round trip: %+v", latest.Bundle.Audience.Labels)
		}
	}
}
