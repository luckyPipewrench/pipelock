// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	listTierKey1       = "a|10.0.0.1"
	listTierKey2       = "b|10.0.0.2"
	listTierKey3       = "c|10.0.0.3"
	listTierAuthHeader = "Bearer " + testSessionAPIToken
)

func TestParseTierFilter(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{"empty means no filter", "", "", false},
		{"none literal", "none", config.AirlockTierNone, false},
		{"normal alias", "normal", config.AirlockTierNone, false},
		{"soft", "soft", config.AirlockTierSoft, false},
		{"hard", "hard", config.AirlockTierHard, false},
		{"drain", "drain", config.AirlockTierDrain, false},
		{"invalid tier rejected", "unknown", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTierFilter(tt.raw)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTierMatches(t *testing.T) {
	// Empty snapshot tier normalizes to "none".
	if !tierMatches("", config.AirlockTierNone) {
		t.Error("empty tier should match none filter")
	}
	if tierMatches("", config.AirlockTierHard) {
		t.Error("empty tier should NOT match hard filter")
	}
	if !tierMatches(config.AirlockTierHard, config.AirlockTierHard) {
		t.Error("hard should match hard")
	}
}

func TestSessionAPI_HandleList_TierFilter(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sess1 := sm.GetOrCreate(listTierKey1)
	sess2 := sm.GetOrCreate(listTierKey2)
	_ = sm.GetOrCreate(listTierKey3) // stays at none
	_, _, _ = sess1.Airlock().SetTier(config.AirlockTierHard)
	_, _, _ = sess2.Airlock().SetTier(config.AirlockTierSoft)

	handler := newTestSessionAPIHandler(t, sm)

	tests := []struct {
		name       string
		query      string
		wantCount  int
		wantStatus int
	}{
		{"no filter returns all", "", 3, http.StatusOK},
		{"hard filter returns 1", "?tier=hard", 1, http.StatusOK},
		{"soft filter returns 1", "?tier=soft", 1, http.StatusOK},
		{"none filter returns 1", "?tier=none", 1, http.StatusOK},
		{"normal alias", "?tier=normal", 1, http.StatusOK},
		{"drain filter returns 0", "?tier=drain", 0, http.StatusOK},
		{"invalid tier 400", "?tier=moist", 0, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions"+tt.query, nil)
			req.Header.Set("Authorization", listTierAuthHeader)
			w := httptest.NewRecorder()
			handler.HandleList(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status: got %d, want %d; body=%s", w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantStatus != http.StatusOK {
				return
			}
			var resp struct {
				Sessions []SessionSnapshot `json:"sessions"`
				Count    int               `json:"count"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Count != tt.wantCount {
				t.Errorf("count: got %d, want %d (sessions=%+v)", resp.Count, tt.wantCount, resp.Sessions)
			}
		})
	}
}
