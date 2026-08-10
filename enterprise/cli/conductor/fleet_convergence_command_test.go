//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/convergence"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/spf13/cobra"
)

const (
	convergenceTestOrg   = "org-example"
	convergenceTestFleet = "production"
	convergenceTestToken = "auditor-token"
)

type convergenceCommandServer struct {
	followers []controlplane.FollowerFleetStatus
	batches   map[string][]controlplane.AuditBatchSummary

	followersStatus int
	followersBody   string
	auditStatus     map[string]int
	auditBody       map[string]string
	auditBarrierAt  int
	auditBarrierHit chan struct{}
	auditRelease    chan struct{}

	mu             sync.Mutex
	requests       int
	auditCalls     map[string]int
	activeAudit    int
	maxActiveAudit int
}

func (s *convergenceCommandServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests++
	s.mu.Unlock()
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "mTLS client certificate required", http.StatusForbidden)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+convergenceTestToken {
		http.Error(w, "auditor bearer token required", http.StatusForbidden)
		return
	}
	if r.URL.Query().Get("org_id") != convergenceTestOrg || r.URL.Query().Get("fleet_id") != convergenceTestFleet {
		http.Error(w, "unexpected query scope", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case controlplane.FollowersPath:
		if s.followersStatus != 0 {
			http.Error(w, "synthetic followers failure", s.followersStatus)
			return
		}
		if s.followersBody != "" {
			_, _ = io.WriteString(w, s.followersBody)
			return
		}
		_ = json.NewEncoder(w).Encode(followersResponse{Followers: s.followers, Count: len(s.followers)})
	case controlplane.AuditBatchesPath:
		instanceID := r.URL.Query().Get("instance_id")
		s.mu.Lock()
		if s.auditCalls == nil {
			s.auditCalls = make(map[string]int)
		}
		s.auditCalls[instanceID]++
		s.activeAudit++
		if s.activeAudit > s.maxActiveAudit {
			s.maxActiveAudit = s.activeAudit
		}
		barrierAt := s.auditBarrierAt
		barrierHit := s.auditBarrierHit
		release := s.auditRelease
		if barrierAt > 0 && barrierHit != nil && s.activeAudit == barrierAt {
			close(barrierHit)
		}
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			s.activeAudit--
			s.mu.Unlock()
		}()
		if release != nil {
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		if status := s.auditStatus[instanceID]; status != 0 {
			http.Error(w, "synthetic audit failure", status)
			return
		}
		if body := s.auditBody[instanceID]; body != "" {
			_, _ = io.WriteString(w, body)
			return
		}
		batches := s.batches[instanceID]
		_ = json.NewEncoder(w).Encode(auditBatchListResponse{Batches: batches, Count: len(batches)})
	default:
		http.NotFound(w, r)
	}
}

func (s *convergenceCommandServer) requestedAuditBatches(instanceID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auditCalls[instanceID]
}

func (s *convergenceCommandServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func (s *convergenceCommandServer) maxConcurrentAuditRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxActiveAudit
}

func TestFleetConvergenceCommand_NoLicenseFailsBeforeNetwork(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	t.Setenv(license.EnvLicenseIntermediateFile, "")
	t.Setenv(license.EnvLicenseRequireIntermediate, "")
	server := &convergenceCommandServer{}
	client := newTestClientServer(t, convergenceTestToken, server)
	inventory := writeConvergenceInventory(t, `[{"instance_id":"current","desired_replicas":1}]`)

	_, err := executeFleetConvergence(t, client, inventory)
	if !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("fleet convergence without license error = %v, want ErrFleetLicenseRequired", err)
	}
	if got := server.requestCount(); got != 0 {
		t.Fatalf("network requests before license gate = %d, want 0", got)
	}
}

func TestFleetConvergenceCommand_HealthyExclusionsDoNotAlert(t *testing.T) {
	installFleetLicense(t)
	now := time.Now().UTC()
	server := &convergenceCommandServer{
		followers: []controlplane.FollowerFleetStatus{
			healthyConvergenceFollower("current"),
		},
		batches: map[string][]controlplane.AuditBatchSummary{
			"current": {convergenceBatch("current", now.Add(-time.Minute), now.Add(-2*time.Minute))},
		},
	}
	client := newTestClientServer(t, convergenceTestToken, server)
	inventory := writeConvergenceInventory(t, `[
  {"instance_id":"current","desired_replicas":1},
  {"instance_id":"local-only","desired_replicas":1,"excluded":true,"excluded_owner":"platform","excluded_reason":"local development proxy"},
  {"instance_id":"scaled-zero","desired_replicas":0}
]`)

	output, err := executeFleetConvergence(t, client, inventory)
	if err != nil {
		t.Fatalf("fleet convergence healthy run: %v", err)
	}
	report := decodeConvergenceReport(t, output)
	if report.DeliveryHealth.Expected != 1 || report.DeliveryHealth.Current != 1 || len(report.DeliveryHealth.Alerting) != 0 {
		t.Fatalf("delivery health = %+v, want one current producer and no alert", report.DeliveryHealth)
	}
	current := findConvergenceFollower(t, report, "current")
	if current.LatestBatch == nil || current.LatestBatch.SignerKeyID != "audit-key-current" || current.LatestBatch.RuntimeBuild != "3.4.1" {
		t.Fatalf("current latest batch = %+v, want signed batch and runtime build", current.LatestBatch)
	}
	if findConvergenceFollower(t, report, "local-only").State != convergence.StateExcluded {
		t.Fatal("local-only producer was not reported as excluded")
	}
	if findConvergenceFollower(t, report, "scaled-zero").State != convergence.StateScaledZero {
		t.Fatal("scaled-zero producer was not reported as scaled_zero")
	}
	if got := server.requestedAuditBatches("current"); got != 1 {
		t.Fatalf("current audit queries = %d, want 1", got)
	}
	for _, instanceID := range []string{"local-only", "scaled-zero"} {
		if got := server.requestedAuditBatches(instanceID); got != 0 {
			t.Fatalf("%s audit queries = %d, want 0", instanceID, got)
		}
	}
}

func TestFleetConvergenceCommand_MissingAndStaleExitNonzero(t *testing.T) {
	installFleetLicense(t)
	now := time.Now().UTC()
	server := &convergenceCommandServer{
		followers: []controlplane.FollowerFleetStatus{
			healthyConvergenceFollower("current"),
			healthyConvergenceFollower("missing"),
			healthyConvergenceFollower("stale"),
		},
		batches: map[string][]controlplane.AuditBatchSummary{
			"current": {convergenceBatch("current", now.Add(-time.Minute), now.Add(-2*time.Minute))},
			"stale":   {convergenceBatch("stale", now.Add(-31*time.Minute), now.Add(-32*time.Minute))},
		},
	}
	client := newTestClientServer(t, convergenceTestToken, server)
	inventory := writeConvergenceInventory(t, `[
  {"instance_id":"current","desired_replicas":1},
  {"instance_id":"missing","desired_replicas":1},
  {"instance_id":"stale","desired_replicas":1},
  {"instance_id":"local-only","desired_replicas":1,"excluded":true,"excluded_owner":"platform","excluded_reason":"local development proxy"},
  {"instance_id":"scaled-zero","desired_replicas":0}
]`)

	output, err := executeFleetConvergence(t, client, inventory)
	if !errors.Is(err, ErrReceiptDeliveryUnhealthy) {
		t.Fatalf("fleet convergence error = %v, want ErrReceiptDeliveryUnhealthy", err)
	}
	report := decodeConvergenceReport(t, output)
	if report.DeliveryHealth.Expected != 3 || report.DeliveryHealth.Current != 1 {
		t.Fatalf("delivery health = %+v, want one of three current", report.DeliveryHealth)
	}
	if got, want := report.DeliveryHealth.Alerting, []string{"missing", "stale"}; !equalStringSlices(got, want) {
		t.Fatalf("alerting = %v, want %v", got, want)
	}
	if got := findConvergenceFollower(t, report, "missing").State; got != convergence.StateCurrentWithoutBatch {
		t.Fatalf("missing state = %q, want %q", got, convergence.StateCurrentWithoutBatch)
	}
	if got := findConvergenceFollower(t, report, "stale").State; got != convergence.StateStale {
		t.Fatalf("stale state = %q, want %q", got, convergence.StateStale)
	}
	for _, instanceID := range []string{"current", "missing", "stale"} {
		if got := server.requestedAuditBatches(instanceID); got != 1 {
			t.Fatalf("%s audit queries = %d, want 1", instanceID, got)
		}
	}
	for _, instanceID := range []string{"local-only", "scaled-zero"} {
		if got := server.requestedAuditBatches(instanceID); got != 0 {
			t.Fatalf("%s audit queries = %d, want 0", instanceID, got)
		}
	}
}

func TestRunFleetConvergence_FailsClosedOnClientAndAPIErrors(t *testing.T) {
	inventory := writeConvergenceInventory(t, `[{"instance_id":"current","desired_replicas":1}]`)
	t.Run("inventory producer limit fails before network", func(t *testing.T) {
		server := &convergenceCommandServer{}
		client := newTestClientServer(t, convergenceTestToken, server)
		producers := "[" + strings.TrimSuffix(strings.Repeat(`{"instance_id":"too-many","desired_replicas":1},`, maxReceiptInventoryProducers+1), ",") + "]"
		tooMany := writeConvergenceInventory(t, producers)

		err := runFleetConvergenceDirect(t, client, tooMany, true, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "supported report limit") {
			t.Fatalf("error = %v, want producer-limit refusal", err)
		}
		if got := server.requestCount(); got != 0 {
			t.Fatalf("network requests = %d, want none before inventory limit refusal", got)
		}
	})

	t.Run("nonpositive stale after", func(t *testing.T) {
		err := runFleetConvergence(&cobra.Command{}, fleetConvergenceOptions{staleAfter: 0})
		if err == nil || !strings.Contains(err.Error(), "--stale-after") {
			t.Fatalf("error = %v, want stale-after validation", err)
		}
	})

	t.Run("overflowing stale after", func(t *testing.T) {
		err := runFleetConvergence(&cobra.Command{}, fleetConvergenceOptions{
			staleAfter: convergence.MaxEvidenceStaleAfter() + time.Nanosecond,
		})
		if err == nil || !strings.Contains(err.Error(), "--stale-after") {
			t.Fatalf("error = %v, want stale-after overflow validation", err)
		}
	})

	t.Run("client setup failure", func(t *testing.T) {
		err := runFleetConvergence(&cobra.Command{}, fleetConvergenceOptions{
			inventory:  inventory,
			staleAfter: time.Minute,
		})
		if err == nil || !strings.Contains(err.Error(), "--server is required") {
			t.Fatalf("error = %v, want client setup failure", err)
		}
	})

	fullRoster := make([]controlplane.FollowerFleetStatus, ReadClientFollowerLimitMax)
	tests := []struct {
		name   string
		server *convergenceCommandServer
		want   string
	}{
		{
			name:   "followers HTTP error",
			server: &convergenceCommandServer{followersStatus: http.StatusBadGateway},
			want:   "read Conductor followers",
		},
		{
			name:   "followers malformed JSON",
			server: &convergenceCommandServer{followersBody: "{"},
			want:   "decode Conductor followers",
		},
		{
			name:   "followers roster truncation",
			server: &convergenceCommandServer{followers: fullRoster},
			want:   "roster exceeds the supported report limit",
		},
		{
			name: "audit HTTP error",
			server: &convergenceCommandServer{
				followers:   []controlplane.FollowerFleetStatus{healthyConvergenceFollower("current")},
				auditStatus: map[string]int{"current": http.StatusBadGateway},
			},
			want: "read latest audit batch",
		},
		{
			name: "audit malformed JSON",
			server: &convergenceCommandServer{
				followers: []controlplane.FollowerFleetStatus{healthyConvergenceFollower("current")},
				auditBody: map[string]string{"current": "{"},
			},
			want: "decode latest audit batch",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := newTestClientServer(t, convergenceTestToken, tc.server)
			err := runFleetConvergenceDirect(t, client, inventory, false, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFetchExpectedLatestBatches_BoundsConcurrencyAndHonorsCancellation(t *testing.T) {
	release := make(chan struct{})
	server := &convergenceCommandServer{
		auditBarrierAt:  maxConcurrentAuditBatchReads,
		auditBarrierHit: make(chan struct{}),
		auditRelease:    release,
	}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	clientOpts := newTestClientServer(t, convergenceTestToken, server)
	client, err := newConductorClient(clientOpts)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	replicas := 1
	inventory := receiptProducerInventory{OrgID: convergenceTestOrg, FleetID: convergenceTestFleet}
	for index := range 2 * maxConcurrentAuditBatchReads {
		inventory.Producers = append(inventory.Producers, receiptProducerIntent{InstanceID: fmt.Sprintf("current-%d", index), DesiredReplicas: &replicas})
	}
	result := make(chan error, 1)
	go func() {
		_, err := fetchExpectedLatestBatches(context.Background(), client, inventory)
		result <- err
	}()
	select {
	case <-server.auditBarrierHit:
	case <-time.After(time.Second):
		t.Fatal("audit reads did not reach the concurrency barrier")
	}
	if got := server.maxConcurrentAuditRequests(); got != maxConcurrentAuditBatchReads {
		t.Fatalf("maximum concurrent audit requests = %d, want %d", got, maxConcurrentAuditBatchReads)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("fetch batches: %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fetchExpectedLatestBatches(canceled, client, inventory); err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled fetch error = %v, want context cancellation", err)
	}
}

func TestRunFleetConvergence_ReturnsWriteError(t *testing.T) {
	now := time.Now().UTC()
	server := &convergenceCommandServer{
		followers: []controlplane.FollowerFleetStatus{healthyConvergenceFollower("current")},
		batches: map[string][]controlplane.AuditBatchSummary{
			"current": {convergenceBatch("current", now.Add(-time.Minute), now.Add(-2*time.Minute))},
		},
	}
	client := newTestClientServer(t, convergenceTestToken, server)
	inventory := writeConvergenceInventory(t, `[{"instance_id":"current","desired_replicas":1}]`)

	err := runFleetConvergenceDirect(t, client, inventory, false, failingWriter{})
	if err == nil || !strings.Contains(err.Error(), "write convergence report") {
		t.Fatalf("error = %v, want write convergence report", err)
	}
}

func TestRunFleetConvergence_InventoryErrorAndDiagnosticMode(t *testing.T) {
	t.Run("inventory read error", func(t *testing.T) {
		err := runFleetConvergence(&cobra.Command{}, fleetConvergenceOptions{
			inventory:  filepath.Join(t.TempDir(), "missing.json"),
			staleAfter: time.Minute,
		})
		if err == nil || !strings.Contains(err.Error(), "read --inventory") {
			t.Fatalf("error = %v, want inventory read error", err)
		}
	})

	t.Run("diagnostic mode reports unhealthy state without nonzero exit", func(t *testing.T) {
		server := &convergenceCommandServer{
			followers: []controlplane.FollowerFleetStatus{healthyConvergenceFollower("missing")},
			batches:   map[string][]controlplane.AuditBatchSummary{},
		}
		client := newTestClientServer(t, convergenceTestToken, server)
		inventory := writeConvergenceInventory(t, `[{"instance_id":"missing","desired_replicas":1}]`)
		var output bytes.Buffer

		if err := runFleetConvergenceDirect(t, client, inventory, false, &output); err != nil {
			t.Fatalf("diagnostic convergence run: %v", err)
		}
		report := decodeConvergenceReport(t, output.Bytes())
		if report.DeliveryHealth.Expected != 1 || report.DeliveryHealth.Current != 0 || len(report.DeliveryHealth.Alerting) != 1 {
			t.Fatalf("diagnostic delivery health = %+v, want one alerting missing producer", report.DeliveryHealth)
		}
	})
}

func healthyConvergenceFollower(instanceID string) controlplane.FollowerFleetStatus {
	return controlplane.FollowerFleetStatus{
		FollowerSummary: controlplane.FollowerSummary{InstanceID: instanceID, Active: true},
		Health:          controlplane.FleetHealthOK,
		RuntimeStatus:   &controlplane.FollowerRuntimeStatus{PipelockVersion: "3.4.1"},
	}
}

func convergenceBatch(instanceID string, receivedAt, emittedAt time.Time) controlplane.AuditBatchSummary {
	return controlplane.AuditBatchSummary{
		BatchID:         "batch-" + instanceID,
		InstanceID:      instanceID,
		AuditSchema:     1,
		SeqStart:        11,
		SeqEnd:          20,
		DroppedCount:    2,
		SignatureKeyIDs: []string{"audit-key-" + instanceID},
		ReceivedAt:      receivedAt,
		EmittedAt:       emittedAt,
	}
}

func writeConvergenceInventory(t *testing.T, producers string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "receipt-producers.json")
	body := `{
  "schema":"pipelock-receipt-producer-inventory-v1",
  "org_id":"org-example",
  "fleet_id":"production",
  "producers":` + producers + `
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	return path
}

func executeFleetConvergence(t *testing.T, client clientOptions, inventory string) ([]byte, error) {
	t.Helper()
	cmd := fleetConvergenceCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--inventory", inventory,
		"--server", client.server,
		"--ca-file", client.caFile,
		"--client-cert", client.clientCertFile,
		"--client-key", client.clientKeyFile,
		"--token-file", client.tokenFile,
		"--server-name", client.serverName,
	})
	err := cmd.Execute()
	return output.Bytes(), err
}

func runFleetConvergenceDirect(t *testing.T, client clientOptions, inventory string, requireCurrent bool, out io.Writer) error {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(out)
	return runFleetConvergence(cmd, fleetConvergenceOptions{
		client:         client,
		inventory:      inventory,
		staleAfter:     time.Minute,
		requireCurrent: requireCurrent,
	})
}

func decodeConvergenceReport(t *testing.T, output []byte) convergence.Report {
	t.Helper()
	var report convergence.Report
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatalf("decode convergence output: %v\n%s", err, output)
	}
	return report
}

func findConvergenceFollower(t *testing.T, report convergence.Report, instanceID string) convergence.FollowerConvergence {
	t.Helper()
	for _, follower := range report.Followers {
		if follower.InstanceID == instanceID {
			return follower
		}
	}
	t.Fatalf("report has no follower %q: %+v", instanceID, report.Followers)
	return convergence.FollowerConvergence{}
}

func equalStringSlices(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
