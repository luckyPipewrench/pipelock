//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/convergence"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/securefile"
)

const (
	receiptProducerInventorySchema = "pipelock-receipt-producer-inventory-v1"
	maxReceiptInventoryBytes       = 1 << 20
	maxReceiptInventoryProducers   = ReadClientFollowerLimitMax - 1
	maxConcurrentAuditBatchReads   = 8
)

var ErrReceiptDeliveryUnhealthy = errors.New("expected receipt producer delivery is unhealthy")

type fleetConvergenceOptions struct {
	client         clientOptions
	inventory      string
	staleAfter     time.Duration
	requireCurrent bool
}

type receiptProducerInventory struct {
	Schema    string                  `json:"schema"`
	OrgID     string                  `json:"org_id"`
	FleetID   string                  `json:"fleet_id"`
	Producers []receiptProducerIntent `json:"producers"`
}

// receiptProducerIntent uses a pointer for desired_replicas so an omitted
// value cannot silently become the scaled-zero exception. Every producer must
// explicitly declare whether it is expected (a positive value) or scaled down
// (zero).
type receiptProducerIntent struct {
	InstanceID      string `json:"instance_id"`
	DesiredReplicas *int   `json:"desired_replicas"`
	DesiredDigest   string `json:"desired_digest,omitempty"`
	Excluded        bool   `json:"excluded,omitempty"`
	ExcludedOwner   string `json:"excluded_owner,omitempty"`
	ExcludedReason  string `json:"excluded_reason,omitempty"`
}

func (inventory receiptProducerInventory) deploymentIntents() []convergence.DeploymentIntent {
	intents := make([]convergence.DeploymentIntent, 0, len(inventory.Producers))
	for _, producer := range inventory.Producers {
		intents = append(intents, convergence.DeploymentIntent{
			InstanceID:      producer.InstanceID,
			DesiredReplicas: *producer.DesiredReplicas,
			DesiredDigest:   producer.DesiredDigest,
			Excluded:        producer.Excluded,
			ExcludedOwner:   producer.ExcludedOwner,
			ExcludedReason:  producer.ExcludedReason,
		})
	}
	return intents
}

// auditBatchListResponse mirrors the metadata-only audit-query response. The
// control-plane response is deliberately private to its HTTP package, while
// this client needs its typed form to retain one latest accepted batch per
// expected producer.
type auditBatchListResponse struct {
	Batches []controlplane.AuditBatchSummary `json:"batches"`
	Count   int                              `json:"count"`
}

func fleetConvergenceCmd() *cobra.Command {
	opts := fleetConvergenceOptions{staleAfter: 5 * time.Minute, requireCurrent: true}
	cmd := &cobra.Command{
		Use:          "convergence",
		Short:        "Check expected receipt-producer delivery",
		SilenceUsage: true,
		Long: `Join the operator-owned receipt-producer inventory with Conductor
runtime status and the latest accepted signed audit batch for each producer.

The JSON report retains the four convergence denominators and adds an explicit
delivery health summary. Expected producers without a recent accepted batch
appear in delivery_health.alerting. Enrollment, runtime health, and bundle
drift remain separate report fields. Local-only and scaled-zero entries stay
visible but do not count as delivery failures.

The command exits nonzero by default when an expected producer has no current
accepted batch. Set --require-current=false only when collecting a diagnostic
snapshot during remediation.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.client.licenseCRLFile}); err != nil {
				return err
			}
			return runFleetConvergence(cmd, opts)
		},
	}
	opts.client.bindFlags(cmd)
	cmd.Flags().StringVar(&opts.inventory, "inventory", "", "path to receipt-producer inventory JSON (required)")
	cmd.Flags().DurationVar(&opts.staleAfter, "stale-after", opts.staleAfter, "maximum runtime-status age before evidence freshness is treated as stale")
	cmd.Flags().BoolVar(&opts.requireCurrent, "require-current", opts.requireCurrent, "exit nonzero when an expected producer has no current accepted signed batch")
	return cmd
}

func runFleetConvergence(cmd *cobra.Command, opts fleetConvergenceOptions) error {
	if opts.staleAfter <= 0 {
		return errors.New("--stale-after must be positive")
	}
	if opts.staleAfter > convergence.MaxEvidenceStaleAfter() {
		return fmt.Errorf("--stale-after must not exceed %s", convergence.MaxEvidenceStaleAfter())
	}
	inventory, err := readReceiptProducerInventory(opts.inventory)
	if err != nil {
		return err
	}
	client, err := newConductorClient(opts.client)
	if err != nil {
		return err
	}
	statuses, err := fetchConvergenceFollowers(cmd.Context(), client, inventory)
	if err != nil {
		return err
	}
	// Use one reference time for the complete audit-batch snapshot. Sampling it
	// after sequential reads would make the first response look older merely
	// because later requests took time to finish.
	reportNow := time.Now().UTC()
	batches, err := fetchExpectedLatestBatches(cmd.Context(), client, inventory)
	if err != nil {
		return err
	}
	report := convergence.Build(convergence.Inputs{
		OrgID:        inventory.OrgID,
		FleetID:      inventory.FleetID,
		Now:          reportNow,
		Intents:      inventory.deploymentIntents(),
		FleetStatus:  statuses,
		AuditBatches: batches,
		StaleAfter:   opts.staleAfter,
	})
	if err := writeConvergenceReport(cmd.OutOrStdout(), report); err != nil {
		return err
	}
	if opts.requireCurrent {
		return requireCurrentDelivery(report.DeliveryHealth)
	}
	return nil
}

func readReceiptProducerInventory(path string) (receiptProducerInventory, error) {
	if strings.TrimSpace(path) == "" {
		return receiptProducerInventory{}, errors.New("--inventory is required")
	}
	clean := filepath.Clean(path)
	data, err := securefile.Read(clean, securefile.Options{MaxBytes: maxReceiptInventoryBytes})
	if err != nil {
		return receiptProducerInventory{}, fmt.Errorf("read --inventory: %w", err)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return receiptProducerInventory{}, fmt.Errorf("decode --inventory: %w", err)
	}
	var inventory receiptProducerInventory
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&inventory); err != nil {
		return receiptProducerInventory{}, fmt.Errorf("decode --inventory: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receiptProducerInventory{}, errors.New("decode --inventory: trailing JSON")
	}
	if err := validateReceiptProducerInventory(inventory); err != nil {
		return receiptProducerInventory{}, err
	}
	return inventory, nil
}

// rejectDuplicateJSONKeys rejects ambiguous JSON before decoding it into the
// inventory schema. encoding/json otherwise accepts repeated object members
// and silently retains the last value.
func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	return rejectDuplicateJSONValue(dec)
}

func rejectDuplicateJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := rejectDuplicateJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := rejectDuplicateJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func validateReceiptProducerInventory(inventory receiptProducerInventory) error {
	if inventory.Schema != receiptProducerInventorySchema {
		return fmt.Errorf("--inventory schema must be %q", receiptProducerInventorySchema)
	}
	if strings.TrimSpace(inventory.OrgID) == "" || strings.TrimSpace(inventory.FleetID) == "" {
		return errors.New("--inventory org_id and fleet_id are required")
	}
	if len(inventory.Producers) == 0 {
		return errors.New("--inventory producers must not be empty")
	}
	if len(inventory.Producers) > maxReceiptInventoryProducers {
		return fmt.Errorf("--inventory producers exceeds supported report limit of %d", maxReceiptInventoryProducers)
	}
	seen := make(map[string]struct{}, len(inventory.Producers))
	for _, producer := range inventory.Producers {
		if strings.TrimSpace(producer.InstanceID) == "" {
			return errors.New("--inventory producer instance_id is required")
		}
		if producer.DesiredReplicas == nil {
			return fmt.Errorf("--inventory producer %q desired_replicas is required", producer.InstanceID)
		}
		if *producer.DesiredReplicas < 0 {
			return fmt.Errorf("--inventory producer %q desired_replicas must not be negative", producer.InstanceID)
		}
		if _, ok := seen[producer.InstanceID]; ok {
			return fmt.Errorf("--inventory contains duplicate producer %q", producer.InstanceID)
		}
		seen[producer.InstanceID] = struct{}{}
		if producer.Excluded {
			if strings.TrimSpace(producer.ExcludedOwner) == "" || strings.TrimSpace(producer.ExcludedReason) == "" {
				return fmt.Errorf("--inventory local-only producer %q requires excluded_owner and excluded_reason", producer.InstanceID)
			}
			if *producer.DesiredReplicas == 0 {
				return fmt.Errorf("--inventory producer %q cannot be both excluded and scaled to zero", producer.InstanceID)
			}
		}
	}
	return nil
}

func fetchConvergenceFollowers(ctx context.Context, client *conductorClient, inventory receiptProducerInventory) ([]controlplane.FollowerFleetStatus, error) {
	params := map[string]string{
		"org_id":   inventory.OrgID,
		"fleet_id": inventory.FleetID,
		"limit":    fmt.Sprintf("%d", ReadClientFollowerLimitMax),
	}
	body, err := client.getJSON(ctx, controlplane.FollowersPath+encodeQuery(params))
	if err != nil {
		return nil, fmt.Errorf("read Conductor followers: %w", err)
	}
	var response followersResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("decode Conductor followers: %w", err)
	}
	// The extra row is a truncation sentinel: this endpoint has no cursor, so
	// treating a full response as complete could falsely report an expected
	// producer unenrolled. Refuse the report instead of guessing.
	if len(response.Followers) >= ReadClientFollowerLimitMax {
		return nil, fmt.Errorf("read Conductor followers: roster exceeds the supported report limit of %d", ReadClientFollowerLimitMax-1)
	}
	return response.Followers, nil
}

func fetchExpectedLatestBatches(ctx context.Context, client *conductorClient, inventory receiptProducerInventory) ([]controlplane.AuditBatchSummary, error) {
	producers := make([]receiptProducerIntent, 0, len(inventory.Producers))
	for _, producer := range inventory.Producers {
		if producer.Excluded || *producer.DesiredReplicas == 0 {
			continue
		}
		producers = append(producers, producer)
	}
	if len(producers) == 0 {
		return nil, nil
	}
	type result struct {
		batch *controlplane.AuditBatchSummary
		err   error
	}
	results := make([]result, len(producers))
	jobs := make(chan int)
	workers := min(maxConcurrentAuditBatchReads, len(producers))
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				producer := producers[index]
				params := map[string]string{"org_id": inventory.OrgID, "fleet_id": inventory.FleetID, "instance_id": producer.InstanceID, "limit": "1"}
				requestCtx, cancel := context.WithTimeout(ctx, clientHTTPTimeout)
				body, err := client.getJSON(requestCtx, controlplane.AuditBatchesPath+encodeQuery(params))
				cancel()
				if err != nil {
					results[index].err = fmt.Errorf("read latest audit batch for %q: %w", producer.InstanceID, err)
					continue
				}
				var response auditBatchListResponse
				if err := json.Unmarshal(body, &response); err != nil {
					results[index].err = fmt.Errorf("decode latest audit batch for %q: %w", producer.InstanceID, err)
					continue
				}
				if len(response.Batches) > 0 {
					results[index].batch = &response.Batches[0]
				}
			}
		}()
	}
	for index := range producers {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, fmt.Errorf("read latest audit batches: %w", ctx.Err())
		}
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("read latest audit batches: %w", ctx.Err())
	}
	batches := make([]controlplane.AuditBatchSummary, 0, len(producers))
	for _, result := range results {
		if result.err != nil {
			return nil, result.err
		}
		if result.batch != nil {
			batches = append(batches, *result.batch)
		}
	}
	return batches, nil
}

func writeConvergenceReport(out io.Writer, report convergence.Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal convergence report: %w", err)
	}
	if _, err := fmt.Fprintln(out, string(data)); err != nil {
		return fmt.Errorf("write convergence report: %w", err)
	}
	return nil
}

func requireCurrentDelivery(health convergence.DeliveryHealth) error {
	if len(health.Alerting) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %d of %d expected producer(s) current; alerting: %s",
		ErrReceiptDeliveryUnhealthy, health.Current, health.Expected, strings.Join(health.Alerting, ", "))
}
