//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	defaultProducerBuffer = 4096

	actionReceiptEntryType = "action_receipt"
	checkpointEntryType    = "checkpoint"

	producerDropChannelFull       = "producer_channel_full"
	producerDropEnqueueError      = "enqueue_error"
	producerDropInvalidCheckpoint = "invalid_checkpoint"
	producerDropPayloadTooLarge   = "payload_too_large"
	producerDropQueueFull         = "queue_full"
	producerDropSequenceGap       = "producer_sequence_gap"
	producerDropShutdownPartial   = "shutdown_without_checkpoint"
)

// Producer observes locally written recorder entries and turns checkpoint
// spans into signed Conductor audit batches. It is intentionally outside
// emit.Emitter: enqueue failures need durable drop accounting rather than
// fire-and-forget sink behavior.
type Producer struct {
	queue               *Queue
	metrics             MetricsSink
	orgID               string
	fleetID             string
	instanceID          string
	auditSignerKeyID    string
	recorderKeyID       string
	followerPubHex      string
	auditSigner         ed25519.PrivateKey
	now                 func() time.Time
	entries             chan recorder.Entry
	done                chan struct{}
	closeOnce           sync.Once
	sendMu              sync.RWMutex
	closed              atomic.Bool
	dropMu              sync.Mutex
	dropped             map[string]uint64
	previousSegmentTail string
}

type ProducerConfig struct {
	Queue             *Queue
	Metrics           MetricsSink
	OrgID             string
	FleetID           string
	InstanceID        string
	AuditSignerKeyID  string
	RecorderKeyID     string
	AuditSigner       ed25519.PrivateKey
	RecorderPublicKey ed25519.PublicKey
	BufferSize        int
	Now               func() time.Time
}

func NewProducer(cfg ProducerConfig) (*Producer, error) {
	if cfg.Queue == nil {
		return nil, errors.New("auditbatcher: producer queue required")
	}
	if len(cfg.AuditSigner) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("auditbatcher: producer private key length=%d want=%d", len(cfg.AuditSigner), ed25519.PrivateKeySize)
	}
	if len(cfg.RecorderPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("auditbatcher: recorder public key length=%d want=%d", len(cfg.RecorderPublicKey), ed25519.PublicKeySize)
	}
	for _, id := range []struct {
		field string
		value string
	}{
		{field: "org_id", value: cfg.OrgID},
		{field: "fleet_id", value: cfg.FleetID},
		{field: "instance_id", value: cfg.InstanceID},
		{field: "audit_signer_key_id", value: cfg.AuditSignerKeyID},
		{field: "recorder_key_id", value: cfg.RecorderKeyID},
	} {
		if err := validateProducerIdentifier(id.field, id.value); err != nil {
			return nil, err
		}
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = defaultProducerBuffer
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	p := &Producer{
		queue:            cfg.Queue,
		metrics:          cfg.Metrics,
		orgID:            cfg.OrgID,
		fleetID:          cfg.FleetID,
		instanceID:       cfg.InstanceID,
		auditSignerKeyID: cfg.AuditSignerKeyID,
		recorderKeyID:    cfg.RecorderKeyID,
		followerPubHex:   hex.EncodeToString(cfg.RecorderPublicKey),
		auditSigner:      append(ed25519.PrivateKey(nil), cfg.AuditSigner...),
		now:              cfg.Now,
		entries:          make(chan recorder.Entry, cfg.BufferSize),
		done:             make(chan struct{}),
		dropped:          map[string]uint64{},
	}
	go p.run()
	return p, nil
}

// ObserveRecorderEntry accepts a post-flush recorder entry without blocking
// enforcement. If the producer falls behind, dropped action receipts are
// accounted in the next successfully enqueued signed batch.
func (p *Producer) ObserveRecorderEntry(entry recorder.Entry) {
	if p == nil || p.closed.Load() {
		return
	}
	p.sendMu.RLock()
	defer p.sendMu.RUnlock()
	if p.closed.Load() {
		return
	}
	select {
	case p.entries <- entry:
	default:
		p.drop(producerDropChannelFull, droppedActionReceiptCount([]recorder.Entry{entry}))
	}
}

func (p *Producer) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.sendMu.Lock()
		defer p.sendMu.Unlock()
		p.closed.Store(true)
		close(p.entries)
		<-p.done
	})
	return nil
}

func (p *Producer) run() {
	defer close(p.done)
	var pending []recorder.Entry
	for entry := range p.entries {
		if entry.Version != recorder.EntryVersion {
			p.drop(producerDropInvalidCheckpoint, droppedActionReceiptCount([]recorder.Entry{entry}))
			continue
		}
		if len(pending) > 0 && entry.Sequence != pending[len(pending)-1].Sequence+1 {
			p.drop(producerDropSequenceGap, droppedActionReceiptCount(pending))
			pending = nil
		}
		pending = append(pending, entry)
		if entry.Type != checkpointEntryType {
			continue
		}
		// enqueueSegment records its own drop accounting and metrics at
		// each failure site, so the returned error is informational only.
		_ = p.enqueueSegment(pending)
		pending = nil
	}
	if len(pending) > 0 {
		p.drop(producerDropShutdownPartial, droppedActionReceiptCount(pending))
	}
}

func (p *Producer) enqueueSegment(entries []recorder.Entry) error {
	if len(entries) == 0 {
		return nil
	}
	checkpoint := entries[len(entries)-1]
	if checkpoint.Type != checkpointEntryType {
		return nil
	}
	// The recorder committed this checkpoint to its local hash chain before
	// we observed it, so advance the chain tail unconditionally - even on a
	// drop. The next segment's PreviousSegmentTail must reflect the true
	// local chain; drops are accounted separately in DroppedAccounting. If a
	// drop path left the tail un-advanced, the next segment would claim
	// continuity across a checkpoint the recorder actually wrote, and a
	// verifier replaying the local recorder file would reject the chain.
	defer func() { p.previousSegmentTail = checkpoint.Hash }()

	droppedActions := droppedActionReceiptCount(entries)
	cp, err := checkpointDetail(checkpoint)
	if err != nil {
		p.drop(producerDropInvalidCheckpoint, droppedActions)
		return fmt.Errorf("%s: %w", producerDropInvalidCheckpoint, err)
	}
	payload, err := marshalEntriesJSONL(entries)
	if err != nil {
		p.drop(producerDropEnqueueError, droppedActions)
		return fmt.Errorf("%s: %w", producerDropEnqueueError, err)
	}
	if len(payload) > conductor.MaxAuditPayloadBytes {
		p.drop(producerDropPayloadTooLarge, droppedActions)
		return fmt.Errorf("%s: payload=%d max=%d", producerDropPayloadTooLarge, len(payload), conductor.MaxAuditPayloadBytes)
	}
	includedDrops := p.droppedAccounting()
	envelope := p.envelope(entries, checkpoint, cp, payload, includedDrops)
	signed, err := SignEnvelope(envelope, p.auditSignerKeyID, p.auditSigner)
	if err != nil {
		p.drop(producerDropEnqueueError, droppedActions)
		return fmt.Errorf("%s: %w", producerDropEnqueueError, err)
	}
	if _, err := p.queue.Enqueue(Batch{Envelope: signed, Payload: payload}); err != nil {
		reason := producerDropEnqueueError
		if errors.Is(err, ErrQueueFull) {
			reason = producerDropQueueFull
		}
		p.drop(reason, droppedActions)
		return fmt.Errorf("%s: %w", reason, err)
	}
	p.releaseDropped(includedDrops)
	p.recordQueue()
	return nil
}

func (p *Producer) envelope(entries []recorder.Entry, checkpoint recorder.Entry, cp recorder.CheckpointDetail, payload []byte, dropped conductor.DroppedAccounting) conductor.AuditBatchEnvelope {
	sum := sha256.Sum256(payload)
	return conductor.AuditBatchEnvelope{
		SchemaVersion:      conductor.SchemaVersion,
		BatchID:            p.nextBatchID(),
		OrgID:              p.orgID,
		FleetID:            p.fleetID,
		InstanceID:         p.instanceID,
		AuditSchemaVersion: recorder.EntryVersion,
		EmittedAt:          p.now().UTC(),
		SeqStart:           entries[0].Sequence,
		SeqEnd:             checkpoint.Sequence,
		EventCount:         uint64(len(entries)),
		PayloadSHA256:      hex.EncodeToString(sum[:]),
		PayloadBytes:       uint64(len(payload)),
		Dropped:            dropped,
		Chain: conductor.EvidenceChain{
			EntryVersion:           recorder.EntryVersion,
			SegmentID:              segmentID(entries[0].SessionID, entries[0].Sequence, checkpoint.Sequence),
			SeqStart:               entries[0].Sequence,
			SeqEnd:                 checkpoint.Sequence,
			PreviousSegmentTail:    p.previousSegmentTail,
			SegmentHeadHash:        entries[0].Hash,
			SegmentTailHash:        checkpoint.Hash,
			CheckpointSeq:          checkpoint.Sequence,
			CheckpointHash:         checkpoint.Hash,
			CheckpointSignature:    ed25519SignatureString(cp.Signature),
			CheckpointSignerKeyID:  p.recorderKeyID,
			FollowerRecorderKeyID:  p.recorderKeyID,
			FollowerRecorderPubHex: p.followerPubHex,
		},
	}
}

func (p *Producer) nextBatchID() string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Sprintf("audit-%020d", p.now().UTC().UnixNano())
	}
	return fmt.Sprintf("audit-%020d-%s", p.now().UTC().UnixNano(), hex.EncodeToString(random[:]))
}

func droppedActionReceiptCount(entries []recorder.Entry) uint64 {
	var count uint64
	for _, entry := range entries {
		if entry.Type == actionReceiptEntryType {
			count++
		}
	}
	return count
}

// drop records a dropped action-receipt count in one place: the in-memory
// accounting that feeds the next envelope's DroppedAccounting AND the
// Prometheus drop metric. Keeping them together prevents the map and the metric
// from ever disagreeing on the reason label.
func (p *Producer) drop(reason string, count uint64) {
	if count == 0 {
		return
	}
	p.addDropped(reason, count)
	p.recordDropMetric(reason)
}

func (p *Producer) addDropped(reason string, count uint64) {
	if count == 0 {
		return
	}
	reason = normalizeAccountingReason(reason)
	p.dropMu.Lock()
	defer p.dropMu.Unlock()
	p.dropped[reason] += count
}

func (p *Producer) droppedAccounting() conductor.DroppedAccounting {
	p.dropMu.Lock()
	defer p.dropMu.Unlock()
	if len(p.dropped) == 0 {
		return conductor.DroppedAccounting{}
	}
	reasons := make([]string, 0, len(p.dropped))
	for reason := range p.dropped {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	out := conductor.DroppedAccounting{Reasons: make([]conductor.DroppedReason, 0, len(reasons))}
	for _, reason := range reasons {
		count := p.dropped[reason]
		out.Count += count
		out.Reasons = append(out.Reasons, conductor.DroppedReason{Reason: reason, Count: count})
	}
	return out
}

func (p *Producer) releaseDropped(included conductor.DroppedAccounting) {
	if included.Count == 0 {
		return
	}
	p.dropMu.Lock()
	defer p.dropMu.Unlock()
	for _, reason := range included.Reasons {
		current := p.dropped[reason.Reason]
		if current <= reason.Count {
			delete(p.dropped, reason.Reason)
			continue
		}
		p.dropped[reason.Reason] = current - reason.Count
	}
}

func (p *Producer) recordQueue() {
	if p.metrics == nil {
		return
	}
	stats, err := p.queue.Stats()
	if err == nil {
		p.metrics.RecordConductorAuditQueue(stats)
	}
}

func (p *Producer) recordDropMetric(reason string) {
	if p.metrics != nil {
		p.metrics.RecordConductorAuditDelivery(deliveryOutcomeDrop, normalizeAccountingReason(reason))
	}
}

func marshalEntriesJSONL(entries []recorder.Entry) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, entry := range entries {
		if err := enc.Encode(entry); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func checkpointDetail(entry recorder.Entry) (recorder.CheckpointDetail, error) {
	data, err := json.Marshal(entry.Detail)
	if err != nil {
		return recorder.CheckpointDetail{}, err
	}
	var detail recorder.CheckpointDetail
	if err := json.Unmarshal(data, &detail); err != nil {
		return recorder.CheckpointDetail{}, err
	}
	if strings.TrimSpace(detail.Signature) == "" {
		return recorder.CheckpointDetail{}, errors.New("checkpoint signature required")
	}
	return detail, nil
}

func ed25519SignatureString(hexSig string) string {
	if strings.HasPrefix(hexSig, conductor.SignaturePrefixEd25519) {
		return hexSig
	}
	return conductor.SignaturePrefixEd25519 + hexSig
}

func segmentID(sessionID string, start, end uint64) string {
	if sessionID == "" {
		sessionID = "recorder"
	}
	return fmt.Sprintf("segment-%s-%020d-%020d", safeSegmentPart(sessionID), start, end)
}

func safeSegmentPart(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '_' || r == '-' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "recorder"
	}
	return b.String()
}

func validateProducerIdentifier(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("auditbatcher: producer %s required", field)
	}
	if len(value) > conductor.MaxIDBytes {
		return fmt.Errorf("auditbatcher: producer %s length=%d max=%d", field, len(value), conductor.MaxIDBytes)
	}
	for i, r := range value {
		if r != '_' && r != '-' && r != '.' && (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return fmt.Errorf("auditbatcher: producer %s contains invalid character %q", field, r)
		}
		if i == 0 && (r == '_' || r == '-' || r == '.') {
			return fmt.Errorf("auditbatcher: producer %s must start with an ASCII letter or digit", field)
		}
	}
	return nil
}
