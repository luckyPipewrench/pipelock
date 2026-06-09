//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	proofSessionID   = "bootstrap-proof"
	proofEntryType   = "bootstrap_demo"
	proofTransport   = "bootstrap"
	enrollTokenID    = "bootstrap-enroll-1"
	enrollTokenTTL   = 5 * time.Minute
	proofHTTPTimeout = 20 * time.Second
	proofReadyTries  = 50
	proofReadyDelay  = 20 * time.Millisecond
)

// ProofResult records what the live round-trip proved. Every field is evidence
// the operator (or a test) can assert against: a real Conductor accepted a
// real follower's signed audit batch over mTLS, and that batch verified offline
// with the existing verifier.
type ProofResult struct {
	ConductorAddr      string
	EnrolledAuditKeyID string
	BatchID            string
	EnvelopeHash       string
	SeqStart           uint64
	SeqEnd             uint64
	EventCount         uint64
	IngestStatus       int
	QueriedBack        bool
	OfflineVerified    bool
	BatchPath          string
}

// runProof stands up one Conductor and one follower in-process and proves a
// signed audit-batch round-trip end to end over mTLS, then verifies the batch
// offline with the existing verifier. It tears everything down before
// returning; the persisted material is what the operator runs for real.
func runProof(ctx context.Context, layout Layout, opts Options, identity controlplane.FollowerIdentity, material *materialSet) (*ProofResult, error) {
	// The proof runs against an ephemeral scratch root, never the persisted
	// operator dirs. This keeps Run idempotent and — critically — keeps the
	// proof's one-shot enrollment and audit state out of the Conductor storage
	// and follower queue the operator will run for real (a persisted proof
	// enrollment would mark the instance active and block the operator's own
	// follower from enrolling).
	scratch, err := os.MkdirTemp(layout.Dir, ".proof-")
	if err != nil {
		return nil, fmt.Errorf("create proof scratch dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()

	srv, err := startConductor(ctx, filepath.Join(scratch, "conductor"), opts, material)
	if err != nil {
		return nil, err
	}
	defer srv.shutdown()

	client := newFollowerHTTPClient(material, opts.ListenHost)
	caller := &proofCaller{client: client, baseURL: "https://" + srv.addr}

	if err := caller.awaitCapabilities(ctx); err != nil {
		return nil, fmt.Errorf("capability handshake: %w", err)
	}

	auditPub, ok := material.auditKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("follower audit key has no ed25519 public key")
	}
	if err := caller.enroll(ctx, opts, identity, material.adminToken, auditPub); err != nil {
		return nil, fmt.Errorf("follower enrollment: %w", err)
	}

	batch, err := produceSignedBatch(ctx, filepath.Join(scratch, "queue"), filepath.Join(scratch, "recorder"), opts, identity, material.auditKey, auditPub)
	if err != nil {
		return nil, fmt.Errorf("produce signed audit batch: %w", err)
	}

	status, ingestResp, err := caller.ingestBatch(ctx, batch)
	if err != nil {
		return nil, fmt.Errorf("audit batch ingest: %w", err)
	}
	if status != http.StatusAccepted {
		return nil, fmt.Errorf("audit batch ingest returned status %d, want 202", status)
	}

	queried, err := caller.queryBatch(ctx, identity, material.auditorToken, batch.Envelope.BatchID)
	if err != nil {
		return nil, fmt.Errorf("audit batch query-back: %w", err)
	}

	if err := verifyBatchOffline(batch.Envelope, auditPub); err != nil {
		return nil, fmt.Errorf("offline audit-batch verification: %w", err)
	}

	if err := persistBatch(layout.AuditBatchPath, batch); err != nil {
		return nil, err
	}

	return &ProofResult{
		ConductorAddr:      srv.addr,
		EnrolledAuditKeyID: auditKeyID,
		BatchID:            batch.Envelope.BatchID,
		EnvelopeHash:       ingestResp.EnvelopeHash,
		SeqStart:           batch.Envelope.SeqStart,
		SeqEnd:             batch.Envelope.SeqEnd,
		EventCount:         batch.Envelope.EventCount,
		IngestStatus:       status,
		QueriedBack:        queried,
		OfflineVerified:    true,
		BatchPath:          layout.AuditBatchPath,
	}, nil
}

// verifyBatchOffline is done-state #2: the signed batch verifies with the
// existing verifier (AuditBatchEnvelope.VerifySignaturesAt) against the
// follower audit public key, with no running Conductor in the loop.
func verifyBatchOffline(envelope conductorcore.AuditBatchEnvelope, auditPub ed25519.PublicKey) error {
	resolve := func(signerKeyID string) (conductorcore.SignatureKey, error) {
		if signerKeyID != auditKeyID {
			return conductorcore.SignatureKey{}, conductorcore.ErrSignatureVerification
		}
		return conductorcore.SignatureKey{
			PublicKey:  auditPub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		}, nil
	}
	return envelope.VerifySignaturesAt(time.Now().UTC(), resolve)
}

// --- in-process Conductor -----------------------------------------------

type conductorServer struct {
	httpServer *http.Server
	listener   net.Listener
	addr       string
	auditStore *controlplane.SQLiteAuditStore
	closers    []func() error
}

func (s *conductorServer) shutdown() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.httpServer.Shutdown(shutdownCtx)
	for _, c := range s.closers {
		_ = c()
	}
}

func startConductor(ctx context.Context, storageDir string, opts Options, material *materialSet) (*conductorServer, error) {
	if err := os.MkdirAll(storageDir, dirPerm); err != nil {
		return nil, fmt.Errorf("create proof storage dir: %w", err)
	}
	store, err := controlplane.OpenFileBundleStore(filepath.Join(storageDir, "policy-bundles"))
	if err != nil {
		return nil, fmt.Errorf("open bundle store: %w", err)
	}
	auditStore, err := controlplane.OpenSQLiteAuditStore(ctx, filepath.Join(storageDir, "audit.db"))
	if err != nil {
		return nil, fmt.Errorf("open audit store: %w", err)
	}
	enrollments, err := controlplane.OpenFileEnrollmentStore(filepath.Join(storageDir, "enrollments.json"))
	if err != nil {
		_ = auditStore.Close()
		return nil, fmt.Errorf("open enrollment store: %w", err)
	}
	identityResolver, err := controlplane.MTLSFollowerIdentityResolver(opts.TrustDomain)
	if err != nil {
		_ = auditStore.Close()
		return nil, err
	}
	publisherAuth, err := controlplane.BearerPublisherAuthorizer(material.publisherToken)
	if err != nil {
		_ = auditStore.Close()
		return nil, err
	}
	bundleAuth, err := controlplane.ScopedBearerBundleAuthorizer([]controlplane.ScopedBearerCredential{
		{Token: material.publisherToken, Role: controlplane.RolePublisher},
	})
	if err != nil {
		_ = auditStore.Close()
		return nil, err
	}
	auditQueryAuth, err := controlplane.ScopedBearerAuditQueryAuthorizer([]controlplane.ScopedBearerCredential{
		{Token: material.auditorToken, Role: controlplane.RoleAuditor},
		{Token: material.adminToken, Role: controlplane.RoleAdmin},
	})
	if err != nil {
		_ = auditStore.Close()
		return nil, err
	}
	adminAuth, err := controlplane.ScopedBearerAdminAuthorizer([]controlplane.ScopedBearerCredential{
		{Token: material.adminToken, Role: controlplane.RoleAdmin},
	})
	if err != nil {
		_ = auditStore.Close()
		return nil, err
	}

	handler, err := controlplane.NewHandler(controlplane.HandlerOptions{
		Store:               store,
		Capabilities:        controlplane.DefaultCapabilities(opts.ConductorID),
		FollowerIdentity:    identityResolver,
		AuthorizePublisher:  publisherAuth,
		AuthorizeBundle:     bundleAuth,
		AuthorizeAuditQuery: auditQueryAuth,
		AuthorizeAdmin:      adminAuth,
		AuditSink:           auditStore,
		AuditKeys:           controlplane.CompositeAuditKeyResolver(enrollments, nil),
		Enrollments:         enrollments,
		Metrics:             metrics.New(),
	})
	if err != nil {
		_ = auditStore.Close()
		return nil, fmt.Errorf("build conductor handler: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(material.caCert)
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{material.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(opts.ListenHost, "0"))
	if err != nil {
		_ = auditStore.Close()
		return nil, fmt.Errorf("bind conductor listener: %w", err)
	}
	httpServer := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    64 * 1024,
	}
	go func() { _ = httpServer.ServeTLS(listener, "", "") }()

	return &conductorServer{
		httpServer: httpServer,
		listener:   listener,
		addr:       listener.Addr().String(),
		auditStore: auditStore,
		closers:    []func() error{auditStore.Close},
	}, nil
}

func newFollowerHTTPClient(material *materialSet, serverName string) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(material.caCert)
	return &http.Client{
		Timeout: proofHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{material.clientCert},
				RootCAs:      pool,
				ServerName:   serverName,
			},
		},
	}
}

// --- producing a real signed audit batch --------------------------------

func produceSignedBatch(ctx context.Context, queueDir, recorderDir string, opts Options, identity controlplane.FollowerIdentity, auditKey ed25519.PrivateKey, auditPub ed25519.PublicKey) (auditbatcher.Batch, error) {
	// Fail closed on a cancelled bootstrap: do not produce or persist audit
	// material once the operator has aborted. The recorder/producer are not
	// context-aware, so this entry check is the cancellation gate.
	if err := ctx.Err(); err != nil {
		return auditbatcher.Batch{}, err
	}
	queue, err := auditbatcher.Open(auditbatcher.Config{
		Dir:             queueDir,
		MaxPayloadBytes: conductorcore.MaxAuditPayloadBytes,
	})
	if err != nil {
		return auditbatcher.Batch{}, fmt.Errorf("open audit queue: %w", err)
	}
	// Release the queue's single-writer lock when the bootstrap proof completes,
	// so a repeated bootstrap (same process, same queue dir) does not fail with
	// ErrQueueLocked.
	defer func() { _ = queue.Close() }()
	producer, err := auditbatcher.NewProducer(auditbatcher.ProducerConfig{
		Queue:             queue,
		OrgID:             identity.OrgID,
		FleetID:           identity.FleetID,
		InstanceID:        identity.InstanceID,
		AuditSignerKeyID:  auditKeyID,
		RecorderKeyID:     recorderKeyID,
		AuditSigner:       auditKey,
		RecorderPublicKey: auditPub,
		Now:               opts.Now,
	})
	if err != nil {
		return auditbatcher.Batch{}, fmt.Errorf("create audit producer: %w", err)
	}

	rec, err := recorder.New(recorder.Config{
		Enabled:         true,
		Dir:             recorderDir,
		SignCheckpoints: true,
		Redact:          false,
		FileMode:        filePerm,
	}, nil, auditKey)
	if err != nil {
		_ = producer.Close()
		return auditbatcher.Batch{}, fmt.Errorf("create flight recorder: %w", err)
	}
	rec.SetObserver(producer)

	// Two real, hash-chained evidence entries; Close() emits the signed
	// checkpoint that the producer turns into a signed audit batch.
	for i := range 2 {
		if err := rec.Record(recorder.Entry{
			SessionID: proofSessionID,
			Type:      proofEntryType,
			Transport: proofTransport,
			Summary:   fmt.Sprintf("dev fleet bootstrap proof entry %d", i+1),
			Detail:    map[string]string{"note": "bootstrap round-trip proof", "fleet": identity.FleetID},
		}); err != nil {
			_ = rec.Close()
			_ = producer.Close()
			return auditbatcher.Batch{}, fmt.Errorf("record proof entry: %w", err)
		}
	}
	if err := rec.Close(); err != nil {
		_ = producer.Close()
		return auditbatcher.Batch{}, fmt.Errorf("close flight recorder: %w", err)
	}
	// Close drains the observer channel and processes the checkpoint segment.
	if err := producer.Close(); err != nil {
		return auditbatcher.Batch{}, fmt.Errorf("close audit producer: %w", err)
	}

	lease, err := queue.Claim()
	if err != nil {
		return auditbatcher.Batch{}, fmt.Errorf("claim signed batch from queue (%w): the recorder checkpoint did not produce a batch", err)
	}
	batch := lease.Batch
	// Ack so the durable queue does not retain the proof batch as pending; the
	// canonical copy is persisted to AuditBatchPath for the operator.
	if err := queue.Ack(lease.ID); err != nil {
		return auditbatcher.Batch{}, fmt.Errorf("ack proof batch: %w", err)
	}
	return batch, nil
}

func persistBatch(path string, batch auditbatcher.Batch) error {
	data, err := json.MarshalIndent(batch, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal proof batch: %w", err)
	}
	data = append(data, '\n')
	return writeFile(path, data)
}

// --- follower HTTP caller ------------------------------------------------

type proofCaller struct {
	client  *http.Client
	baseURL string
}

func (c *proofCaller) awaitCapabilities(ctx context.Context) error {
	var lastErr error
	for range proofReadyTries {
		resp, err := c.do(ctx, http.MethodGet, conductorcore.CapabilitiesPath, "", nil)
		if err != nil {
			lastErr = err
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(proofReadyDelay):
			}
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("capabilities status %d: %s", resp.StatusCode, snippet(body))
		}
		var caps conductorcore.CapabilitiesResponse
		if err := json.Unmarshal(body, &caps); err != nil {
			return fmt.Errorf("decode capabilities: %w", err)
		}
		if err := caps.Validate(); err != nil {
			return fmt.Errorf("conductor advertised invalid capabilities: %w", err)
		}
		return nil
	}
	return fmt.Errorf("conductor never became ready: %w", lastErr)
}

func (c *proofCaller) enroll(ctx context.Context, opts Options, identity controlplane.FollowerIdentity, adminToken string, auditPub ed25519.PublicKey) error {
	tokenReq := map[string]any{
		"token_id":    enrollTokenID,
		"org_id":      identity.OrgID,
		"fleet_id":    identity.FleetID,
		"instance_id": identity.InstanceID,
		"environment": identity.Environment,
		"expires_at":  opts.Now().UTC().Add(enrollTokenTTL),
	}
	resp, err := c.do(ctx, http.MethodPost, controlplane.EnrollmentTokensPath, adminToken, tokenReq)
	if err != nil {
		return err
	}
	tokenBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create enrollment token status %d: %s", resp.StatusCode, snippet(tokenBody))
	}
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(tokenBody, &issued); err != nil {
		return fmt.Errorf("decode enrollment token: %w", err)
	}
	if issued.Token == "" {
		return errors.New("conductor returned an empty enrollment token")
	}

	enrollReq := map[string]any{
		"token":            issued.Token,
		"audit_key_id":     auditKeyID,
		"audit_public_key": signing.EncodePublicKey(auditPub),
	}
	enrollResp, err := c.do(ctx, http.MethodPost, controlplane.EnrollPath, "", enrollReq)
	if err != nil {
		return err
	}
	enrollBody, _ := io.ReadAll(io.LimitReader(enrollResp.Body, 1<<16))
	_ = enrollResp.Body.Close()
	if enrollResp.StatusCode != http.StatusCreated {
		return fmt.Errorf("enroll status %d: %s", enrollResp.StatusCode, snippet(enrollBody))
	}
	return nil
}

func (c *proofCaller) ingestBatch(ctx context.Context, batch auditbatcher.Batch) (int, ingestResponse, error) {
	body := map[string]any{
		"envelope": batch.Envelope,
		"payload":  batch.Payload,
	}
	resp, err := c.do(ctx, http.MethodPost, conductorcore.AuditBatchesPath, "", body)
	if err != nil {
		return 0, ingestResponse{}, err
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return resp.StatusCode, ingestResponse{}, fmt.Errorf("ingest rejected: %s", snippet(raw))
	}
	var out ingestResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return resp.StatusCode, ingestResponse{}, fmt.Errorf("decode ingest response: %w", err)
	}
	return resp.StatusCode, out, nil
}

func (c *proofCaller) queryBatch(ctx context.Context, identity controlplane.FollowerIdentity, auditorToken, batchID string) (bool, error) {
	path := fmt.Sprintf("%s?org_id=%s&fleet_id=%s", conductorcore.AuditBatchesPath, identity.OrgID, identity.FleetID)
	resp, err := c.do(ctx, http.MethodGet, path, auditorToken, nil)
	if err != nil {
		return false, err
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("audit query status %d: %s", resp.StatusCode, snippet(raw))
	}
	// The metadata-only query returns the accepted batch summaries; the proof
	// batch must appear by id.
	if !bytes.Contains(raw, []byte(batchID)) {
		return false, fmt.Errorf("queried audit batches do not include proof batch %q", batchID)
	}
	return true, nil
}

func (c *proofCaller) do(ctx context.Context, method, path, bearer string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return c.client.Do(req)
}

type ingestResponse struct {
	BatchID      string    `json:"batch_id"`
	EnvelopeHash string    `json:"envelope_hash"`
	SeqStart     uint64    `json:"seq_start"`
	SeqEnd       uint64    `json:"seq_end"`
	AcceptedAt   time.Time `json:"accepted_at"`
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	const maxLen = 256
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return s
}
