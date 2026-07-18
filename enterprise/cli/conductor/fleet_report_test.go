//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestFleetReportCmdRegistered(t *testing.T) {
	cmd := fleetCmd()
	report, _, err := cmd.Find([]string{"report"})
	if err != nil {
		t.Fatalf("Find(report) error = %v", err)
	}
	if report == nil || report.Name() != "report" {
		t.Fatalf("Find(report) = %v", report)
	}
	for _, flag := range []string{"storage-dir", "org-id", "fleet-id", "from", "to", "signing-key", "out", "trusted-audit-key"} {
		if report.Flags().Lookup(flag) == nil {
			t.Fatalf("report flag %q not registered", flag)
		}
	}
}

func TestValidateFleetReportOptions(t *testing.T) {
	opts := fleetReportOptions{
		storageDir:  "/var/lib/pipelock/conductor",
		orgID:       "org-main",
		fleetID:     "prod",
		from:        "2026-06-13T00:00:00Z",
		to:          "2026-06-14T00:00:00Z",
		signingKey:  "/tmp/fleet-report.key",
		out:         "/tmp/fleet-receipt.dsse.json",
		conductorID: "conductor",
	}
	if err := validateFleetReportOptions(opts); err != nil {
		t.Fatalf("validateFleetReportOptions(valid) error = %v", err)
	}
	opts.limit = -1
	if err := validateFleetReportOptions(opts); err == nil || !strings.Contains(err.Error(), "--limit") {
		t.Fatalf("validateFleetReportOptions(negative limit) error = %v, want --limit", err)
	}
	opts.limit = 0
	opts.orgID = ""
	if err := validateFleetReportOptions(opts); err == nil || !strings.Contains(err.Error(), "--org-id") {
		t.Fatalf("validateFleetReportOptions(missing org) error = %v, want --org-id", err)
	}
}

func TestLoadFleetReportSigningKeyPurpose(t *testing.T) {
	dir := t.TempDir()
	_, reportPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(report): %v", err)
	}
	reportPath := writeFleetReportKeyFile(t, dir, "report.key", "report-key-1", signing.PurposeFleetReportSigning, reportPriv)
	keyID, gotPriv, err := loadFleetReportSigningKey(reportPath)
	if err != nil {
		t.Fatalf("loadFleetReportSigningKey() error = %v", err)
	}
	if keyID != "report-key-1" || len(gotPriv) != ed25519.PrivateKeySize {
		t.Fatalf("loadFleetReportSigningKey() = %q len=%d", keyID, len(gotPriv))
	}
	zeroizeKey(gotPriv)

	_, wrongPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(wrong): %v", err)
	}
	wrongPath := writeFleetReportKeyFile(t, dir, "wrong.key", "policy-key-1", signing.PurposePolicyBundleSigning, wrongPriv)
	if _, _, err := loadFleetReportSigningKey(wrongPath); err == nil || !strings.Contains(err.Error(), "wrong key purpose") {
		t.Fatalf("loadFleetReportSigningKey(wrong purpose) error = %v, want wrong key purpose", err)
	}
}

func TestLoadFleetReportSigningKeyRejectsMalformedFiles(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(report): %v", err)
	}
	otherPub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(other): %v", err)
	}
	base := publishKeyFile{
		SchemaVersion: keyFileSchemaVersion,
		Purpose:       signing.PurposeFleetReportSigning.String(),
		KeyID:         "report-key-1",
		Public:        hex.EncodeToString(pub),
		Private:       hex.EncodeToString(priv),
		CreatedAt:     "2026-06-13T00:00:00Z",
	}
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{name: "malformed json", content: `{"schema_version":`, want: "decode --signing-key"},
		{name: "trailing json", content: fleetReportKeyJSON(t, base) + `{}`, want: "trailing JSON"},
		{name: "wrong schema", content: fleetReportKeyJSON(t, withFleetReportKey(base, func(k *publishKeyFile) {
			k.SchemaVersion = keyFileSchemaVersion + 1
		})), want: "unsupported schema_version"},
		{name: "invalid purpose", content: fleetReportKeyJSON(t, withFleetReportKey(base, func(k *publishKeyFile) {
			k.Purpose = "not-a-real-purpose"
		})), want: "unknown key_purpose"},
		{name: "missing key id", content: fleetReportKeyJSON(t, withFleetReportKey(base, func(k *publishKeyFile) {
			k.KeyID = " "
		})), want: "missing key_id"},
		{name: "malformed public", content: fleetReportKeyJSON(t, withFleetReportKey(base, func(k *publishKeyFile) {
			k.Public = "zz"
		})), want: "malformed public key"},
		{name: "malformed private", content: fleetReportKeyJSON(t, withFleetReportKey(base, func(k *publishKeyFile) {
			k.Private = "zz"
		})), want: "malformed private key"},
		{name: "mismatched private", content: fleetReportKeyJSON(t, withFleetReportKey(base, func(k *publishKeyFile) {
			k.Public = hex.EncodeToString(otherPub)
		})), want: "private key does not match"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(c.name, " ", "-")+".key")
			if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
				t.Fatalf("WriteFile(key): %v", err)
			}
			if _, _, err := loadFleetReportSigningKey(path); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("loadFleetReportSigningKey() error = %v, want substring %q", err, c.want)
			}
		})
	}
	missing := filepath.Join(dir, "missing.key")
	if _, _, err := loadFleetReportSigningKey(missing); err == nil || !strings.Contains(err.Error(), "read --signing-key") {
		t.Fatalf("loadFleetReportSigningKey(missing) error = %v, want read error", err)
	}
}

func TestOpenFleetReportAuditStoreRequiresExistingDB(t *testing.T) {
	cmd := fleetReportCmd()
	_, err := openFleetReportAuditStore(cmd, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "stat Conductor audit store") {
		t.Fatalf("openFleetReportAuditStore(missing) error = %v, want stat error", err)
	}
}

func TestOpenFleetReportAuditStoreRejectsNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "audit.db"), 0o750); err != nil {
		t.Fatalf("Mkdir(audit.db): %v", err)
	}
	cmd := fleetReportCmd()
	_, err := openFleetReportAuditStore(cmd, dir)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("openFleetReportAuditStore(directory) error = %v, want not regular", err)
	}
}

func TestRunFleetReportRejectsInvalidInputs(t *testing.T) {
	dir := t.TempDir()
	_, reportPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(report) error = %v", err)
	}
	keyPath := writeFleetReportKeyFile(t, dir, "report.key", "report-key-1", signing.PurposeFleetReportSigning, reportPriv)
	base := fleetReportOptions{
		storageDir:  dir,
		orgID:       "org-main",
		fleetID:     "prod",
		from:        "2026-06-13T00:00:00Z",
		to:          "2026-06-13T01:00:00Z",
		signingKey:  keyPath,
		out:         filepath.Join(dir, "fleet-receipt.dsse.json"),
		conductorID: "conductor-1",
		limit:       10,
	}
	emptyStoreDir := t.TempDir()
	emptyStore, err := controlplane.OpenSQLiteAuditStore(context.Background(), filepath.Join(emptyStoreDir, "audit.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteAuditStore(empty) error = %v", err)
	}
	if err := emptyStore.Close(); err != nil {
		t.Fatalf("Close(empty store) error = %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*fleetReportOptions)
		want   string
	}{
		{name: "bad from", mutate: func(o *fleetReportOptions) { o.from = "not-rfc3339" }, want: "parse --from"},
		{name: "bad to", mutate: func(o *fleetReportOptions) { o.to = "not-rfc3339" }, want: "parse --to"},
		{name: "bad trusted audit key", mutate: func(o *fleetReportOptions) {
			o.trustedAuditKeys = []string{"id=audit-key-1,org=org-main"}
		}, want: "invalid --trusted-audit-key"},
		{name: "missing store", mutate: func(o *fleetReportOptions) {
			o.storageDir = filepath.Join(dir, "missing-store")
		}, want: "stat Conductor audit store"},
		{name: "no evidence", mutate: func(o *fleetReportOptions) {
			o.storageDir = emptyStoreDir
		}, want: "no audit-batch evidence"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := base
			c.mutate(&opts)
			cmd := fleetReportCmd()
			cmd.SetContext(context.Background())
			if err := runFleetReport(cmd, opts); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("runFleetReport() error = %v, want substring %q", err, c.want)
			}
		})
	}
}

func TestRunFleetReportWritesVerifiedEnvelope(t *testing.T) {
	dir := t.TempDir()
	store, err := controlplane.OpenSQLiteAuditStore(context.Background(), filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteAuditStore() error = %v", err)
	}
	auditPub, auditPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(audit) error = %v", err)
	}
	if _, err := store.IngestAuditBatch(context.Background(), cliTestAcceptedAuditBatch(t, auditPriv)); err != nil {
		t.Fatalf("IngestAuditBatch() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(store) error = %v", err)
	}

	reportPub, reportPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(report) error = %v", err)
	}
	keyPath := writeFleetReportKeyFile(t, dir, "report.key", "report-key-1", signing.PurposeFleetReportSigning, reportPriv)
	outPath := filepath.Join(dir, "fleet-receipt.dsse.json")

	cmd := fleetReportCmd()
	cmd.SetContext(context.Background())
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	err = runFleetReport(cmd, fleetReportOptions{
		storageDir:       dir,
		orgID:            "org-main",
		fleetID:          "prod",
		from:             "2026-06-13T00:00:00Z",
		to:               "2026-06-13T01:00:00Z",
		signingKey:       keyPath,
		out:              outPath,
		conductorID:      "conductor-1",
		trustedAuditKeys: []string{"id=audit-key-1,inline=" + hex.EncodeToString(auditPub) + ",org=org-main,fleet=prod,instance=pl-1"},
		limit:            10,
		conductorVersion: "v2.8.0-test",
		licenseCRLFile:   "",
		signingKeyID:     "override-report-key",
	})
	if err != nil {
		t.Fatalf("runFleetReport() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "fleet receipt report written") || !strings.Contains(stdout.String(), "total_actions: 1") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("Stat(out) error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("out mode = %v, want 0600", got)
	}
	raw, err := os.ReadFile(filepath.Clean(outPath)) //nolint:gosec // test reads the temp output path it just wrote
	if err != nil {
		t.Fatalf("ReadFile(out) error = %v", err)
	}
	var envelope fleetreceipt.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("Unmarshal(envelope) error = %v", err)
	}
	verified, err := fleetreceipt.VerifyEnvelope(envelope, map[string]ed25519.PublicKey{"override-report-key": reportPub})
	if err != nil {
		t.Fatalf("VerifyEnvelope() error = %v", err)
	}
	if verified.Statement.Predicate.ReportID == "" || verified.Statement.Predicate.Summary.TotalActions != 1 {
		t.Fatalf("verified predicate = %+v", verified.Statement.Predicate)
	}
}

func TestRunFleetReportStdoutRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := controlplane.OpenSQLiteAuditStore(context.Background(), filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteAuditStore() error = %v", err)
	}
	auditPub, auditPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(audit) error = %v", err)
	}
	if _, err := store.IngestAuditBatch(context.Background(), cliTestAcceptedAuditBatch(t, auditPriv)); err != nil {
		t.Fatalf("IngestAuditBatch() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(store) error = %v", err)
	}

	reportPub, reportPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(report) error = %v", err)
	}
	keyPath := writeFleetReportKeyFile(t, dir, "report.key", "report-key-1", signing.PurposeFleetReportSigning, reportPriv)

	cmd := fleetReportCmd()
	cmd.SetContext(context.Background())
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err = runFleetReport(cmd, fleetReportOptions{
		storageDir:       dir,
		orgID:            "org-main",
		fleetID:          "prod",
		from:             "2026-06-13T00:00:00Z",
		to:               "2026-06-13T01:00:00Z",
		signingKey:       keyPath,
		out:              "-",
		conductorID:      "conductor-1",
		trustedAuditKeys: []string{"id=audit-key-1,inline=" + hex.EncodeToString(auditPub) + ",org=org-main,fleet=prod,instance=pl-1"},
		limit:            10,
		signingKeyID:     "stdout-report-key",
	})
	if err != nil {
		t.Fatalf("runFleetReport(--out -) error = %v", err)
	}

	// stdout must be a clean DSSE envelope with no summary text mixed in;
	// the human-readable summary belongs on stderr.
	if strings.Contains(stdout.String(), "fleet receipt report written") {
		t.Fatalf("stdout leaked summary text: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "fleet receipt report written: <stdout>") || !strings.Contains(stderr.String(), "total_actions: 1") {
		t.Fatalf("stderr = %q", stderr.String())
	}

	envelopeBytes := stdout.Bytes()
	var envelope fleetreceipt.Envelope
	if err := json.Unmarshal(envelopeBytes, &envelope); err != nil {
		t.Fatalf("Unmarshal(stdout envelope) error = %v", err)
	}
	trusted := map[string]ed25519.PublicKey{"stdout-report-key": reportPub}
	verified, err := fleetreceipt.VerifyEnvelope(envelope, trusted)
	if err != nil {
		t.Fatalf("VerifyEnvelope(stdout) error = %v", err)
	}
	if verified.Statement.Predicate.Summary.TotalActions != 1 {
		t.Fatalf("verified predicate = %+v", verified.Statement.Predicate)
	}

	// Tamper one byte of the signed payload: verification must fail closed.
	tampered := envelope
	payloadRaw, err := base64.StdEncoding.DecodeString(tampered.Payload)
	if err != nil {
		t.Fatalf("DecodeString(payload) error = %v", err)
	}
	payloadRaw[0] ^= 0x01
	tampered.Payload = base64.StdEncoding.EncodeToString(payloadRaw)
	if _, err := fleetreceipt.VerifyEnvelope(tampered, trusted); err == nil {
		t.Fatal("VerifyEnvelope(tampered) succeeded, want fail-closed error")
	}
}

func TestWriteFleetReportEnvelopeToPropagatesWriterError(t *testing.T) {
	err := writeFleetReportEnvelopeTo(failingWriter{}, map[string]any{"ok": 1})
	if err == nil || !strings.Contains(err.Error(), "write fleet report to stdout") {
		t.Fatalf("writeFleetReportEnvelopeTo(failing writer) error = %v, want write error", err)
	}
	if err := writeFleetReportEnvelopeTo(&bytes.Buffer{}, map[string]any{"bad": make(chan int)}); err == nil ||
		!strings.Contains(err.Error(), "marshal fleet report envelope") {
		t.Fatalf("writeFleetReportEnvelopeTo(unmarshalable) error = %v, want marshal error", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("boom")
}

func TestRunFleetReportPropagatesWriteFailure(t *testing.T) {
	dir := t.TempDir()
	store, err := controlplane.OpenSQLiteAuditStore(context.Background(), filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteAuditStore() error = %v", err)
	}
	auditPub, auditPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(audit) error = %v", err)
	}
	if _, err := store.IngestAuditBatch(context.Background(), cliTestAcceptedAuditBatch(t, auditPriv)); err != nil {
		t.Fatalf("IngestAuditBatch() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(store) error = %v", err)
	}
	_, reportPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(report) error = %v", err)
	}
	keyPath := writeFleetReportKeyFile(t, dir, "report.key", "report-key-1", signing.PurposeFleetReportSigning, reportPriv)
	cmd := fleetReportCmd()
	cmd.SetContext(context.Background())
	err = runFleetReport(cmd, fleetReportOptions{
		storageDir:       dir,
		orgID:            "org-main",
		fleetID:          "prod",
		from:             "2026-06-13T00:00:00Z",
		to:               "2026-06-13T01:00:00Z",
		signingKey:       keyPath,
		out:              filepath.Join(dir, "missing", "fleet-receipt.dsse.json"),
		conductorID:      "conductor-1",
		trustedAuditKeys: []string{"id=audit-key-1,inline=" + hex.EncodeToString(auditPub) + ",org=org-main,fleet=prod,instance=pl-1"},
		limit:            10,
	})
	if err == nil || !strings.Contains(err.Error(), "write --out") {
		t.Fatalf("runFleetReport(write failure) error = %v, want write --out", err)
	}
}

func TestWriteFleetReportEnvelopeRejectsUnmarshalableEnvelope(t *testing.T) {
	err := writeFleetReportEnvelope(filepath.Join(t.TempDir(), "out.json"), map[string]any{"bad": make(chan int)})
	if err == nil || !strings.Contains(err.Error(), "marshal fleet report envelope") {
		t.Fatalf("writeFleetReportEnvelope(unmarshalable) error = %v, want marshal error", err)
	}
}

func writeFleetReportKeyFile(t *testing.T, dir, name, keyID string, purpose signing.KeyPurpose, priv ed25519.PrivateKey) string {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	data := `{
  "schema_version": 1,
  "purpose": "` + purpose.String() + `",
  "key_id": "` + keyID + `",
  "public": "` + hex.EncodeToString(pub) + `",
  "private": "` + hex.EncodeToString(priv) + `",
  "created_at": "2026-06-13T00:00:00Z"
}
`
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile(key): %v", err)
	}
	return path
}

func withFleetReportKey(k publishKeyFile, mutate func(*publishKeyFile)) publishKeyFile {
	mutate(&k)
	return k
}

func fleetReportKeyJSON(t *testing.T, k publishKeyFile) string {
	t.Helper()
	data, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("Marshal(key): %v", err)
	}
	return string(data)
}

func cliTestAcceptedAuditBatch(t *testing.T, auditPriv ed25519.PrivateKey) controlplane.AcceptedAuditBatch {
	t.Helper()
	now := time.Date(2026, 6, 13, 0, 15, 0, 0, time.UTC)
	rcpt := cliTestActionReceipt(t, now, auditPriv)
	entry := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  1,
		Timestamp: now,
		SessionID: "proxy",
		Type:      "action_receipt",
		EventKind: string(rcpt.ActionRecord.ActionType),
		Transport: rcpt.ActionRecord.Transport,
		Summary:   "receipt",
		Detail:    rcpt,
		PrevHash:  recorder.GenesisHash,
	}
	entry.Hash = recorder.ComputeHash(entry)
	checkpoint := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  2,
		Timestamp: now.Add(time.Second),
		SessionID: "proxy",
		Type:      "checkpoint",
		EventKind: "checkpoint",
		Transport: "recorder",
		Summary:   "checkpoint",
		Detail: recorder.CheckpointDetail{
			EntryCount: 2,
			FirstSeq:   1,
			LastSeq:    2,
			Signature:  strings.Repeat("1", ed25519.SignatureSize*2),
		},
		PrevHash: entry.Hash,
	}
	checkpoint.Hash = recorder.ComputeHash(checkpoint)

	payload := cliTestRecorderPayload(t, []recorder.Entry{entry, checkpoint})
	sum := sha256.Sum256(payload)
	envelope := conductorcore.AuditBatchEnvelope{
		SchemaVersion:      conductorcore.SchemaVersion,
		BatchID:            "audit-batch-1",
		OrgID:              "org-main",
		FleetID:            "prod",
		InstanceID:         "pl-1",
		AuditSchemaVersion: recorder.EntryVersion,
		EmittedAt:          now,
		SeqStart:           1,
		SeqEnd:             2,
		EventCount:         2,
		PayloadSHA256:      hex.EncodeToString(sum[:]),
		PayloadBytes:       uint64(len(payload)),
		Dropped:            conductorcore.DroppedAccounting{},
		Chain: conductorcore.EvidenceChain{
			EntryVersion:           recorder.EntryVersion,
			SegmentID:              "segment-audit-batch-1",
			SeqStart:               1,
			SeqEnd:                 2,
			SegmentHeadHash:        entry.Hash,
			SegmentTailHash:        checkpoint.Hash,
			CheckpointSeq:          2,
			CheckpointHash:         checkpoint.Hash,
			CheckpointSignature:    conductorcore.SignaturePrefixEd25519 + strings.Repeat("1", ed25519.SignatureSize*2),
			CheckpointSignerKeyID:  "recorder-key-1",
			FollowerRecorderKeyID:  "recorder-key-1",
			FollowerRecorderPubHex: strings.Repeat("2", ed25519.PublicKeySize*2),
		},
	}
	signed, err := auditbatcher.SignEnvelope(envelope, "audit-key-1", auditPriv)
	if err != nil {
		t.Fatalf("SignEnvelope() error = %v", err)
	}
	envelopeHash, err := signed.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash() error = %v", err)
	}
	return controlplane.AcceptedAuditBatch{
		Identity: controlplane.FollowerIdentity{
			OrgID:       "org-main",
			FleetID:     "prod",
			InstanceID:  "pl-1",
			Environment: "prod",
		},
		Envelope:     signed,
		EnvelopeHash: envelopeHash,
		Payload:      payload,
		ReceivedAt:   now.Add(time.Second),
	}
}

func cliTestActionReceipt(t *testing.T, now time.Time, priv ed25519.PrivateKey) receipt.Receipt {
	t.Helper()
	rcpt, err := receipt.Sign(receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        "action-1",
		ActionType:      receipt.ActionRead,
		Timestamp:       now,
		Principal:       "agent",
		Actor:           "agent",
		Target:          "https://example.com",
		SideEffectClass: receipt.SideEffectExternalRead,
		Reversibility:   receipt.ReversibilityFull,
		PolicyHash:      strings.Repeat("a", 64),
		Verdict:         "allow",
		Transport:       "fetch",
		Layer:           "url",
		Severity:        "low",
		ChainPrevHash:   receipt.GenesisHash,
		ChainSeq:        1,
	}, priv)
	if err != nil {
		t.Fatalf("receipt.Sign() error = %v", err)
	}
	return rcpt
}

func cliTestRecorderPayload(t *testing.T, entries []recorder.Entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, entry := range entries {
		if err := enc.Encode(entry); err != nil {
			t.Fatalf("Encode(entry) error = %v", err)
		}
	}
	return buf.Bytes()
}
