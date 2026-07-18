//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/emergency"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/enrollmentclient"
	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/securefile"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	conductorEnrolledStateFileName = "enrolled.json"
	conductorEnrollmentFileMaxSize = 64 << 10
)

var newConductorEnrollmentHTTPClient = func(cfg config.Conductor) (enrollmentclient.HTTPDoer, error) {
	return newConductorMTLSClient(cfg)
}

type conductorEnrollmentMarker struct {
	Version     int       `json:"version"`
	OrgID       string    `json:"org_id"`
	FleetID     string    `json:"fleet_id"`
	InstanceID  string    `json:"instance_id"`
	Environment string    `json:"environment"`
	AuditKeyID  string    `json:"audit_key_id"`
	EnrolledAt  time.Time `json:"enrolled_at"`
	MarkedAt    time.Time `json:"marked_at"`
}

func (s *Server) initConductorEnrollment(cfg *config.Config, recPrivKey ed25519.PrivateKey, stderr io.Writer) error {
	enrolled, err := runConductorAutoEnroll(context.Background(), cfg, recPrivKey, nil)
	if err != nil {
		if conductorEnrollmentRequired(cfg) {
			return fmt.Errorf("conductor enrollment failed: %w", err)
		}
		if stderr != nil {
			_, _ = fmt.Fprintf(stderr, "pipelock: conductor enrollment skipped: %v\n", err)
		}
		return nil
	}
	if enrolled && stderr != nil {
		_, _ = fmt.Fprintf(stderr, "  Conductor: follower enrollment completed\n")
	}
	return nil
}

func runConductorAutoEnroll(ctx context.Context, cfg *config.Config, recPrivKey ed25519.PrivateKey, client enrollmentclient.HTTPDoer) (bool, error) {
	if cfg == nil || !cfg.Conductor.Enabled || strings.TrimSpace(cfg.Conductor.EnrollmentTokenPath) == "" {
		return false, nil
	}
	markerPath := filepath.Join(cfg.Conductor.BundleCacheDir, conductorEnrolledStateFileName)
	marked, err := conductorEnrollmentMarked(markerPath, cfg.Conductor)
	if err != nil {
		return false, err
	}
	if marked {
		if err := initializeConductorReplayBaseline(cfg.Conductor); err != nil {
			return false, err
		}
		return false, nil
	}
	token, err := readConductorEnrollmentToken(cfg.Conductor.EnrollmentTokenPath)
	if err != nil {
		return false, err
	}
	auditPub, err := conductorRecorderPublicKey(recPrivKey)
	if err != nil {
		return false, err
	}
	if client == nil {
		client, err = newConductorEnrollmentHTTPClient(cfg.Conductor)
		if err != nil {
			return false, err
		}
	}
	enroller, err := enrollmentclient.New(enrollmentclient.Config{
		BaseURL: cfg.Conductor.ConductorURL,
		Client:  client,
	})
	if err != nil {
		return false, err
	}
	resp, err := enroller.Enroll(ctx, enrollmentclient.Request{
		Token:          token,
		AuditKeyID:     cfg.Conductor.AuditSigningKeyID,
		AuditPublicKey: signing.EncodePublicKey(auditPub),
	})
	if err != nil {
		return false, err
	}
	if err := initializeConductorReplayBaseline(cfg.Conductor); err != nil {
		return false, err
	}
	if err := writeConductorEnrollmentMarker(markerPath, resp); err != nil {
		return false, err
	}
	return true, nil
}

func initializeConductorReplayBaseline(cfg config.Conductor) error {
	// Write an initial remote-kill replay baseline alongside the enrollment
	// marker. Without it, a freshly enrolled follower would wedge on restart:
	// the marker counts as "follower context present", but replay state is only
	// written on the first remote kill.
	baselinePath := filepath.Join(cfg.BundleCacheDir, emergency.RemoteKillStateFileName)
	if err := emergency.InitializeReplayBaseline(baselinePath, time.Now().UTC()); err != nil {
		return fmt.Errorf("initialize conductor remote kill replay baseline: %w", err)
	}
	return nil
}

func conductorEnrollmentRequired(cfg *config.Config) bool {
	return cfg != nil && cfg.Conductor.Enabled && strings.TrimSpace(cfg.Conductor.EnrollmentTokenPath) != ""
}

func conductorEnrollmentMarked(path string, cfg config.Conductor) (bool, error) {
	_, marked, err := readConductorEnrollmentMarker(path, cfg)
	return marked, err
}

func readConductorEnrollmentMarker(path string, cfg config.Conductor) (conductorEnrollmentMarker, bool, error) {
	data, err := securefile.Read(path, securefile.Options{MaxBytes: conductorEnrollmentFileMaxSize, DisallowedPerms: 0o077})
	if os.IsNotExist(err) {
		return conductorEnrollmentMarker{}, false, nil
	}
	if err != nil {
		return conductorEnrollmentMarker{}, false, fmt.Errorf("read conductor enrollment marker: %w", err)
	}
	var marker conductorEnrollmentMarker
	if err := contract.DecodeStrictJSON(data, &marker); err != nil {
		return conductorEnrollmentMarker{}, false, fmt.Errorf("parse conductor enrollment marker: %w", err)
	}
	if marker.Version != 1 {
		return conductorEnrollmentMarker{}, false, fmt.Errorf("conductor enrollment marker has unsupported version %d", marker.Version)
	}
	if marker.OrgID == cfg.OrgID &&
		marker.FleetID == cfg.FleetID &&
		marker.InstanceID == cfg.InstanceID &&
		marker.AuditKeyID == cfg.AuditSigningKeyID {
		return marker, true, nil
	}
	return conductorEnrollmentMarker{}, false, nil
}

func readConductorEnrollmentToken(path string) (string, error) {
	data, err := securefile.Read(path, securefile.Options{MaxBytes: conductorEnrollmentFileMaxSize, DisallowedPerms: 0o027})
	if err != nil {
		return "", fmt.Errorf("read conductor enrollment token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("conductor enrollment token file is empty")
	}
	return token, nil
}

func writeConductorEnrollmentMarker(path string, resp enrollmentclient.Response) error {
	clean := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(clean), 0o750); err != nil {
		return fmt.Errorf("create conductor enrollment state dir: %w", err)
	}
	now := time.Now().UTC()
	data, err := json.MarshalIndent(conductorEnrollmentMarker{
		Version:     1,
		OrgID:       resp.OrgID,
		FleetID:     resp.FleetID,
		InstanceID:  resp.InstanceID,
		Environment: resp.Environment,
		AuditKeyID:  resp.AuditKeyID,
		EnrolledAt:  resp.EnrolledAt.UTC(),
		MarkedAt:    now,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal conductor enrollment marker: %w", err)
	}
	if err := atomicfile.Write(clean, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write conductor enrollment marker: %w", err)
	}
	return nil
}
