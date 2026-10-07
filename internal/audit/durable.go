// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// CommitmentKeyLifecycleEvent records a commitment-key lifecycle operation.
// It intentionally carries metadata only: callers must never place key
// material or private evidence views in these fields.
type CommitmentKeyLifecycleEvent struct {
	Operation     string
	Phase         string
	Outcome       string
	OperationID   string
	KeyID         string
	Epoch         uint64
	Timestamp     string
	Reason        string
	Authorization string
}

// LogCommitmentKeyLifecycle records a commitment-key lifecycle operation.
// Lifecycle records always bypass the allowed/blocked sampling controls: a
// denied key operation is security evidence even when routine request logging
// is reduced.
func (l *Logger) LogCommitmentKeyLifecycle(ev CommitmentKeyLifecycleEvent) {
	zlEvent := l.zl.Info()
	if ev.Outcome == "denied" {
		zlEvent = l.zl.Warn()
	}
	e := newLogEntry(zlEvent, EventCommitmentKeyLifecycle).
		str("event_type", string(EventCommitmentKeyLifecycle)).
		str("operation", ev.Operation).
		str("outcome", ev.Outcome).
		optStr("phase", ev.Phase).
		optStr("operation_id", ev.OperationID).
		optStr("key_id", ev.KeyID).
		optStr("timestamp", ev.Timestamp).
		optStr("reason", ev.Reason).
		optStr("authorization", ev.Authorization)
	if ev.Epoch != 0 {
		e.event = e.event.Uint64("epoch", ev.Epoch)
		e.fields["epoch"] = ev.Epoch
	}
	e.msg("commitment key lifecycle")
}

// WriteDurableCommitmentKeyLifecycle appends and syncs one lifecycle record.
// It is deliberately separate from LogCommitmentKeyLifecycle: zerolog's
// regular logging API reports write failures only through its global error
// handler, while a lifecycle mutation must receive the write and fsync error
// before it is allowed to proceed.
func (l *Logger) WriteDurableCommitmentKeyLifecycle(ev CommitmentKeyLifecycleEvent) error {
	if l.fileHandle == nil || l.filePath == "" {
		return errors.New("durable audit log file is not open")
	}
	if err := l.verifyDurableFileBinding(); err != nil {
		return err
	}
	now := sanitizeString(ev.Timestamp)
	if now == "" {
		now = time.Now().UTC().Format(time.RFC3339Nano)
	}
	record := durableCommitmentKeyLifecycleRecord{
		Level:         "info",
		Component:     "pipelock",
		Event:         string(EventCommitmentKeyLifecycle),
		EventType:     string(EventCommitmentKeyLifecycle),
		Operation:     sanitizeString(ev.Operation),
		Phase:         sanitizeString(ev.Phase),
		Outcome:       sanitizeString(ev.Outcome),
		OperationID:   sanitizeString(ev.OperationID),
		KeyID:         sanitizeString(ev.KeyID),
		Epoch:         ev.Epoch,
		Reason:        sanitizeString(ev.Reason),
		Authorization: sanitizeString(ev.Authorization),
		Time:          now,
		Timestamp:     now,
		Message:       "commitment key lifecycle",
	}
	if ev.Outcome == "denied" {
		record.Level = "warn"
	}
	if err := writeAndSyncLifecycleRecord(l.fileHandle, record); err != nil {
		return err
	}
	if err := l.verifyDurableFileBinding(); err != nil {
		return err
	}
	return nil
}

type durableCommitmentKeyLifecycleRecord struct {
	Level         string `json:"level"`
	Component     string `json:"component"`
	Event         string `json:"event"`
	EventType     string `json:"event_type"`
	Operation     string `json:"operation"`
	Phase         string `json:"phase,omitempty"`
	Outcome       string `json:"outcome"`
	OperationID   string `json:"operation_id,omitempty"`
	KeyID         string `json:"key_id,omitempty"`
	Epoch         uint64 `json:"epoch,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Authorization string `json:"authorization,omitempty"`
	Time          string `json:"time"`
	Timestamp     string `json:"timestamp"`
	Message       string `json:"message"`
}

type lifecycleRecordFile interface {
	io.Writer
	Sync() error
}

// writeAndSyncLifecycleRecord uses leading and trailing newlines as record
// boundaries. The trailing newline makes each successful record independently
// parseable by ordinary JSON Lines producers. The leading newline still
// isolates the next lifecycle record after a partial append. Each lifecycle
// record is one Write call, so O_APPEND preserves boundaries between concurrent
// commands.
func writeAndSyncLifecycleRecord(file lifecycleRecordFile, record durableCommitmentKeyLifecycleRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal lifecycle audit record: %w", err)
	}
	data = append(append([]byte{'\n'}, data...), '\n')
	n, err := file.Write(data)
	if err != nil {
		return fmt.Errorf("write lifecycle audit record: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("write lifecycle audit record: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync lifecycle audit record: %w", err)
	}
	return nil
}

func (l *Logger) verifyDurableFileBinding() error {
	pathInfo, err := os.Stat(l.filePath)
	if err != nil {
		return fmt.Errorf("stat configured audit log file: %w", err)
	}
	handleInfo, err := l.fileHandle.Stat()
	if err != nil {
		return fmt.Errorf("stat open audit log file: %w", err)
	}
	if !os.SameFile(pathInfo, handleInfo) {
		return fmt.Errorf("configured audit log file was replaced or rotated: %s", l.filePath)
	}
	return nil
}

// RejectDurableFileAliases proves that the already-open durable file is not a
// protected lifecycle file. It compares descriptor identity after the open so
// a pathname swap between a cheap preflight check and the open cannot redirect
// lifecycle records into a keyring, config, backup, or private-view file.
func (l *Logger) RejectDurableFileAliases(protectedPaths ...string) error {
	if l.fileHandle == nil || l.filePath == "" {
		return errors.New("durable audit log file is not open")
	}
	handleInfo, err := l.fileHandle.Stat()
	if err != nil {
		return fmt.Errorf("stat open audit log file: %w", err)
	}
	for _, protectedPath := range protectedPaths {
		if protectedPath == "" || protectedPath == "-" {
			continue
		}
		info, err := os.Stat(filepath.Clean(protectedPath))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stat protected lifecycle file: %w", err)
		}
		if os.SameFile(handleInfo, info) {
			return errors.New("logging.file must not refer to the commitment keyring or a lifecycle input/output file")
		}
	}
	return l.verifyDurableFileBinding()
}
