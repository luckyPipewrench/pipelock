// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Receipt kinds the harness accounts for. v2 receipts carry neither an
// ActionID nor a decision phase by design, so they are only ever attributed to
// a request through the workload key in their target.
type receiptKind int

const (
	kindV1Intent receiptKind = iota
	kindV1Outcome
	kindV1Allow
	kindV1Block
	kindV1Other
	kindV2
	kindAEL
	kindCount
)

var kindNames = [kindCount]string{"v1_intent", "v1_outcome", "v1_allow", "v1_block", "v1_other", "v2", "ael"}

func (k receiptKind) String() string { return kindNames[k] }

const (
	scanLineLimit    = 8 * 1024 * 1024
	maxOrphanSamples = 8

	recordTypeAction   = "action_receipt"
	recordTypeEvidence = "evidence_receipt"

	verdictAllow = "allow"
	verdictBlock = "block"
)

// slotObservation is everything the recorder holds for one planned request.
type slotObservation struct {
	counts    [kindCount]int32
	actionIDs []string
	session   string
}

func (o *slotObservation) add(kind receiptKind) { o.counts[kind]++ }

func (o *slotObservation) addActionID(id string) {
	for _, existing := range o.actionIDs {
		if existing == id {
			return
		}
	}
	o.actionIDs = append(o.actionIDs, id)
}

// recorderObservation is the harness's reading of a recorder directory,
// attributed to planned requests by identity.
type recorderObservation struct {
	slots []slotObservation

	// orphans are receipts for the sink that name a workload key outside the
	// plan, per kind. uncorrelatable receipts target the sink (or were
	// sanitized past recognition) but carry no usable key, so no request can
	// be assigned to them.
	orphans         [kindCount]int
	uncorrelatable  [kindCount]int
	orphanSamples   []string
	controlReceipts int

	recorderFiles int
	aelFiles      int
	lastReceipt   time.Time
	latestFileMod time.Time
	nativeRuns    map[string]string
}

func newRecorderObservation(total int) *recorderObservation {
	return &recorderObservation{slots: make([]slotObservation, total), nativeRuns: make(map[string]string)}
}

func (r *recorderObservation) slot(slot int) *slotObservation { return &r.slots[slot] }

func (r *recorderObservation) sampleOrphan(text string) {
	if len(r.orphanSamples) < maxOrphanSamples {
		r.orphanSamples = append(r.orphanSamples, text)
	}
}

type recorderScanner struct {
	plan     workload
	sinkAddr string
	obs      *recorderObservation

	// actionSlot maps a v1 ActionID to its planned request; controlIDs are
	// ActionIDs of receipts that are not request receipts (session control).
	actionSlot map[string]int
	controlIDs map[string]struct{}
	// aelIDs collects AEL activity ids so they can be attributed after every
	// v1 receipt has been read.
	aelIDs     []aelActivity
	actionRuns map[string]string
	eventIDs   map[string]bool
}

// scanRecorder reads every v1 and v2 evidence record and every native AEL
// activity under dir and attributes them to the planned requests.
func scanRecorder(dir string, plan workload, sinkAddr string) (*recorderObservation, error) {
	s := &recorderScanner{
		plan:       plan,
		sinkAddr:   sinkAddr,
		obs:        newRecorderObservation(plan.total()),
		actionSlot: make(map[string]int),
		controlIDs: make(map[string]struct{}),
		eventIDs:   make(map[string]bool),
		actionRuns: make(map[string]string),
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		base := filepath.Base(path)
		switch {
		case strings.HasPrefix(base, "evidence-") && strings.HasSuffix(base, ".jsonl"):
			s.obs.recorderFiles++
			return s.scanFile(root, rel, path, s.evidenceLine)
		case strings.HasSuffix(base, ".jsonl") && strings.Contains(filepath.ToSlash(rel), "ael/") && strings.Contains(filepath.ToSlash(rel), "/recorders/"):
			s.obs.aelFiles++
			return s.scanFile(root, rel, path, s.aelLine)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.attributeAEL(); err != nil {
		return nil, err
	}
	return s.obs, nil
}

func (s *recorderScanner) scanFile(root *os.Root, rel, path string, handle func(line []byte) error) error {
	f, err := root.Open(rel)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if info, statErr := f.Stat(); statErr == nil && info.ModTime().After(s.obs.latestFileMod) {
		s.obs.latestFileMod = info.ModTime()
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), scanLineLimit)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if len(scanner.Bytes()) == 0 {
			continue
		}
		if err := handle(scanner.Bytes()); err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
	}
	return scanner.Err()
}

type evidenceEnvelope struct {
	Session string          `json:"session_id"`
	Type    string          `json:"type"`
	TS      time.Time       `json:"ts"`
	Detail  json.RawMessage `json:"detail"`
}

func (s *recorderScanner) evidenceLine(line []byte) error {
	var env evidenceEnvelope
	if err := json.Unmarshal(line, &env); err != nil {
		return fmt.Errorf("envelope: %w", err)
	}
	switch env.Type {
	case recordTypeAction:
		return s.v1Receipt(env)
	case recordTypeEvidence:
		return s.v2Receipt(env)
	}
	return nil
}

func v1Kind(phase, verdict string) receiptKind {
	switch {
	case phase == "intent":
		return kindV1Intent
	case phase == "outcome":
		return kindV1Outcome
	case phase == "" && verdict == verdictAllow:
		return kindV1Allow
	case phase == "" && verdict == verdictBlock:
		return kindV1Block
	}
	return kindV1Other
}

func (s *recorderScanner) v1Receipt(env evidenceEnvelope) error {
	var detail struct {
		ActionRecord struct {
			ActionID string `json:"action_id"`
			RunNonce string `json:"run_nonce"`
			Phase    string `json:"decision_phase"`
			Verdict  string `json:"verdict"`
			Target   string `json:"target"`
		} `json:"action_record"`
		SignerKey string `json:"signer_key"`
	}
	if err := json.Unmarshal(env.Detail, &detail); err != nil {
		return fmt.Errorf("action detail: %w", err)
	}
	ar := detail.ActionRecord
	if run, seen := s.actionRuns[ar.ActionID]; seen && run != ar.RunNonce {
		return errors.New("ActionID maps to multiple native runs")
	}
	s.actionRuns[ar.ActionID] = ar.RunNonce
	if ar.RunNonce != "" {
		if signer, seen := s.obs.nativeRuns[ar.RunNonce]; seen && signer != detail.SignerKey {
			return errors.New("native AEL run has conflicting signers")
		}
		s.obs.nativeRuns[ar.RunNonce] = detail.SignerKey
	}
	kind := v1Kind(ar.Phase, ar.Verdict)
	switch s.classify(ar.Target) {
	case targetControl:
		s.obs.controlReceipts++
		if ar.ActionID != "" {
			s.controlIDs[ar.ActionID] = struct{}{}
		}
	case targetUncorrelatable:
		s.obs.uncorrelatable[kind]++
		s.obs.sampleOrphan(kind.String() + " without a usable workload key: " + ar.Target)
	case targetWorkload:
		key, _ := keyFromTarget(ar.Target)
		slot, ok := s.plan.parseKey(key)
		if !ok {
			s.obs.orphans[kind]++
			s.obs.sampleOrphan(kind.String() + " for key outside the plan: " + key)
			break
		}
		if ar.ActionID == "" {
			return errors.New("workload receipt has no ActionID")
		}
		if owner, seen := s.actionSlot[ar.ActionID]; seen && owner != slot {
			return errors.New("ActionID maps to multiple workload keys")
		}
		if (kind == kindV1Intent || kind == kindV1Outcome) && ar.Verdict != verdictAllow {
			return errors.New("workload phase has an unexpected verdict")
		}
		o := s.obs.slot(slot)
		if o.session != "" && o.session != env.Session {
			return errors.New("workload key maps to multiple recorder shards")
		}
		o.session = env.Session
		o.add(kind)
		o.addActionID(ar.ActionID)
		if _, seen := s.actionSlot[ar.ActionID]; !seen {
			s.actionSlot[ar.ActionID] = slot
		}
		s.noteReceiptTime(env.TS)
	}
	return nil
}

func (s *recorderScanner) v2Receipt(env evidenceEnvelope) error {
	var detail struct {
		EventID string `json:"event_id"`
		Payload struct {
			Target string `json:"target"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(env.Detail, &detail); err != nil {
		return fmt.Errorf("v2 detail: %w", err)
	}
	if detail.EventID == "" || s.eventIDs[detail.EventID] {
		return errors.New("missing or duplicate v2 EventID")
	}
	s.eventIDs[detail.EventID] = true
	switch s.classify(detail.Payload.Target) {
	case targetControl:
		s.obs.controlReceipts++
	case targetUncorrelatable:
		s.obs.uncorrelatable[kindV2]++
		s.obs.sampleOrphan("v2 without a usable workload key: " + detail.Payload.Target)
	case targetWorkload:
		key, _ := keyFromTarget(detail.Payload.Target)
		slot, ok := s.plan.parseKey(key)
		if !ok {
			s.obs.orphans[kindV2]++
			s.obs.sampleOrphan("v2 for key outside the plan: " + key)
			break
		}
		o := s.obs.slot(slot)
		if o.session != "" && o.session != env.Session {
			return errors.New("v2 workload key maps to another recorder shard")
		}
		o.session = env.Session
		o.add(kindV2)
		s.noteReceiptTime(env.TS)
	}
	return nil
}

func (s *recorderScanner) noteReceiptTime(ts time.Time) {
	if ts.After(s.obs.lastReceipt) {
		s.obs.lastReceipt = ts
	}
}

type targetClass int

const (
	targetControl targetClass = iota
	targetWorkload
	targetUncorrelatable
)

// classify decides whether a receipt target belongs to the workload. A target
// aimed at the sink with a key is a workload receipt; one aimed at the sink
// without a usable key, or sanitized to a bare marker, cannot be attributed to
// any request and is reported as uncorrelatable rather than guessed at.
func (s *recorderScanner) classify(target string) targetClass {
	if strings.HasPrefix(target, "[redacted-") {
		return targetUncorrelatable
	}
	switch target {
	case "pipelock://session/open", "pipelock://session/heartbeat", "pipelock://session/close":
		return targetControl
	}
	if targetHost(target) != s.sinkAddr {
		return targetUncorrelatable
	}
	key, ok := keyFromTarget(target)
	if !ok || strings.HasPrefix(key, "[redacted-") {
		return targetUncorrelatable
	}
	return targetWorkload
}

// aelPayload is the decoded payload of one native AEL activity record. The
// event id is the v1 ActionID of the action the activity describes.
type aelActivity struct{ id, run string }

type aelPayload struct {
	Run   string `json:"run"`
	Type  string `json:"type"`
	Event struct {
		ID string `json:"id"`
	} `json:"event"`
}

func (s *recorderScanner) aelLine(line []byte) error {
	// A native AEL record is a base64url payload and a signature joined by a
	// dot; the payload carries the record type and, for an activity, the
	// ActionID of the action it describes.
	parts := strings.Split(string(line), ".")
	if len(parts) != 2 {
		return errors.New("ael record is not payload.signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("ael payload: %w", err)
	}
	var p aelPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("ael payload: %w", err)
	}
	if p.Type == "activity" {
		s.aelIDs = append(s.aelIDs, aelActivity{id: p.Event.ID, run: p.Run})
	}
	return nil
}

// attributeAEL assigns each activity to the request whose v1 ActionID it
// names. An activity whose id matches neither a request nor a control receipt
// is an orphan.
func (s *recorderScanner) attributeAEL() error {
	for _, activity := range s.aelIDs {
		id := activity.id
		if run, ok := s.actionRuns[id]; ok && run != activity.run {
			return errors.New("AEL activity belongs to another native run")
		}
		if slot, ok := s.actionSlot[id]; ok {
			s.obs.slot(slot).add(kindAEL)
			continue
		}
		if _, ok := s.controlIDs[id]; ok {
			s.obs.controlReceipts++
			continue
		}
		s.obs.orphans[kindAEL]++
		s.obs.sampleOrphan("ael activity for unknown action id: " + id)
	}
	return nil
}
