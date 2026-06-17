// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
)

const (
	deferResolverManifestEnv    = "__PIPELOCK_DEFER_RESOLVER_MANIFEST"
	maxDeferResolverOutputBytes = 4096
)

// DeferResolverRuntime owns async resolver goroutines and subprocess
// cancellation for one proxy invocation.
type DeferResolverRuntime struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newDeferResolverRuntime(parent context.Context) *DeferResolverRuntime {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &DeferResolverRuntime{ctx: ctx, cancel: cancel}
}

func (r *DeferResolverRuntime) Go(fn func(context.Context)) {
	if r == nil {
		go fn(context.Background())
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		fn(r.ctx)
	}()
}

func (r *DeferResolverRuntime) Cancel() {
	if r != nil {
		r.cancel()
	}
}

func (r *DeferResolverRuntime) Wait() {
	if r != nil {
		r.wg.Wait()
	}
}

type cappedOutputBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedOutputBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		return len(p), nil
	}
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *cappedOutputBuffer) String() string {
	return b.buf.String()
}

type deferResolverManifest struct {
	Profile           string `json:"profile"`
	Reason            string `json:"reason,omitempty"`
	DeferID           string `json:"defer_id"`
	Target            string `json:"target"`
	Method            string `json:"method"`
	Surface           string `json:"surface"`
	HoldReason        string `json:"hold_reason,omitempty"`
	Principal         string `json:"principal,omitempty"`
	Actor             string `json:"actor,omitempty"`
	SessionID         string `json:"session_id,omitempty"`
	SessionIDOriginal string `json:"session_id_original,omitempty"`
	ArgDigest         string `json:"arg_digest,omitempty"`
	Arguments         string `json:"arguments,omitempty"`
	DeadlineUnixNano  int64  `json:"deadline_unix_nano,omitempty"`
}

func maybeStartDeferApprovalResolver(
	runtime *DeferResolverRuntime,
	manager *deferred.Manager,
	held deferred.HeldAction,
	profileName string,
	profile config.DeferResolverProfile,
	rawArgs string,
	integrityCfg *config.MCPBinaryIntegrity,
	logW io.Writer,
) {
	if manager == nil {
		return
	}
	if !held.RulePolicy.AllowOn.Approval && !held.RulePolicy.StepUpOn.ApprovalRequestsHuman {
		return
	}
	runtime.Go(func(ctx context.Context) {
		decision, err := executeDeferApprovalResolver(ctx, held, profileName, profile, rawArgs, integrityCfg, logW)
		if err != nil {
			_ = manager.Resolve(held.DeferID, config.ActionBlock, deferred.SourceApproval)
			return
		}
		_ = manager.ResolveApproval(held.DeferID, decision)
	})
}

func executeDeferApprovalResolver(
	parent context.Context,
	held deferred.HeldAction,
	profileName string,
	profile config.DeferResolverProfile,
	rawArgs string,
	integrityCfg *config.MCPBinaryIntegrity,
	logW io.Writer,
) (string, error) {
	if len(profile.Exec) == 0 || profile.Exec[0] == "" {
		return config.ActionBlock, fmt.Errorf("defer resolver profile %q has empty exec", profileName)
	}
	if held.Deadline.IsZero() {
		return config.ActionBlock, errors.New("defer resolver missing deadline")
	}
	if time.Now().UTC().After(held.Deadline) {
		return config.ActionBlock, context.DeadlineExceeded
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithDeadline(parent, held.Deadline)
	defer cancel()

	args := append([]string(nil), profile.Exec[1:]...)
	cmd := configValidatedCommand(ctx, profile.Exec[0], args...)
	setupChildProcessGroup(cmd)
	cmd.Env = safeEnv()
	if integrityCfg != nil && integrityCfg.Enabled {
		if err := VerifyBinaryIntegrity(profile.Exec, integrityCfg, logW); err != nil {
			return config.ActionBlock, err
		}
	}
	manifest := deferResolverManifest{
		Profile:           profileName,
		Reason:            profile.Reason,
		DeferID:           held.DeferID,
		Target:            held.Target,
		Method:            held.Method,
		Surface:           held.Surface,
		HoldReason:        held.Reason,
		Principal:         held.Authority.Principal,
		Actor:             held.Authority.Actor,
		SessionID:         held.Authority.SessionID,
		SessionIDOriginal: held.Authority.SessionIDOriginal,
		ArgDigest:         held.ArgDigest,
		DeadlineUnixNano:  held.Deadline.UnixNano(),
	}
	if profile.IncludeArgs {
		manifest.Arguments = rawArgs
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return config.ActionBlock, fmt.Errorf("marshal defer resolver manifest: %w", err)
	}
	cmd.Env = append(cmd.Env, deferResolverManifestEnv+"="+string(manifestJSON))
	var stdout, stderr cappedOutputBuffer
	stdout.limit = maxDeferResolverOutputBytes
	stderr.limit = maxDeferResolverOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		if ctx.Err() != nil {
			return config.ActionBlock, ctx.Err()
		}
		return config.ActionBlock, fmt.Errorf("defer resolver failed to start: %w", err)
	}
	pgid := captureChildPgid(cmd.Process.Pid)
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	var waitErr error
	select {
	case waitErr = <-waitCh:
	case <-ctx.Done():
		terminateProcessGroup(pgid)
		waitErr = <-waitCh
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return config.ActionBlock, ctx.Err()
		}
		return config.ActionBlock, fmt.Errorf("defer resolver failed: %w (stderr: %s)", waitErr, stderr.String())
	}
	if stdout.truncated || stderr.truncated {
		return config.ActionBlock, fmt.Errorf("defer resolver output exceeded %d bytes", maxDeferResolverOutputBytes)
	}
	return parseDeferResolverDecision(stdout.String())
}

var _ io.Writer = (*cappedOutputBuffer)(nil)

func parseDeferResolverDecision(stdout string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(stdout))
	if len(fields) != 1 {
		return config.ActionBlock, fmt.Errorf("defer resolver output must be exactly one terminal token")
	}
	switch fields[0] {
	case config.ActionAllow:
		return config.ActionAllow, nil
	case config.ActionBlock:
		return config.ActionBlock, nil
	case "step_up":
		return "step_up", nil
	default:
		return config.ActionBlock, fmt.Errorf("invalid defer resolver terminal token %q", fields[0])
	}
}
