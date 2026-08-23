// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/authority"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	mcpReceiptLayerAuthority   = "authority"
	mcpReceiptPatternAuthority = "authority verification failed"
)

func authorityReceiptAttribution() (layer, pattern, severity string) {
	return mcpReceiptLayerAuthority, mcpReceiptPatternAuthority, config.SeverityHigh
}

func (o MCPProxyOpts) authorityActor() string {
	for _, actor := range []string{o.AuthorityActor, o.addressProtectionAgent(), o.ContractAgent, o.Profile} {
		if actor = strings.TrimSpace(actor); actor != "" {
			return actor
		}
	}
	return ""
}

func (o MCPProxyOpts) authorityDestination() string {
	for _, destination := range []string{o.AuthorityDestination, o.ContractServer, o.ServerName} {
		if destination = strings.TrimSpace(destination); destination != "" {
			return destination
		}
	}
	return ""
}

func authorizeMCP(ctx context.Context, ref string, carrierErr error, frame MCPFrame, opts MCPProxyOpts) error {
	if opts.AuthorityVerifier == nil {
		return nil
	}
	action := receipt.ClassifyMCPTool(frame.ToolCallName, frame.Method)
	result, err := authority.Evaluate(ctx, opts.AuthorityVerifier, authority.Request{
		Actor:        opts.authorityActor(),
		Action:       string(action),
		Destination:  opts.authorityDestination(),
		AuthorityRef: ref,
	}, carrierErr)
	if opts.AuditLogger != nil {
		resource := frame.ToolCallName
		if resource == "" {
			resource = frame.Method
		}
		if resource == "" {
			resource = "mcp-request"
		}
		opts.AuditLogger.LogAuthorityVerification(
			mustMCPAuditContext(opts.AuditLogger, frame.Method, resource),
			audit.NewAuthorityVerification(
				opts.Transport,
				result.Decision.String(),
				string(result.Reason),
				result.Issuer,
				result.Reference,
				err,
			),
		)
	}
	return err
}

func authorityBlockedRequest(frame MCPFrame) *BlockedRequest {
	return &BlockedRequest{
		ID:             frame.ID,
		IsNotification: isRPCNotification(frame.ID),
		LogMessage:     "authority verification failed",
		ErrorCode:      -32008,
		ErrorMessage:   "pipelock: authority verification failed",
		ErrorData:      mcpBlockReasonData(blockreason.AuthorityMismatch),
	}
}
