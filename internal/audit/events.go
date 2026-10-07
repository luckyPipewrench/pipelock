// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"github.com/luckyPipewrench/pipelock/internal/eventcatalog"
)

// EventType describes the kind of audit event.
type EventType string

// Event type constants for structured audit log entries.
const (
	EventStartup                EventType = eventcatalog.EventStartup
	EventShutdown               EventType = eventcatalog.EventShutdown
	EventAllowed                EventType = eventcatalog.EventAllowed
	EventBlocked                EventType = eventcatalog.EventBlocked
	EventError                  EventType = eventcatalog.EventError
	EventAnomaly                EventType = eventcatalog.EventAnomaly
	EventResponseScan           EventType = eventcatalog.EventResponseScan
	EventResponseScanSuppressed EventType = eventcatalog.EventResponseScanSuppressed
	EventRedirect               EventType = eventcatalog.EventRedirect
	EventTunnelOpen             EventType = eventcatalog.EventTunnelOpen
	EventTunnelClose            EventType = eventcatalog.EventTunnelClose
	EventForwardHTTP            EventType = eventcatalog.EventForwardHTTP
	EventInterceptHTTP          EventType = eventcatalog.EventInterceptHTTP
	EventConfigReload           EventType = eventcatalog.EventConfigReload
	EventWSOpen                 EventType = eventcatalog.EventWSOpen
	EventWSClose                EventType = eventcatalog.EventWSClose
	EventWSBlocked              EventType = eventcatalog.EventWSBlocked
	EventWSScan                 EventType = eventcatalog.EventWSScan
	EventSessionAnomaly         EventType = eventcatalog.EventSessionAnomaly
	EventAdaptiveEscalation     EventType = eventcatalog.EventAdaptiveEscalation
	EventAdaptiveRecovery       EventType = eventcatalog.EventAdaptiveRecovery
	EventMCPUnknownTool         EventType = eventcatalog.EventMCPUnknownTool
	EventKillSwitchDeny         EventType = eventcatalog.EventKillSwitchDeny
	EventSNIMismatch            EventType = eventcatalog.EventSNIMismatch
	EventBodyDLP                EventType = eventcatalog.EventBodyDLP
	EventBodyPromptInjection    EventType = eventcatalog.EventBodyPromptInjection
	EventHeaderDLP              EventType = eventcatalog.EventHeaderDLP
	EventChainDetection         EventType = eventcatalog.EventChainDetection
	EventAddressProtection      EventType = eventcatalog.EventAddressProtection
	EventAgentListener          EventType = eventcatalog.EventAgentListener
	EventFileSentryDLP          EventType = eventcatalog.EventFileSentryDLP

	EventCrossRequestEntropyExceeded EventType = eventcatalog.EventCrossRequestEntropyExceeded
	EventCrossRequestDLPMatch        EventType = eventcatalog.EventCrossRequestDLPMatch
	EventCrossRequestEntropyAnomaly  EventType = eventcatalog.EventCrossRequestEntropyAnomaly

	EventAdaptiveUpgrade    EventType = eventcatalog.EventAdaptiveUpgrade
	EventToolRedirect       EventType = eventcatalog.EventToolRedirect
	EventSessionAdmin       EventType = eventcatalog.EventSessionAdmin
	EventResponseScanExempt EventType = eventcatalog.EventResponseScanExempt
	EventTaintDecision      EventType = eventcatalog.EventTaintDecision

	EventAirlockEnter           EventType = eventcatalog.EventAirlockEnter
	EventAirlockDeny            EventType = eventcatalog.EventAirlockDeny
	EventAirlockDeescalate      EventType = eventcatalog.EventAirlockDeescalate
	EventShieldRewrite          EventType = eventcatalog.EventShieldRewrite
	EventMediaExposure          EventType = eventcatalog.EventMediaExposure
	EventLicenseExpiry          EventType = eventcatalog.EventLicenseExpiry
	EventRuleBundleDegraded     EventType = eventcatalog.EventRuleBundleDegraded
	EventCommitmentKeyLifecycle EventType = eventcatalog.EventCommitmentKeyLifecycle
	EventContainmentMetricsDeny EventType = eventcatalog.EventContainmentMetricsDeny
	EventAuthorityVerification  EventType = eventcatalog.EventAuthorityVerification
)
