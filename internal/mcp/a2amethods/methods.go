// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package a2amethods is the shared source of truth for A2A JSON-RPC method
// names used by request classification and A2A session-binding inventory.
package a2amethods

import "strings"

// Known returns a copy of the A2A JSON-RPC method inventory.
func Known() map[string]bool {
	methods := make(map[string]bool, len(known))
	for method := range known {
		methods[method] = true
	}
	return methods
}

// Is reports whether method is a recognized A2A JSON-RPC method. Matching is
// case-insensitive to preserve the existing tolerant classifier behavior.
func Is(method string) bool {
	return known[method] || normalized[strings.ToLower(method)]
}

// Canonical returns the canonical A2A method name for a recognized method and
// reports whether it is recognized. Enforcement (policy matching, redirect
// target, receipts, binding identity) must use the canonical form so a case
// variant cannot be classified as A2A for one purpose while evading a rule
// written against the canonical name.
func Canonical(method string) (string, bool) {
	if known[method] {
		return method, true
	}
	if canonical, ok := canonicalByLower[strings.ToLower(method)]; ok {
		return canonical, true
	}
	return "", false
}

var canonicalByLower = func() map[string]string {
	m := make(map[string]string, len(known))
	for method := range known {
		m[strings.ToLower(method)] = method
	}
	return m
}()

var known = map[string]bool{
	"SendMessage":                      true,
	"SendStreamingMessage":             true,
	"GetTask":                          true,
	"ListTasks":                        true,
	"CancelTask":                       true,
	"SubscribeToTask":                  true,
	"CreateTaskPushNotificationConfig": true,
	"GetTaskPushNotificationConfig":    true,
	"ListTaskPushNotificationConfigs":  true,
	"DeleteTaskPushNotificationConfig": true,
	"GetExtendedAgentCard":             true,
	// Current A2A JSON-RPC method names use slash-delimited lowercase
	// verbs. Keep the legacy CamelCase names above for compatibility.
	"message/send":                        true,
	"message/stream":                      true,
	"tasks/get":                           true,
	"tasks/list":                          true,
	"tasks/cancel":                        true,
	"tasks/resubscribe":                   true,
	"tasks/pushNotificationConfig/set":    true,
	"tasks/pushNotificationConfig/get":    true,
	"tasks/pushNotificationConfig/list":   true,
	"tasks/pushNotificationConfig/delete": true,
	"agent/getAuthenticatedExtendedCard":  true,
}

var normalized = func() map[string]bool {
	methods := make(map[string]bool, len(known))
	for method := range known {
		methods[strings.ToLower(method)] = true
	}
	return methods
}()
