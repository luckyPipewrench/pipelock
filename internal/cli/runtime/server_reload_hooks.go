// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import "sync/atomic"

var (
	reloadAfterProxySwapHook atomic.Pointer[func(*Server)]
	reloadLockHook           atomic.Pointer[func(acquired bool)]
)

func setReloadLockHookForTest(fn func(acquired bool)) (restore func()) {
	prev := reloadLockHook.Load()
	if fn == nil {
		reloadLockHook.Store(nil)
	} else {
		reloadLockHook.Store(&fn)
	}
	return func() { reloadLockHook.Store(prev) }
}

func fireReloadLockHook(acquired bool) {
	if p := reloadLockHook.Load(); p != nil {
		(*p)(acquired)
	}
}

func setReloadAfterProxySwapHookForTest(fn func(*Server)) (restore func()) {
	prev := reloadAfterProxySwapHook.Load()
	if fn == nil {
		reloadAfterProxySwapHook.Store(nil)
	} else {
		reloadAfterProxySwapHook.Store(&fn)
	}
	return func() { reloadAfterProxySwapHook.Store(prev) }
}

func fireReloadAfterProxySwapHook(s *Server) {
	if p := reloadAfterProxySwapHook.Load(); p != nil {
		(*p)(s)
	}
}

var reloadBeforeProxySwapHook atomic.Pointer[func(*Server)]

// setReloadBeforeProxySwapHookForTest installs a seam that runs after the
// kill-switch controller starts watching the candidate's sources and before
// the proxy publishes the candidate.
func setReloadBeforeProxySwapHookForTest(fn func(*Server)) (restore func()) {
	prev := reloadBeforeProxySwapHook.Load()
	if fn == nil {
		reloadBeforeProxySwapHook.Store(nil)
	} else {
		reloadBeforeProxySwapHook.Store(&fn)
	}
	return func() { reloadBeforeProxySwapHook.Store(prev) }
}

func fireReloadBeforeProxySwapHook(s *Server) {
	if p := reloadBeforeProxySwapHook.Load(); p != nil {
		(*p)(s)
	}
}
