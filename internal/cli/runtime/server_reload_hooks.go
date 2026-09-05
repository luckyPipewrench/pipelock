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
