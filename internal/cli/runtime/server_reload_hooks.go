// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import "sync/atomic"

var reloadAfterProxySwapHook atomic.Pointer[func(*Server)]

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
