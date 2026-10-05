// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"
	"time"
)

const (
	testCorrelationHeaderOld = "X-Correlation-Id"
	testCorrelationHeaderNew = "X-Test-Case"
	emitRestartWarning       = "emit settings changed"
)

// emit.correlation_header follows the rest of the emit block: a hot reload
// that changes it is ignored with a warning and the live value is kept, and a
// reload that leaves it alone reports nothing about emit.
func TestServerReload_EmitCorrelationHeaderIsRestartOnly(t *testing.T) {
	t.Parallel()
	cfgPath := writeServerTestConfig(t, "\nemit:\n  correlation_header: x-correlation-id\n")
	s, buf := newTestServer(t, func(o *ServerOpts) { o.ConfigFile = cfgPath })
	if got := s.proxy.CurrentConfig().Emit.CorrelationHeader; got != testCorrelationHeaderOld {
		t.Fatalf("startup correlation_header = %q, want %q", got, testCorrelationHeaderOld)
	}

	t.Run("change is ignored", func(t *testing.T) {
		s.lastReloadAt = time.Time{}
		changed := s.proxy.CurrentConfig().Clone()
		changed.Emit.CorrelationHeader = testCorrelationHeaderNew
		buf.reset()
		if err := s.Reload(changed); err != nil {
			t.Fatalf("Reload: %v", err)
		}
		if !strings.Contains(buf.String(), emitRestartWarning) {
			t.Fatalf("reload output missing restart-only warning:\n%s", buf.String())
		}
		if got := s.proxy.CurrentConfig().Emit.CorrelationHeader; got != testCorrelationHeaderOld {
			t.Fatalf("live correlation_header = %q, want preserved %q", got, testCorrelationHeaderOld)
		}
	})

	t.Run("no change is silent", func(t *testing.T) {
		s.lastReloadAt = time.Time{}
		same := s.proxy.CurrentConfig().Clone()
		same.Emit.CorrelationHeader = testCorrelationHeaderOld
		buf.reset()
		if err := s.Reload(same); err != nil {
			t.Fatalf("Reload: %v", err)
		}
		if strings.Contains(buf.String(), emitRestartWarning) {
			t.Fatalf("unchanged correlation_header produced an emit warning:\n%s", buf.String())
		}
		if got := s.proxy.CurrentConfig().Emit.CorrelationHeader; got != testCorrelationHeaderOld {
			t.Fatalf("live correlation_header = %q, want %q", got, testCorrelationHeaderOld)
		}
	})
}
