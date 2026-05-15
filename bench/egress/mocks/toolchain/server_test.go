package toolchain

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleEmitsConfiguredToolUseRoundsThenEndTurn(t *testing.T) {
	t.Parallel()
	s := &Server{chainLen: 3}
	wantReasons := []string{"tool_use", "tool_use", "tool_use", "end_turn"}
	for i, want := range wantReasons {
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		s.handle(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d status=%d, want 200", i, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"stop_reason": "`+want+`"`) {
			t.Fatalf("request %d body=%s, want stop_reason %q", i, rec.Body.String(), want)
		}
	}
}
