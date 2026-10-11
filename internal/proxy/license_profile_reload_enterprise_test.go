//go:build enterprise

package proxy

import (
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func twoProfileConfig(cfg *config.Config) {
	revocationConnectionConfig(cfg)
	cfg.Agents["other"] = config.AgentProfile{SourceCIDRs: []string{"198.51.100.0/24"}}
}

// Removing an unrelated profile preserves a surviving licensed connection.
func TestLicenseProfileRemovalKeepsSurvivor(t *testing.T) {
	backend, stop := wsEchoServer(t)
	defer stop()
	addr, p, cleanup := setupWSProxyDefaultWithProxy(t, twoProfileConfig)
	defer cleanup()
	conn := dialWS(t, addr, backend)
	defer func() { _ = conn.Close() }()
	if err := wsutil.WriteClientText(conn, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := wsutil.ReadServerData(conn); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	if _, ok := p.Edition().LookupProfile("client"); !ok {
		t.Fatal("positive control: client not active")
	}
	next := p.CurrentConfig().Clone()
	next.Agents = map[string]config.AgentProfile{"client": {SourceCIDRs: []string{"127.0.0.0/8"}}}
	if !p.Reload(next, scanner.MustNew(next)) {
		t.Fatal("reload failed")
	}
	if _, ok := p.Edition().LookupProfile("client"); !ok {
		t.Errorf("surviving paid profile 'client' no longer selectable after removing 'other' under the same licence")
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := wsutil.WriteClientText(conn, []byte("after")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if _, _, err := wsutil.ReadServerData(conn); err != nil {
		t.Fatalf("surviving connection severed: %v", err)
	}
	if err := wsutil.WriteClientMessage(conn, ws.OpClose, ws.NewCloseFrameBody(ws.StatusNormalClosure, "done")); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

// Re-adding profiles after removal preserves the unchanged license generation.
func TestLicenseProfileReaddAfterRemoval(t *testing.T) {
	_, p, cleanup := setupForwardProxyWithInstance(t, revocationConnectionConfig)
	defer cleanup()
	next := p.CurrentConfig().Clone()
	next.Agents = nil
	if !p.Reload(next, scanner.MustNew(next)) {
		t.Fatal("reload1")
	}
	again := p.CurrentConfig().Clone()
	again.Agents = map[string]config.AgentProfile{"client": {SourceCIDRs: []string{"127.0.0.0/8"}}}
	if !p.Reload(again, scanner.MustNew(again)) {
		t.Fatal("reload2")
	}
	if _, ok := p.Edition().LookupProfile("client"); !ok {
		t.Errorf("re-added profile under the same valid licence is revoked until the next CRL tick")
	}
}
