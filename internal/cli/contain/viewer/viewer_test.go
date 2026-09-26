// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package viewer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

func testViewer(t *testing.T) (*Viewer, *time.Time) {
	t.Helper()
	now := time.Now()
	v, err := New(Config{Display: "display", Origin: "https://viewer.example:8443", SocketPath: "/unused", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return v, &now
}

func TestTickets(t *testing.T) {
	v, now := testViewer(t)
	id, err := v.MintTicket("display", "view")
	if err != nil {
		t.Fatal(err)
	}
	s, err := v.Exchange(id)
	if err != nil || s.Display != "display" {
		t.Fatalf("exchange: %+v %v", s, err)
	}
	if _, err = v.Exchange(id); err == nil {
		t.Fatal("ticket reused")
	}
	id, _ = v.MintTicket("display", "view")
	*now = now.Add(ticketLifetime)
	if _, err = v.Exchange(id); err == nil {
		t.Fatal("expired ticket accepted")
	}
	for range maxTickets {
		if _, err = v.MintTicket("display", "view"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = v.MintTicket("display", "view"); err == nil {
		t.Fatal("cap ignored")
	}
}

func TestSessionHTTP(t *testing.T) {
	v, _ := testViewer(t)
	id, _ := v.MintTicket("display", "control")
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		r := httptest.NewRequestWithContext(context.Background(), method, "https://viewer.example:8443/session", strings.NewReader(url.Values{"ticket": {id}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", v.cfg.Origin)
		w := httptest.NewRecorder()
		v.ServeHTTP(w, r)
		if method == http.MethodGet {
			if w.Code != 405 {
				t.Fatalf("GET: %d", w.Code)
			}
			continue
		}
		if w.Code != 204 {
			t.Fatalf("POST: %d", w.Code)
		}
		c := w.Result().Cookies()[0]
		if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
			t.Fatalf("cookie: %+v", c)
		}
		v.Revoke(c.Value)
		if _, ok := v.session(c.Value); ok {
			t.Fatal("revoked session valid")
		}
	}
}

func TestOrigin(t *testing.T) {
	v, _ := testViewer(t)
	s, _ := v.MintTicket("display", "view")
	sess, _ := v.Exchange(s)
	for _, tc := range []struct{ name, origin string }{{"missing", ""}, {"port", "https://viewer.example"}, {"scheme", "http://viewer.example:8443"}, {"host", "https://other.example:8443"}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal/ws", nil)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("X-Forwarded-Host", "viewer.example:8443")
			r.AddCookie(&http.Cookie{Name: "viewer_session", Value: sess.ID, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			w := httptest.NewRecorder()
			v.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("status %d", w.Code)
			}
		})
	}
}
func handshake() []byte { return append([]byte("RFB 003.008\n"), 1, 1) }
func cut(n uint32) []byte {
	p := make([]byte, 8+int(n))
	p[0] = 6
	binary.BigEndian.PutUint32(p[4:8], n)
	return p
}

func TestFilter(t *testing.T) {
	control := false
	f := newFilter(func() bool { return control }, true)
	var got []byte
	for _, b := range handshake() {
		out, err := f.feed([]byte{b})
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, out...)
	}
	if !bytes.Equal(got, handshake()) {
		t.Fatal("split handshake changed")
	}
	update := []byte{3, 1, 0, 1, 0, 2, 0, 3, 0, 4}
	for _, p := range [][]byte{{4, 1, 0, 0, 0, 0, 0, 1}, {5, 1, 0, 1, 0, 2}, cut(1), update} {
		out, err := f.feed(p)
		if err != nil {
			t.Fatal(err)
		}
		if p[0] == 3 && !bytes.Equal(out, p) {
			t.Fatal("update changed")
		}
		if p[0] != 3 && len(out) != 0 {
			t.Fatalf("input forwarded: %d", p[0])
		}
	}
	control = true
	for _, p := range [][]byte{{4, 1, 0, 0, 0, 0, 0, 1}, {5, 1, 0, 1, 0, 2}, cut(1)} {
		out, err := f.feed(p)
		if err != nil || !bytes.Equal(out, p) {
			t.Fatalf("control: %v %x", err, out)
		}
	}
	control = false
	if out, _ := f.feed([]byte{4, 1, 0, 0, 0, 0, 0, 1}); len(out) != 0 {
		t.Fatal("lease loss did not disable input")
	}
}

func TestFilterRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  []byte
	}{{"unknown", []byte{150}}, {"cut", []byte{6, 0, 0, 0, 0, 4, 0, 1}}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFilter(func() bool { return false }, false)
			_, _ = f.feed(handshake())
			if _, err := f.feed(tc.msg); err == nil {
				t.Fatal("accepted malformed input")
			}
		})
	}
}

func TestLeaseExpiry(t *testing.T) {
	v, now := testViewer(t)
	id, _ := v.MintTicket("display", "control")
	s, _ := v.Exchange(id)
	if !v.Acquire(s) || !v.controls(s) {
		t.Fatal("lease not acquired")
	}
	*now = now.Add(leaseLifetime)
	if v.controls(s) {
		t.Fatal("expired lease controls")
	}
	if !v.Acquire(s) {
		t.Fatal("cannot reacquire")
	}
	v.Release(s)
	if v.controls(s) {
		t.Fatal("release controls")
	}
}

func TestBridgeRevoke(t *testing.T) {
	server, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	v, err := New(Config{Display: "display", Origin: "http://viewer.example", Dial: func() (net.Conn, error) { return server, nil }})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(v)
	defer ts.Close()
	id, _ := v.MintTicket("display", "view")
	s, _ := v.Exchange(id)
	u := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws"
	conn, _, _, err := (ws.Dialer{Header: ws.HandshakeHeaderHTTP(http.Header{"Origin": []string{"http://viewer.example"}, "Cookie": []string{"viewer_session=" + s.ID}})}).Dial(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	if err := wsutil.WriteClientBinary(conn, handshake()); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len(handshake()))
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = io.ReadFull(peer, b); err != nil || !bytes.Equal(b, handshake()) {
		t.Fatalf("bridge: %v %x", err, b)
	}
	v.Revoke(s.ID)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err = wsutil.ReadServerData(conn); err == nil {
		t.Fatal("revoked socket stayed open")
	}
}

func TestBridgeRejectsWrongRFBPeer(t *testing.T) {
	server, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	v, err := New(Config{
		Display: "display", Origin: "http://viewer.example", ExpectedUID: 42,
		Dial:    func() (net.Conn, error) { return server, nil },
		PeerUID: func(net.Conn) (uint32, error) { return 43, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(v)
	defer ts.Close()
	id, _ := v.MintTicket("display", "view")
	s, _ := v.Exchange(id)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "http://viewer.example")
	req.AddCookie(&http.Cookie{Name: "viewer_session", Value: s.ID, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("wrong peer status: %d", resp.StatusCode)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("upstream remains open: %v", err)
	}
}

func TestViewerCapAndDialFailure(t *testing.T) {
	for _, dialFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(dialFailure), func(t *testing.T) {
			var peers []net.Conn
			v, err := New(Config{Display: "display", Origin: "http://viewer.example", MaxViewers: 1, Dial: func() (net.Conn, error) {
				if dialFailure {
					return nil, errors.New("unavailable")
				}
				a, b := net.Pipe()
				peers = append(peers, b)
				return a, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			ts := httptest.NewServer(v)
			defer ts.Close()
			defer func() {
				for _, p := range peers {
					_ = p.Close()
				}
			}()
			id, _ := v.MintTicket("display", "view")
			s, _ := v.Exchange(id)
			dial := func() (net.Conn, error) {
				d := ws.Dialer{Header: ws.HandshakeHeaderHTTP(http.Header{"Origin": []string{"http://viewer.example"}, "Cookie": []string{"viewer_session=" + s.ID}})}
				c, _, _, e := d.Dial(context.Background(), strings.Replace(ts.URL, "http://", "ws://", 1)+"/ws")
				return c, e
			}
			first, e := dial()
			if dialFailure {
				if e == nil {
					_ = first.Close()
					t.Fatal("dial failure upgraded")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = first.Close() }()
			if second, e := dial(); e == nil {
				_ = second.Close()
				t.Fatal("viewer cap bypassed")
			}
		})
	}
}

func TestSlowClientCloses(t *testing.T) {
	v, _ := testViewer(t)
	client, reader := net.Pipe()
	upstream, writer := net.Pipe()
	defer func() { _ = reader.Close(); _ = writer.Close(); _ = client.Close(); _ = upstream.Close() }()
	done := make(chan struct{})
	go func() { defer close(done); v.serverToClient(client, upstream, new(sync.Mutex)) }()
	writeDone := make(chan struct{})
	go func() { defer close(writeDone); _, _ = writer.Write(make([]byte, 32<<10)) }()
	select {
	case <-done:
	case <-time.After(12 * time.Second):
		t.Fatal("slow client write did not time out")
	}
	_ = writer.Close()
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("writer leaked")
	}
}

func TestLeaseRejectsForgedDisplayAndControlCSRF(t *testing.T) {
	v, _ := testViewer(t)
	id, _ := v.MintTicket("display", "control")
	s, _ := v.Exchange(id)
	forged := s
	forged.Display = "other"
	if v.Acquire(forged) {
		t.Fatal("forged display acquired")
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://viewer.example:8443/control/acquire", nil)
	req.AddCookie(&http.Cookie{Name: "viewer_session", Value: s.ID, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	rec := httptest.NewRecorder()
	v.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing origin: %d", rec.Code)
	}
	req.Header.Set("Origin", "https://viewer.example:8443")
	rec = httptest.NewRecorder()
	v.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("valid acquire: %d", rec.Code)
	}
}

func TestRFBFramingAndLeaseSwitch(t *testing.T) {
	v, now := testViewer(t)
	id, _ := v.MintTicket("display", "control")
	s, _ := v.Exchange(id)
	if !v.Acquire(s) {
		t.Fatal("lease")
	}
	f := newFilter(func() bool { return v.controls(s) }, false)
	_, _ = f.feed(handshake())
	format := make([]byte, 20)
	format[0] = 0
	enc := []byte{2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1}
	for _, msg := range [][]byte{format, enc} {
		var got []byte
		for _, b := range msg {
			out, err := f.feed([]byte{b})
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, out...)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("framing changed: %x", got)
		}
	}
	if out, err := f.feed(cut(1)); err != nil || len(out) != 0 {
		t.Fatal("clipboard disabled but forwarded")
	}
	key := []byte{4, 1, 0, 0, 0, 0, 0, 1}
	if out, _ := f.feed(key); !bytes.Equal(out, key) {
		t.Fatal("lease did not forward key")
	}
	*now = now.Add(leaseLifetime)
	if out, _ := f.feed(key); len(out) != 0 {
		t.Fatal("expired lease forwarded key")
	}
	if _, err := v.MintTicket("other", "view"); err == nil {
		t.Fatal("ticket for other display accepted")
	}
}

func TestHeartbeatDoesNotExtendSession(t *testing.T) {
	v, now := testViewer(t)
	id, _ := v.MintTicket("display", "view")
	s, _ := v.Exchange(id)
	*now = now.Add(idleLifetime - time.Second)
	if !v.sessionValid(s.ID) {
		t.Fatal("valid session rejected")
	}
	*now = now.Add(time.Second)
	if v.sessionValid(s.ID) {
		t.Fatal("heartbeat extended idle session")
	}
}

func TestMalformedRFBClosesSocket(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  []byte
	}{{"unknown", []byte{150}}, {"oversize-cut", []byte{6, 0, 0, 0, 0, 4, 0, 1}}} {
		t.Run(tc.name, func(t *testing.T) {
			server, peer := net.Pipe()
			defer func() { _ = peer.Close() }()
			v, err := New(Config{Display: "display", Origin: "http://viewer.example", Dial: func() (net.Conn, error) { return server, nil }})
			if err != nil {
				t.Fatal(err)
			}
			ts := httptest.NewServer(v)
			defer ts.Close()
			id, _ := v.MintTicket("display", "view")
			s, _ := v.Exchange(id)
			d := ws.Dialer{Header: ws.HandshakeHeaderHTTP(http.Header{"Origin": []string{"http://viewer.example"}, "Cookie": []string{"viewer_session=" + s.ID}})}
			conn, _, _, err := d.Dial(context.Background(), strings.Replace(ts.URL, "http://", "ws://", 1)+"/ws")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			if err = wsutil.WriteClientBinary(conn, handshake()); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, len(handshake()))
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err = io.ReadFull(peer, b); err != nil {
				t.Fatal(err)
			}
			if err = wsutil.WriteClientBinary(conn, tc.msg); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err = wsutil.ReadServerData(conn); err == nil {
				t.Fatal("malformed RFB did not close socket")
			}
		})
	}
}

// noVNC 1.5.0's _sendEncodings list (core/rfb.js): the extension
// pseudo-encodings must not reach the server, or it enables client messages
// the filter closes on and the first keypress drops the viewer.
func TestFilterStripsExtensionEncodings(t *testing.T) {
	// neg(n) is the wire form of encoding -n.
	neg := func(n uint32) uint32 { return ^(n - 1) }
	novnc := []uint32{1, 7, neg(260), 16, 21, 5, 2, 0, neg(26), neg(254), neg(223), neg(224), neg(258), neg(261), neg(308), neg(309), neg(312), neg(313), neg(307), 0xC0A1E5CE, 0x574D5664, neg(239)}
	want := []uint32{1, 7, neg(260), 16, 21, 5, 2, 0, neg(26), neg(254), neg(223), neg(224), neg(307), 0x574D5664, neg(239)}
	const novncCount = 22
	if len(novnc) != novncCount {
		t.Fatalf("fixture has %d encodings, header says %d", len(novnc), novncCount)
	}
	msg := []byte{2, 0, 0, novncCount}
	for _, e := range novnc {
		msg = binary.BigEndian.AppendUint32(msg, e)
	}
	f := newFilter(func() bool { return true }, true)
	handshake := append([]byte("RFB 003.008\n"), 1, 1)
	if _, err := f.feed(handshake); err != nil {
		t.Fatal(err)
	}
	out, err := f.feed(msg)
	if err != nil {
		t.Fatal(err)
	}
	if got := int(binary.BigEndian.Uint16(out[2:4])); got != len(want) || len(out) != 4+4*len(want) {
		t.Fatalf("count=%d len=%d, want %d encodings", got, len(out), len(want))
	}
	for i, e := range want {
		if got := binary.BigEndian.Uint32(out[4+4*i:]); got != e {
			t.Fatalf("encoding %d = %#x, want %#x", i, got, e)
		}
	}
}

// A hostile ClientInit byte equal to the SetEncodings type must pass through
// as the one-byte handshake message it is, not be parsed as SetEncodings.
func TestFilterClientInitByteIsNotAMessage(t *testing.T) {
	f := newFilter(func() bool { return false }, false)
	out, err := f.feed(append([]byte("RFB 003.008\n"), 1, msgSetEncodings))
	if err != nil {
		t.Fatal(err)
	}
	if want := append([]byte("RFB 003.008\n"), 1, msgSetEncodings); string(out) != string(want) {
		t.Fatalf("handshake altered: %q", out)
	}
}

// A foreign or missing Origin cannot exchange a ticket, and the refused
// attempt must not consume it.
func TestSessionExchangeRequiresOrigin(t *testing.T) {
	v, _ := testViewer(t)
	id, err := v.MintTicket("display", "control")
	if err != nil {
		t.Fatal(err)
	}
	post := func(origin string) int {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://viewer.example:8443/session", strings.NewReader(url.Values{"ticket": {id}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		v.ServeHTTP(w, r)
		return w.Code
	}
	for _, origin := range []string{"", "https://attacker.example", "http://viewer.example:8443"} {
		if code := post(origin); code != http.StatusForbidden {
			t.Fatalf("origin %q: %d, want 403", origin, code)
		}
	}
	if code := post(v.cfg.Origin); code != http.StatusNoContent {
		t.Fatalf("ticket consumed by refused attempts: %d", code)
	}
}
