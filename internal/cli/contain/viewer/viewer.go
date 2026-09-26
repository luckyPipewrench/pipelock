// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package viewer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	leaseLifetime  = 30 * time.Second
	defaultViewers = 4
	maxFrame       = 1 << 20
	maxCutText     = 256 << 10
)

// Config identifies the agent-owned RFB socket and its expected peer.
type Config struct {
	Display     string
	SocketPath  string
	Clipboard   bool
	MaxViewers  int
	Dial        func() (net.Conn, error)
	ExpectedUID uint32
	PeerUID     func(net.Conn) (uint32, error)
	Now         func() time.Time
	Logger      *slog.Logger
}

type lease struct {
	conn    net.Conn
	expires time.Time
}

type Viewer struct {
	cfg     Config
	mu      sync.Mutex
	lease   lease
	viewers int
}

func New(cfg Config) (*Viewer, error) {
	if cfg.Display == "" {
		return nil, errors.New("viewer: missing display")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxViewers <= 0 {
		cfg.MaxViewers = defaultViewers
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Dial == nil {
		if cfg.SocketPath == "" {
			return nil, errors.New("viewer: missing socket")
		}
		cfg.Dial = func() (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(context.Background(), "unix", cfg.SocketPath)
		}
	}
	if cfg.PeerUID == nil {
		cfg.PeerUID = peerUID
	}
	return &Viewer{cfg: cfg}, nil
}

// Serve joins one authorized operator connection to the agent-owned RFB socket.
// It writes the one-line control response before forwarding raw RFB bytes.
func (v *Viewer) Serve(ctx context.Context, client net.Conn, mode string) error {
	if mode != "view" && mode != "control" {
		_, _ = io.WriteString(client, "denied\n")
		return errors.New("viewer: invalid mode")
	}
	v.mu.Lock()
	if v.viewers >= v.cfg.MaxViewers {
		v.mu.Unlock()
		_, _ = io.WriteString(client, "denied\n")
		return errors.New("viewer: viewer cap reached")
	}
	if mode == "control" && v.lease.conn != nil {
		v.mu.Unlock()
		_, _ = io.WriteString(client, "busy\n")
		return errors.New("viewer: control busy")
	}
	v.viewers++
	if mode == "control" {
		v.lease = lease{client, v.cfg.Now().Add(leaseLifetime)}
	}
	v.mu.Unlock()
	defer func() {
		v.mu.Lock()
		v.viewers--
		if v.lease.conn == client {
			v.lease = lease{}
		}
		v.mu.Unlock()
	}()

	upstream, err := v.cfg.Dial()
	if err != nil {
		_, _ = io.WriteString(client, "denied\n")
		return fmt.Errorf("viewer: dial RFB: %w", err)
	}
	defer func() { _ = upstream.Close() }()
	if v.cfg.ExpectedUID != 0 {
		uid, peerErr := v.cfg.PeerUID(upstream)
		if peerErr != nil {
			_, _ = io.WriteString(client, "denied\n")
			return fmt.Errorf("viewer: inspect RFB peer: %w", peerErr)
		}
		if uid != v.cfg.ExpectedUID {
			_, _ = io.WriteString(client, "denied\n")
			return fmt.Errorf("viewer: RFB peer uid %d differs from expected uid %d", uid, v.cfg.ExpectedUID)
		}
	}
	if _, err := io.WriteString(client, "ok\n"); err != nil {
		return fmt.Errorf("viewer: acknowledge operator: %w", err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
			_ = upstream.Close()
		case <-stop:
		}
	}()
	if mode == "control" {
		go v.renewLease(stop, client)
	}
	serverDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(client, upstream)
		serverDone <- copyErr
		_ = client.Close()
	}()
	filter := newFilter(func() bool { return v.controls(client) }, v.cfg.Clipboard)
	buf := make([]byte, 32<<10)
	var inputErr error
	handshakeDeadline := time.Now().Add(10 * time.Second)
	for {
		deadline := time.Now().Add(5 * time.Minute)
		if filter.stage < 3 {
			deadline = handshakeDeadline
		}
		_ = client.SetReadDeadline(deadline)
		n, readErr := client.Read(buf)
		if n > 0 {
			out, filterErr := filter.feed(buf[:n])
			if filterErr != nil {
				inputErr = fmt.Errorf("viewer: filter RFB input: %w", filterErr)
				break
			}
			if len(out) > 0 {
				_ = upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, writeErr := upstream.Write(out); writeErr != nil {
					inputErr = fmt.Errorf("viewer: write RFB input: %w", writeErr)
					break
				}
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) && ctx.Err() == nil {
				inputErr = fmt.Errorf("viewer: read RFB input: %w", readErr)
			}
			break
		}
	}
	_ = upstream.Close()
	_ = client.Close()
	serverErr := <-serverDone
	if inputErr != nil {
		return inputErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if serverErr != nil && !errors.Is(serverErr, net.ErrClosed) {
		return fmt.Errorf("viewer: read RFB display: %w", serverErr)
	}
	return nil
}

func (v *Viewer) controls(client net.Conn) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lease.conn == client && v.cfg.Now().Before(v.lease.expires)
}

func (v *Viewer) renewLease(stop <-chan struct{}, client net.Conn) {
	ticker := time.NewTicker(leaseLifetime / 3)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			v.mu.Lock()
			if v.lease.conn == client {
				v.lease.expires = v.cfg.Now().Add(leaseLifetime)
			}
			v.mu.Unlock()
		}
	}
}
