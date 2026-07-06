// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package emit

import (
	"context"
	"errors"
	"log/syslog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseSyslogAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		wantNet  string
		wantAddr string
		wantErr  bool
	}{
		{name: "udp valid", addr: "udp://syslog.example.com:514", wantNet: networkUDP, wantAddr: testSyslogAddr514},
		{name: "tcp valid", addr: "tcp://syslog.example.com:514", wantNet: "tcp", wantAddr: testSyslogAddr514},
		{name: "UDP uppercase", addr: "UDP://syslog.example.com:514", wantNet: networkUDP, wantAddr: testSyslogAddr514},
		{name: "localhost with port", addr: "udp://127.0.0.1:1514", wantNet: networkUDP, wantAddr: "127.0.0.1:1514"},
		{name: "unsupported scheme", addr: "http://syslog.example.com:514", wantErr: true},
		{name: "empty scheme", addr: "://syslog.example.com:514", wantErr: true},
		{name: "missing host", addr: "udp://", wantErr: true},
		{name: "missing port", addr: "udp://syslog.example.com", wantErr: true},
		{name: "empty string", addr: "", wantErr: true},
		{name: "garbage", addr: "not-a-url", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNet, gotAddr, err := parseSyslogAddress(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseSyslogAddress(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if gotNet != tt.wantNet {
				t.Errorf("network = %q, want %q", gotNet, tt.wantNet)
			}
			if gotAddr != tt.wantAddr {
				t.Errorf("address = %q, want %q", gotAddr, tt.wantAddr)
			}
		})
	}
}

func TestParseFacility(t *testing.T) {
	tests := []struct {
		name string
		want syslog.Priority
	}{
		{"kern", syslog.LOG_KERN},
		{"user", syslog.LOG_USER},
		{"mail", syslog.LOG_MAIL},
		{"daemon", syslog.LOG_DAEMON},
		{"auth", syslog.LOG_AUTH},
		{"syslog", syslog.LOG_SYSLOG},
		{"lpr", syslog.LOG_LPR},
		{"news", syslog.LOG_NEWS},
		{"uucp", syslog.LOG_UUCP},
		{"local0", syslog.LOG_LOCAL0},
		{"local1", syslog.LOG_LOCAL1},
		{"local2", syslog.LOG_LOCAL2},
		{"local3", syslog.LOG_LOCAL3},
		{"local4", syslog.LOG_LOCAL4},
		{"local5", syslog.LOG_LOCAL5},
		{"local6", syslog.LOG_LOCAL6},
		{"local7", syslog.LOG_LOCAL7},
		{"LOCAL0", syslog.LOG_LOCAL0}, // case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseFacility(tt.name); got != tt.want {
				t.Errorf("parseFacility(%q) = %d, want %d", tt.name, got, tt.want)
			}
		})
	}

	// Unrecognized value defaults to LOG_LOCAL0
	t.Run("unrecognized", func(t *testing.T) {
		if got := parseFacility("bogus"); got != syslog.LOG_LOCAL0 {
			t.Errorf("parseFacility(\"bogus\") = %d, want LOG_LOCAL0 (%d)", got, syslog.LOG_LOCAL0)
		}
	})
}

func TestSyslogSink_Close_NilReceiver(t *testing.T) {
	var s *SyslogSink
	if err := s.Close(); err != nil {
		t.Errorf("Close() on nil receiver: %v", err)
	}
}

func TestSyslogSink_Close_NilWriter(t *testing.T) {
	s := &SyslogSink{}
	if err := s.Close(); err != nil {
		t.Errorf("Close() on nil writer: %v", err)
	}
}

func TestSyslogSink_EmitReturnsBeforeSlowWriter(t *testing.T) {
	writer := newBlockingSyslogWriter()
	sink := newSyslogSink(writer, &syslogConfig{queueLen: 1})

	event := Event{
		Severity:  SeverityWarn,
		Type:      testEventBlocked,
		Timestamp: time.Now(),
		Fields:    map[string]any{},
	}

	done := make(chan error, 1)
	go func() {
		done <- sink.Emit(context.Background(), event)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Emit returned error: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Emit blocked on syslog writer")
	}

	writer.waitStarted(t)
	writer.release()
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSyslogSink_EmitQueueFullIsBounded(t *testing.T) {
	writer := newBlockingSyslogWriter()
	sink := newSyslogSink(writer, &syslogConfig{queueLen: 1})

	event := Event{
		Severity:  SeverityWarn,
		Type:      testEventBlocked,
		Timestamp: time.Now(),
		Fields:    map[string]any{},
	}

	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	writer.waitStarted(t)

	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("second Emit: %v", err)
	}
	if err := sink.Emit(context.Background(), event); !errors.Is(err, ErrSyslogQueueFull) {
		t.Fatalf("third Emit error = %v, want ErrSyslogQueueFull", err)
	}
	stats := sink.Stats()
	if stats.Dropped != 1 || !stats.Degraded || stats.LastError != "queue_full" {
		t.Fatalf("stats = %+v, want queue_full drop", stats)
	}

	writer.release()
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSyslogSink_CloseDrainsQueuedEvents(t *testing.T) {
	writer := newBlockingSyslogWriter()
	sink := newSyslogSink(writer, &syslogConfig{queueLen: 4})

	for i := 0; i < 3; i++ {
		event := Event{
			Severity:  SeverityWarn,
			Type:      testEventBlocked,
			Timestamp: time.Now(),
			Fields:    map[string]any{"n": i},
		}
		if err := sink.Emit(context.Background(), event); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}

	writer.waitStarted(t)
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- sink.Close()
	}()
	waitSinkClosed(t, sink)
	writer.release()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Close")
	}
	if got := writer.count.Load(); got != 3 {
		t.Fatalf("writer calls = %d, want 3", got)
	}
	if err := sink.Emit(context.Background(), Event{Severity: SeverityWarn}); err == nil {
		t.Fatal("expected Emit to fail after Close")
	}
}

func TestSyslogSink_EmitSnapshotsFieldsBeforeEnqueue(t *testing.T) {
	writer := newBlockingSyslogWriter()
	sink := newSyslogSink(writer, &syslogConfig{queueLen: 4})

	first := Event{
		Severity:  SeverityWarn,
		Type:      testEventBlocked,
		Timestamp: time.Now(),
		Fields:    map[string]any{"reason": "first"},
	}
	if err := sink.Emit(context.Background(), first); err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	writer.waitStarted(t)

	nested := map[string]any{"value": "before"}
	list := []string{"before"}
	fields := map[string]any{"reason": "before"}
	fields["nested"] = nested
	fields["list"] = list
	second := Event{
		Severity:  SeverityWarn,
		Type:      testEventBlocked,
		Timestamp: time.Now(),
		Fields:    fields,
	}
	if err := sink.Emit(context.Background(), second); err != nil {
		t.Fatalf("second Emit: %v", err)
	}
	fields["reason"] = "after"
	nested["value"] = "after"
	list[0] = "after"

	writer.release()
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	messages := writer.messages()
	if len(messages) != 2 {
		t.Fatalf("messages = %d, want 2", len(messages))
	}
	if !contains(messages[1], `"reason":"before"`) {
		t.Fatalf("second message missing original field value:\n%s", messages[1])
	}
	if contains(messages[1], `"reason":"after"`) {
		t.Fatalf("second message used mutated field value:\n%s", messages[1])
	}
	if !contains(messages[1], `"nested":{"value":"before"}`) {
		t.Fatalf("second message missing original nested value:\n%s", messages[1])
	}
	if contains(messages[1], `"nested":{"value":"after"}`) {
		t.Fatalf("second message used mutated nested value:\n%s", messages[1])
	}
	if !contains(messages[1], `"list":["before"]`) {
		t.Fatalf("second message missing original slice value:\n%s", messages[1])
	}
	if contains(messages[1], `"list":["after"]`) {
		t.Fatalf("second message used mutated slice value:\n%s", messages[1])
	}
}

func TestSyslogSink_PanicDropsOnlyCurrentEvent(t *testing.T) {
	writer := &panicOnceSyslogWriter{}
	sink := newSyslogSink(writer, &syslogConfig{queueLen: 2})

	for i := 0; i < 2; i++ {
		event := Event{
			Severity:  SeverityWarn,
			Type:      testEventBlocked,
			Timestamp: time.Now(),
			Fields:    map[string]any{"n": i},
		}
		if err := sink.Emit(context.Background(), event); err != nil {
			if !errors.Is(err, ErrSyslogDegraded) {
				t.Fatalf("Emit %d: %v", i, err)
			}
		}
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := writer.count.Load(); got != 2 {
		t.Fatalf("writer calls = %d, want 2", got)
	}
}

func TestSyslogSink_CloseTimeoutBoundsWait(t *testing.T) {
	oldTimeout := syslogDrainTimeout
	syslogDrainTimeout = 25 * time.Millisecond
	defer func() { syslogDrainTimeout = oldTimeout }()

	writer := newBlockingSyslogWriter()
	sink := newSyslogSink(writer, &syslogConfig{queueLen: 1})
	event := Event{
		Severity:  SeverityWarn,
		Type:      testEventBlocked,
		Timestamp: time.Now(),
		Fields:    map[string]any{},
	}
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	writer.waitStarted(t)

	start := time.Now()
	err := sink.Close()
	if !errors.Is(err, ErrSyslogCloseTimeout) {
		t.Fatalf("Close error = %v, want ErrSyslogCloseTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close took %s, want bounded wait", elapsed)
	}

	waitDone := make(chan struct{})
	go func() {
		sink.closeWG.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit after writer close")
	}
}

func TestSyslogSink_DrainTimeoutBoundsQueuedSend(t *testing.T) {
	oldTimeout := syslogDrainTimeout
	syslogDrainTimeout = -time.Nanosecond
	defer func() { syslogDrainTimeout = oldTimeout }()

	writer := &countingSyslogWriter{}
	sink := &SyslogSink{
		writer: writer,
		queue:  make(chan syslogMessage, 1),
	}
	msg, err := makeSyslogMessage(Event{
		Severity:  SeverityWarn,
		Type:      testEventBlocked,
		Timestamp: time.Now(),
		Fields:    map[string]any{},
	}, FormatJSON, "")
	if err != nil {
		t.Fatalf("makeSyslogMessage: %v", err)
	}
	sink.queue <- msg

	start := time.Now()
	sink.drain()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("drain took %s, want bounded wait", elapsed)
	}
	if got := writer.count.Load(); got != 0 {
		t.Fatalf("writer calls = %d, want 0", got)
	}
	stats := sink.Stats()
	if stats.Abandoned != 1 || !stats.Degraded {
		t.Fatalf("stats = %+v, want abandoned degraded event", stats)
	}
}

func TestSyslogSink_QueueSizeClamped(t *testing.T) {
	cfg := &syslogConfig{}
	WithSyslogQueueSize(MaxSyslogQueueSize + 1)(cfg)
	if cfg.queueLen != MaxSyslogQueueSize {
		t.Fatalf("queueLen = %d, want %d", cfg.queueLen, MaxSyslogQueueSize)
	}

	writer := &countingSyslogWriter{}
	sink := newSyslogSink(writer, cfg)
	defer func() { _ = sink.Close() }()
	if cap(sink.queue) != MaxSyslogQueueSize {
		t.Fatalf("queue capacity = %d, want %d", cap(sink.queue), MaxSyslogQueueSize)
	}
}

func TestSyslogSink_QueueSizeDefaults(t *testing.T) {
	cfg := &syslogConfig{}
	WithSyslogQueueSize(0)(cfg)
	if cfg.queueLen != DefaultSyslogQueueSize {
		t.Fatalf("queueLen = %d, want default %d", cfg.queueLen, DefaultSyslogQueueSize)
	}
}

func TestSyslogSink_EmitRejectsUninitialized(t *testing.T) {
	var nilSink *SyslogSink
	if err := nilSink.Emit(context.Background(), Event{}); err == nil {
		t.Fatal("expected nil sink Emit to fail")
	}

	emptySink := &SyslogSink{}
	if err := emptySink.Emit(context.Background(), Event{}); err == nil {
		t.Fatal("expected empty sink Emit to fail")
	}
}

func TestSyslogSink_DegradedAfterWriteErrorAndReturnsCloseError(t *testing.T) {
	writer := &errorSyslogWriter{closeErr: errSyslogWriterFailure}
	sink := newSyslogSink(writer, &syslogConfig{queueLen: 1})

	if err := sink.Emit(context.Background(), Event{
		Severity:  SeverityWarn,
		Type:      testEventBlocked,
		Timestamp: time.Now(),
		Fields:    map[string]any{},
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := sink.Close(); !errors.Is(err, errSyslogWriterFailure) {
		t.Fatalf("Close error = %v, want %v", err, errSyslogWriterFailure)
	}
	if got := writer.count.Load(); got != 1 {
		t.Fatalf("writer calls = %d, want 1", got)
	}
	stats := sink.Stats()
	if stats.Failed != 1 || !stats.Degraded || stats.LastError == "" {
		t.Fatalf("stats = %+v, want failed degraded sink with last error", stats)
	}
}

func TestSyslogSink_CloseReturnsStoredErrorOnRepeatedCalls(t *testing.T) {
	writer := &errorSyslogWriter{closeErr: errSyslogWriterFailure}
	sink := newSyslogSink(writer, &syslogConfig{queueLen: 1})

	if err := sink.Close(); !errors.Is(err, errSyslogWriterFailure) {
		t.Fatalf("first Close error = %v, want %v", err, errSyslogWriterFailure)
	}
	if err := sink.Close(); !errors.Is(err, errSyslogWriterFailure) {
		t.Fatalf("second Close error = %v, want %v", err, errSyslogWriterFailure)
	}
	if got := writer.closeCount.Load(); got != 1 {
		t.Fatalf("writer Close calls = %d, want 1", got)
	}
}

func TestSyslogSink_EmitSignalsPriorDegradedState(t *testing.T) {
	writer := newBlockingSyslogWriter()
	sink := newSyslogSink(writer, &syslogConfig{queueLen: 2})
	sink.degraded.Store(true)

	err := sink.Emit(context.Background(), Event{
		Severity:  SeverityWarn,
		Type:      testEventBlocked,
		Timestamp: time.Now(),
		Fields:    map[string]any{},
	})
	if !errors.Is(err, ErrSyslogDegraded) {
		t.Fatalf("Emit error = %v, want ErrSyslogDegraded", err)
	}
	writer.waitStarted(t)
	writer.release()
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if stats := sink.Stats(); stats.Delivered != 1 || stats.Degraded {
		t.Fatalf("stats = %+v, want successful send to clear degraded state", stats)
	}
}

// startUDPSyslog starts a minimal UDP listener that acts as a syslog endpoint.
// Returns the listener address and a channel that receives each message.
func startUDPSyslog(t *testing.T) (string, <-chan string) {
	t.Helper()
	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(context.Background(), networkUDP, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	msgs := make(chan string, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			msgs <- string(buf[:n])
		}
	}()

	return conn.LocalAddr().String(), msgs
}

func TestNewSyslogSink_And_Emit(t *testing.T) {
	addr, msgs := startUDPSyslog(t)
	sink, err := NewSyslogSink("udp://"+addr, WithSyslogTag(testStr))
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	event := Event{
		Severity:   SeverityWarn,
		Type:       testEventBlocked,
		Timestamp:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		InstanceID: "test-1",
		Fields:     map[string]any{testFieldReason: "dlp_secret"},
	}

	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	select {
	case msg := <-msgs:
		// Syslog prepends a header; the JSON payload should be in there
		if len(msg) == 0 {
			t.Fatal("received empty message")
		}
		// Verify it contains our payload fields
		for _, want := range []string{`"severity":"warn"`, `"type":"blocked"`, `"pipelock_instance":"test-1"`, `"reason":"dlp_secret"`} {
			if !contains(msg, want) {
				t.Errorf("message missing %q:\n%s", want, msg)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for syslog message")
	}
}

func TestSyslogSink_Emit_CriticalSeverity(t *testing.T) {
	addr, msgs := startUDPSyslog(t)
	sink, err := NewSyslogSink("udp://" + addr)
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	event := Event{
		Severity:  SeverityCritical,
		Type:      EventKillSwitchDeny,
		Timestamp: time.Now(),
		Fields:    map[string]any{},
	}

	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	select {
	case msg := <-msgs:
		if !contains(msg, `"severity":"critical"`) {
			t.Errorf("expected critical severity in message:\n%s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for syslog message")
	}
}

func TestSyslogSink_Emit_InfoSeverity(t *testing.T) {
	addr, msgs := startUDPSyslog(t)
	sink, err := NewSyslogSink("udp://" + addr)
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	event := Event{
		Severity:  SeverityInfo,
		Type:      verdictAllowed,
		Timestamp: time.Now(),
		Fields:    map[string]any{},
	}

	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	select {
	case msg := <-msgs:
		if !contains(msg, `"severity":"info"`) {
			t.Errorf("expected info severity in message:\n%s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for syslog message")
	}
}

func TestSyslogSink_Emit_BelowMinSeverity(t *testing.T) {
	addr, msgs := startUDPSyslog(t)
	sink, err := NewSyslogSink("udp://"+addr, WithSyslogMinSeverity(SeverityWarn))
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	event := Event{
		Severity:  SeverityInfo,
		Type:      verdictAllowed,
		Timestamp: time.Now(),
		Fields:    map[string]any{},
	}

	// Should be silently dropped
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	select {
	case msg := <-msgs:
		t.Fatalf("expected no message, got: %s", msg)
	case <-time.After(200 * time.Millisecond):
		// Good - nothing received
	}
}

func TestNewSyslogSink_InvalidAddress(t *testing.T) {
	_, err := NewSyslogSink("http://example.com:514")
	if err == nil {
		t.Error("expected error for unsupported scheme")
	}
}

func TestNewSyslogSink_DialFailure(t *testing.T) {
	// Bind a TCP port, then close it - guarantees nothing is listening.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	_, err = NewSyslogSink("tcp://" + addr)
	if err == nil {
		t.Error("expected error for unreachable address")
	}
}

func TestNewSyslogSinkFromConfig(t *testing.T) {
	addr, _ := startUDPSyslog(t)

	sink, err := NewSyslogSinkFromConfig("udp://"+addr, "local3", "myapp", testSeverityWarn, WithSyslogFormat(FormatJSON, ""))
	if err != nil {
		t.Fatalf("NewSyslogSinkFromConfig: %v", err)
	}
	defer func() { _ = sink.Close() }()

	if sink.minSev != SeverityWarn {
		t.Errorf("minSev = %v, want SeverityWarn", sink.minSev)
	}
}

func TestNewSyslogSinkFromConfig_Defaults(t *testing.T) {
	addr, _ := startUDPSyslog(t)

	sink, err := NewSyslogSinkFromConfig("udp://"+addr, "", "", "")
	if err != nil {
		t.Fatalf("NewSyslogSinkFromConfig: %v", err)
	}
	defer func() { _ = sink.Close() }()
}

func TestNewSyslogSinkFromConfig_InvalidAddress(t *testing.T) {
	_, err := NewSyslogSinkFromConfig("not-valid", "", "", "")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestNewSyslogSinkFromConfig_InvalidFormat(t *testing.T) {
	addr, _ := startUDPSyslog(t)

	_, err := NewSyslogSinkFromConfig("udp://"+addr, "", "", "", WithSyslogFormat("xml", ""))
	if err == nil {
		t.Fatal("expected invalid format error")
	}
	if !contains(err.Error(), `unsupported syslog format "xml"`) {
		t.Fatalf("error = %v", err)
	}
}

func TestMakeSyslogMessage_CEF(t *testing.T) {
	msg, err := makeSyslogMessage(Event{
		Severity:   SeverityWarn,
		Type:       EventHeaderDLP,
		Timestamp:  time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC),
		InstanceID: testInstanceName,
		Fields: map[string]any{
			"action":    conventionActionBlock,
			"agent":     "agent-a",
			fieldReason: "header token",
		},
	}, FormatCEF, "1.2.3")
	if err != nil {
		t.Fatalf("makeSyslogMessage CEF: %v", err)
	}
	want := "CEF:0|Pipelock|Pipelock|1.2.3|header_dlp|header_dlp: header token|6|act=block cat=header_dlp msg=header token pipelockEvent=header_dlp pipelockInstance=test-instance pipelockSeverity=warn rt=2026-07-05T12:00:00Z suser=agent-a"
	if msg.message != want {
		t.Fatalf("message =\n%s\nwant\n%s", msg.message, want)
	}
}

func TestMakeSyslogMessage_InvalidFormat(t *testing.T) {
	_, err := makeSyslogMessage(Event{
		Severity:  SeverityWarn,
		Type:      EventHeaderDLP,
		Timestamp: time.Now(),
	}, "xml", "")
	if err == nil {
		t.Fatal("expected invalid format error")
	}
	if !contains(err.Error(), `unsupported syslog format "xml"`) {
		t.Fatalf("error = %v", err)
	}
}

func TestSyslogSink_Emit_MarshalError(t *testing.T) {
	writer := &countingSyslogWriter{}
	sink := newSyslogSink(writer, &syslogConfig{queueLen: 1})

	// Channel field is unmarshalable. Async delivery logs the marshal failure
	// before enqueue and drops the event without doing writer I/O.
	event := Event{
		Severity:  SeverityWarn,
		Type:      testEventBlocked,
		Timestamp: time.Now(),
		Fields:    map[string]any{"bad": make(chan int)},
	}

	err := sink.Emit(context.Background(), event)
	if err == nil {
		t.Fatal("expected marshal error from Emit")
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := writer.count.Load(); got != 0 {
		t.Fatalf("writer calls = %d, want 0", got)
	}
}

func TestSyslogOptions(t *testing.T) {
	cfg := &syslogConfig{}

	WithSyslogFacility(syslog.LOG_AUTH)(cfg)
	if cfg.facility != syslog.LOG_AUTH {
		t.Errorf("facility = %v, want LOG_AUTH", cfg.facility)
	}

	WithSyslogTag("custom")(cfg)
	if cfg.tag != "custom" {
		t.Errorf("tag = %q, want %q", cfg.tag, "custom")
	}

	WithSyslogMinSeverity(SeverityCritical)(cfg)
	if cfg.minSev != SeverityCritical {
		t.Errorf("minSev = %v, want SeverityCritical", cfg.minSev)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

type blockingSyslogWriter struct {
	started  chan struct{}
	releaseC chan struct{}
	mu       sync.Mutex
	logs     []string
	count    atomic.Int64
	closed   atomic.Bool
}

func newBlockingSyslogWriter() *blockingSyslogWriter {
	return &blockingSyslogWriter{
		started:  make(chan struct{}),
		releaseC: make(chan struct{}),
	}
}

func (w *blockingSyslogWriter) Crit(msg string) error {
	return w.write(msg)
}

func (w *blockingSyslogWriter) Warning(msg string) error {
	return w.write(msg)
}

func (w *blockingSyslogWriter) Info(msg string) error {
	return w.write(msg)
}

func (w *blockingSyslogWriter) Close() error {
	w.closed.Store(true)
	w.release()
	return nil
}

func (w *blockingSyslogWriter) write(msg string) error {
	w.count.Add(1)
	w.mu.Lock()
	w.logs = append(w.logs, msg)
	w.mu.Unlock()
	select {
	case <-w.started:
	default:
		close(w.started)
	}
	<-w.releaseC
	return nil
}

func (w *blockingSyslogWriter) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-w.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for syslog writer")
	}
}

func (w *blockingSyslogWriter) release() {
	select {
	case <-w.releaseC:
	default:
		close(w.releaseC)
	}
}

func (w *blockingSyslogWriter) messages() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, len(w.logs))
	copy(out, w.logs)
	return out
}

func waitSinkClosed(t *testing.T, sink *SyslogSink) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		sink.closeMu.Lock()
		closed := sink.closed
		sink.closeMu.Unlock()
		if closed {
			return
		}
		select {
		case <-deadline:
			t.Fatal("timeout waiting for sink close to start")
		case <-ticker.C:
		}
	}
}

type countingSyslogWriter struct {
	count  atomic.Int64
	closed atomic.Bool
}

func (w *countingSyslogWriter) Crit(msg string) error {
	return w.write(msg)
}

func (w *countingSyslogWriter) Warning(msg string) error {
	return w.write(msg)
}

func (w *countingSyslogWriter) Info(msg string) error {
	return w.write(msg)
}

func (w *countingSyslogWriter) Close() error {
	w.closed.Store(true)
	return nil
}

func (w *countingSyslogWriter) write(_ string) error {
	w.count.Add(1)
	return nil
}

type panicOnceSyslogWriter struct {
	count  atomic.Int64
	closed atomic.Bool
}

func (w *panicOnceSyslogWriter) Crit(msg string) error {
	return w.write(msg)
}

func (w *panicOnceSyslogWriter) Warning(msg string) error {
	return w.write(msg)
}

func (w *panicOnceSyslogWriter) Info(msg string) error {
	return w.write(msg)
}

func (w *panicOnceSyslogWriter) Close() error {
	w.closed.Store(true)
	return nil
}

func (w *panicOnceSyslogWriter) write(_ string) error {
	if w.count.Add(1) == 1 {
		panic("syslog write panic")
	}
	return nil
}

var errSyslogWriterFailure = errors.New("syslog writer failure")

type errorSyslogWriter struct {
	count      atomic.Int64
	closeCount atomic.Int64
	closeErr   error
}

func (w *errorSyslogWriter) Crit(msg string) error {
	return w.write(msg)
}

func (w *errorSyslogWriter) Warning(msg string) error {
	return w.write(msg)
}

func (w *errorSyslogWriter) Info(msg string) error {
	return w.write(msg)
}

func (w *errorSyslogWriter) Close() error {
	w.closeCount.Add(1)
	return w.closeErr
}

func (w *errorSyslogWriter) write(_ string) error {
	w.count.Add(1)
	return errSyslogWriterFailure
}
