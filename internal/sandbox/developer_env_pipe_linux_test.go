// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestDeveloperEnvironmentPipeWriteFailsClosedWhenReaderDoesNotDrain(t *testing.T) {
	payload := "SECRET=" + strings.Repeat("x", developerEnvironmentMaxPayload-64)
	pipe, err := newDeveloperEnvironmentPipe([]string{payload})
	if err != nil {
		t.Fatalf("newDeveloperEnvironmentPipe: %v", err)
	}
	defer pipe.close()

	result := make(chan error, 1)
	go func() { result <- pipe.writeAndCloseWithin(250 * time.Millisecond) }()

	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("writeAndCloseWithin error = %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("writeAndCloseWithin hung after the reader did not drain")
	}
}

func TestDeveloperEnvironmentPipeWriteFailsClosedWhenReaderCloses(t *testing.T) {
	pipe, err := newDeveloperEnvironmentPipe([]string{"SECRET=value"})
	if err != nil {
		t.Fatalf("newDeveloperEnvironmentPipe: %v", err)
	}
	defer pipe.close()
	if err := pipe.reader.Close(); err != nil {
		t.Fatalf("close pipe reader: %v", err)
	}

	if err := pipe.writeAndCloseWithin(time.Second); err == nil {
		t.Fatal("writeAndCloseWithin succeeded after the reader closed")
	}
}

func TestDeveloperEnvironmentPipeWritesMaximumPayloadWhenReaderDrains(t *testing.T) {
	entry := "SECRET=" + strings.Repeat("x", developerEnvironmentMaxPayload-16-len("SECRET="))
	pipe, err := newDeveloperEnvironmentPipe([]string{entry})
	if err != nil {
		t.Fatalf("newDeveloperEnvironmentPipe: %v", err)
	}
	defer pipe.close()
	if len(pipe.payload) != developerEnvironmentMaxPayload {
		t.Fatalf("payload length = %d, want %d", len(pipe.payload), developerEnvironmentMaxPayload)
	}

	decoded := make(chan []string, 1)
	readErr := make(chan error, 1)
	go func() {
		payload, err := io.ReadAll(pipe.reader)
		if err != nil {
			readErr <- err
			return
		}
		environment, err := decodeDeveloperEnvironment(payload)
		if err != nil {
			readErr <- err
			return
		}
		decoded <- environment
	}()

	if err := pipe.writeAndClose(); err != nil {
		t.Fatalf("writeAndClose: %v", err)
	}
	select {
	case err := <-readErr:
		t.Fatalf("reading pipe: %v", err)
	case environment := <-decoded:
		if len(environment) != 1 || environment[0] != entry {
			t.Fatal("maximum developer environment payload did not round trip")
		}
	case <-time.After(time.Second):
		t.Fatal("reader did not receive the maximum developer environment payload")
	}
}
