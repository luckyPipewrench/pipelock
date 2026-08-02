// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

type developerEnvironmentPipe struct {
	reader  *os.File
	writer  *os.File
	payload []byte
}

func newDeveloperEnvironmentPipe(environment []string) (*developerEnvironmentPipe, error) {
	payload, err := encodeDeveloperEnvironment(environment)
	if err != nil {
		return nil, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("creating developer environment pipe: %w", err)
	}
	// The parent copies reader into ExtraFiles for the re-exec child. Mark both
	// original descriptors close-on-exec so neither can reach another process.
	syscall.CloseOnExec(int(reader.Fd()))
	syscall.CloseOnExec(int(writer.Fd()))
	return &developerEnvironmentPipe{reader: reader, writer: writer, payload: payload}, nil
}

func (p *developerEnvironmentPipe) writeAndClose() error {
	if p == nil || p.writer == nil {
		return errors.New("sandbox: developer environment pipe is unavailable")
	}
	defer func() { _ = p.writer.Close() }()
	n, err := p.writer.Write(p.payload)
	if err != nil {
		return fmt.Errorf("writing developer environment: %w", err)
	}
	if n != len(p.payload) {
		return io.ErrShortWrite
	}
	return nil
}

func (p *developerEnvironmentPipe) close() {
	if p == nil {
		return
	}
	if p.reader != nil {
		_ = p.reader.Close()
	}
	if p.writer != nil {
		_ = p.writer.Close()
	}
}
