// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const developerEnvironmentPipeWriteTimeout = 5 * time.Second

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
	return p.writeAndCloseWithin(developerEnvironmentPipeWriteTimeout)
}

// writeAndCloseWithin writes the bounded payload while retaining a deadline for
// the case where a re-exec child remains alive but never reads its descriptor.
// Nonblocking writes plus poll avoid an uninterruptible write syscall, so the
// caller can kill the child and fail closed instead of waiting forever.
func (p *developerEnvironmentPipe) writeAndCloseWithin(timeout time.Duration) error {
	if p == nil || p.writer == nil {
		return errors.New("sandbox: developer environment pipe is unavailable")
	}
	defer func() { _ = p.writer.Close() }()

	rawFD := p.writer.Fd()
	if rawFD > math.MaxInt32 {
		return errors.New("sandbox: developer environment pipe descriptor is out of range")
	}
	fd := int(rawFD)
	if err := unix.SetNonblock(fd, true); err != nil {
		return fmt.Errorf("setting developer environment pipe nonblocking: %w", err)
	}
	deadline := time.Now().Add(timeout)
	remaining := p.payload
	for len(remaining) > 0 {
		n, err := unix.Write(fd, remaining)
		if n > 0 {
			remaining = remaining[n:]
		}
		if err == nil {
			if n == 0 {
				return io.ErrShortWrite
			}
			continue
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			return fmt.Errorf("writing developer environment: %w", err)
		}
		if timeout <= 0 {
			return errors.New("sandbox: developer environment pipe write timed out")
		}

		wait := time.Until(deadline)
		if wait <= 0 {
			return errors.New("sandbox: developer environment pipe write timed out")
		}
		waitMillis := int((wait + time.Millisecond - 1) / time.Millisecond)
		ready, pollErr := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}, waitMillis)
		if pollErr != nil {
			if errors.Is(pollErr, unix.EINTR) {
				continue
			}
			return fmt.Errorf("waiting to write developer environment: %w", pollErr)
		}
		if ready == 0 {
			return errors.New("sandbox: developer environment pipe write timed out")
		}
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
