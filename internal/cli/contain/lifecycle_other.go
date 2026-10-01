// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package contain

import (
	"context"
	"errors"
)

func newContainRunLifecycle(string) (*containRunLifecycle, error) {
	return nil, errors.New("contain lifecycle evidence requires Linux")
}

func containRunLifecycleContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(ctx)
}
