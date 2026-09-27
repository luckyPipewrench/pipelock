// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package contain

import (
	"context"
	"errors"
	"os"
)

func runViewerACLCommand(context.Context, *os.File, string, ...string) (string, int, error) {
	return "", -1, errors.New("legacy viewer ACL cleanup requires Linux")
}

func removeViewerTraverseACLNoFollow(_ context.Context, env *installEnv) error {
	if env.agentHome == "" {
		return nil
	}
	return errors.New("legacy viewer ACL cleanup requires Linux")
}
