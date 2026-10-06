// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestVerifyCountsFilesystemOffWithoutFailing(t *testing.T) {
	env := allPassEnv(t)
	env.filesystemProbe = func(context.Context, *probeEnv) (string, string) {
		return statusFilesystemOff, "filesystem profile: off"
	}
	cmd := newVerifyCmd(t)
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := runVerify(cmd, env, verifyOpts{}); err != nil {
		t.Fatalf("runVerify = %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "[OFF]") || !strings.Contains(out, "1 OFF") {
		t.Fatalf("output =\n%s", out)
	}
	if strings.Contains(out, "[N/A] probe") && strings.Contains(out, "filesystem") {
		t.Fatalf("off filesystem was rendered as not applicable:\n%s", out)
	}
}
