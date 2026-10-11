// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func probeDoctorRuntimeSockets(ctx context.Context, env *doctorEnv) doctorResult {
	if env.readFile == nil || env.runCmd == nil {
		return unknown("runtime socket isolation could not be read", "restore access and rerun `pipelock contain doctor`")
	}
	wrapperDir := env.wrapperDir
	if wrapperDir == "" {
		wrapperDir = defaultWrapperDir
	}
	wrapperPath := filepath.Join(wrapperDir, "plk-contained-launch")
	body, err := env.readFile(wrapperPath)
	if os.IsNotExist(err) {
		return fail(classInfra, "managed contained-launch wrapper is missing", installRemedy)
	}
	if err != nil {
		return unknown("managed contained-launch wrapper could not be read", "restore access and rerun `pipelock contain doctor`")
	}
	flags := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		flags[strings.TrimSpace(line)] = true
	}
	for _, mount := range runtimeSocketTemporaryFileSystems() {
		if !flags["--property=TemporaryFileSystem="+mount] {
			return fail(classInfra, "managed contained-launch wrapper lacks runtime socket isolation", installRemedy)
		}
	}
	probe := filesystemProbeEnvForDoctor(env)
	services, problem, unusable := declaredContainmentLoopbackServicesForVerify(probe, probe.port)
	if unusable {
		return fail(classInfra, "managed runtime socket units cannot be determined: "+problem, installRemedy)
	}
	if problem != "" && !strings.HasPrefix(problem, "no managed config was found at ") {
		return unknown("managed runtime socket units cannot be determined: "+problem, "restore access and rerun `pipelock contain doctor`")
	}
	units := []string{containedNamespaceForwarderUnit}
	for _, service := range services {
		units = append(units, loopbackForwarderUnitBase(service.Host, service.Port)+"-netns.service")
	}
	if env.configPath != "" {
		cfg, loadErr := config.LoadForInspection(env.configPath)
		if loadErr != nil && !os.IsNotExist(loadErr) {
			return unknown("managed display runtime mounts cannot be determined from the configuration", "repair the managed configuration and rerun `pipelock contain install`")
		}
		if loadErr == nil && cfg.Containment.Display.IsEnabled(true) {
			displayUnit := env.displayUnitPath
			if displayUnit == "" {
				displayUnit = defaultDisplayUnitPath
			}
			units = append(units, filepath.Base(displayUnit))
		}
	}
	for _, unit := range units {
		out, _, showErr := env.runCmd(ctx, "systemctl", "show", unit, "--property=TemporaryFileSystem", "--value")
		if showErr != nil {
			return unknown("runtime mounts for "+unit+" could not be read", "restore access to systemctl and rerun `pipelock contain doctor`")
		}
		if err := sameLifecyclePathList(strings.TrimSpace(out), runtimeSocketTemporaryFileSystems()); err != nil {
			return fail(classInfra, "managed unit "+unit+" lacks runtime socket isolation", installRemedy)
		}
	}
	return pass("managed contained-launch wrapper and namespace/display units hide host runtime sockets")
}
