// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"bytes"
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
		return unknown("managed contained-launch wrapper could not be read", "restore access to the managed wrapper and rerun `pipelock contain install`")
	}
	if !doctorContainedLaunchWrapperMatches(body, wrapperDir, env) {
		return fail(classInfra, "managed contained-launch wrapper differs from the installed template; runtime socket isolation cannot be established", installRemedy)
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
	proxyParent := filepath.Dir(containedDoorwaySocketPath)
	expectedBinds := map[string]string{
		containedNamespaceForwarderUnit: canonicalBind(proxyParent, proxyParent, "rbind"),
	}
	for _, service := range services {
		unit := loopbackForwarderUnitBase(service.Host, service.Port) + "-netns.service"
		units = append(units, unit)
		parent := filepath.Dir(declaredLoopbackDoorwayPath(service.Host, service.Port))
		expectedBinds[unit] = canonicalBind(parent, parent, "rbind")
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
		out, code, showErr := env.runCmd(ctx, "systemctl", "show", unit, "--property=TemporaryFileSystem", "--value")
		if showErr != nil || code != 0 {
			return unknown("runtime mounts for "+unit+" could not be read", "restore access to systemctl and rerun `pipelock contain doctor`")
		}
		if err := sameLifecyclePathList(strings.TrimSpace(out), runtimeSocketTemporaryFileSystems()); err != nil {
			return fail(classInfra, "managed unit "+unit+" lacks runtime socket isolation", installRemedy)
		}
		if expected, forwarder := expectedBinds[unit]; forwarder {
			out, code, showErr := env.runCmd(ctx, "systemctl", "show", unit, "--property=BindReadOnlyPaths", "--value")
			if showErr != nil || code != 0 {
				return unknown("runtime doorway bind for "+unit+" could not be read", "restore access to systemctl and rerun `pipelock contain doctor`")
			}
			binds, parseErr := parseSystemdBindShow(strings.TrimSpace(out))
			if parseErr != nil || !sameBindList(binds, []string{expected}) {
				return fail(classInfra, "managed unit "+unit+" lacks its runtime doorway bind", installRemedy)
			}
		}
	}
	return pass("managed contained-launch wrapper and configured namespace/display units specify runtime socket masks; live mounts are verified at launch")
}

func doctorContainedLaunchWrapperMatches(body []byte, wrapperDir string, env *doctorEnv) bool {
	expected := &installEnv{
		wrapperDir:               wrapperDir,
		networkNamespaceUnitPath: containedNetworkNamespaceUnit,
		pipelockTarget:           env.pipelockTarget,
		agentUserName:            env.agentUserName,
		agentHome:                env.agentHome,
		bashPath:                 env.bashPath,
	}
	// Installation supports both systemd versions with and without this
	// optional flag. Require the entire generated script, including the exec
	// invocation, so unused arrays or altered control flow cannot pass.
	for _, version := range []int{0, systemdExpandEnvironmentMinVersion} {
		expected.systemdVersion = version
		if bytes.Equal(body, []byte(renderContainedLaunchWrapper(expected))) {
			return true
		}
	}
	return false
}
