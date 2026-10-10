// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	doctorCheckMCPIdentities = "mcp_identities"
	goosLinux                = "linux"
)

// checkDoctorMCPIdentities summarizes the mcp_identities registry: how many
// verified local services are registered, what each one matches and which
// acknowledgment binding mode it produces. A matched registration refuses to
// start on a host that cannot verify the kernel owner of the connection, so the
// non-Linux case is a warning rather than a note.
func checkDoctorMCPIdentities(cfg *config.Config, goos string) doctorReportCheck {
	if len(cfg.MCPIdentities) == 0 {
		return doctorReportCheck{
			Name:    doctorCheckMCPIdentities,
			Surface: doctorSurfaceMCP,
			Status:  doctorStatusInfo,
			Detail:  "no verified local services registered",
			Next:    "register a local MCP service with `pipelock mcp identity register` when a per-session credential should be acknowledged once per service",
		}
	}

	parts := make([]string, 0, len(cfg.MCPIdentities))
	for i := range cfg.MCPIdentities {
		parts = append(parts, describeMCPIdentity(cfg.MCPIdentities[i]))
	}
	check := doctorReportCheck{
		Name:       doctorCheckMCPIdentities,
		Surface:    doctorSurfaceMCP,
		Status:     doctorStatusOK,
		Configured: true,
		Detail:     fmt.Sprintf("%d registered: %s", len(parts), strings.Join(parts, "; ")),
		Next:       "run `pipelock mcp identity inspect --upstream <url>` against the live service to prove the pins still match",
	}
	if goos != goosLinux {
		check.Status = doctorStatusWarn
		check.Detail = fmt.Sprintf("%d registered, but verified local service requires Linux: any launch whose upstream matches a registration will refuse to start on %s; %s", len(parts), goos, strings.Join(parts, "; "))
		check.Next = "load these registrations only on Linux hosts, or remove them from configs this host loads"
	}
	return check
}

func describeMCPIdentity(id config.MCPIdentity) string {
	svc := id.VerifiedLocalService
	if svc == nil {
		return id.Name + " (no verified_local_service)"
	}
	shape := []string{fmt.Sprintf("%s://%s%s", svc.Scheme, svc.Host, svc.Path)}
	if svc.SessionHeader != nil {
		shape = append(shape, "session header "+svc.SessionHeader.Name)
	} else {
		shape = append(shape, "no session header")
	}
	shape = append(shape, fmt.Sprintf("%d mapped files", len(svc.MappedFiles)))
	shape = append(shape, fmt.Sprintf("%d control env", len(svc.ControlEnvironment)))
	shape = append(shape, "binding "+config.MCPAckBindingModeVerifiedLocalSession)
	return id.Name + " (" + strings.Join(shape, ", ") + ")"
}

func currentDoctorGOOS() string { return runtime.GOOS }
