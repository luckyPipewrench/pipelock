// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package broker is the always-on front door for the public playground. It owns
// the abuse controls that cannot live inside a per-visitor microVM (per-IP /
// per-code / global rate limits + daily budgets, and the concurrency cap as a
// count of live machines), and it leases one ephemeral microVM per visitor via a
// MachineProvider, reverse-proxying the visitor's session to it and destroying
// it at session end.
//
// The per-visitor VM is the filesystem + visitor-vs-visitor isolation boundary;
// Pipelock plus the in-VM nft owner-match rule are the egress firewall inside
// it. The broker never sees agent secrets and holds no model-provider key beyond
// passing a per-session credential into the leased VM's environment.
package broker

import "context"

// Machine is the broker's view of one leased per-visitor microVM. Fields are the
// subset the broker needs to route to and tear down the VM; provider-specific
// detail stays in the adapter.
type Machine struct {
	// ID is the provider's machine identifier (used for wait/destroy).
	ID string
	// State is the provider-reported lifecycle state (e.g. "created",
	// "started", "stopped", "destroyed").
	State string
	// PrivateIP is the address the broker dials to reach the VM's server over
	// the provider's private network (Fly 6PN is an IPv6 address). Empty until
	// the machine has been assigned one.
	PrivateIP string
}

// MachineSpec describes the per-visitor VM to create. The broker fills it per
// lease; the provider adapter translates it to the provider's API.
type MachineSpec struct {
	// Image is the OCI image reference the VM boots (the playground image).
	Image string
	// Env is the environment passed to the VM (PLAYGROUND_* config plus the
	// per-session secrets and single-use invite code). Never logged.
	Env map[string]string
	// Region is the provider region to place the VM in. Empty = provider default.
	Region string
	// MemoryMB and CPUs size the guest. Zero = provider default.
	MemoryMB int
	CPUs     int
	// InternalPort is the port the VM's server listens on, reachable to the
	// broker over the private network. Zero = the spec's default.
	InternalPort int
}

// MachineProvider leases and tears down ephemeral per-visitor microVMs. It is an
// interface so the broker's lease lifecycle and abuse controls are tested
// against an in-memory fake, and the concrete provider (Fly Machines) is a thin,
// independently live-verified adapter. All methods must be context-cancellable
// and safe for concurrent use.
type MachineProvider interface {
	// CreateMachine provisions a VM from spec and returns it once the provider
	// has accepted it (state may still be "created"; call WaitReady before use).
	CreateMachine(ctx context.Context, spec MachineSpec) (*Machine, error)
	// WaitReady blocks until the machine reaches a started/usable state or the
	// context/provider timeout elapses. It must fail (not silently succeed) if
	// the machine never starts, so the broker fails closed and tears it down.
	WaitReady(ctx context.Context, id string) error
	// DestroyMachine force-destroys the machine. It must be idempotent: a
	// machine already gone is not an error, so teardown on a half-failed lease
	// never wedges.
	DestroyMachine(ctx context.Context, id string) error
}
