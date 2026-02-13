package registry

import (
	"context"
	"time"
)

// Registration represents a single port registration.
type Registration struct {
	User        string
	Machine     string
	Port        int
	TailscaleIP string
	ExpiresAt   time.Time
	Alias       string // Optional alias name for this port
}

// MachineRef identifies a user/machine pair.
type MachineRef struct {
	User    string
	Machine string
}

// Store defines the interface for managing port registrations.
type Store interface {
	// Register records that a user's machine is exposing a port.
	Register(ctx context.Context, user, machine string, port int, tailscaleIP string) error

	// Deregister removes a port registration.
	Deregister(ctx context.Context, user, machine string, port int) error

	// RefreshHeartbeat extends the TTL on the given ports.
	RefreshHeartbeat(ctx context.Context, user, machine string, ports []int) error

	// Lookup returns the Tailscale IP for a given user/machine/port, or empty string if not found.
	Lookup(ctx context.Context, user, machine string, port int) (tailscaleIP string, err error)

	// ListByMachine returns all active registrations for a user's machine.
	ListByMachine(ctx context.Context, user, machine string) ([]Registration, error)

	// ListActiveMachines returns all user/machine pairs that have active registrations.
	ListActiveMachines(ctx context.Context) ([]MachineRef, error)

	// SaveUser persists user profile information.
	SaveUser(ctx context.Context, tailscaleID, loginName, displayName string) error

	// SaveMachine persists machine-to-IP mapping.
	SaveMachine(ctx context.Context, user, machineName, tailscaleIP string) error

	// RegisterAlias maps an alias to a port for a user's machine.
	RegisterAlias(ctx context.Context, user, machine, alias string, port int) error

	// DeregisterAlias removes an alias mapping.
	DeregisterAlias(ctx context.Context, user, machine, alias string) error

	// LookupAlias returns the port for a given alias, or 0 if not found.
	LookupAlias(ctx context.Context, user, machine, alias string) (port int, err error)

	// RefreshAliasHeartbeat extends the TTL on aliases for the given machine.
	RefreshAliasHeartbeat(ctx context.Context, user, machine string, aliases []string) error
}
