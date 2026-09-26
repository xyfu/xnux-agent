// Package raw defines what the watchers hand to the rules engine (spec A3):
// either a finished event type with its data, or a security log record
// that only the security state machine turns into events (spec A4.2).
package raw

import "time"

// Security log record kinds (spec A3.3). They never leave the agent as-is.
const (
	SSHFail        = "ssh_fail"
	SSHInvalidUser = "ssh_invalid_user"
	SSHMaxAuth     = "ssh_max_auth"
	SSHAccept      = "ssh_accept"
	SudoCmd        = "sudo_cmd"
	SudoFail       = "sudo_fail"
	UserCreated    = "user_created"
	SuRoot         = "su_root"
)

// Record is one observation from a watcher.
type Record struct {
	// Kind is an event type (proto.Event*) or a security record kind above.
	Kind string
	TS   time.Time
	// Key is the fingerprint's primary key: unit, victim, device, exe, …
	Key string
	// Severity overrides the default for Kind (procscan decides per rule).
	Severity string
	Data     map[string]any
}
