// Package ipc implements the controller<->worker protocol from
// docs/design/phase3-technical-design.md section 4: versioned JSON
// over a peer-credential-checked Unix domain socket, one
// newline-delimited frame per message. The message struct definitions
// below must be kept in sync with that document if it changes.
package ipc

// ProtocolVersion is the "v" field every message carries. A worker
// that receives a message with a different version must refuse it
// (see dispatch.go) rather than guess at compatibility.
const ProtocolVersion = 1

// Target is the wire representation of one device -- IP/MAC as
// strings, parsed by the caller (worker.Target uses net.IP /
// net.HardwareAddr instead).
type Target struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

// Envelope is used to peek at "v" and "op" before unmarshaling the
// full message into its concrete type.
type Envelope struct {
	V  int    `json:"v"`
	Op string `json:"op"`
}

// ReplaceTargets is the controller->worker "replace_targets" op: a
// full replacement of the current generation, never an incremental
// add/remove.
type ReplaceTargets struct {
	V          int      `json:"v"`
	Op         string   `json:"op"`
	Generation uint64   `json:"generation"`
	Gateway    Target   `json:"gateway"`
	Targets    []Target `json:"targets"`
	FullDuplex bool     `json:"full_duplex"`
}

// Heartbeat is the controller->worker "heartbeat" op that keeps the
// worker's lease alive (see worker.LeaseMonitor).
type Heartbeat struct {
	V        int    `json:"v"`
	Op       string `json:"op"`
	Sequence uint64 `json:"sequence"`
}

// ShutdownMsg is the controller->worker "shutdown" op: an intentional,
// graceful stop (as opposed to a lease expiry, which the worker
// detects on its own).
type ShutdownMsg struct {
	V      int    `json:"v"`
	Op     string `json:"op"`
	Reason string `json:"reason"`
}

// GenerationApplied is the worker->controller reply to a successfully
// (or partially) applied replace_targets.
type GenerationApplied struct {
	V                  int      `json:"v"`
	Op                 string   `json:"op"`
	Generation         uint64   `json:"generation"`
	TargetCount        int      `json:"target_count"`
	ResolutionFailures []string `json:"resolution_failures"`
}

// HeartbeatAck is the worker->controller reply to a heartbeat,
// carrying per-target sent-packet counters plus a global
// consecutive-send-failure count so the controller can escalate a
// sustained ARP-transmission failure (e.g. the bound interface going
// down) into a real fail_open report instead of that only ever
// showing up as a local worker log line (see
// worker.Worker.ConsecutiveSendFailures's own doc comment).
type HeartbeatAck struct {
	V                       int               `json:"v"`
	Op                      string            `json:"op"`
	Sequence                uint64            `json:"sequence"`
	SentCounters            map[string]uint64 `json:"sent_counters"`
	ConsecutiveSendFailures uint64            `json:"consecutive_send_failures"`
}

// Fault is an unsolicited worker->controller message reporting a
// problem the worker detected on its own (e.g. a lease expiry).
type Fault struct {
	V      int    `json:"v"`
	Op     string `json:"op"`
	Reason string `json:"reason"`
	Action string `json:"action"`
}
