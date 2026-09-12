//go:build linux

package ipc

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// peerAllowed checks the connecting peer's UID via SO_PEERCRED. This
// is what makes the controller<->worker socket trust the actual
// process identity, not just "whoever can open this path" -- see
// docs/design/phase3-technical-design.md section 4.
//
// Examined 2026-09-12 (code review flagged this as "UID-only, not
// process/container identity" -- worth recording why it was left as-is
// rather than tightened): a UID match alone WOULD be too coarse if
// this socket's path were reachable from more than the one legitimate
// caller, but docker-compose.yml's own `optigate_run` volume comment
// ("Shared between arp-worker and controller ONLY") is enforced by
// Docker's per-container mount namespacing, not just convention --
// `nftables-manager`, `dashboard`, `proxy`, and `adguard` never mount
// this volume at all, so they have no filesystem path to this socket
// regardless of what UID they run as. `controller/Dockerfile` has no
// USER directive (runs as root, UID 0, matching this flag's own
// `${CONTROLLER_UID:-0}` compose default) and is the only OTHER
// container sharing this volume -- exactly the one caller this check
// is meant to allow. The residual gap (any OTHER process presenting
// host UID 0 on this socket, e.g. a compromised host root shell
// reaching the volume's real path directly, or a future sibling
// container that starts mounting `optigate_run`) is a real but
// separate exposure this check was never going to close: a compromised
// host root already has strictly worse options available (the shared
// DB, the containers themselves), and Docker's default (no
// `--userns-remap`) means container UID 0 and host UID 0 are the same
// identity project-wide, not something fixable in this one file. If
// `optigate_run` is ever mounted into a container OTHER than
// arp-worker/controller, or if user-namespace remapping changes what
// UID 0 means across containers, revisit this -- until then, no code
// change is warranted here.
//
// NOT VERIFIED against a real build (no Go toolchain in this dev
// environment -- see the design doc's header note). unix.GetsockoptUcred
// is written from memory of golang.org/x/sys/unix's documented shape;
// confirm the exact signature once `go get golang.org/x/sys` has run.
func peerAllowed(conn *net.UnixConn, allowedUID uint32) (ok bool, peerUID uint32, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false, 0, fmt.Errorf("syscall conn: %w", err)
	}

	var ucred *unix.Ucred
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return false, 0, ctrlErr
	}
	if sockErr != nil {
		return false, 0, sockErr
	}

	return ucred.Uid == allowedUID, ucred.Uid, nil
}

func unixRemoveStale(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
