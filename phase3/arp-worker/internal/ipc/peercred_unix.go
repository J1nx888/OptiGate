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
// A UID match alone would be too coarse if this socket's path were
// reachable from more than the one legitimate caller, but Docker's
// per-container mount namespacing -- not just the `optigate_run`
// volume's naming convention -- means `nftables-manager`, `dashboard`,
// `proxy`, and `adguard` never mount this volume at all, so they have
// no filesystem path to this socket regardless of what UID they run
// as. `controller` runs as root (UID 0, matching this flag's own
// `${CONTROLLER_UID:-0}` compose default) and is the only other
// container sharing this volume. The residual gap -- some other
// process presenting host UID 0 on this socket, e.g. a compromised
// host root shell reaching the volume's real path directly -- is a
// real but separate exposure this check isn't meant to close: a
// compromised host root already has strictly worse options available,
// and without `--userns-remap` container UID 0 and host UID 0 are the
// same identity project-wide anyway. Revisit this check if
// `optigate_run` is ever mounted into a container other than
// arp-worker/controller, or if user-namespace remapping changes what
// UID 0 means across containers.
//
// NOT VERIFIED against a real build (no Go toolchain in this dev
// environment). unix.GetsockoptUcred is written from memory of
// golang.org/x/sys/unix's documented shape; confirm the exact
// signature once `go get golang.org/x/sys` has run.
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
