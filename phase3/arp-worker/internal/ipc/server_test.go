package ipc

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestServerNotify_DeliversToActiveConnection is a real, end-to-end
// check (a genuine Unix socket, not just the dispatch()-level fakes in
// dispatch_test.go) that Notify() actually reaches a connected client
// -- proving it writes to the wire, not just that the Go source
// compiles.
func TestServerNotify_DeliversToActiveConnection(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	h := &fakeHandler{}
	srv, err := Listen(sockPath, uint32(os.Getuid()), h)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	go func() { _ = srv.Serve() }()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// A real heartbeat round-trip first, rather than a fixed sleep, is
	// the deterministic way to know handleConn's own goroutine has
	// actually accepted the connection and installed its encoder before
	// Notify is expected to find one.
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	if err := enc.Encode(Heartbeat{V: ProtocolVersion, Op: "heartbeat", Sequence: 1}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
	var ack HeartbeatAck
	if err := dec.Decode(&ack); err != nil {
		t.Fatalf("decode heartbeat ack: %v", err)
	}

	fault := Fault{V: ProtocolVersion, Op: "fault", Reason: "lease_expired", Action: "entering_repair_only_mode"}
	if err := srv.Notify(fault); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var got Fault
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decode notified fault: %v", err)
	}
	if got.Reason != "lease_expired" || got.Action != "entering_repair_only_mode" {
		t.Fatalf("expected the exact fault Notify() sent, got %+v", got)
	}
}

// TestServerNotify_NoActiveConnectionReturnsError confirms Notify()
// fails cleanly (an error, not a panic or a silently dropped message)
// when nothing is connected -- e.g. the controller hasn't connected
// yet, or dropped between requests.
func TestServerNotify_NoActiveConnectionReturnsError(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test2.sock")
	h := &fakeHandler{}
	srv, err := Listen(sockPath, uint32(os.Getuid()), h)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	if err := srv.Notify(Fault{V: ProtocolVersion, Op: "fault", Reason: "x", Action: "y"}); err == nil {
		t.Fatal("expected Notify to return an error with no active connection, got nil")
	}
}

// TestServerNotify_ClearsEncoderAfterDisconnect confirms a SECOND
// Notify(), issued after the one connection that was active has
// disconnected, also fails cleanly rather than writing into a closed
// net.Conn -- setEncoder(nil) in handleConn's own deferred cleanup is
// what this depends on.
func TestServerNotify_ClearsEncoderAfterDisconnect(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test3.sock")
	h := &fakeHandler{}
	srv, err := Listen(sockPath, uint32(os.Getuid()), h)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	go func() { _ = srv.Serve() }()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	if err := enc.Encode(Heartbeat{V: ProtocolVersion, Op: "heartbeat", Sequence: 1}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
	var ack HeartbeatAck
	if err := dec.Decode(&ack); err != nil {
		t.Fatalf("decode heartbeat ack: %v", err)
	}
	conn.Close()

	// Give handleConn's own goroutine a moment to notice the closed
	// connection (scanner.Scan() returning false) and run its deferred
	// setEncoder(nil) -- polling Notify() itself is the deterministic
	// condition to wait on, rather than a fixed sleep guessing how long
	// that takes.
	deadline := time.Now().Add(2 * time.Second)
	var notifyErr error
	for time.Now().Before(deadline) {
		notifyErr = srv.Notify(Fault{V: ProtocolVersion, Op: "fault", Reason: "x", Action: "y"})
		if notifyErr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if notifyErr == nil {
		t.Fatal("expected Notify to return an error once the only connection has disconnected, got nil")
	}
}
