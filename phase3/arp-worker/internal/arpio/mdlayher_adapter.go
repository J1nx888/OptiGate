//go:build linux

// Package arpio adapts github.com/mdlayher/arp to the worker.ARPSender
// interface (see internal/worker/types.go). This is the one piece of
// the whole project that actually needs CAP_NET_RAW.
//
// github.com/mdlayher/arp's Client.Resolve and arp.NewPacket take
// netip.Addr, not net.IP -- the conversion happens at the boundary
// (see toAddr) so the rest of the codebase (worker.ARPSender) can keep
// using net.IP, matching the stdlib and the rest of this project.
package arpio

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/arp"
)

// Client wraps *arp.Client to satisfy worker.ARPSender.
type Client struct {
	c *arp.Client
}

// Dial opens a raw-socket ARP client bound to ifi. Requires
// CAP_NET_RAW (or root) -- this should be the only capability the
// arp-worker binary is ever granted (see the systemd unit sketch in
// the design doc).
func Dial(ifi *net.Interface) (*Client, error) {
	c, err := arp.Dial(ifi)
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

// Close releases the underlying raw socket.
func (cl *Client) Close() error {
	return cl.c.Close()
}

// Resolve performs a genuine ARP request/reply exchange -- never
// served from a cache -- to learn ip's real hardware address. Used
// only by worker.ResolveGateway during startup safety checks.
func (cl *Client) Resolve(ip net.IP) (net.HardwareAddr, error) {
	addr, err := toAddr(ip)
	if err != nil {
		return nil, err
	}
	return cl.c.Resolve(addr)
}

// Reply sends an ARP reply claiming senderIP is at senderMAC,
// addressed on the wire directly to dstMAC (unicast rather than
// broadcast -- what actually matters is the target's own ARP cache
// update, not whether the rest of the segment also observes the
// frame).
func (cl *Client) Reply(senderIP net.IP, senderMAC net.HardwareAddr, dstIP net.IP, dstMAC net.HardwareAddr) error {
	srcAddr, err := toAddr(senderIP)
	if err != nil {
		return err
	}
	dstAddr, err := toAddr(dstIP)
	if err != nil {
		return err
	}
	pkt, err := arp.NewPacket(arp.OperationReply, senderMAC, srcAddr, dstMAC, dstAddr)
	if err != nil {
		return err
	}
	return cl.c.WriteTo(pkt, dstMAC)
}

// toAddr converts a net.IP (as used throughout worker.ARPSender and
// the rest of this project) to the netip.Addr that mdlayher/arp's
// current API requires. IPv4-only, matching the rest of this project
// (Generation/Target are IPv4-only per the design doc).
func toAddr(ip net.IP) (netip.Addr, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return netip.Addr{}, fmt.Errorf("not an IPv4 address: %v", ip)
	}
	addr, ok := netip.AddrFromSlice(ip4)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid IPv4 address: %v", ip)
	}
	return addr, nil
}
