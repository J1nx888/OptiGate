package worker

import (
	"fmt"
	"net"
)

// Rejection records why a candidate target was refused, so callers can
// report it back to the controller (e.g. as a "generation_applied"
// resolution_failures entry) instead of silently dropping it.
type Rejection struct {
	Target Target
	Reason string
}

// ValidateTargets implements the startup/per-generation safety checks
// from docs/design/phase3-technical-design.md section 3: never poison
// the gateway itself, the worker's own interface, the subnet broadcast
// address, any multicast address, or anything the controller marked
// bypass_v4.
func ValidateTargets(selfIP net.IP, gateway Target, subnet *net.IPNet, bypass map[string]bool, candidates []Target) (accepted []Target, rejected []Rejection) {
	broadcast := broadcastAddr(subnet)
	for _, t := range candidates {
		switch {
		case t.IP.Equal(gateway.IP):
			rejected = append(rejected, Rejection{Target: t, Reason: "is_gateway"})
		case t.IP.Equal(selfIP):
			rejected = append(rejected, Rejection{Target: t, Reason: "is_self"})
		case broadcast != nil && t.IP.Equal(broadcast):
			rejected = append(rejected, Rejection{Target: t, Reason: "is_broadcast"})
		case t.IP.IsMulticast():
			rejected = append(rejected, Rejection{Target: t, Reason: "is_multicast"})
		case bypass[t.IP.String()]:
			rejected = append(rejected, Rejection{Target: t, Reason: "bypass_v4"})
		default:
			accepted = append(accepted, t)
		}
	}
	return accepted, rejected
}

// broadcastAddr computes subnet's IPv4 broadcast address, or nil if
// subnet is nil or not a valid IPv4 network.
func broadcastAddr(subnet *net.IPNet) net.IP {
	if subnet == nil {
		return nil
	}
	ip4 := subnet.IP.To4()
	mask := subnet.Mask
	if ip4 == nil || len(mask) != 4 {
		return nil
	}
	bcast := make(net.IP, 4)
	for i := range ip4 {
		bcast[i] = ip4[i] | ^mask[i]
	}
	return bcast
}

// ResolveGateway performs a genuine ARP request/reply exchange to
// learn the gateway's real hardware address. This must never be
// satisfied from the OS neighbor cache: the cache could already be
// poisoned -- by this worker's own prior ungraceful crash, or by
// another actor on the LAN -- which would make the worker treat
// existing poisoning as ground truth.
func ResolveGateway(sender ARPSender, gatewayIP net.IP) (net.HardwareAddr, error) {
	mac, err := sender.Resolve(gatewayIP)
	if err != nil {
		return nil, fmt.Errorf("resolve gateway %s: %w", gatewayIP, err)
	}
	return mac, nil
}
