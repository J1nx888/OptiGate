#!/usr/bin/env bash
# OptiGate: best-effort NIC RX-steering + interrupt-coalescing tuning.
#
# Written 2026-09-12 after a real production sustained-upload failure was
# traced to a single-queue consumer NIC (Realtek RTL8168h/8111h, driver
# r8169) with every hardware interrupt pinned to one CPU core -- confirmed
# live via /proc/interrupts (100% of ~1.3M interrupts on one core),
# /proc/net/softnet_stat (drops recorded only on that same core), and a
# genuine nonzero `ethtool -S <iface> rx_missed` counter. See RoadMap.md's
# "Item 3 revisited" entry for the full diagnosis. OptiGate's interception
# mode does real kernel packet forwarding for every intercepted device's
# traffic, so a cheap single-queue NIC bottlenecking one core under
# sustained load is a real risk on hardware like this, not a hypothetical.
#
# This does two things, both standard, safe, reversible Linux networking
# tuning -- neither changes routing/forwarding behavior:
#   1. RPS (Receive Packet Steering): spreads RX packet *processing*
#      across every CPU core in software. The hardware interrupt itself
#      still lands on whichever core the NIC/IRQ affinity picked -- RPS
#      operates one layer up, in the softirq handler -- so this helps even
#      on hardware where the interrupt itself can never be redistributed
#      (confirmed on the box above: `ethtool -l` reports "Operation not
#      supported" for multi-queue/RSS, but RPS doesn't need that).
#   2. Interrupt coalescing: batches multiple received frames per hardware
#      interrupt instead of firing one interrupt per frame (the box above
#      shipped configured at rx-usecs=0/rx-frames=1, i.e. no batching at
#      all), cutting per-packet interrupt/context-switch overhead on
#      whichever core does end up handling them.
#
# Deliberately auto-detects the interface every time (via the default
# route) rather than hardcoding one -- interface names vary across
# hardware/distros, and this same unit should keep working if the host is
# ever moved to different NIC hardware or the interface is renamed.
#
# Best-effort throughout: never treats an unsupported knob on a given NIC
# as fatal. A NIC with real multi-queue/RSS support gets RPS applied too
# (harmless -- it's a no-op in practice when hardware already spreads
# interrupts) rather than being special-cased out.
set -u

log() { echo "[optigate-nic-tuning] $*"; }

iface="$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)"
if [ -z "$iface" ]; then
  log "could not auto-detect the primary network interface (no default route yet?) -- skipping."
  exit 0
fi
log "tuning interface: $iface"

cpu_count="$(nproc 2>/dev/null || echo 1)"
mask="$(printf '%x' $(( (1 << cpu_count) - 1 )))"

found_any=0
for q in /sys/class/net/"$iface"/queues/rx-*; do
  [ -d "$q" ] || continue
  found_any=1
  if [ -w "$q/rps_cpus" ] && echo "$mask" > "$q/rps_cpus" 2>/dev/null; then
    log "  $q/rps_cpus -> $mask (all $cpu_count cores)"
  else
    log "  could not set $q/rps_cpus (needs root, or not supported here) -- skipping."
  fi
done
if [ "$found_any" = "0" ]; then
  log "no RX queue sysfs entries found for $iface -- skipping RPS."
fi

if command -v ethtool >/dev/null 2>&1; then
  if ethtool -C "$iface" rx-usecs 50 rx-frames 8 >/dev/null 2>&1; then
    log "  interrupt coalescing set: rx-usecs=50 rx-frames=8"
  else
    log "  interrupt coalescing not supported/permitted on $iface -- skipping (RPS above still applies)."
  fi
else
  log "ethtool not installed -- skipping interrupt coalescing (RPS above doesn't need it)."
fi
