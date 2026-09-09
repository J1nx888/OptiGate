// Command pp-nftables-manager is the Milestone 5/6/7 nftables-manager
// process: a small, CAP_NET_ADMIN-scoped daemon that maintains the
// dedicated "optigate" nftables table and reconciles its four
// named policy sets against the DesiredPolicy blob
// controller/policy_state.py (Python) computes and writes into the
// shared SQLite database's interception_runtime table.
//
// Deployed live as of Milestone 9/10 (see phase3/nftables-manager's own
// Dockerfile and docker-compose.yml's nftables-manager service) --
// the doc comment above used to say this was "not a real deployable
// yet"; corrected 2026-09-08 while fixing the SIGTERM-teardown gap
// below, since that claim had been stale for a while and would mislead
// anyone reading this file fresh. EnsureBaseline is safe to call
// against an already-populated table (idempotent, see its own doc
// comment).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"

	"github.com/J1nx888/parental_proxy/phase3/nftables-manager/internal/dbsource"
	"github.com/J1nx888/parental_proxy/phase3/nftables-manager/internal/nft"
	"github.com/J1nx888/parental_proxy/phase3/nftables-manager/internal/policy"
)

func main() {
	dbPath := flag.String(
		"db-path", "",
		"Path to the shared SQLite database. Required unless -bootstrap-only is set.",
	)
	pollInterval := flag.Duration(
		"poll-interval", 5*time.Second,
		"How often to re-read desired policy from the DB and reconcile it against nftables.",
	)
	bootstrapOnly := flag.Bool(
		"bootstrap-only", false,
		"Create the baseline table/sets/chain and exit, without a reconciliation loop.",
	)
	dnsRedirectPort := flag.Int(
		"dns-redirect-port", nft.DefaultDNSRedirectPort,
		"Local port the baseline ruleset redirects DNS/DoT traffic to (AdGuard's own DNS listener, "+
			"docker-compose.yml's ADGUARD_DNS_PORT). Added 2026-09-08 after a real deployment found the "+
			"previous hardcoded 5353 conflicting with avahi-daemon (mDNS), a common default service on "+
			"many Linux distributions -- keep this in sync with ADGUARD_DNS_PORT, whatever it's set to.",
	)
	flag.Parse()

	mgr, err := nft.New(*dnsRedirectPort)
	if err != nil {
		log.Fatalf("open nftables interface (needs CAP_NET_ADMIN): %v", err)
	}

	ctx := context.Background()
	if err := mgr.EnsureBaseline(ctx); err != nil {
		log.Fatalf("create baseline table/sets/chain: %v", err)
	}
	log.Print("baseline table/sets/chain created (or already present)")

	if *bootstrapOnly {
		return
	}
	if *dbPath == "" {
		log.Fatal("-db-path is required unless -bootstrap-only is set")
	}

	if ok, notifyErr := daemon.SdNotify(false, daemon.SdNotifyReady); notifyErr != nil {
		log.Printf("sd_notify READY failed (non-fatal, likely not running under systemd): %v", notifyErr)
	} else if !ok {
		log.Print("sd_notify not supported here (not running under systemd) -- continuing without watchdog pings")
	} else {
		go watchdogLoop()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

	ticker := time.NewTicker(*pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sig:
			log.Print("shutting down: removing the optigate table and its rules")
			// Fixed 2026-09-08: this used to just log and return, leaving
			// every baseline redirect rule (DNS/HTTP/HTTPS DNAT, the
			// DOCKER-USER exception) active in the kernel with this
			// process gone -- found live shutting down a soak-test
			// window, where it forced a manual `sudo nft delete table
			// inet optigate` on the host to actually return the box to
			// normal pass-through. Teardown is idempotent/best-effort
			// the same way EnsureBaseline is -- logged, not fatal, since
			// the process is exiting either way and a half-torn-down
			// table is still strictly better than a fully-intact one.
			if err := mgr.Teardown(ctx); err != nil {
				log.Printf("teardown failed (a future EnsureBaseline call, e.g. this process "+
					"restarting, will reconverge the table itself, but a manual `sudo nft delete "+
					"table inet optigate` may be needed until then): %v", err)
			}
			return
		case <-ticker.C:
			if err := reconcileOnce(ctx, mgr, *dbPath); err != nil {
				log.Printf("reconcile cycle failed (will retry next cycle against fresh actual state): %v", err)
				if werr := dbsource.WriteHealth(*dbPath, "fail_open", err); werr != nil {
					log.Printf("also failed to write fail_open health: %v", werr)
				}
				continue
			}
			if werr := dbsource.WriteHealth(*dbPath, "running", nil); werr != nil {
				log.Printf("failed to write healthy status: %v", werr)
			}
		}
	}
}

// reconcileOnce is one full read-resolve-diff-apply cycle. Every step
// re-reads its own fresh state (desired from the DB, actual from the
// kernel) rather than trusting anything cached from a previous cycle
// -- if this process crashed or errored mid-cycle last time, the next
// call to reconcileOnce recovers on its own with no special-cased
// resume logic, which is the Milestone 9 "partial nftables failure"
// answer: knftables' Run() is atomic (all-or-nothing) so the kernel
// itself can't be left half-updated, and this loop's own
// read-fresh-every-time structure means a mid-cycle process failure
// just gets corrected on the very next tick.
func reconcileOnce(ctx context.Context, mgr *nft.Manager, dbPath string) error {
	desired, err := dbsource.ReadDesiredPolicy(dbPath)
	if err != nil {
		return err
	}

	resolved, conflicts := policy.ResolveConflicts(desired)
	for _, c := range conflicts {
		log.Printf("policy conflict: ip=%s requested in %v, kept in %s", c.IP, c.Sets, c.Resolved)
	}

	actual, err := mgr.ReadActual(ctx)
	if err != nil {
		return err
	}

	diffs := policy.Reconcile(resolved, actual)
	if len(diffs) == 0 {
		return nil
	}
	if err := mgr.ApplyDiffs(ctx, diffs); err != nil {
		return err
	}
	log.Printf("applied %d set diffs", len(diffs))

	// Real gap found live 2026-09-09: the set diffs above are the whole
	// story for a device's NEW connections (correctly blocked the moment
	// it's added to unauthenticated_v4/quarantine_v4), but never revoked
	// an already-open one -- see (*nft.Manager).
	// FlushConntrackForReclassifiedDevices's own doc comment for the full
	// story (an Amazon Echo kept answering voice commands well after
	// being reclassified, until power-cycled). Best-effort and
	// deliberately non-fatal: a flush failure here is strictly less
	// severe than an ApplyDiffs failure above (the firewall rules
	// already correctly deny this device's new traffic either way), so
	// it's logged and the loop keeps going, the same posture already
	// used for policy conflicts above.
	for _, err := range mgr.FlushConntrackForReclassifiedDevices(ctx, diffs) {
		log.Printf("warning: %v", err)
	}
	return nil
}

func watchdogLoop() {
	interval, err := daemon.SdWatchdogEnabled(false)
	if err != nil || interval == 0 {
		return // WatchdogSec not set in the unit file -- nothing to do
	}
	ticker := time.NewTicker(interval / 3) // notify at ~3x the required rate, standard sd_notify practice
	defer ticker.Stop()
	for range ticker.C {
		_, _ = daemon.SdNotify(false, daemon.SdNotifyWatchdog)
	}
}
