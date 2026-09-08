// Command pp-nftables-manager is the Milestone 5/6/7 nftables-manager
// process: a small, CAP_NET_ADMIN-scoped daemon that maintains the
// dedicated "optigate" nftables table and reconciles its four
// named policy sets against the DesiredPolicy blob
// controller/policy_state.py (Python) computes and writes into the
// shared SQLite database's interception_runtime table.
//
// NOT a real deployable yet: there's no systemd unit or Dockerfile for
// this component, and EnsureBaseline isn't yet safe to call against an
// already-populated table (see internal/nft's own note) -- a restart
// of this process against a live table would currently duplicate the
// baseline rules. See RoadMap.md's Milestone 5-7 entries.
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
	flag.Parse()

	mgr, err := nft.New()
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
			log.Print("shutting down")
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
