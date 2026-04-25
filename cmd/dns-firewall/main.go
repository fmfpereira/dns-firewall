package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dns-firewall/internal/config"
	"dns-firewall/internal/dns"
	"dns-firewall/internal/firewall"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/dns-firewall/config.json", "path to configuration file")
	once := flag.Bool("once", false, "run one sync and exit")
	dryRun := flag.Bool("dry-run", false, "log firewall commands without applying them")
	verbose := flag.Bool("verbose", false, "enable debug logging")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *configPath, *once, *dryRun); err != nil {
		slog.Error("service failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath string, once bool, dryRunFlag bool) error {
	for {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}

		if err := syncOnce(ctx, cfg, dryRunFlag || cfg.DryRun); err != nil {
			return err
		}
		if once {
			return nil
		}

		timer := time.NewTimer(cfg.PollInterval.Duration)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func syncOnce(ctx context.Context, cfg config.Config, dryRun bool) error {
	allowlist, err := dns.CollectAllowedAddresses(ctx, cfg.Records, cfg.Nameservers)
	if err != nil {
		slog.Error("DNS collection failed; keeping existing firewall rules", "error", err)
		return nil
	}

	if len(allowlist) == 0 {
		slog.Warn("no addresses resolved; keeping existing firewall rules")
		return nil
	}

	manager := firewall.NewManager(cfg.Firewall, dryRun)
	if err := manager.Apply(ctx, allowlist); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return err
	}

	slog.Info("sync complete", "addresses", len(allowlist), "dry_run", dryRun)
	return nil
}
