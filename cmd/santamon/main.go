package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
	"github.com/0x4d31/santamon/internal/baseline"
	"github.com/0x4d31/santamon/internal/config"
	"github.com/0x4d31/santamon/internal/correlation"
	"github.com/0x4d31/santamon/internal/events"
	"github.com/0x4d31/santamon/internal/lineage"
	"github.com/0x4d31/santamon/internal/logutil"
	"github.com/0x4d31/santamon/internal/rules"
	"github.com/0x4d31/santamon/internal/shipper"
	"github.com/0x4d31/santamon/internal/signals"
	"github.com/0x4d31/santamon/internal/spool"
	"github.com/0x4d31/santamon/internal/state"
	"golang.org/x/sync/errgroup"
)

var (
	version           = "dev"
	commit            = "none"
	date              = "unknown"
	defaultConfigPath = "/etc/santamon/config.yaml"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "run":
		runCommand()
	case "status":
		statusCommand()
	case "db":
		dbCommand()
	case "rules":
		rulesCommand()
	case "version":
		fmt.Printf("santamon version %s\n", version)
		fmt.Printf("commit: %s\n", commit)
		fmt.Printf("built: %s\n", date)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`santamon - Lightweight macOS Detection Agent

Usage:
  santamon run [options]            Run the agent
  santamon status [--config PATH]   Show agent status
  santamon db <stats|compact> [--config PATH]
                                    Database operations
  santamon rules validate           Validate rules configuration
  santamon version                  Show version
  santamon help                     Show this help

Run Options:
  --config PATH                     Configuration file path (default: /etc/santamon/config.yaml)
  --verbose                         Verbose mode (show additional details and timestamps)

Environment Variables:
  SANTAMON_API_KEY                  API key for backend authentication`)
}

// shortenPath shortens a long path for display
func shortenPath(path string) string {
	// If path is short enough, return as-is
	if len(path) <= 60 {
		return path
	}

	// Split the path and get last few components
	parts := strings.Split(path, "/")
	if len(parts) <= 3 {
		return path
	}

	// Show first part (e.g., /Library) and last 2 components
	// Example: /Library/.../Python.app/Contents/MacOS/Python
	shortened := parts[0]
	if shortened == "" && len(parts) > 1 {
		shortened = "/" + parts[1] // Handle absolute paths
	}

	// Add last 2 components
	lastTwo := strings.Join(parts[len(parts)-2:], "/")
	return shortened + "/.../" + lastTwo
}

// formatSignalContext formats signal context into a readable string for display
func formatSignalContext(context map[string]any) string {
	if len(context) == 0 {
		return ""
	}

	var parts []string

	// Display key context fields in a specific order: kind, actor_path, target_path, decision first
	priorityKeys := []string{"kind", "actor_path", "target_path", "decision", "target_sha256", "process", "pid", "path", "hash"}

	for _, key := range priorityKeys {
		if val, ok := context[key]; ok && val != nil {
			// Skip event and other verbose fields in normal mode
			if key == "event" {
				continue
			}

			// Format the value
			var strVal string
			switch v := val.(type) {
			case string:
				// Truncate long hashes
				if (key == "target_sha256" || key == "hash") && len(v) > 12 {
					strVal = v[:12] + "…"
				} else if key == "actor_path" || key == "target_path" || key == "path" {
					// Shorten long paths
					strVal = shortenPath(v)
				} else {
					strVal = v
				}
			default:
				strVal = fmt.Sprintf("%v", v)
			}

			if strVal != "" {
				parts = append(parts, fmt.Sprintf("%s=%s", key, strVal))
			}
		}
	}

	return strings.Join(parts, " ")
}

func formatBaselinePattern(pattern string) string {
	if pattern == "" {
		return ""
	}
	parts := strings.Split(pattern, "|")
	var path, hash string
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := kv[0], kv[1]
		if strings.Contains(key, "executable.path") {
			path = val
		}
		if strings.Contains(key, "executable.hash.hash") || strings.Contains(key, "executable.cdhash") {
			hash = val
		}
	}
	if path == "" && hash == "" {
		return pattern
	}
	if hash != "" && len(hash) > 12 {
		hash = hash[:12] + "…"
	}
	if path != "" && hash != "" {
		return fmt.Sprintf("path=%s hash=%s", path, hash)
	}
	if path != "" {
		return fmt.Sprintf("path=%s", path)
	}
	return fmt.Sprintf("hash=%s", hash)
}

func runCommand() {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "Configuration file path")
	verbose := fs.Bool("verbose", false, "Verbose mode (show additional details and timestamps)")
	_ = fs.Parse(os.Args[2:])

	// Set verbosity level and timestamps
	if *verbose {
		logutil.SetVerbosity(logutil.VerboseLevel)
		logutil.SetTimestamps(true)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logutil.Error("Failed to load config: %v", err)
		os.Exit(1)
	}

	// Startup banner (no timestamps even in verbose mode)
	fmt.Println()
	fmt.Println("                   _                           ")
	fmt.Println("  ___ _____ ____ _| |_ _____ ____   ___  ____  ")
	fmt.Println(" /___|____ |  _ (_   _|____ |    \\ / _ \\|  _ \\ ")
	fmt.Println("|___ / ___ | | | || |_/ ___ | | | | |_| | | | |")
	fmt.Println("(___/\\_____|_| |_| \\__)_____|_|_|_|\\___/|_| |_|")
	fmt.Println("                                               ")
	fmt.Printf("  %s - Lightweight macOS Detection Agent\n", version)
	fmt.Printf("  commit: %s, built: %s\n\n", commit, date)
	fmt.Printf("\033[92m✓\033[0m Loaded configuration from %s\n", *configPath)
	fmt.Printf("\033[92m✓\033[0m Agent ID: %s\n", cfg.Agent.ID)

	// Open state database
	db, err := state.Open(cfg.State.DBPath, cfg.State.FirstSeen.MaxEntries, cfg.State.SyncWrites)
	if err != nil {
		logutil.Error("Failed to open database: %v", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	// Store agent metadata
	if err := db.SetMeta("agent_id", cfg.Agent.ID); err != nil {
		log.Printf("Warning: Failed to store agent_id metadata: %v", err)
	}
	if err := db.SetMeta("version", version); err != nil {
		log.Printf("Warning: Failed to store version metadata: %v", err)
	}

	// Load detection rules (supports both file and directory)
	rulesConfig, err := rules.Load(cfg.Rules.Path)
	if err != nil {
		logutil.Error("Failed to load rules: %v", err)
		os.Exit(1)
	}
	fmt.Printf("\033[92m✓\033[0m Detection rules: %d simple, %d correlation, %d baseline\n",
		len(rulesConfig.Rules), len(rulesConfig.Correlations), len(rulesConfig.Baselines))

	// Create rules engine
	engine, err := rules.NewEngine()
	if err != nil {
		logutil.Error("Failed to create rules engine: %v", err)
		os.Exit(1)
	}

	if err := engine.LoadRules(rulesConfig); err != nil {
		logutil.Error("Failed to compile rules: %v", err)
		os.Exit(1)
	}

	// Create correlation window manager
	windowMgr := correlation.NewWindowManager(
		db,
		cfg.State.Windows.MaxEvents,
		cfg.State.Windows.GCInterval,
	)

	// Create baseline processor
	baselineProc := baseline.NewProcessor(db)

	// Create lineage store only if any enabled rule requests process trees
	var lineageStore *lineage.Store
	for _, r := range rulesConfig.Rules {
		if r.Enabled && r.IncludeProcessTree {
			lineageStore = lineage.NewStore(lineage.Config{})
			break
		}
	}

	// Create signal generator
	sigGen := signals.NewGenerator(cfg.Agent.ID, lineageStore)

	// Create spool watcher
	watcher, err := spool.NewWatcherWithOptions(cfg.Santa.SpoolDir, cfg.Santa.StabilityWait, spool.WatcherOptions{ArchiveDir: cfg.Santa.ArchiveDir})
	if err != nil {
		logutil.Error("Failed to create watcher: %v", err)
		os.Exit(1)
	}
	defer func() { _ = watcher.Close() }()

	// Create shipper
	ship := shipper.NewShipper(&cfg.Shipper, db, cfg.Agent.ID, version)

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for graceful shutdown and reload
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Use errgroup for coordinated goroutine management
	g, gctx := errgroup.WithContext(ctx)

	// Start shipper in errgroup
	g.Go(func() error {
		return ship.Start(gctx)
	})

	// Start heartbeat in errgroup
	g.Go(func() error {
		return ship.StartHeartbeat(gctx)
	})

	// Start watcher in errgroup
	g.Go(func() error {
		return watcher.Start(gctx)
	})

	// Channel to signal rule reload
	reloadCh := make(chan struct{}, 1)

	// Handle signals (SIGINT/SIGTERM for shutdown, SIGHUP for reload)
	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				// Trigger rule reload
				select {
				case reloadCh <- struct{}{}:
				default:
					// Reload already pending
				}
			case syscall.SIGINT, syscall.SIGTERM:
				// Trigger shutdown
				fmt.Fprintln(os.Stderr, "\nShutting down...")
				cancel()
				return
			}
		}
	}()

	fmt.Println()
	fmt.Println("\033[90mℹ\033[0m Watching for security events...")

	// Main event processing loop
	decoder := spool.NewDecoder()
	eventCount := 0
	signalCount := 0

	eventsCh := watcher.Events()

	for {
		select {
		case <-gctx.Done():
			// Context cancelled, wait for all goroutines to finish
			if err := g.Wait(); err != nil && err != context.Canceled {
				logutil.Error("Service error: %v", err)
			}
			logutil.Verbose("Processed %d events, generated %d signals", eventCount, signalCount)
			logutil.Success("Shutdown complete")
			return

		case <-reloadCh:
			// Reload rules (SIGHUP received)
			logutil.Info("Reloading detection rules...")

			newRulesConfig, err := rules.Load(cfg.Rules.Path)
			if err != nil {
				logutil.Error("Failed to reload rules: %v", err)
				continue
			}

			newEngine, err := rules.NewEngine()
			if err != nil {
				logutil.Error("Failed to create new rules engine: %v", err)
				continue
			}

			if err := newEngine.LoadRules(newRulesConfig); err != nil {
				logutil.Error("Failed to compile reloaded rules: %v", err)
				continue
			}

			// Atomically replace the old engine with the new one
			// (safe because this is single-threaded event loop)
			engine = newEngine
			rulesConfig = newRulesConfig

			// Recreate lineage store if process tree requirements changed
			needsLineage := false
			for _, r := range rulesConfig.Rules {
				if r.Enabled && r.IncludeProcessTree {
					needsLineage = true
					break
				}
			}
			if needsLineage && lineageStore == nil {
				lineageStore = lineage.NewStore(lineage.Config{})
			} else if !needsLineage {
				lineageStore = nil
			}

			// Update signal generator with new lineage store
			sigGen = signals.NewGenerator(cfg.Agent.ID, lineageStore)

			logutil.Success("Reloaded %d simple, %d correlation, %d baseline rules",
				len(rulesConfig.Rules), len(rulesConfig.Correlations), len(rulesConfig.Baselines))

		case filePath, ok := <-eventsCh:
			if !ok {
				// Watcher closed, wait for all goroutines to finish
				cancel() // Trigger shutdown
				if err := g.Wait(); err != nil && err != context.Canceled {
					logutil.Error("Service error: %v", err)
				}
				logutil.Warn("Watcher events channel closed")
				logutil.Verbose("Processed %d events, generated %d signals", eventCount, signalCount)
				logutil.Success("Shutdown complete")
				return
			}
			// Skip if we've already processed this file (journaled)
			if je, _ := db.GetJournalEntry(filePath); je != nil {
				if info, err := os.Stat(filePath); err == nil {
					// If file hasn't changed since last processed, skip
					if !info.ModTime().After(je.ProcessedTS) {
						if os.Getenv("SANTAMON_DEBUG") == "1" {
							log.Printf("Skipping already-processed spool file: %s", filePath)
						}
						continue
					}
				}
			}
			if os.Getenv("SANTAMON_DEBUG") == "1" {
				log.Printf("Processing file: %s", filePath)
			}

			spoolArchivePath := ""
			if cfg.Santa.ArchiveDir != "" {
				spoolArchivePath = filepath.Join(cfg.Santa.ArchiveDir, filepath.Base(filePath))
			}
			spoolContext := map[string]any{}
			if spoolArchivePath != "" {
				spoolContext["spool_archive_path"] = spoolArchivePath
			}

			fileHasSignals := false

			// Decode events from file
			messages, err := decoder.DecodeEvents(filePath)
			if err != nil {
				log.Printf("Failed to decode file: %v", err)
				// Update journal even on error to avoid reprocessing
				if err := db.UpdateJournal(filePath, 0); err != nil {
					log.Printf("Warning: Failed to update journal: %v", err)
				}
				continue
			}

			// Process each event
			for _, msg := range messages {
				eventCount++

				// Update process lineage store for execution events, when enabled
				if lineageStore != nil {
					if ev, ok := msg.GetEvent().(*santapb.SantaMessage_Execution); ok {
						lineageStore.UpsertFromExecution(msg, ev.Execution)
					}
				}

				// Evaluate simple rules
				matches, err := engine.Evaluate(msg)
				if err != nil {
					log.Printf("Rule evaluation error: %v", err)
					continue
				}

				// Process simple rule matches
				for _, match := range matches {
					signal := sigGen.FromRuleMatch(match)

					// Check if this is the first time we've seen this artifact
					if hash := events.TargetSHA256(match.Message); hash != "" {
						isFirst, err := db.IsFirstSeen("sha256", hash)
						if err != nil {
							log.Printf("Warning: Failed to check first seen: %v", err)
						} else if isFirst {
							sigGen.EnrichSignal(signal, map[string]any{
								"first_seen": true,
							})
						}
					}

					sigGen.EnrichSignal(signal, spoolContext)
					fileHasSignals = true

					if err := ship.EnqueueSignal(signal); err != nil {
						logutil.Error("Failed to enqueue signal: %v", err)
					} else {
						signalCount++
						// Format context for display
						ctx := formatSignalContext(signal.Context)
						logutil.Signal("rule", signal.RuleID, signal.Severity, signal.Title, ctx)
					}
				}

				// Evaluate correlation rules
				correlations := engine.GetCorrelations()
				if len(correlations) > 0 {
					windowMatches, err := windowMgr.Process(msg, correlations)
					if err != nil {
						log.Printf("Correlation processing error: %v", err)
						continue
					}
					for _, wmatch := range windowMatches {
						signal := sigGen.FromWindowMatch(wmatch, msg.GetBootSessionUuid())
						sigGen.EnrichSignal(signal, spoolContext)
						fileHasSignals = true
						if err := ship.EnqueueSignal(signal); err != nil {
							logutil.Error("Failed to enqueue correlation signal: %v", err)
						} else {
							signalCount++
							// Format context for correlation signals
							ctx := fmt.Sprintf("correlation=%d events %s", wmatch.Count, formatSignalContext(signal.Context))
							logutil.Signal("correlation", signal.RuleID, signal.Severity, signal.Title, ctx)
						}
					}
				}

				// Evaluate baseline rules
				baselines := engine.GetBaselines()
				if len(baselines) > 0 {
					baselineMatches, err := baselineProc.Process(msg, baselines, engine)
					if err != nil {
						logutil.Error("Baseline processing error: %v", err)
						continue
					}
					for _, bmatch := range baselineMatches {
						// Skip alerts during learning period if configured
						if bmatch.InLearning {
							// Show learning mode signals with INFO severity
							ctx := formatBaselinePattern(bmatch.Pattern)
							logutil.Signal("baseline", bmatch.RuleID, "info", bmatch.Title+" (learning)", ctx)
							continue
						}

						signal := sigGen.FromBaselineMatch(bmatch)
						sigGen.EnrichSignal(signal, spoolContext)
						fileHasSignals = true
						if err := ship.EnqueueSignal(signal); err != nil {
							logutil.Error("Failed to enqueue baseline signal: %v", err)
						} else {
							signalCount++
							ctx := formatBaselinePattern(bmatch.Pattern)
							logutil.Signal("baseline", signal.RuleID, signal.Severity, signal.Title, ctx)
						}
					}
				}
			}

			// Update journal after successful processing
			if err := db.UpdateJournal(filePath, 0); err != nil {
				log.Printf("Warning: Failed to update journal: %v", err)
			}

			// Delete processed files with no signals, archive files that produced alerts
			if fileHasSignals {
				if err := watcher.ArchiveFile(filePath); err != nil {
					log.Printf("Warning: Failed to archive spool file %s: %v", filePath, err)
				} else if os.Getenv("SANTAMON_DEBUG") == "1" && spoolArchivePath != "" {
					log.Printf("Archived spool file %s to %s", filePath, spoolArchivePath)
				}
			} else {
				if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
					log.Printf("Warning: Failed to delete spool file %s: %v", filePath, err)
				} else if os.Getenv("SANTAMON_DEBUG") == "1" {
					log.Printf("Deleted spool file %s (no signals)", filePath)
				}
			}

			if os.Getenv("SANTAMON_DEBUG") == "1" {
				log.Printf("Processed %d events from %s", len(messages), filePath)
			}
		}
	}
}

func statusCommand() {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "Configuration file path")
	_ = fs.Parse(os.Args[2:])

	cfg, err := config.LoadForReadOnly(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := state.Open(cfg.State.DBPath, cfg.State.FirstSeen.MaxEntries, cfg.State.SyncWrites)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer func() { _ = db.Close() }()

	stats, err := db.Stats()
	if err != nil {
		log.Fatalf("Failed to read stats: %v", err)
	}

	fmt.Printf("santamon %s\n", version)
	fmt.Printf("Agent ID:   %s\n", cfg.Agent.ID)
	fmt.Printf("State DB:   %s\n", cfg.State.DBPath)
	fmt.Printf("Signals queued: %v\n", stats["signals"])
	fmt.Printf("Signals shipped: %v\n", stats["shipped"])

	encoded, _ := json.MarshalIndent(stats, "", "  ")
	fmt.Printf("\nFull stats:\n%s\n", string(encoded))
}

func newDBFlagSet(errorHandling flag.ErrorHandling) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("db", errorHandling)
	configPath := fs.String("config", defaultConfigPath, "Configuration file path")
	return fs, configPath
}

func dbCommand() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: santamon db <stats|compact> [--config PATH]")
		os.Exit(1)
	}

	subCmd := os.Args[2]

	fs, configPath := newDBFlagSet(flag.ExitOnError)
	_ = fs.Parse(os.Args[3:])

	// Load config to get DB path (skip shipper validation for read-only ops)
	cfg, err := config.LoadForReadOnly(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := state.Open(cfg.State.DBPath, cfg.State.FirstSeen.MaxEntries, cfg.State.SyncWrites)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer func() { _ = db.Close() }()

	switch subCmd {
	case "stats":
		stats, err := db.Stats()
		if err != nil {
			log.Fatalf("Failed to get stats: %v", err)
		}

		data, _ := json.MarshalIndent(stats, "", "  ")
		fmt.Println(string(data))

	case "compact":
		fmt.Println("Compacting database...")
		if err := db.Compact(); err != nil {
			log.Fatalf("Failed to compact: %v", err)
		}
		fmt.Println("Done")

	default:
		fmt.Printf("Unknown db command: %s\n", subCmd)
		os.Exit(1)
	}
}

func rulesCommand() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: santamon rules <validate> [--config PATH]")
		os.Exit(1)
	}

	subCmd := os.Args[2]

	// Parse config flag
	fs := flag.NewFlagSet("rules", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "Configuration file path")
	_ = fs.Parse(os.Args[3:])

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	switch subCmd {
	case "validate":
		rulesConfig, err := rules.Load(cfg.Rules.Path)
		if err != nil {
			log.Fatalf("Validation failed: %v", err)
		}

		// Try to compile rules
		engine, err := rules.NewEngine()
		if err != nil {
			log.Fatalf("Failed to create engine: %v", err)
		}

		if err := engine.LoadRules(rulesConfig); err != nil {
			log.Fatalf("Failed to compile rules: %v", err)
		}

		fmt.Printf("✓ Rules validated successfully\n")
		fmt.Printf("  %d rules\n", len(rulesConfig.Rules))
		fmt.Printf("  %d correlations\n", len(rulesConfig.Correlations))
		fmt.Printf("  %d baselines\n", len(rulesConfig.Baselines))

	default:
		fmt.Printf("Unknown rules command: %s\n", subCmd)
		os.Exit(1)
	}
}
