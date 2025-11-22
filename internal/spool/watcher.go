package spool

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/0x4d31/santamon/internal/logutil"
	"github.com/fsnotify/fsnotify"
)

// Watcher monitors the Santa spool directory for new files
type Watcher struct {
	spoolDir        string
	stabilityWait   time.Duration
	eventChan       chan string
	watcher         *fsnotify.Watcher
	archiveDir      string        // Directory to move processed files (empty = delete)
	checkInterval   time.Duration // How often to check file stability
	maxPendingFiles int           // Maximum files in stability map
	stabMu          sync.Mutex    // Protects fileStability map from concurrent access
}

// NewWatcher creates a new spool directory watcher with default settings
func NewWatcher(spoolDir string, stabilityWait time.Duration) (*Watcher, error) {
	return NewWatcherWithOptions(spoolDir, stabilityWait, WatcherOptions{})
}

// WatcherOptions contains optional configuration for the watcher
type WatcherOptions struct {
	ArchiveDir      string        // Directory to move processed files (empty = delete)
	CheckInterval   time.Duration // How often to check file stability (default: 1s)
	MaxPendingFiles int           // Maximum files waiting for stability (default: 1000)
	ChannelBuffer   int           // Size of event channel buffer (default: 100)
}

// NewWatcherWithOptions creates a new spool directory watcher with custom options
func NewWatcherWithOptions(spoolDir string, stabilityWait time.Duration, opts WatcherOptions) (*Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	// Watch the "new" subdirectory (maildir-style)
	newDir := filepath.Join(spoolDir, "new")
	if err := os.MkdirAll(newDir, 0755); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to create spool/new directory: %w", err)
	}

	if err := watcher.Add(newDir); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to watch directory: %w", err)
	}

	// Set defaults
	if opts.CheckInterval == 0 {
		opts.CheckInterval = 1 * time.Second
	}
	if opts.MaxPendingFiles == 0 {
		opts.MaxPendingFiles = 1000
	}
	if opts.ChannelBuffer == 0 {
		opts.ChannelBuffer = 100
	}

	// Create archive directory if specified
	if opts.ArchiveDir != "" {
		if err := os.MkdirAll(opts.ArchiveDir, 0755); err != nil {
			watcher.Close()
			return nil, fmt.Errorf("failed to create archive directory: %w", err)
		}
	}

	return &Watcher{
		spoolDir:        spoolDir,
		stabilityWait:   stabilityWait,
		eventChan:       make(chan string, opts.ChannelBuffer),
		watcher:         watcher,
		archiveDir:      opts.ArchiveDir,
		checkInterval:   opts.CheckInterval,
		maxPendingFiles: opts.MaxPendingFiles,
	}, nil
}

// Events returns the channel of file paths ready for processing
func (w *Watcher) Events() <-chan string {
	return w.eventChan
}

// Start begins watching for new files
func (w *Watcher) Start(ctx context.Context) error {
	// First, process any existing files in the spool
	if err := w.processExistingFiles(); err != nil {
		logutil.Warn("Failed to process existing files: %v", err)
	}

	// Track file modification times for stability check
	fileStability := make(map[string]time.Time)

	// Start stability checker goroutine
	stabilityTicker := time.NewTicker(w.checkInterval)
	defer stabilityTicker.Stop()

	// Cleanup goroutine to prevent unbounded map growth
	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			close(w.eventChan)
			// Clean up any remaining pending files
			return ctx.Err()

		case event, ok := <-w.watcher.Events:
			if !ok {
				return fmt.Errorf("watcher events channel closed")
			}

			// Only care about Create and Write events
			if event.Op&fsnotify.Create == fsnotify.Create ||
				event.Op&fsnotify.Write == fsnotify.Write {
				w.stabMu.Lock()
				// Check if we're at max capacity
				if len(fileStability) >= w.maxPendingFiles {
					log.Printf("Warning: max pending files reached (%d), dropping oldest", w.maxPendingFiles)
					// Remove oldest entry
					var oldest string
					var oldestTime time.Time
					for p, t := range fileStability {
						if oldest == "" || t.Before(oldestTime) {
							oldest = p
							oldestTime = t
						}
					}
					delete(fileStability, oldest)
				}
				// Mark file as recently modified
				fileStability[event.Name] = time.Now()
				w.stabMu.Unlock()
			}

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return fmt.Errorf("watcher errors channel closed")
			}
			log.Printf("Watcher error: %v", err)

		case <-stabilityTicker.C:
			// Check for stable files
			now := time.Now()
			w.stabMu.Lock()
			for path, lastMod := range fileStability {
				if now.Sub(lastMod) >= w.stabilityWait {
					// Verify file still exists before sending
					if _, err := os.Stat(path); err != nil {
						delete(fileStability, path)
						continue
					}

					// File is stable, send for processing (unlock before blocking send)
					w.stabMu.Unlock()
					select {
					case w.eventChan <- path:
						w.stabMu.Lock()
						delete(fileStability, path)
					case <-ctx.Done():
						return ctx.Err()
					}
					continue
				}
			}
			w.stabMu.Unlock()

		case <-cleanupTicker.C:
			// Remove stale entries (files that have been pending too long)
			maxWait := w.stabilityWait * 10 // 10x stability wait is too long
			now := time.Now()
			w.stabMu.Lock()
			for path, lastMod := range fileStability {
				if now.Sub(lastMod) > maxWait {
					logutil.Warn("Removing stale pending file: %s (pending for %v)", path, now.Sub(lastMod))
					delete(fileStability, path)
				}
			}
			w.stabMu.Unlock()
		}
	}
}

// ArchiveFile moves or deletes a processed file
func (w *Watcher) ArchiveFile(path string) error {
	if w.archiveDir == "" {
		// Delete file by default (tests rely on this behavior). Runtime may choose not to call this.
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete file: %w", err)
		}
		return nil
	}

	// Move to archive directory
	filename := filepath.Base(path)
	archivePath := filepath.Join(w.archiveDir, filename)

	if err := os.Rename(path, archivePath); err != nil {
		// If rename fails (e.g., cross-device), try copy+delete
		if err := w.copyFile(path, archivePath); err != nil {
			return fmt.Errorf("failed to archive file: %w", err)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove original file: %w", err)
		}
	}

	return nil
}

// copyFile copies a file from src to dst
func (w *Watcher) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	return dstFile.Sync()
}

// processExistingFiles scans the spool directory for existing files
func (w *Watcher) processExistingFiles() error {
	newDir := filepath.Join(w.spoolDir, "new")
	entries, err := os.ReadDir(newDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(newDir, entry.Name())

		// Check file age to ensure it's stable
		info, err := entry.Info()
		if err != nil {
			logutil.Warn("Failed to stat file %s: %v", path, err)
			continue
		}

		if time.Since(info.ModTime()) >= w.stabilityWait {
			w.eventChan <- path
		}
	}

	return nil
}

// Close stops the watcher and releases resources
func (w *Watcher) Close() error {
	return w.watcher.Close()
}
