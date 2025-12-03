package spool

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func TestNewWatcher(t *testing.T) {
	spoolDir := t.TempDir()
	w, err := NewWatcher(spoolDir, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	if w.spoolDir != spoolDir {
		t.Errorf("Expected spoolDir %s, got %s", spoolDir, w.spoolDir)
	}
	if w.stabilityWait != 100*time.Millisecond {
		t.Errorf("Expected stabilityWait 100ms, got %v", w.stabilityWait)
	}

	// Check that spool/new directory was created
	newDir := filepath.Join(spoolDir, "new")
	if _, err := os.Stat(newDir); os.IsNotExist(err) {
		t.Error("spool/new directory was not created")
	}
}

func TestNewWatcherWithOptions(t *testing.T) {
	spoolDir := t.TempDir()
	archiveDir := filepath.Join(t.TempDir(), "archive")

	opts := WatcherOptions{
		ArchiveDir:      archiveDir,
		CheckInterval:   500 * time.Millisecond,
		MaxPendingFiles: 50,
		ChannelBuffer:   25,
	}

	w, err := NewWatcherWithOptions(spoolDir, 100*time.Millisecond, opts)
	if err != nil {
		t.Fatalf("NewWatcherWithOptions failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	if w.archiveDir != archiveDir {
		t.Errorf("Expected archiveDir %s, got %s", archiveDir, w.archiveDir)
	}
	if w.checkInterval != 500*time.Millisecond {
		t.Errorf("Expected checkInterval 500ms, got %v", w.checkInterval)
	}
	if w.maxPendingFiles != 50 {
		t.Errorf("Expected maxPendingFiles 50, got %d", w.maxPendingFiles)
	}

	// Check that archive directory was created
	if _, err := os.Stat(archiveDir); os.IsNotExist(err) {
		t.Error("archive directory was not created")
	}
}

func TestWatcherProcessExistingFiles(t *testing.T) {
	spoolDir := t.TempDir()
	newDir := filepath.Join(spoolDir, "new")
	if err := os.MkdirAll(newDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a test file
	testFile := filepath.Join(newDir, "test.pb")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait to ensure file is stable
	time.Sleep(50 * time.Millisecond)

	w, err := NewWatcher(spoolDir, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start watcher in background
	go func() {
		_ = w.Start(ctx)
	}()

	// Should receive the existing file
	select {
	case path := <-w.Events():
		if path != testFile {
			t.Errorf("Expected path %s, got %s", testFile, path)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for existing file event")
	}
}

func TestWatcherNewFile(t *testing.T) {
	spoolDir := t.TempDir()
	w, err := NewWatcher(spoolDir, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Start watcher in background
	go func() {
		_ = w.Start(ctx)
	}()

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Create a new file
	newDir := filepath.Join(spoolDir, "new")
	testFile := filepath.Join(newDir, "newfile.pb")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	// Should receive the new file after stability wait
	select {
	case path := <-w.Events():
		if path != testFile {
			t.Errorf("Expected path %s, got %s", testFile, path)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for new file event")
	}
}

func TestWatcherFileStability(t *testing.T) {
	spoolDir := t.TempDir()
	w, err := NewWatcher(spoolDir, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start watcher in background
	go func() {
		_ = w.Start(ctx)
	}()

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Create and continuously modify a file
	newDir := filepath.Join(spoolDir, "new")
	testFile := filepath.Join(newDir, "unstable.pb")

	// Write and modify file multiple times quickly
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// File should only be sent once it's stable (no modifications for 500ms)
	startTime := time.Now()

	select {
	case path := <-w.Events():
		elapsed := time.Since(startTime)
		if path != testFile {
			t.Errorf("Expected path %s, got %s", testFile, path)
		}
		// Should wait at least the stability period
		if elapsed < 500*time.Millisecond {
			t.Errorf("File sent too early: %v < 500ms", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for stable file event")
	}
}

func TestArchiveFileDelete(t *testing.T) {
	spoolDir := t.TempDir()
	// Create watcher without archive directory (should delete files)
	w, err := NewWatcher(spoolDir, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	testFile := filepath.Join(spoolDir, "test.pb")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	// Archive (delete) the file
	if err := w.ArchiveFile(testFile); err != nil {
		t.Fatalf("ArchiveFile failed: %v", err)
	}

	// File should be deleted
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("File should have been deleted")
	}
}

func TestArchiveFileMove(t *testing.T) {
	spoolDir := t.TempDir()
	archiveDir := filepath.Join(t.TempDir(), "archive")

	opts := WatcherOptions{
		ArchiveDir: archiveDir,
	}

	w, err := NewWatcherWithOptions(spoolDir, 100*time.Millisecond, opts)
	if err != nil {
		t.Fatalf("NewWatcherWithOptions failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	testFile := filepath.Join(spoolDir, "test.pb")
	testContent := []byte("test data")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Archive (move) the file
	if err := w.ArchiveFile(testFile); err != nil {
		t.Fatalf("ArchiveFile failed: %v", err)
	}

	// Original file should be gone
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("Original file should have been moved")
	}

	// File should exist in archive
	archivedFile := filepath.Join(archiveDir, "test.pb")
	content, err := os.ReadFile(archivedFile)
	if err != nil {
		t.Fatalf("Failed to read archived file: %v", err)
	}

	if string(content) != string(testContent) {
		t.Errorf("Archived file content mismatch: got %s, want %s", content, testContent)
	}
}

func TestArchiveFileNonexistent(t *testing.T) {
	spoolDir := t.TempDir()
	w, err := NewWatcher(spoolDir, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	// Archiving nonexistent file should not error
	err = w.ArchiveFile("/nonexistent/file.pb")
	if err != nil {
		t.Errorf("ArchiveFile should handle nonexistent files gracefully, got error: %v", err)
	}
}

func TestWatcherMaxPendingFiles(t *testing.T) {
	spoolDir := t.TempDir()
	opts := WatcherOptions{
		MaxPendingFiles: 3,
		CheckInterval:   100 * time.Millisecond,
	}

	w, err := NewWatcherWithOptions(spoolDir, 2*time.Second, opts) // Long stability wait
	if err != nil {
		t.Fatalf("NewWatcherWithOptions failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start watcher in background
	go func() {
		_ = w.Start(ctx)
	}()

	// Give watcher time to start
	time.Sleep(200 * time.Millisecond)

	// Create more files than the max pending limit
	newDir := filepath.Join(spoolDir, "new")
	for i := 0; i < 5; i++ {
		testFile := filepath.Join(newDir, "test"+string(rune('0'+i))+".pb")
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Watcher should handle this gracefully without crashing
	// (oldest files will be dropped from pending map)
	time.Sleep(500 * time.Millisecond)
}

func TestWatcherContextCancellation(t *testing.T) {
	spoolDir := t.TempDir()
	w, err := NewWatcher(spoolDir, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewWatcher failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())

	// Start watcher in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- w.Start(ctx)
	}()

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context
	cancel()

	// Watcher should stop and return context error
	select {
	case err := <-errChan:
		if err != context.Canceled {
			t.Errorf("Expected context.Canceled, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("Watcher did not stop after context cancellation")
	}

	// Events channel should be closed
	select {
	case _, ok := <-w.Events():
		if ok {
			t.Error("Events channel should be closed after context cancellation")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Events channel not closed")
	}
}

func TestWatcherStartupRecentFile(t *testing.T) {
	spoolDir := t.TempDir()
	newDir := filepath.Join(spoolDir, "new")
	if err := os.MkdirAll(newDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a file shortly before watcher start (younger than stabilityWait)
	testFile := filepath.Join(newDir, "recent.pb")
	if err := os.WriteFile(testFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	opts := WatcherOptions{
		CheckInterval: 10 * time.Millisecond,
	}
	w, err := NewWatcherWithOptions(spoolDir, 200*time.Millisecond, opts)
	if err != nil {
		t.Fatalf("NewWatcherWithOptions failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	go func() { _ = w.Start(ctx) }()

	select {
	case path := <-w.Events():
		if path != testFile {
			t.Fatalf("Expected path %s, got %s", testFile, path)
		}
		if elapsed := time.Since(start); elapsed < 180*time.Millisecond {
			t.Fatalf("File delivered too soon after startup: %v", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for recently-created startup file")
	}
}

func TestWatcherStartupBacklogDoesNotBlock(t *testing.T) {
	spoolDir := t.TempDir()
	newDir := filepath.Join(spoolDir, "new")
	if err := os.MkdirAll(newDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create more files than the channel buffer
	fileCount := 5
	for i := 0; i < fileCount; i++ {
		f := filepath.Join(newDir, fmt.Sprintf("file%d.pb", i))
		if err := os.WriteFile(f, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// Ensure they are stable before start
	time.Sleep(50 * time.Millisecond)

	opts := WatcherOptions{
		ChannelBuffer: 1, // Force backlog
		CheckInterval: 10 * time.Millisecond,
	}
	w, err := NewWatcherWithOptions(spoolDir, 20*time.Millisecond, opts)
	if err != nil {
		t.Fatalf("NewWatcherWithOptions failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = w.Start(ctx) }()

	seen := make(map[string]bool)
	timeout := time.After(2 * time.Second)
	for len(seen) < fileCount {
		select {
		case path := <-w.Events():
			seen[path] = true
		case <-timeout:
			t.Fatalf("Timed out waiting for backlog files, saw %d/%d", len(seen), fileCount)
		}
	}
}

func TestWatcherOverflowResyncs(t *testing.T) {
	spoolDir := t.TempDir()
	opts := WatcherOptions{
		CheckInterval: 10 * time.Millisecond,
	}
	w, err := NewWatcherWithOptions(spoolDir, 50*time.Millisecond, opts)
	if err != nil {
		t.Fatalf("NewWatcherWithOptions failed: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = w.Start(ctx) }()

	time.Sleep(50 * time.Millisecond) // allow Start to begin

	newDir := filepath.Join(spoolDir, "new")
	if err := w.watcher.Remove(newDir); err != nil {
		t.Fatalf("Failed to remove watch: %v", err)
	}

	testFile := filepath.Join(newDir, "overflow.pb")
	if err := os.WriteFile(testFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Trigger overflow handling to force rescan
	go func() {
		w.watcher.Errors <- fsnotify.ErrEventOverflow
	}()

	select {
	case path := <-w.Events():
		if path != testFile {
			t.Fatalf("Expected path %s from resync, got %s", testFile, path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for resynced file after overflow")
	}
}
