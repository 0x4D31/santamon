package state

import (
	"path/filepath"
	"testing"
	"time"
)

// setupTestDB creates a temporary database for testing
func setupTestDB(t *testing.T) (*DB, string) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := Open(dbPath, 1000, true)
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	return db, dbPath
}

// TestOpen tests database initialization
func TestOpen(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		maxFirstSeen  int
		syncWrites    bool
		expectError   bool
		errorContains string
	}{
		{
			name:         "valid parameters",
			path:         filepath.Join(t.TempDir(), "valid.db"),
			maxFirstSeen: 1000,
			syncWrites:   true,
			expectError:  false,
		},
		{
			name:          "empty path",
			path:          "",
			maxFirstSeen:  1000,
			syncWrites:    true,
			expectError:   true,
			errorContains: "path cannot be empty",
		},
		{
			name:          "zero maxFirstSeen",
			path:          filepath.Join(t.TempDir(), "zero.db"),
			maxFirstSeen:  0,
			syncWrites:    true,
			expectError:   true,
			errorContains: "must be positive",
		},
		{
			name:          "negative maxFirstSeen",
			path:          filepath.Join(t.TempDir(), "negative.db"),
			maxFirstSeen:  -1,
			syncWrites:    true,
			expectError:   true,
			errorContains: "must be positive",
		},
		{
			name:          "maxFirstSeen too large",
			path:          filepath.Join(t.TempDir(), "toolarge.db"),
			maxFirstSeen:  10000001,
			syncWrites:    true,
			expectError:   true,
			errorContains: "too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Open(tt.path, tt.maxFirstSeen, tt.syncWrites)
			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			defer func() { _ = db.Close() }()

			// Verify database is open and functional
			if db.DB == nil {
				t.Fatal("Database is nil")
			}
		})
	}
}

// TestEnqueueDequeueSignals tests signal queue operations
func TestEnqueueDequeueSignals(t *testing.T) {
	db, _ := setupTestDB(t)
	defer func() { _ = db.Close() }()

	// Create test signals
	signals := []*Signal{
		{
			ID:       "signal-1",
			TS:       time.Now(),
			HostID:   "host-1",
			RuleID:   "RULE-001",
			Severity: "high",
			Title:    "Test Signal 1",
			Tags:     []string{"test"},
			Context:  map[string]any{"key": "value1"},
		},
		{
			ID:       "signal-2",
			TS:       time.Now(),
			HostID:   "host-1",
			RuleID:   "RULE-002",
			Severity: "critical",
			Title:    "Test Signal 2",
			Tags:     []string{"test"},
			Context:  map[string]any{"key": "value2"},
		},
	}

	// Enqueue signals
	for _, sig := range signals {
		if err := db.EnqueueSignal(sig); err != nil {
			t.Fatalf("Failed to enqueue signal: %v", err)
		}
	}

	// Dequeue all signals
	dequeued, err := db.DequeueSignals(10)
	if err != nil {
		t.Fatalf("Failed to dequeue signals: %v", err)
	}

	if len(dequeued) != 2 {
		t.Fatalf("Expected 2 signals, got %d", len(dequeued))
	}

	// Verify signal content
	for i, sig := range dequeued {
		if sig.ID != signals[i].ID {
			t.Errorf("Signal %d: expected ID %q, got %q", i, signals[i].ID, sig.ID)
		}
		if sig.Severity != signals[i].Severity {
			t.Errorf("Signal %d: expected severity %q, got %q", i, signals[i].Severity, sig.Severity)
		}
	}
}

// TestEnqueueSignalIfNotShipped tests atomic check-and-enqueue
func TestEnqueueSignalIfNotShipped(t *testing.T) {
	db, _ := setupTestDB(t)
	defer func() { _ = db.Close() }()

	sig := &Signal{
		ID:       "signal-1",
		TS:       time.Now(),
		HostID:   "host-1",
		RuleID:   "RULE-001",
		Severity: "high",
		Title:    "Test Signal",
		Tags:     []string{"test"},
		Context:  map[string]any{"key": "value"},
	}

	// First enqueue should succeed
	enqueued, err := db.EnqueueSignalIfNotShipped(sig)
	if err != nil {
		t.Fatalf("Failed to enqueue signal: %v", err)
	}
	if !enqueued {
		t.Fatal("Expected signal to be enqueued")
	}

	// Mark as shipped
	if err := db.MarkShipped(sig.ID); err != nil {
		t.Fatalf("Failed to mark as shipped: %v", err)
	}

	// Second enqueue should fail (already shipped)
	enqueued, err = db.EnqueueSignalIfNotShipped(sig)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if enqueued {
		t.Fatal("Expected signal to not be enqueued (already shipped)")
	}
}

// TestIsFirstSeen tests first-seen tracking
func TestIsFirstSeen(t *testing.T) {
	db, _ := setupTestDB(t)
	defer func() { _ = db.Close() }()

	kind := "execution"
	id := "sha256:abcd1234"

	// First check should return true (first time seeing it)
	first, err := db.IsFirstSeen(kind, id)
	if err != nil {
		t.Fatalf("Failed to check first seen: %v", err)
	}
	if !first {
		t.Fatal("Expected first seen to be true")
	}

	// Second check should return false (already seen)
	first, err = db.IsFirstSeen(kind, id)
	if err != nil {
		t.Fatalf("Failed to check first seen: %v", err)
	}
	if first {
		t.Fatal("Expected first seen to be false")
	}

	// Different ID should be first seen
	first, err = db.IsFirstSeen(kind, "sha256:different")
	if err != nil {
		t.Fatalf("Failed to check first seen: %v", err)
	}
	if !first {
		t.Fatal("Expected different ID to be first seen")
	}
}

// TestFirstSeenLRUEviction tests LRU eviction
func TestFirstSeenLRUEviction(t *testing.T) {
	// Create DB with small max size for testing
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := Open(dbPath, 5, true) // Max 5 entries
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer func() { _ = db.Close() }()

	kind := "execution"

	// Fill cache to capacity
	ids := []string{"id1", "id2", "id3", "id4", "id5"}
	for _, id := range ids {
		first, err := db.IsFirstSeen(kind, id)
		if err != nil {
			t.Fatalf("Failed to check first seen: %v", err)
		}
		if !first {
			t.Fatalf("Expected %s to be first seen", id)
		}
	}

	// Add one more (should evict oldest)
	first, err := db.IsFirstSeen(kind, "id6")
	if err != nil {
		t.Fatalf("Failed to check first seen: %v", err)
	}
	if !first {
		t.Fatal("Expected id6 to be first seen")
	}

	// Check that id1 (oldest) was evicted and is now "first seen" again
	first, err = db.IsFirstSeen(kind, "id1")
	if err != nil {
		t.Fatalf("Failed to check first seen: %v", err)
	}
	if !first {
		t.Fatal("Expected id1 to be first seen again after eviction")
	}
}

// TestStoreWindowEvent tests window event storage
func TestStoreWindowEvent(t *testing.T) {
	db, _ := setupTestDB(t)
	defer func() { _ = db.Close() }()

	ruleID := "CORR-001"
	groupKey := "user:alice"
	event1 := map[string]any{"ts": time.Now().Unix(), "action": "login"}
	event2 := map[string]any{"ts": time.Now().Unix(), "action": "exec"}

	// Store events
	if err := db.StoreWindowEvent(ruleID, groupKey, event1); err != nil {
		t.Fatalf("Failed to store event 1: %v", err)
	}
	if err := db.StoreWindowEvent(ruleID, groupKey, event2); err != nil {
		t.Fatalf("Failed to store event 2: %v", err)
	}

	// Retrieve events
	events, err := db.GetWindowEvents(ruleID, groupKey)
	if err != nil {
		t.Fatalf("Failed to get events: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(events))
	}
}

// TestDatabaseRecovery tests database recovery after close
func TestDatabaseRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "recovery.db")

	// Create DB and write data
	db1, err := Open(dbPath, 1000, true)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	sig := &Signal{
		ID:       "signal-1",
		TS:       time.Now(),
		HostID:   "host-1",
		RuleID:   "RULE-001",
		Severity: "high",
		Title:    "Test Signal",
		Tags:     []string{"test"},
		Context:  map[string]any{"key": "value"},
	}

	if err := db1.EnqueueSignal(sig); err != nil {
		t.Fatalf("Failed to enqueue signal: %v", err)
	}

	// Close database normally
	if err := db1.Close(); err != nil {
		t.Fatalf("Failed to close database: %v", err)
	}

	// Reopen database
	db2, err := Open(dbPath, 1000, true)
	if err != nil {
		t.Fatalf("Failed to reopen database: %v", err)
	}
	defer func() { _ = db2.Close() }()

	// Verify data persisted
	dequeued, err := db2.DequeueSignals(10)
	if err != nil {
		t.Fatalf("Failed to dequeue signals: %v", err)
	}

	if len(dequeued) != 1 {
		t.Fatalf("Expected 1 signal, got %d", len(dequeued))
	}

	if dequeued[0].ID != sig.ID {
		t.Errorf("Expected signal ID %q, got %q", sig.ID, dequeued[0].ID)
	}
}

// Helper function
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
