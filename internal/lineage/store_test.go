package lineage

import (
	"testing"
	"time"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
)

// TestFromProcessID tests Key creation from ProcessID
func TestFromProcessID(t *testing.T) {
	bootUUID := "test-boot-uuid"
	pidVal := int32(1234)
	pidVersionVal := int32(5678)
	pid := &santapb.ProcessID{
		Pid:        &pidVal,
		Pidversion: &pidVersionVal,
	}

	key := FromProcessID(bootUUID, pid)

	if key.BootUUID != bootUUID {
		t.Errorf("Expected BootUUID %q, got %q", bootUUID, key.BootUUID)
	}
	if key.Pid != 1234 {
		t.Errorf("Expected Pid 1234, got %d", key.Pid)
	}
	if key.PidVersion != 5678 {
		t.Errorf("Expected PidVersion 5678, got %d", key.PidVersion)
	}

	// Test nil ProcessID
	nilKey := FromProcessID(bootUUID, nil)
	if !nilKey.IsZero() {
		t.Error("Expected zero key for nil ProcessID")
	}
}

// TestKeyIsZero tests the IsZero method
func TestKeyIsZero(t *testing.T) {
	tests := []struct {
		name     string
		key      Key
		expected bool
	}{
		{
			name:     "zero key",
			key:      Key{},
			expected: true,
		},
		{
			name:     "only boot UUID",
			key:      Key{BootUUID: "test"},
			expected: false,
		},
		{
			name:     "only PID",
			key:      Key{Pid: 123},
			expected: false,
		},
		{
			name:     "complete key",
			key:      Key{BootUUID: "test", Pid: 123, PidVersion: 456},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.key.IsZero(); got != tt.expected {
				t.Errorf("IsZero() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestNewStore tests store initialization
func TestNewStore(t *testing.T) {
	tests := []struct {
		name           string
		cfg            Config
		expectDefaults bool
	}{
		{
			name: "with config",
			cfg: Config{
				MaxEntries: 1000,
				TTL:        30 * time.Minute,
			},
			expectDefaults: false,
		},
		{
			name:           "zero config uses defaults",
			cfg:            Config{},
			expectDefaults: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewStore(tt.cfg)

			if store == nil {
				t.Fatal("Expected non-nil store")
			}

			if tt.expectDefaults {
				if store.maxEntries != 50000 {
					t.Errorf("Expected default maxEntries 50000, got %d", store.maxEntries)
				}
				if store.ttl != time.Hour {
					t.Errorf("Expected default TTL 1h, got %v", store.ttl)
				}
			} else {
				if store.maxEntries != tt.cfg.MaxEntries {
					t.Errorf("Expected maxEntries %d, got %d", tt.cfg.MaxEntries, store.maxEntries)
				}
				if store.ttl != tt.cfg.TTL {
					t.Errorf("Expected TTL %v, got %v", tt.cfg.TTL, store.ttl)
				}
			}
		})
	}
}

// TestBasicLineageTracking tests basic parent-child tracking
func TestBasicLineageTracking(t *testing.T) {
	store := NewStore(Config{MaxEntries: 100, TTL: time.Hour})
	bootUUID := "test-boot"

	// Create process chain: parent -> child -> grandchild
	parentKey := Key{BootUUID: bootUUID, Pid: 1, PidVersion: 100}
	childKey := Key{BootUUID: bootUUID, Pid: 2, PidVersion: 200}
	grandchildKey := Key{BootUUID: bootUUID, Pid: 3, PidVersion: 300}

	store.mu.Lock()
	// Insert parent
	store.nodes[parentKey] = &Node{
		Key:    parentKey,
		Parent: Key{}, // No parent
		Path:   "/bin/bash",
		User:   "root",
		Args:   []string{"/bin/bash"},
	}

	// Insert child
	store.nodes[childKey] = &Node{
		Key:    childKey,
		Parent: parentKey,
		Path:   "/usr/bin/python",
		User:   "user1",
		Args:   []string{"python", "script.py"},
	}

	// Insert grandchild
	store.nodes[grandchildKey] = &Node{
		Key:    grandchildKey,
		Parent: childKey,
		Path:   "/usr/bin/curl",
		User:   "user1",
		Args:   []string{"curl", "http://example.com"},
	}
	store.mu.Unlock()

	// Get lineage for grandchild
	lineage := store.Lineage(grandchildKey, 10)

	if len(lineage) != 3 {
		t.Fatalf("Expected lineage length 3, got %d", len(lineage))
	}

	// Verify order: grandchild -> child -> parent
	if lineage[0].Key != grandchildKey {
		t.Error("Expected first element to be grandchild")
	}
	if lineage[1].Key != childKey {
		t.Error("Expected second element to be child")
	}
	if lineage[2].Key != parentKey {
		t.Error("Expected third element to be parent")
	}
}

// TestCycleDetection tests that lineage handles cycles
func TestCycleDetection(t *testing.T) {
	store := NewStore(Config{MaxEntries: 100, TTL: time.Hour})
	bootUUID := "test-boot"

	// Create a cycle: A -> B -> C -> A
	keyA := Key{BootUUID: bootUUID, Pid: 1, PidVersion: 100}
	keyB := Key{BootUUID: bootUUID, Pid: 2, PidVersion: 200}
	keyC := Key{BootUUID: bootUUID, Pid: 3, PidVersion: 300}

	store.mu.Lock()
	store.nodes[keyA] = &Node{
		Key:    keyA,
		Parent: keyC, // Points back to C, creating cycle
		Path:   "/bin/bash",
	}

	store.nodes[keyB] = &Node{
		Key:    keyB,
		Parent: keyA,
		Path:   "/usr/bin/python",
	}

	store.nodes[keyC] = &Node{
		Key:    keyC,
		Parent: keyB,
		Path:   "/usr/bin/curl",
	}
	store.mu.Unlock()

	// Get lineage for A - should detect cycle and stop
	lineage := store.Lineage(keyA, 10)

	// Should have stopped when cycle detected
	if len(lineage) > 3 {
		t.Fatalf("Expected cycle detection to stop lineage, got length %d", len(lineage))
	}

	// Verify we got at least the starting node
	if len(lineage) == 0 {
		t.Fatal("Expected at least one node in lineage")
	}
}

// TestMaxDepthLimit tests that lineage respects max depth
func TestMaxDepthLimit(t *testing.T) {
	store := NewStore(Config{MaxEntries: 100, TTL: time.Hour})
	bootUUID := "test-boot"

	// Create a long chain
	keys := make([]Key, 20)
	for i := 0; i < 20; i++ {
		keys[i] = Key{BootUUID: bootUUID, Pid: int32(i + 1), PidVersion: int32((i + 1) * 100)}
	}

	store.mu.Lock()
	// Link them: 0 <- 1 <- 2 <- ... <- 19
	store.nodes[keys[0]] = &Node{
		Key:    keys[0],
		Parent: Key{}, // Root
		Path:   "/sbin/launchd",
	}

	for i := 1; i < 20; i++ {
		store.nodes[keys[i]] = &Node{
			Key:    keys[i],
			Parent: keys[i-1],
			Path:   "/usr/bin/test",
		}
	}
	store.mu.Unlock()

	// Get lineage with depth limit of 5
	lineage := store.Lineage(keys[19], 5)

	if len(lineage) != 5 {
		t.Fatalf("Expected lineage length 5 (depth limit), got %d", len(lineage))
	}
}

// TestTTLEviction tests that old entries are evicted
func TestTTLEviction(t *testing.T) {
	store := NewStore(Config{
		MaxEntries: 100,
		TTL:        100 * time.Millisecond, // Very short TTL for testing
	})

	bootUUID := "test-boot"
	key := Key{BootUUID: bootUUID, Pid: 1, PidVersion: 100}

	// Add a node
	store.mu.Lock()
	store.nodes[key] = &Node{
		Key:       key,
		Parent:    Key{},
		Path:      "/bin/bash",
		CreatedAt: time.Now().Add(-200 * time.Millisecond), // Already expired
	}

	// Call eviction (must hold lock)
	store.evictExpiredLocked(time.Now())

	// Should be evicted
	_, exists := store.nodes[key]
	store.mu.Unlock()

	if exists {
		t.Error("Expected expired node to be evicted")
	}
}

// TestMaxEntriesEviction tests that oldest entries are evicted when limit reached
func TestMaxEntriesEviction(t *testing.T) {
	store := NewStore(Config{
		MaxEntries: 3, // Small limit
		TTL:        time.Hour,
	})

	bootUUID := "test-boot"

	// Add 3 nodes with different ages (node 3 is oldest)
	for i := 1; i <= 3; i++ {
		key := Key{BootUUID: bootUUID, Pid: int32(i), PidVersion: int32(i * 100)}
		store.mu.Lock()
		store.nodes[key] = &Node{
			Key:       key,
			Path:      "/bin/test",
			CreatedAt: time.Now().Add(-time.Duration(i) * time.Minute), // Higher i = older timestamp
		}
		store.mu.Unlock()
	}

	// Evict oldest
	store.mu.Lock()
	store.evictOldestLocked()
	store.mu.Unlock()

	// Should have 2 nodes now
	store.mu.RLock()
	count := len(store.nodes)
	store.mu.RUnlock()

	if count != 2 {
		t.Errorf("Expected 2 nodes after eviction, got %d", count)
	}

	// Node 3 (oldest, created at now - 3 minutes) should be gone
	oldestKey := Key{BootUUID: bootUUID, Pid: 3, PidVersion: 300}
	store.mu.RLock()
	_, exists := store.nodes[oldestKey]
	store.mu.RUnlock()

	if exists {
		t.Error("Expected oldest node to be evicted")
	}
}

// TestSerialize tests lineage serialization
func TestSerialize(t *testing.T) {
	now := time.Now()

	nodes := []*Node{
		{
			Key:       Key{BootUUID: "test", Pid: 1, PidVersion: 100},
			Path:      "/usr/bin/curl",
			User:      "user1",
			UID:       501,
			Group:     "staff",
			GID:       20,
			SessionID: 100,
			Args:      []string{"curl", "http://example.com"},
			StartTime: now,
		},
		{
			Key:       Key{BootUUID: "test", Pid: 2, PidVersion: 200},
			Path:      "/usr/bin/python",
			User:      "user1",
			UID:       501,
			Group:     "staff",
			GID:       20,
			SessionID: 100,
			Args:      []string{"python", "script.py"},
			StartTime: now,
		},
		{
			Key:       Key{BootUUID: "test", Pid: 3, PidVersion: 300},
			Path:      "/bin/bash",
			User:      "user1",
			UID:       501,
			Group:     "staff",
			GID:       20,
			SessionID: 100,
			Args:      []string{"/bin/bash"},
			StartTime: now,
		},
	}

	serialized := Serialize(nodes)

	if len(serialized) != 3 {
		t.Fatalf("Expected 3 serialized nodes, got %d", len(serialized))
	}

	// Verify first node (target)
	if serialized[0]["relation"] != "target" {
		t.Errorf("Expected relation 'target', got %v", serialized[0]["relation"])
	}
	if serialized[0]["depth"] != 0 {
		t.Errorf("Expected depth 0, got %v", serialized[0]["depth"])
	}

	// Verify second node (parent)
	if serialized[1]["relation"] != "parent" {
		t.Errorf("Expected relation 'parent', got %v", serialized[1]["relation"])
	}
	if serialized[1]["depth"] != 1 {
		t.Errorf("Expected depth 1, got %v", serialized[1]["depth"])
	}

	// Verify third node (ancestor)
	if serialized[2]["relation"] != "ancestor" {
		t.Errorf("Expected relation 'ancestor', got %v", serialized[2]["relation"])
	}
	if serialized[2]["depth"] != 2 {
		t.Errorf("Expected depth 2, got %v", serialized[2]["depth"])
	}

	// Verify empty slice returns nil
	if Serialize(nil) != nil {
		t.Error("Expected nil for nil input")
	}
	if Serialize([]*Node{}) != nil {
		t.Error("Expected nil for empty slice")
	}
}

// TestConcurrentAccess tests concurrent reads and writes
func TestConcurrentAccess(t *testing.T) {
	store := NewStore(Config{MaxEntries: 1000, TTL: time.Hour})
	bootUUID := "test-boot"

	// Start multiple goroutines adding nodes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				key := Key{BootUUID: bootUUID, Pid: int32(id*100 + j), PidVersion: int32(id*1000 + j)}
				// Use proper locking when accessing nodes map
				store.mu.Lock()
				store.nodes[key] = &Node{
					Key:       key,
					Path:      "/bin/test",
					CreatedAt: time.Now(),
				}
				store.mu.Unlock()

				// Also try reading (Lineage already has proper locking)
				_ = store.Lineage(key, 5)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have many nodes
	store.mu.RLock()
	count := len(store.nodes)
	store.mu.RUnlock()

	if count == 0 {
		t.Error("Expected some nodes to be stored")
	}
}

// TestEmptyLineage tests lineage for non-existent node
func TestEmptyLineage(t *testing.T) {
	store := NewStore(Config{MaxEntries: 100, TTL: time.Hour})

	nonExistentKey := Key{BootUUID: "test", Pid: 999, PidVersion: 999}

	lineage := store.Lineage(nonExistentKey, 10)

	if lineage != nil {
		t.Error("Expected nil lineage for non-existent key")
	}
}
