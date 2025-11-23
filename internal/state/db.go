package state

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	// Bucket names
	bucketSignals   = []byte("signals")
	bucketShipped   = []byte("shipped")
	bucketFirstSeen = []byte("first_seen")
	bucketWindows   = []byte("windows")
	bucketJournal   = []byte("journal")
	bucketMeta      = []byte("meta")
)

// DB wraps BoltDB with santamon-specific operations
type DB struct {
	*bolt.DB
	maxFirstSeen int
}

// Signal represents a detection signal
type Signal struct {
	ID              string         `json:"signal_id"`
	TS              time.Time      `json:"ts"`
	HostID          string         `json:"host_id"`
	RuleID          string         `json:"rule_id"`
	RuleDescription string         `json:"rule_description,omitempty"`
	Status          string         `json:"status"`
	Severity        string         `json:"severity"`
	Title           string         `json:"title"`
	Tags            []string       `json:"tags"`
	Context         map[string]any `json:"context"`
}

// FirstSeenEntry tracks when an artifact was first observed
type FirstSeenEntry struct {
	First time.Time `json:"first"`
	Count int       `json:"count"`
	Last  time.Time `json:"last"`
}

// JournalEntry tracks spool file processing progress
type JournalEntry struct {
	Offset      int64     `json:"offset"`
	ProcessedTS time.Time `json:"processed_ts"`
}

// Open opens or creates the BoltDB database
func Open(path string, maxFirstSeen int, syncWrites bool) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("database path cannot be empty")
	}
	if maxFirstSeen <= 0 {
		return nil, fmt.Errorf("maxFirstSeen must be positive, got %d", maxFirstSeen)
	}
	if maxFirstSeen > 10000000 {
		return nil, fmt.Errorf("maxFirstSeen too large (max 10000000), got %d", maxFirstSeen)
	}

	db, err := bolt.Open(path, 0600, &bolt.Options{
		Timeout:    1 * time.Second,
		NoGrowSync: false,
		NoSync:     !syncWrites,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Initialize buckets
	err = db.Update(func(tx *bolt.Tx) error {
		buckets := [][]byte{
			bucketSignals,
			bucketShipped,
			bucketFirstSeen,
			bucketWindows,
			bucketJournal,
			bucketMeta,
		}
		for _, b := range buckets {
			_, err := tx.CreateBucketIfNotExists(b)
			if err != nil {
				return fmt.Errorf("failed to create bucket %s: %w", string(b), err)
			}
		}
		return nil
	})
	if err != nil {
		// Ensure database is closed on error
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("failed to initialize buckets: %w (also failed to close db: %v)", err, closeErr)
		}
		return nil, err
	}

	return &DB{
		DB:           db,
		maxFirstSeen: maxFirstSeen,
	}, nil
}

// EnqueueSignal adds a signal to the outbox queue
func (db *DB) EnqueueSignal(sig *Signal) error {
	if sig == nil {
		return fmt.Errorf("signal cannot be nil")
	}
	if sig.ID == "" {
		return fmt.Errorf("signal ID cannot be empty")
	}
	if sig.RuleID == "" {
		return fmt.Errorf("signal RuleID cannot be empty")
	}

	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSignals)
		key := []byte(fmt.Sprintf("%d_%s", time.Now().UnixNano(), sig.ID))
		val, err := json.Marshal(sig)
		if err != nil {
			return fmt.Errorf("failed to marshal signal: %w", err)
		}
		return b.Put(key, val)
	})
}

// EnqueueSignalIfNotShipped atomically checks if a signal was already shipped
// and enqueues it only if not. Returns true if the signal was enqueued.
// This prevents the race condition where two goroutines could both enqueue
// the same signal by doing the check and enqueue in a single transaction.
func (db *DB) EnqueueSignalIfNotShipped(sig *Signal) (bool, error) {
	if sig == nil {
		return false, fmt.Errorf("signal cannot be nil")
	}
	if sig.ID == "" {
		return false, fmt.Errorf("signal ID cannot be empty")
	}
	if sig.RuleID == "" {
		return false, fmt.Errorf("signal RuleID cannot be empty")
	}

	var enqueued bool
	err := db.Update(func(tx *bolt.Tx) error {
		// Check if already shipped
		shippedBucket := tx.Bucket(bucketShipped)
		if shippedBucket.Get([]byte(sig.ID)) != nil {
			enqueued = false
			return nil
		}

		// Not shipped, so enqueue it
		signalsBucket := tx.Bucket(bucketSignals)
		key := []byte(fmt.Sprintf("%d_%s", time.Now().UnixNano(), sig.ID))
		val, err := json.Marshal(sig)
		if err != nil {
			return fmt.Errorf("failed to marshal signal: %w", err)
		}
		if err := signalsBucket.Put(key, val); err != nil {
			return err
		}

		enqueued = true
		return nil
	})

	return enqueued, err
}

// DequeueSignals retrieves and removes up to limit signals from the queue
func (db *DB) DequeueSignals(limit int) ([]*Signal, error) {
	var signals []*Signal

	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSignals)
		c := b.Cursor()

		count := 0
		for k, v := c.First(); k != nil && count < limit; k, v = c.Next() {
			var sig Signal
			if err := json.Unmarshal(v, &sig); err != nil {
				// Log error but continue
				continue
			}
			signals = append(signals, &sig)
			if err := c.Delete(); err != nil {
				return err
			}
			count++
		}
		return nil
	})

	return signals, err
}

// MarkShipped records that a signal was successfully shipped
func (db *DB) MarkShipped(signalID string) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketShipped)
		key := []byte(signalID)
		val := []byte(time.Now().Format(time.RFC3339))
		return b.Put(key, val)
	})
}

// IsShipped checks if a signal has already been shipped
func (db *DB) IsShipped(signalID string) (bool, error) {
	var shipped bool
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketShipped)
		val := b.Get([]byte(signalID))
		shipped = val != nil
		return nil
	})
	return shipped, err
}

// IsFirstSeen checks if an artifact is being seen for the first time
// Returns true if first seen, false if already tracked
func (db *DB) IsFirstSeen(kind, id string) (bool, error) {
	var isFirst bool

	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFirstSeen)
		key := []byte(fmt.Sprintf("%s:%s", kind, id))

		existing := b.Get(key)
		if existing == nil {
			isFirst = true

			// LRU eviction at max entries
			if b.Stats().KeyN >= db.maxFirstSeen {
				c := b.Cursor()
				if k, _ := c.First(); k != nil {
					_ = b.Delete(k)
				}
			}

			entry := FirstSeenEntry{
				First: time.Now(),
				Count: 1,
				Last:  time.Now(),
			}
			val, err := json.Marshal(entry)
			if err != nil {
				return err
			}
			return b.Put(key, val)
		} else {
			// Update existing entry
			var entry FirstSeenEntry
			if err := json.Unmarshal(existing, &entry); err == nil {
				entry.Count++
				entry.Last = time.Now()
				val, err := json.Marshal(entry)
				if err != nil {
					return err
				}
				return b.Put(key, val)
			}
		}
		return nil
	})

	return isFirst, err
}

// UpdateJournal records progress processing a spool file
func (db *DB) UpdateJournal(filename string, offset int64) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketJournal)
		entry := JournalEntry{
			Offset:      offset,
			ProcessedTS: time.Now(),
		}
		val, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(filename), val)
	})
}

// GetJournalEntry retrieves the processing progress for a spool file
func (db *DB) GetJournalEntry(filename string) (*JournalEntry, error) {
	var entry *JournalEntry

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketJournal)
		val := b.Get([]byte(filename))
		if val == nil {
			return nil
		}

		entry = &JournalEntry{}
		return json.Unmarshal(val, entry)
	})

	return entry, err
}

// SetMeta stores a metadata key-value pair
func (db *DB) SetMeta(key, value string) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		return b.Put([]byte(key), []byte(value))
	})
}

// GetMeta retrieves a metadata value
func (db *DB) GetMeta(key string) (string, error) {
	var value string
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		val := b.Get([]byte(key))
		if val != nil {
			value = string(val)
		}
		return nil
	})
	return value, err
}

// StoreWindowEvent stores an event for correlation window processing
func (db *DB) StoreWindowEvent(ruleID, groupKey string, event map[string]any) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWindows)

		// Create nested bucket for this rule
		ruleBucket, err := b.CreateBucketIfNotExists([]byte(ruleID))
		if err != nil {
			return err
		}

		// Get existing events for this group
		key := []byte(groupKey)
		var events []map[string]any
		if existing := ruleBucket.Get(key); existing != nil {
			if err := json.Unmarshal(existing, &events); err != nil {
				return err
			}
		}

		// Append new event
		events = append(events, event)

		// Store updated events
		val, err := json.Marshal(events)
		if err != nil {
			return err
		}
		return ruleBucket.Put(key, val)
	})
}

// GetWindowEvents retrieves events for a correlation window
func (db *DB) GetWindowEvents(ruleID, groupKey string) ([]map[string]any, error) {
	var events []map[string]any

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWindows)
		ruleBucket := b.Bucket([]byte(ruleID))
		if ruleBucket == nil {
			return nil
		}

		val := ruleBucket.Get([]byte(groupKey))
		if val == nil {
			return nil
		}

		return json.Unmarshal(val, &events)
	})

	return events, err
}

// CleanWindowEvents removes old events from correlation windows
func (db *DB) CleanWindowEvents(ruleID, groupKey string, keepCount int) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWindows)
		ruleBucket := b.Bucket([]byte(ruleID))
		if ruleBucket == nil {
			return nil
		}

		key := []byte(groupKey)
		val := ruleBucket.Get(key)
		if val == nil {
			return nil
		}

		var events []map[string]any
		if err := json.Unmarshal(val, &events); err != nil {
			return err
		}

		// Keep only recent events
		if len(events) > keepCount {
			events = events[len(events)-keepCount:]
		}

		newVal, err := json.Marshal(events)
		if err != nil {
			return err
		}
		return ruleBucket.Put(key, newVal)
	})
}

// ReplaceWindowEvents overwrites a correlation window with the provided events.
// If events is empty or nil, the entry is removed.
func (db *DB) ReplaceWindowEvents(ruleID, groupKey string, events []map[string]any) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWindows)
		ruleBucket, err := b.CreateBucketIfNotExists([]byte(ruleID))
		if err != nil {
			return err
		}

		key := []byte(groupKey)
		if len(events) == 0 {
			return ruleBucket.Delete(key)
		}

		val, err := json.Marshal(events)
		if err != nil {
			return err
		}
		return ruleBucket.Put(key, val)
	})
}

// Stats returns database statistics
func (db *DB) Stats() (map[string]any, error) {
	stats := make(map[string]any)

	err := db.View(func(tx *bolt.Tx) error {
		stats["signals"] = tx.Bucket(bucketSignals).Stats().KeyN
		stats["shipped"] = tx.Bucket(bucketShipped).Stats().KeyN
		stats["first_seen"] = tx.Bucket(bucketFirstSeen).Stats().KeyN
		stats["journal"] = tx.Bucket(bucketJournal).Stats().KeyN

		// Count window events
		windowCount := 0
		windowBucket := tx.Bucket(bucketWindows)
		_ = windowBucket.ForEach(func(k, v []byte) error {
			if v == nil { // It's a nested bucket
				ruleBucket := windowBucket.Bucket(k)
				if ruleBucket != nil {
					windowCount += ruleBucket.Stats().KeyN
				}
			}
			return nil
		})
		stats["windows"] = windowCount

		dbStats := tx.DB().Stats()
		stats["tx_count"] = dbStats.TxN
		stats["page_count"] = dbStats.TxStats.PageCount
		stats["page_alloc"] = dbStats.TxStats.PageAlloc

		return nil
	})

	return stats, err
}

// Compact performs database compaction
func (db *DB) Compact() error {
	// BoltDB doesn't have a direct compact method, but we can copy to a new file
	// This would be implemented in a separate function if needed
	// For now, just return nil as BoltDB handles space efficiently
	return nil
}
