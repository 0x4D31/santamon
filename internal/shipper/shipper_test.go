package shipper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x4d31/santamon/internal/config"
	"github.com/0x4d31/santamon/internal/state"
)

func TestNewShipper(t *testing.T) {
	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := &config.ShipperConfig{
		Endpoint:      "https://test.example.com",
		APIKey:        "test-key-1234567890",
		BatchSize:     10,
		FlushInterval: 5 * time.Second,
		Timeout:       10 * time.Second,
		Retry: config.RetryConfig{
			MaxAttempts: 3,
			Backoff:     "exponential",
			Initial:     1 * time.Second,
			Max:         30 * time.Second,
		},
	}

	s := NewShipper(cfg, db, "test-agent", "1.0.0")
	if s == nil {
		t.Fatal("NewShipper returned nil")
	}
	if s.config != cfg {
		t.Error("Config not set correctly")
	}
	if s.db != db {
		t.Error("DB not set correctly")
	}
	if s.userAgent != "github.com/0x4d31/santamon/1.0.0" {
		t.Errorf("User-Agent incorrect: %s", s.userAgent)
	}
}

func TestSendHTTPSuccess(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("Missing Content-Type header")
		}
		if r.Header.Get("X-API-Key") != "test-key-1234567890" {
			t.Error("Missing or incorrect API key")
		}

		// Verify body is valid JSON
		var sig state.Signal
		if err := json.NewDecoder(r.Body).Decode(&sig); err != nil {
			t.Errorf("Invalid JSON body: %v", err)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := testConfig(server.URL)
	s := NewShipper(cfg, db, "test-agent", "1.0.0")

	sig := &state.Signal{
		ID:       "test-signal-1",
		HostID:   "test-host",
		RuleID:   "TEST-001",
		Severity: "high",
	}

	err := s.sendHTTPWithContext(context.Background(), sig)
	if err != nil {
		t.Fatalf("sendHTTP failed: %v", err)
	}
}

func TestSendHTTPServerError(t *testing.T) {
	// Create test server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := testConfig(server.URL)
	s := NewShipper(cfg, db, "test-agent", "1.0.0")

	sig := &state.Signal{ID: "test-signal-1"}

	err := s.sendHTTPWithContext(context.Background(), sig)
	if err == nil {
		t.Error("Expected error for 500 response")
	}
	if isPermanentError(err) {
		t.Error("500 error should not be permanent")
	}
}

func TestSendHTTPClientError(t *testing.T) {
	// Create test server that returns 400
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid request"))
	}))
	defer server.Close()

	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := testConfig(server.URL)
	s := NewShipper(cfg, db, "test-agent", "1.0.0")

	sig := &state.Signal{ID: "test-signal-1"}

	err := s.sendHTTPWithContext(context.Background(), sig)
	if err == nil {
		t.Error("Expected error for 400 response")
	}
	if !isPermanentError(err) {
		t.Error("400 error should be permanent")
	}
}

func TestSendSignalRetry(t *testing.T) {
	attempts := atomic.Int32{}

	// Create test server that fails twice then succeeds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := testConfig(server.URL)
	cfg.Retry.MaxAttempts = 3
	cfg.Retry.Initial = 10 * time.Millisecond
	s := NewShipper(cfg, db, "test-agent", "1.0.0")

	sig := &state.Signal{ID: "test-signal-1"}

	err := s.sendSignalWithContext(context.Background(), sig)
	if err != nil {
		t.Fatalf("sendSignal failed after retries: %v", err)
	}

	if attempts.Load() != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts.Load())
	}
}

func TestSendSignalNoPermanentRetry(t *testing.T) {
	attempts := atomic.Int32{}

	// Create test server that always returns 400
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := testConfig(server.URL)
	cfg.Retry.MaxAttempts = 3
	s := NewShipper(cfg, db, "test-agent", "1.0.0")

	sig := &state.Signal{ID: "test-signal-1"}

	err := s.sendSignalWithContext(context.Background(), sig)
	if err == nil {
		t.Error("Expected error for permanent failure")
	}

	// Should only attempt once (no retry for permanent errors)
	if attempts.Load() != 1 {
		t.Errorf("Expected 1 attempt for permanent error, got %d", attempts.Load())
	}
}

func TestFlushRetainsPermanentFailures(t *testing.T) {
	// Server always returns 400 (permanent)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := testConfig(server.URL)
	cfg.BatchSize = 5
	s := NewShipper(cfg, db, "test-agent", "1.0.0")

	sig := &state.Signal{
		ID:       "perm-1",
		HostID:   "host-1",
		RuleID:   "RULE-001",
		Severity: "high",
	}
	if err := s.EnqueueSignal(sig); err != nil {
		t.Fatalf("Failed to enqueue signal: %v", err)
	}

	if err := s.flushWithContext(context.Background()); err != nil {
		t.Fatalf("flushWithContext returned error: %v", err)
	}

	// Signal should remain queued for later retry instead of being dropped
	queued, err := db.DequeueSignals(10)
	if err != nil {
		t.Fatalf("Failed to dequeue signals: %v", err)
	}
	if len(queued) != 1 {
		t.Fatalf("Expected 1 queued signal after permanent failure, got %d", len(queued))
	}
	if queued[0].ID != sig.ID {
		t.Errorf("Queued signal ID = %s, want %s", queued[0].ID, sig.ID)
	}
}

func TestSendSignalContextCancellation(t *testing.T) {
	// Create test server that delays
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := testConfig(server.URL)
	s := NewShipper(cfg, db, "test-agent", "1.0.0")

	sig := &state.Signal{ID: "test-signal-1"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := s.sendSignalWithContext(ctx, sig)
	if err == nil {
		t.Error("Expected error for context cancellation")
	}
	if err != context.DeadlineExceeded && err != context.Canceled {
		t.Errorf("Expected context error, got: %v", err)
	}
}

func TestBackoffWithJitter(t *testing.T) {
	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := testConfig("https://test.example.com")
	cfg.Retry.Backoff = "exponential"
	cfg.Retry.Initial = 1 * time.Second
	cfg.Retry.Max = 30 * time.Second
	s := NewShipper(cfg, db, "test-agent", "1.0.0")

	// Test multiple attempts to ensure jitter varies
	delays := make(map[time.Duration]bool)
	for i := 0; i < 10; i++ {
		delay := s.calculateBackoffWithJitter(1)
		delays[delay] = true

		// Should be around 2s ±25% = 1.5s to 2.5s
		if delay < 1500*time.Millisecond || delay > 2500*time.Millisecond {
			t.Errorf("Delay %v out of expected range for attempt 1", delay)
		}
	}

	// Should have at least some variety (not all the same)
	if len(delays) < 3 {
		t.Error("Jitter not providing enough variety")
	}
}

func TestCircuitBreaker(t *testing.T) {
	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := testConfig("https://test.example.com")
	s := NewShipper(cfg, db, "test-agent", "1.0.0")

	// Initially circuit should be closed
	if s.isCircuitOpen() {
		t.Error("Circuit should initially be closed")
	}

	// Record failures to open circuit
	for i := 0; i < circuitBreakerThreshold; i++ {
		s.recordFailure()
	}

	// Circuit should now be open
	if !s.isCircuitOpen() {
		t.Error("Circuit should be open after threshold failures")
	}

	// Record success should reset
	s.recordSuccess()
	s.circuitOpen.Store(false) // Manually reset for test

	// Circuit should be closed again
	if s.isCircuitOpen() {
		t.Error("Circuit should be closed after success")
	}
}

func TestCircuitBreakerTimeout(t *testing.T) {
	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := testConfig("https://test.example.com")
	s := NewShipper(cfg, db, "test-agent", "1.0.0")

	// Open circuit
	for i := 0; i < circuitBreakerThreshold; i++ {
		s.recordFailure()
	}

	if !s.isCircuitOpen() {
		t.Fatal("Circuit should be open")
	}

	// Set circuit to expire immediately
	s.circuitOpenUntil.Store(time.Now().Add(-1 * time.Second).Unix())

	// Circuit should now be closed (timeout elapsed)
	if s.isCircuitOpen() {
		t.Error("Circuit should be closed after timeout")
	}

	// Consecutive fails should be reset
	if s.consecutiveFails.Load() != 0 {
		t.Error("Consecutive fails should be reset")
	}
}

func TestGetMetrics(t *testing.T) {
	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := testConfig("https://test.example.com")
	s := NewShipper(cfg, db, "test-agent", "1.0.0")

	// Initially zero
	sent, failed, requeued := s.GetMetrics()
	if sent != 0 || failed != 0 || requeued != 0 {
		t.Error("Initial metrics should be zero")
	}

	// Update metrics
	s.sentCount.Store(10)
	s.failCount.Store(2)
	s.requeueCount.Store(1)

	sent, failed, requeued = s.GetMetrics()
	if sent != 10 || failed != 2 || requeued != 1 {
		t.Errorf("Metrics incorrect: sent=%d, failed=%d, requeued=%d", sent, failed, requeued)
	}
}

func TestEnqueueSignal(t *testing.T) {
	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := testConfig("https://test.example.com")
	flushOn := true
	cfg.FlushOnEnqueue = &flushOn
	s := NewShipper(cfg, db, "test-agent", "1.0.0")

	sig := &state.Signal{
		ID:       "test-signal-1",
		HostID:   "test-host",
		RuleID:   "TEST-001",
		Severity: "high",
	}

	err := s.EnqueueSignal(sig)
	if err != nil {
		t.Fatalf("EnqueueSignal failed: %v", err)
	}

	// Verify signal was enqueued
	signals, err := db.DequeueSignals(10)
	if err != nil {
		t.Fatal(err)
	}

	if len(signals) != 1 {
		t.Fatalf("Expected 1 signal, got %d", len(signals))
	}

	if signals[0].ID != "test-signal-1" {
		t.Errorf("Signal ID mismatch: got %s", signals[0].ID)
	}
}

func TestEnqueueSignalDeduplication(t *testing.T) {
	db := setupTestDB(t)
	defer func() { _ = db.Close() }()

	cfg := testConfig("https://test.example.com")
	s := NewShipper(cfg, db, "test-agent", "1.0.0")

	sig := &state.Signal{
		ID:       "test-signal-1",
		HostID:   "test-host",
		RuleID:   "TEST-001",
		Severity: "high",
	}

	// Enqueue, dequeue, and mark as shipped (simulating successful send)
	if err := s.EnqueueSignal(sig); err != nil {
		t.Fatal(err)
	}

	// Dequeue the signal (simulating it being sent)
	signals, err := db.DequeueSignals(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 1 {
		t.Fatalf("Expected 1 signal, got %d", len(signals))
	}

	// Mark as shipped
	if err := db.MarkShipped(sig.ID); err != nil {
		t.Fatal(err)
	}

	// Try to enqueue again - should be skipped due to deduplication
	err = s.EnqueueSignal(sig)
	if err != nil {
		t.Fatalf("EnqueueSignal failed: %v", err)
	}

	// Should not have been enqueued again
	signals, err = db.DequeueSignals(10)
	if err != nil {
		t.Fatal(err)
	}

	if len(signals) != 0 {
		t.Errorf("Expected 0 signals (deduplication), got %d", len(signals))
	}
}

func TestIsPermanentError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		permanent bool
	}{
		{"nil error", nil, false},
		{"regular error", fmt.Errorf("test error"), false},
		{"permanent error", &PermanentError{error: fmt.Errorf("permanent")}, true},
		{"wrapped permanent", fmt.Errorf("wrapped: %w", &PermanentError{error: fmt.Errorf("permanent")}), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPermanentError(tt.err)
			if result != tt.permanent {
				t.Errorf("isPermanentError() = %v, want %v", result, tt.permanent)
			}
		})
	}
}

// Helper functions

func setupTestDB(t *testing.T) *state.DB {
	t.Helper()
	dbPath := t.TempDir() + "/test.db"
	db, err := state.Open(dbPath, 1000, false)
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	return db
}

func testConfig(endpoint string) *config.ShipperConfig {
	return &config.ShipperConfig{
		Endpoint:      endpoint,
		APIKey:        "test-key-1234567890",
		BatchSize:     10,
		FlushInterval: 5 * time.Second,
		Timeout:       10 * time.Second,
		Retry: config.RetryConfig{
			MaxAttempts: 3,
			Backoff:     "exponential",
			Initial:     100 * time.Millisecond,
			Max:         30 * time.Second,
		},
	}
}
