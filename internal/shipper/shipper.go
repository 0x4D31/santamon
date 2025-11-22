package shipper

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0x4d31/santamon/internal/config"
	"github.com/0x4d31/santamon/internal/logutil"
	"github.com/0x4d31/santamon/internal/state"
)

// Shipper sends signals to the backend
type Shipper struct {
	config     *config.ShipperConfig
	db         *state.DB
	httpClient *http.Client
	userAgent  string
	agentID    string
	version    string
	osVersion  string
	flushCh    chan struct{}
	flushMu    sync.Mutex

	// Circuit breaker state
	circuitOpen      atomic.Bool
	circuitOpenUntil atomic.Int64
	consecutiveFails atomic.Int32

	// Metrics
	sentCount    atomic.Int64
	failCount    atomic.Int64
	requeueCount atomic.Int64
}

// getOSVersion returns the macOS version string (e.g., "14.2.1")
func getOSVersion() string {
	cmd := exec.Command("sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// NewShipper creates a new signal shipper
func NewShipper(cfg *config.ShipperConfig, db *state.DB, agentID, version string) *Shipper {
	// Create HTTP client with optional TLS skip verify
	transport := &http.Transport{}
	if cfg.TLSSkipVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
		// Print warning without timestamp (startup message)
		fmt.Println("\033[93m⚠\033[0m TLS certificate verification disabled")
	}

	s := &Shipper{
		config:    cfg,
		db:        db,
		agentID:   agentID,
		version:   version,
		osVersion: getOSVersion(),
		userAgent: fmt.Sprintf("github.com/0x4d31/santamon/%s", version),
		httpClient: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
	}
	// Enable immediate flush channel only when configured
	flushOn := cfg.FlushOnEnqueue == nil || (cfg.FlushOnEnqueue != nil && *cfg.FlushOnEnqueue)
	if flushOn {
		s.flushCh = make(chan struct{}, 1)
	}
	return s
}

// Start begins the shipping loop
func (s *Shipper) Start(ctx context.Context) error {
	ticker := time.NewTicker(s.config.FlushInterval)
	defer ticker.Stop()

	// Immediate flush on start to clear any queued signals
	if err := s.flushWithContext(ctx); err != nil && err != context.Canceled {
		logutil.Warn("Initial flush error: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			// Final flush before shutdown (with short timeout)
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.flushWithContext(shutdownCtx)

			// Log final metrics
			s.logMetrics()
			return ctx.Err()

		case <-ticker.C:
			if err := s.flushWithContext(ctx); err != nil && err != context.Canceled {
				logutil.Warn("Flush error: %v", err)
			}
		case <-s.flushCh:
			if err := s.flushWithContext(ctx); err != nil && err != context.Canceled {
				logutil.Warn("Flush error: %v", err)
			}
		}
	}
}

//

// flushWithContext sends queued signals to the backend with context
func (s *Shipper) flushWithContext(ctx context.Context) error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	// Check circuit breaker
	if s.isCircuitOpen() {
		return fmt.Errorf("circuit breaker open, skipping flush")
	}

	// Dequeue signals from database
	signals, err := s.db.DequeueSignals(s.config.BatchSize)
	if err != nil {
		return fmt.Errorf("failed to dequeue signals: %w", err)
	}

	if len(signals) == 0 {
		return nil
	}

	// Use worker pool for concurrent sending
	const maxWorkers = 5
	workers := min(maxWorkers, len(signals))

	type result struct {
		sig *state.Signal
		err error
	}

	signalsCh := make(chan *state.Signal, len(signals))
	resultsCh := make(chan result, len(signals))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sig := range signalsCh {
				err := s.sendSignalWithContext(ctx, sig)
				resultsCh <- result{sig: sig, err: err}
			}
		}()
	}

	// Send signals to workers
	for _, sig := range signals {
		signalsCh <- sig
	}
	close(signalsCh)

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Process results
	successCount := 0
	for res := range resultsCh {
		if res.err != nil {
			logutil.Error("Failed to send signal %s: %v", res.sig.ID, res.err)
			s.failCount.Add(1)
			s.recordFailure()

			// Re-queue signal on failure, even for permanent errors, to avoid losing data.
			if err := s.db.EnqueueSignal(res.sig); err != nil {
				logutil.Error("Failed to re-queue signal: %v", err)
			} else {
				s.requeueCount.Add(1)
				if isPermanentError(res.err) {
					logutil.Warn("Permanent error sending signal %s; keeping in queue for retry", res.sig.ID)
				}
			}
		} else {
			// Mark as shipped - this is done atomically with send
			// so we don't mark shipped unless send succeeded
			if err := s.db.MarkShipped(res.sig.ID); err != nil {
				logutil.Error("Failed to mark signal as shipped: %v", err)
			} else {
				successCount++
				s.sentCount.Add(1)
				s.recordSuccess()
			}
		}
	}

	if successCount > 0 {
		if successCount == len(signals) {
			logutil.Success("Shipped %d signal%s", successCount, pluralize(successCount))
		} else {
			logutil.Warn("Shipped %d/%d signals (some failed)", successCount, len(signals))
		}
	}

	return nil
}

// pluralize returns "s" if count is not 1, empty string otherwise
func pluralize(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

//

// sendSignalWithContext sends a single signal to the backend with retry and context
func (s *Shipper) sendSignalWithContext(ctx context.Context, sig *state.Signal) error {
	var lastErr error

	for attempt := 0; attempt < s.config.Retry.MaxAttempts; attempt++ {
		// Check context before each attempt
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if attempt > 0 {
			// Calculate backoff delay with jitter
			delay := s.calculateBackoffWithJitter(attempt)

			// Respect context during backoff
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}

			logutil.Warn("Retry attempt %d/%d for signal %s", attempt+1, s.config.Retry.MaxAttempts, sig.ID)
		}

		// Try to send with context
		if err := s.sendHTTPWithContext(ctx, sig); err != nil {
			lastErr = err

			// Don't retry on permanent errors (4xx)
			if isPermanentError(err) {
				return fmt.Errorf("permanent error, not retrying: %w", err)
			}

			continue
		}

		// Success
		return nil
	}

	return fmt.Errorf("all %d retry attempts failed: %w", s.config.Retry.MaxAttempts, lastErr)
}

//

// sendHTTPWithContext sends a signal via HTTP POST with context
func (s *Shipper) sendHTTPWithContext(ctx context.Context, sig *state.Signal) error {
	if sig == nil {
		return &PermanentError{error: fmt.Errorf("signal cannot be nil")}
	}

	// Marshal signal to JSON
	data, err := json.Marshal(sig)
	if err != nil {
		return &PermanentError{error: fmt.Errorf("failed to marshal signal: %w", err)}
	}

	// Create request with context (timeout already set in parent context)
	req, err := http.NewRequestWithContext(ctx, "POST", s.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", s.config.APIKey)
	req.Header.Set("User-Agent", s.userAgent)

	// Send request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer func() {
		// Always drain and close body to prevent connection leaks
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
	}()

	// Check response status
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// 4xx errors are permanent (client errors)
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		// Try to read error body for context
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return &PermanentError{
			error: fmt.Errorf("client error %d: %s", resp.StatusCode, string(bodyBytes)),
		}
	}

	// 5xx errors are retryable (server errors)
	return fmt.Errorf("server error: status code %d", resp.StatusCode)
}

// calculateBackoff calculates retry backoff delay
func (s *Shipper) calculateBackoff(attempt int) time.Duration {
	if s.config.Retry.Backoff == "linear" {
		delay := s.config.Retry.Initial * time.Duration(attempt)
		if delay > s.config.Retry.Max {
			return s.config.Retry.Max
		}
		return delay
	}

	// Exponential backoff with overflow protection
	// Cap at attempt 10 to prevent overflow (2^10 = 1024)
	if attempt > 10 {
		attempt = 10
	}
	delay := s.config.Retry.Initial * time.Duration(1<<uint(attempt))
	if delay > s.config.Retry.Max || delay < 0 { // Check for overflow
		delay = s.config.Retry.Max
	}

	return delay
}

// calculateBackoffWithJitter calculates retry backoff delay with jitter to prevent thundering herd
func (s *Shipper) calculateBackoffWithJitter(attempt int) time.Duration {
	baseDelay := s.calculateBackoff(attempt)

	// Add ±25% jitter
	jitterRange := int64(baseDelay) / 4
	jitter := rand.Int63n(jitterRange*2+1) - jitterRange

	delay := time.Duration(int64(baseDelay) + jitter)
	if delay < 0 {
		delay = 0
	}
	if delay > s.config.Retry.Max {
		delay = s.config.Retry.Max
	}

	return delay
}

// Circuit breaker constants
const (
	circuitBreakerThreshold = 5                // Open circuit after 5 consecutive failures
	circuitBreakerTimeout   = 30 * time.Second // Keep circuit open for 30 seconds
)

// isCircuitOpen checks if the circuit breaker is open
func (s *Shipper) isCircuitOpen() bool {
	if !s.circuitOpen.Load() {
		return false
	}

	// Check if timeout has elapsed
	openUntil := s.circuitOpenUntil.Load()
	if time.Now().Unix() > openUntil {
		// Reset circuit breaker
		s.circuitOpen.Store(false)
		s.consecutiveFails.Store(0)
		logutil.Info("Circuit breaker reset")
		return false
	}

	return true
}

// recordFailure records a send failure for circuit breaker
func (s *Shipper) recordFailure() {
	fails := s.consecutiveFails.Add(1)
	if fails >= circuitBreakerThreshold {
		if !s.circuitOpen.Load() {
			s.circuitOpen.Store(true)
			s.circuitOpenUntil.Store(time.Now().Add(circuitBreakerTimeout).Unix())
			logutil.Warn("Circuit breaker opened after %d consecutive failures", fails)
		}
	}
}

// recordSuccess records a successful send for circuit breaker
func (s *Shipper) recordSuccess() {
	s.consecutiveFails.Store(0)
}

// logMetrics logs current shipping metrics
func (s *Shipper) logMetrics() {
	sent := s.sentCount.Load()
	failed := s.failCount.Load()
	requeued := s.requeueCount.Load()

	logutil.Info("Shipper metrics: sent=%d, failed=%d, requeued=%d", sent, failed, requeued)
}

// GetMetrics returns current metrics (for testing/monitoring)
func (s *Shipper) GetMetrics() (sent, failed, requeued int64) {
	return s.sentCount.Load(), s.failCount.Load(), s.requeueCount.Load()
}

// PermanentError represents a non-retryable error
type PermanentError struct {
	error
}

// isPermanentError checks if an error is permanent (shouldn't retry)
func isPermanentError(err error) bool {
	if err == nil {
		return false
	}
	// Check if error is or wraps a PermanentError
	for err != nil {
		if _, ok := err.(*PermanentError); ok {
			return true
		}
		// Try to unwrap
		if unwrapper, ok := err.(interface{ Unwrap() error }); ok {
			err = unwrapper.Unwrap()
		} else {
			break
		}
	}
	return false
}

// EnqueueSignal adds a signal to the shipping queue
func (s *Shipper) EnqueueSignal(sig *state.Signal) error {
	// Atomically check if already shipped and enqueue if not
	// This prevents race conditions where two goroutines could
	// both enqueue the same signal
	enqueued, err := s.db.EnqueueSignalIfNotShipped(sig)
	if err != nil {
		return fmt.Errorf("failed to enqueue signal: %w", err)
	}

	if !enqueued {
		// Signal was already shipped, skip
		return nil
	}

	// Request an immediate flush (non-blocking)
	if s.flushCh != nil {
		select {
		case s.flushCh <- struct{}{}:
		default:
			// a flush is already pending
		}
	}
	return nil
}

// Heartbeat represents an agent heartbeat message
type Heartbeat struct {
	AgentID   string    `json:"agent_id"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
	OSVersion string    `json:"os_version"`
	Uptime    float64   `json:"uptime_seconds,omitempty"`
}

// StartHeartbeat begins sending periodic heartbeat pings to the backend
func (s *Shipper) StartHeartbeat(ctx context.Context) error {
	if !s.config.Heartbeat.Enabled {
		return nil // Heartbeat disabled
	}

	ticker := time.NewTicker(s.config.Heartbeat.Interval)
	defer ticker.Stop()

	startTime := time.Now()
	logutil.Verbose("Heartbeat enabled: sending every %s", s.config.Heartbeat.Interval)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := s.sendHeartbeat(ctx, startTime); err != nil {
				logutil.Verbose("Heartbeat failed: %v", err)
			}
		}
	}
}

// sendHeartbeat sends a single heartbeat to the backend
func (s *Shipper) sendHeartbeat(ctx context.Context, startTime time.Time) error {
	hb := Heartbeat{
		AgentID:   s.agentID,
		Timestamp: time.Now(),
		Version:   s.version,
		OSVersion: s.osVersion,
		Uptime:    time.Since(startTime).Seconds(),
	}

	data, err := json.Marshal(hb)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	// Parse base URL and append /agents/heartbeat path
	baseURL := s.config.Endpoint
	// Remove /ingest suffix if present
	baseURL = strings.TrimSuffix(baseURL, "/ingest")
	heartbeatURL := baseURL + "/agents/heartbeat"

	req, err := http.NewRequestWithContext(ctx, "POST", heartbeatURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create heartbeat request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", s.config.APIKey)
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat request failed: %w", err)
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logutil.Verbose("Heartbeat sent successfully")
		return nil
	}

	return fmt.Errorf("heartbeat failed with status %d", resp.StatusCode)
}
