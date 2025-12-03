package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid config",
			path:    "testdata/valid.yaml",
			wantErr: false,
		},
		{
			name:    "non-existent file",
			path:    "testdata/nonexistent.yaml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && cfg == nil {
				t.Error("Load() returned nil config without error")
			}
		})
	}
}

func TestValidConfig(t *testing.T) {
	cfg, err := Load("testdata/valid.yaml")
	if err != nil {
		t.Fatalf("Failed to load valid config: %v", err)
	}

	// Test agent config
	if cfg.Agent.ID != "test-agent" {
		t.Errorf("Agent.ID = %v, want test-agent", cfg.Agent.ID)
	}
	if cfg.Agent.StateDir != "/tmp/santamon" {
		t.Errorf("Agent.StateDir = %v, want /tmp/santamon", cfg.Agent.StateDir)
	}
	if cfg.Agent.LogLevel != "info" {
		t.Errorf("Agent.LogLevel = %v, want info", cfg.Agent.LogLevel)
	}

	// Test santa config
	if cfg.Santa.Mode != "json" {
		t.Errorf("Santa.Mode = %v, want json", cfg.Santa.Mode)
	}
	if cfg.Santa.SpoolDir != "/var/db/santa/spool" {
		t.Errorf("Santa.SpoolDir = %v, want /var/db/santa/spool", cfg.Santa.SpoolDir)
	}
	if cfg.Santa.ArchiveDir != "/tmp/santamon/spool_hits" {
		t.Errorf("Santa.ArchiveDir = %v, want /tmp/santamon/spool_hits", cfg.Santa.ArchiveDir)
	}
	if cfg.Santa.StabilityWait != 2*time.Second {
		t.Errorf("Santa.StabilityWait = %v, want 2s", cfg.Santa.StabilityWait)
	}

	// Test state config
	if cfg.State.FirstSeen.MaxEntries != 10000 {
		t.Errorf("State.FirstSeen.MaxEntries = %v, want 10000", cfg.State.FirstSeen.MaxEntries)
	}
	if cfg.State.FirstSeen.Eviction != "lru" {
		t.Errorf("State.FirstSeen.Eviction = %v, want lru", cfg.State.FirstSeen.Eviction)
	}

	// Test shipper config
	if cfg.Shipper.Endpoint != "https://backend.example.com/ingest" {
		t.Errorf("Shipper.Endpoint = %v, want https://backend.example.com/ingest", cfg.Shipper.Endpoint)
	}
	if cfg.Shipper.APIKey != "test-secret-key-1234567890" {
		t.Errorf("Shipper.APIKey = %v, want test-secret-key-1234567890", cfg.Shipper.APIKey)
	}
	if cfg.Shipper.BatchSize != 100 {
		t.Errorf("Shipper.BatchSize = %v, want 100", cfg.Shipper.BatchSize)
	}
	if cfg.Shipper.Retry.MaxAttempts != 3 {
		t.Errorf("Shipper.Retry.MaxAttempts = %v, want 3", cfg.Shipper.Retry.MaxAttempts)
	}
	if cfg.Shipper.Retry.Backoff != "exponential" {
		t.Errorf("Shipper.Retry.Backoff = %v, want exponential", cfg.Shipper.Retry.Backoff)
	}
}

func TestValidateHTTPSEnforcement(t *testing.T) {
	_, err := Load("testdata/invalid_http.yaml")
	if err == nil {
		t.Fatal("Expected error for HTTP to remote host, got nil")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("Error should mention HTTPS requirement, got: %v", err)
	}
}

func TestValidateEmptyAgentID(t *testing.T) {
	cfg := &Config{
		Agent: AgentConfig{
			ID:       "",
			StateDir: "/tmp/test",
			LogLevel: "info",
		},
		Santa: SantaConfig{
			Mode:     "json",
			SpoolDir: "/tmp/spool",
		},
		Rules: RulesConfig{
			Path: "/tmp/rules.yaml",
		},
		State: StateConfig{
			DBPath: "/tmp/state.db",
			FirstSeen: FirstSeenConfig{
				MaxEntries: 1000,
				Eviction:   "lru",
			},
		},
		Shipper: ShipperConfig{
			Endpoint:  "https://localhost/ingest",
			APIKey:    "1234567890123456",
			BatchSize: 10,
			Retry: RetryConfig{
				MaxAttempts: 1,
				Backoff:     "linear",
			},
		},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "agent.id") {
		t.Errorf("Expected agent.id validation error, got: %v", err)
	}
}

func TestValidateAPIKeyLength(t *testing.T) {
	cfg := validTestConfig()
	cfg.Shipper.APIKey = "short" // Too short

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "api_key") || !strings.Contains(err.Error(), "16") {
		t.Errorf("Expected API key length validation error, got: %v", err)
	}
}

func TestValidateRelativePaths(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		value    string
		modifier func(*Config)
	}{
		{
			name:  "relative state_dir",
			field: "agent.state_dir",
			value: "relative/path",
			modifier: func(cfg *Config) {
				cfg.Agent.StateDir = "relative/path"
			},
		},
		{
			name:  "relative spool_dir",
			field: "santa.spool_dir",
			value: "relative/spool",
			modifier: func(cfg *Config) {
				cfg.Santa.SpoolDir = "relative/spool"
			},
		},
		{
			name:  "relative db_path",
			field: "state.db_path",
			value: "relative/db.db",
			modifier: func(cfg *Config) {
				cfg.State.DBPath = "relative/db.db"
			},
		},
		{
			name:  "relative archive_dir",
			field: "santa.archive_dir",
			value: "relative/archive",
			modifier: func(cfg *Config) {
				cfg.Santa.ArchiveDir = "relative/archive"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig()
			tt.modifier(cfg)

			err := cfg.Validate()
			if err == nil {
				t.Errorf("Expected validation error for relative path in %s", tt.field)
			}
			if !strings.Contains(err.Error(), "absolute") {
				t.Errorf("Error should mention absolute path requirement, got: %v", err)
			}
		})
	}
}

func TestValidateInvalidLogLevel(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.LogLevel = "invalid"

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "log level") {
		t.Errorf("Expected log level validation error, got: %v", err)
	}
}

func TestValidateInvalidSantaMode(t *testing.T) {
	cfg := validTestConfig()
	cfg.Santa.Mode = "invalid"

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "santa.mode") {
		t.Errorf("Expected santa.mode validation error, got: %v", err)
	}
}

func TestValidateBounds(t *testing.T) {
	tests := []struct {
		name     string
		modifier func(*Config)
		wantErr  string
	}{
		{
			name: "first_seen.max_entries too large",
			modifier: func(cfg *Config) {
				cfg.State.FirstSeen.MaxEntries = 2000000
			},
			wantErr: "max_entries too large",
		},
		{
			name: "first_seen.max_entries negative",
			modifier: func(cfg *Config) {
				cfg.State.FirstSeen.MaxEntries = -1
			},
			wantErr: "must be positive",
		},
		{
			name: "batch_size too large",
			modifier: func(cfg *Config) {
				cfg.Shipper.BatchSize = 20000
			},
			wantErr: "batch_size too large",
		},
		{
			name: "batch_size negative",
			modifier: func(cfg *Config) {
				cfg.Shipper.BatchSize = -1
			},
			wantErr: "must be positive",
		},
		{
			name: "retry.max_attempts too large",
			modifier: func(cfg *Config) {
				cfg.Shipper.Retry.MaxAttempts = 20
			},
			wantErr: "max_attempts too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig()
			tt.modifier(cfg)

			err := cfg.Validate()
			if err == nil {
				t.Errorf("Expected validation error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Error should contain %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()

	// Check defaults are applied
	if cfg.Agent.LogLevel != "info" {
		t.Errorf("Default LogLevel = %v, want info", cfg.Agent.LogLevel)
	}
	if cfg.Santa.Mode != "protobuf" {
		t.Errorf("Default Santa.Mode = %v, want protobuf", cfg.Santa.Mode)
	}
	if cfg.Santa.ArchiveDir != filepath.Join(cfg.Agent.StateDir, "spool_hits") {
		t.Errorf("Default Santa.ArchiveDir = %v, want %v", cfg.Santa.ArchiveDir, filepath.Join(cfg.Agent.StateDir, "spool_hits"))
	}
	if cfg.Santa.StabilityWait != 2*time.Second {
		t.Errorf("Default StabilityWait = %v, want 2s", cfg.Santa.StabilityWait)
	}
	if cfg.Shipper.BatchSize != 100 {
		t.Errorf("Default BatchSize = %v, want 100", cfg.Shipper.BatchSize)
	}
	if cfg.Shipper.Retry.Backoff != "exponential" {
		t.Errorf("Default Backoff = %v, want exponential", cfg.Shipper.Retry.Backoff)
	}
}

func TestEnvironmentVariableExpansion(t *testing.T) {
	// Set test environment variable
	if err := os.Setenv("TEST_API_KEY", "expanded-key-1234567890"); err != nil {
		t.Fatalf("Failed to set TEST_API_KEY: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("TEST_API_KEY")
	}()

	// Create config with env var
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `agent:
  id: "test"
  state_dir: "/tmp/test"
santa:
  mode: "json"
  spool_dir: "/tmp/spool"
rules:
  path: "/tmp/rules.yaml"
state:
  db_path: "/tmp/test.db"
  first_seen:
    max_entries: 1000
shipper:
  endpoint: "https://localhost/ingest"
  api_key: "${TEST_API_KEY}"
  batch_size: 10
`

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Shipper.APIKey != "expanded-key-1234567890" {
		t.Errorf("APIKey = %v, want expanded-key-1234567890", cfg.Shipper.APIKey)
	}
}

func TestLocalhostHTTPAllowed(t *testing.T) {
	cfg := validTestConfig()
	cfg.Shipper.Endpoint = "http://localhost:8443/ingest"

	err := cfg.Validate()
	if err != nil {
		t.Errorf("HTTP to localhost should be allowed, got error: %v", err)
	}

	cfg.Shipper.Endpoint = "http://127.0.0.1:8443/ingest"
	err = cfg.Validate()
	if err != nil {
		t.Errorf("HTTP to 127.0.0.1 should be allowed, got error: %v", err)
	}
}

// Helper function to create a valid test config
func validTestConfig() *Config {
	return &Config{
		Agent: AgentConfig{
			ID:       "test-agent",
			StateDir: "/tmp/test",
			LogLevel: "info",
		},
		Santa: SantaConfig{
			Mode:          "json",
			SpoolDir:      "/tmp/spool",
			ArchiveDir:    "/tmp/test/spool_hits",
			StabilityWait: 2 * time.Second,
		},
		Rules: RulesConfig{
			Path: "/tmp/rules.yaml",
		},
		State: StateConfig{
			DBPath: "/tmp/state.db",
			FirstSeen: FirstSeenConfig{
				MaxEntries: 10000,
				Eviction:   "lru",
			},
			Windows: WindowsConfig{
				GCInterval: 1 * time.Minute,
				MaxEvents:  1000,
			},
		},
		Shipper: ShipperConfig{
			Endpoint:  "https://backend.example.com/ingest",
			APIKey:    "test-secret-key-1234567890",
			BatchSize: 100,
			Timeout:   10 * time.Second,
			Retry: RetryConfig{
				MaxAttempts: 3,
				Backoff:     "exponential",
				Initial:     1 * time.Second,
				Max:         30 * time.Second,
			},
		},
	}
}
