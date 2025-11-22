package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete santamon configuration
type Config struct {
	Agent   AgentConfig   `yaml:"agent"`
	Santa   SantaConfig   `yaml:"santa"`
	Rules   RulesConfig   `yaml:"rules"`
	State   StateConfig   `yaml:"state"`
	Shipper ShipperConfig `yaml:"shipper"`
}

// AgentConfig contains agent-level settings
type AgentConfig struct {
	ID       string `yaml:"id"`
	StateDir string `yaml:"state_dir"`
	LogLevel string `yaml:"log_level"`
}

// SantaConfig defines Santa spool settings
type SantaConfig struct {
	Mode          string        `yaml:"mode"`
	SpoolDir      string        `yaml:"spool_dir"`
	StabilityWait time.Duration `yaml:"stability_wait"`
}

// RulesConfig defines detection rules settings
type RulesConfig struct {
	Path     string `yaml:"path"`
	ReloadOn string `yaml:"reload_on"`
}

// StateConfig defines database settings
type StateConfig struct {
	DBPath          string          `yaml:"db_path"`
	SyncWrites      bool            `yaml:"sync_writes"`
	CompactInterval time.Duration   `yaml:"compact_interval"`
	FirstSeen       FirstSeenConfig `yaml:"first_seen"`
	Windows         WindowsConfig   `yaml:"windows"`
}

// FirstSeenConfig defines first-seen tracking settings
type FirstSeenConfig struct {
	MaxEntries int    `yaml:"max_entries"`
	Eviction   string `yaml:"eviction"`
}

// WindowsConfig defines correlation window settings
type WindowsConfig struct {
	GCInterval time.Duration `yaml:"gc_interval"`
	MaxEvents  int           `yaml:"max_events"`
}

// ShipperConfig defines signal shipping settings
type ShipperConfig struct {
    Endpoint       string          `yaml:"endpoint"`
    APIKey         string          `yaml:"api_key"`
    BatchSize      int             `yaml:"batch_size"`
    FlushInterval  time.Duration   `yaml:"flush_interval"`
    Timeout        time.Duration   `yaml:"timeout"`
    Retry          RetryConfig     `yaml:"retry"`
    FlushOnEnqueue *bool           `yaml:"flush_on_enqueue"`
    TLSSkipVerify  bool            `yaml:"tls_skip_verify"`
    Heartbeat      HeartbeatConfig `yaml:"heartbeat"`
}

// HeartbeatConfig defines agent heartbeat settings
type HeartbeatConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
}

// RetryConfig defines retry behavior
type RetryConfig struct {
	MaxAttempts int           `yaml:"max_attempts"`
	Backoff     string        `yaml:"backoff"`
	Initial     time.Duration `yaml:"initial"`
	Max         time.Duration `yaml:"max"`
}

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	return LoadWithOptions(path, false)
}

// LoadForReadOnly loads config without validating shipper (for status/db commands)
func LoadForReadOnly(path string) (*Config, error) {
	return LoadWithOptions(path, true)
}

// LoadWithOptions reads configuration with optional validation skips
func LoadWithOptions(path string, skipShipperValidation bool) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables
	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Apply defaults
	cfg.applyDefaults()

	// Validate
	if err := cfg.ValidateWithOptions(skipShipperValidation); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// applyDefaults sets default values for optional fields
func (c *Config) applyDefaults() {
	if c.Agent.ID == "" {
		hostname, _ := os.Hostname()
		c.Agent.ID = hostname
	}
	if c.Agent.StateDir == "" {
		c.Agent.StateDir = "/var/lib/santamon"
	}
	if c.Agent.LogLevel == "" {
		c.Agent.LogLevel = "info"
	}

	if c.Santa.Mode == "" {
		c.Santa.Mode = "protobuf"
	}
	if c.Santa.SpoolDir == "" {
		c.Santa.SpoolDir = "/var/db/santa/spool"
	}
	if c.Santa.StabilityWait == 0 {
		c.Santa.StabilityWait = 2 * time.Second
	}

	if c.Rules.Path == "" {
		c.Rules.Path = "/etc/santamon/rules.yaml"
	}
	if c.Rules.ReloadOn == "" {
		c.Rules.ReloadOn = "SIGHUP"
	}

	if c.State.DBPath == "" {
		c.State.DBPath = "/var/lib/santamon/state.db"
	}
	if c.State.CompactInterval == 0 {
		c.State.CompactInterval = 24 * time.Hour
	}
	if c.State.FirstSeen.MaxEntries == 0 {
		c.State.FirstSeen.MaxEntries = 10000
	}
	if c.State.FirstSeen.Eviction == "" {
		c.State.FirstSeen.Eviction = "lru"
	}
	if c.State.Windows.GCInterval == 0 {
		c.State.Windows.GCInterval = 1 * time.Minute
	}
	if c.State.Windows.MaxEvents == 0 {
		c.State.Windows.MaxEvents = 1000
	}

	if c.Shipper.BatchSize == 0 {
		c.Shipper.BatchSize = 100
	}
    if c.Shipper.FlushInterval == 0 {
        c.Shipper.FlushInterval = 30 * time.Second
    }
    // Default to immediate flush on enqueue for low-latency alerts
    if c.Shipper.FlushOnEnqueue == nil {
        v := true
        c.Shipper.FlushOnEnqueue = &v
    }
	if c.Shipper.Timeout == 0 {
		c.Shipper.Timeout = 10 * time.Second
	}
	if c.Shipper.Retry.MaxAttempts == 0 {
		c.Shipper.Retry.MaxAttempts = 3
	}
	if c.Shipper.Retry.Backoff == "" {
		c.Shipper.Retry.Backoff = "exponential"
	}
	if c.Shipper.Retry.Initial == 0 {
		c.Shipper.Retry.Initial = 1 * time.Second
	}
	if c.Shipper.Retry.Max == 0 {
		c.Shipper.Retry.Max = 30 * time.Second
	}
	// Heartbeat defaults (enabled by default with 30s interval)
	if c.Shipper.Heartbeat.Interval == 0 {
		c.Shipper.Heartbeat.Interval = 30 * time.Second
	}
}

// Validate checks the configuration for errors
func (c *Config) Validate() error {
	return c.ValidateWithOptions(false)
}

// ValidateWithOptions checks configuration with optional validation skips
func (c *Config) ValidateWithOptions(skipShipper bool) error {
	// Validate agent config
	if c.Agent.ID == "" {
		return fmt.Errorf("agent.id is required")
	}
	if len(c.Agent.ID) > 255 {
		return fmt.Errorf("agent.id too long (max 255 characters)")
	}
	if !isValidLogLevel(c.Agent.LogLevel) {
		return fmt.Errorf("invalid log level: %s", c.Agent.LogLevel)
	}
	if !filepath.IsAbs(c.Agent.StateDir) {
		return fmt.Errorf("agent.state_dir must be an absolute path")
	}

	// Validate Santa config
	if c.Santa.Mode != "protobuf" && c.Santa.Mode != "json" {
		return fmt.Errorf("santa.mode must be 'protobuf' or 'json'")
	}
	if !filepath.IsAbs(c.Santa.SpoolDir) {
		return fmt.Errorf("santa.spool_dir must be an absolute path")
	}
	if c.Santa.StabilityWait < 0 {
		return fmt.Errorf("santa.stability_wait cannot be negative")
	}
	if c.Santa.StabilityWait > 60*time.Second {
		return fmt.Errorf("santa.stability_wait too large (max 60s)")
	}

	// Validate rules config
	if !filepath.IsAbs(c.Rules.Path) {
		return fmt.Errorf("rules.path must be an absolute path")
	}

	// Validate state config
	if !filepath.IsAbs(c.State.DBPath) {
		return fmt.Errorf("state.db_path must be an absolute path")
	}
	if c.State.FirstSeen.MaxEntries <= 0 {
		return fmt.Errorf("state.first_seen.max_entries must be positive")
	}
	if c.State.FirstSeen.MaxEntries > 1000000 {
		return fmt.Errorf("state.first_seen.max_entries too large (max 1000000)")
	}
	if c.State.FirstSeen.Eviction != "lru" {
		return fmt.Errorf("state.first_seen.eviction must be 'lru'")
	}
	if c.State.Windows.MaxEvents <= 0 {
		return fmt.Errorf("state.windows.max_events must be positive")
	}
	if c.State.Windows.MaxEvents > 100000 {
		return fmt.Errorf("state.windows.max_events too large (max 100000)")
	}

	// Validate shipper config (skip for read-only commands)
	if !skipShipper {
		if c.Shipper.Endpoint == "" {
			return fmt.Errorf("shipper.endpoint is required")
		}
		// Validate URL format
		u, err := url.Parse(c.Shipper.Endpoint)
		if err != nil {
			return fmt.Errorf("shipper.endpoint invalid URL: %w", err)
		}
		// Ensure HTTPS for security (allow HTTP only for localhost testing)
		if u != nil {
			if u.Scheme == "http" {
				host := u.Hostname()
				if host != "localhost" && host != "127.0.0.1" && host != "::1" {
					return fmt.Errorf("shipper.endpoint must use HTTPS (not HTTP) for remote hosts")
				}
			}
		}
		if c.Shipper.APIKey == "" {
			return fmt.Errorf("shipper.api_key is required")
		}
		if len(c.Shipper.APIKey) < 16 {
			return fmt.Errorf("shipper.api_key too short (min 16 characters)")
		}
		if c.Shipper.BatchSize <= 0 {
			return fmt.Errorf("shipper.batch_size must be positive")
		}
		if c.Shipper.BatchSize > 10000 {
			return fmt.Errorf("shipper.batch_size too large (max 10000)")
		}
		if c.Shipper.Timeout <= 0 {
			return fmt.Errorf("shipper.timeout must be positive")
		}
		if c.Shipper.Retry.MaxAttempts < 0 {
			return fmt.Errorf("shipper.retry.max_attempts cannot be negative")
		}
		if c.Shipper.Retry.MaxAttempts > 10 {
			return fmt.Errorf("shipper.retry.max_attempts too large (max 10)")
		}
		if c.Shipper.Retry.Backoff != "exponential" && c.Shipper.Retry.Backoff != "linear" {
			return fmt.Errorf("shipper.retry.backoff must be 'exponential' or 'linear'")
		}
	}

	return nil
}

func isValidLogLevel(level string) bool {
	level = strings.ToLower(level)
	return level == "debug" || level == "info" || level == "warn" || level == "error"
}
