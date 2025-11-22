package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// RulesConfig represents the rules.yaml file structure
type RulesConfig struct {
	Rules        []*Rule            `yaml:"rules"`
	Correlations []*CorrelationRule `yaml:"correlations"`
	Baselines    []*BaselineRule    `yaml:"baselines,omitempty"`
}

// Rule represents a single detection rule
type Rule struct {
	ID                 string   `yaml:"id"`
	Title              string   `yaml:"title"`
	Description        string   `yaml:"description,omitempty"`
	Expr               string   `yaml:"expr"`
	Severity           string   `yaml:"severity"`
	Tags               []string `yaml:"tags,omitempty"`
	Enabled            bool     `yaml:"enabled"`
	ExtraContext       []string `yaml:"extra_context,omitempty"`        // Optional extra fields to include in signal context
	IncludeEvent       bool     `yaml:"include_event,omitempty"`        // If true, include full event map in signal context
	IncludeProcessTree bool     `yaml:"include_process_tree,omitempty"` // If true, include process lineage in signal context
}

// CorrelationRule represents a time-window correlation rule
type CorrelationRule struct {
	ID            string        `yaml:"id"`
	Title         string        `yaml:"title"`
	Description   string        `yaml:"description,omitempty"`
	Expr          string        `yaml:"expr"`           // Filter expression
	Window        time.Duration `yaml:"window"`         // Time window
	GroupBy       []string      `yaml:"group_by"`       // Fields to group by
	CountDistinct string        `yaml:"count_distinct"` // Field to count distinct values
	Threshold     int           `yaml:"threshold"`      // Count threshold
	Severity      string        `yaml:"severity"`
	Tags          []string      `yaml:"tags,omitempty"`
	Enabled       bool          `yaml:"enabled"`
}

// Load loads rules from either a file or directory, auto-detecting the type
func Load(path string) (*RulesConfig, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat rules path: %w", err)
	}

	if info.IsDir() {
		return LoadRulesDir(path)
	}
	return LoadRulesFile(path)
}

// LoadRulesFile loads and parses the rules YAML file
func LoadRulesFile(path string) (*RulesConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	var config RulesConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %w", err)
	}

	// Validate rules
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid rules configuration: %w", err)
	}

	return &config, nil
}

// LoadRulesDir loads and merges all .yaml/.yml files from a directory recursively
func LoadRulesDir(dirPath string) (*RulesConfig, error) {
	// Check if path is a directory
	info, err := os.Stat(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat rules directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", dirPath)
	}

	// Track all rule IDs and their source files for better error messages
	idToFile := make(map[string]string)
	merged := &RulesConfig{
		Rules:        make([]*Rule, 0),
		Correlations: make([]*CorrelationRule, 0),
		Baselines:    make([]*BaselineRule, 0),
	}

	// Walk directory recursively
	err = filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Only process .yaml and .yml files
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		// Load the file
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		var config RulesConfig
		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		// Check for duplicate IDs before merging
		for _, rule := range config.Rules {
			if existingFile, exists := idToFile[rule.ID]; exists {
				return fmt.Errorf("duplicate rule ID %s: found in both %s and %s", rule.ID, existingFile, path)
			}
			idToFile[rule.ID] = path
		}
		for _, corr := range config.Correlations {
			if existingFile, exists := idToFile[corr.ID]; exists {
				return fmt.Errorf("duplicate correlation ID %s: found in both %s and %s", corr.ID, existingFile, path)
			}
			idToFile[corr.ID] = path
		}
		for _, baseline := range config.Baselines {
			if existingFile, exists := idToFile[baseline.ID]; exists {
				return fmt.Errorf("duplicate baseline ID %s: found in both %s and %s", baseline.ID, existingFile, path)
			}
			idToFile[baseline.ID] = path
		}

		// Merge into combined config
		merged.Rules = append(merged.Rules, config.Rules...)
		merged.Correlations = append(merged.Correlations, config.Correlations...)
		merged.Baselines = append(merged.Baselines, config.Baselines...)

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Validate the merged configuration
	if err := merged.Validate(); err != nil {
		return nil, fmt.Errorf("invalid merged rules configuration: %w", err)
	}

	return merged, nil
}

// Merge combines another RulesConfig into this one
func (rc *RulesConfig) Merge(other *RulesConfig) {
	rc.Rules = append(rc.Rules, other.Rules...)
	rc.Correlations = append(rc.Correlations, other.Correlations...)
	rc.Baselines = append(rc.Baselines, other.Baselines...)
}

// Validate checks the rules configuration for errors
func (rc *RulesConfig) Validate() error {
	// Check for duplicate rule IDs across all rule types
	seen := make(map[string]bool)

	for _, rule := range rc.Rules {
		if seen[rule.ID] {
			return fmt.Errorf("duplicate rule ID: %s", rule.ID)
		}
		seen[rule.ID] = true

		if err := rule.Validate(); err != nil {
			return fmt.Errorf("invalid rule %s: %w", rule.ID, err)
		}
	}

	// Validate correlation rules and check for ID conflicts
	for _, corr := range rc.Correlations {
		if seen[corr.ID] {
			return ErrDuplicateIDConflict(corr.ID)
		}
		seen[corr.ID] = true

		if err := corr.Validate(); err != nil {
			return fmt.Errorf("invalid correlation rule %s: %w", corr.ID, err)
		}
	}

	// Validate baseline rules and check for ID conflicts
	for _, baseline := range rc.Baselines {
		if seen[baseline.ID] {
			return ErrDuplicateIDConflict(baseline.ID)
		}
		seen[baseline.ID] = true

		if err := baseline.Validate(); err != nil {
			return fmt.Errorf("invalid baseline rule %s: %w", baseline.ID, err)
		}
	}

	return nil
}

// Validate checks a single rule
func (r *Rule) Validate() error {
	if r.ID == "" {
		return ErrRequired("rule ID")
	}
	if r.Title == "" {
		return ErrRequired("rule title")
	}
	if r.Expr == "" {
		return ErrRequired("rule expression")
	}
	if r.Severity == "" {
		return ErrRequired("rule severity")
	}

	// Validate severity
	if !ValidSeverities[r.Severity] {
		return ErrInvalidSeverity(r.Severity)
	}

	return nil
}

// Validate checks a correlation rule
func (cr *CorrelationRule) Validate() error {
	if cr.ID == "" {
		return ErrRequired("correlation ID")
	}
	if cr.Title == "" {
		return ErrRequired("correlation title")
	}
	if cr.Expr == "" {
		return ErrRequired("correlation expression")
	}
	if cr.Window == 0 {
		return ErrRequired("correlation window")
	}
	if cr.Threshold <= 0 {
		return fmt.Errorf("correlation threshold must be greater than 0")
	}
	if cr.Severity == "" {
		return ErrRequired("correlation severity")
	}

	// Validate severity
	if !ValidSeverities[cr.Severity] {
		return ErrInvalidSeverity(cr.Severity)
	}

	// Validate group_by fields are not empty strings
	for i, field := range cr.GroupBy {
		if field == "" {
			return ErrInvalidField("group_by", i)
		}
	}

	return nil
}
