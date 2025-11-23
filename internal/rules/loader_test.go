package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRulesDir(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Test case 1: Valid multi-file rules directory
	t.Run("valid multi-file directory", func(t *testing.T) {
		// Create subdirectories
		credDir := filepath.Join(tmpDir, "credential-access")
		if err := os.MkdirAll(credDir, 0755); err != nil {
			t.Fatal(err)
		}

		persistDir := filepath.Join(tmpDir, "persistence")
		if err := os.MkdirAll(persistDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Write test rule files
		rule1 := `rules:
  - id: TEST-001
    title: "Test credential access rule"
    description: "Test rule for credential access"
    expr: kind == "file_access"
    severity: high
    tags: ["T1539"]
    enabled: true
`
		if err := os.WriteFile(filepath.Join(credDir, "test-001.yaml"), []byte(rule1), 0644); err != nil {
			t.Fatal(err)
		}

		rule2 := `rules:
  - id: TEST-002
    title: "Test persistence rule"
    description: "Test rule for persistence"
    expr: kind == "launch_item"
    severity: medium
    tags: ["T1543"]
    enabled: true
`
		if err := os.WriteFile(filepath.Join(persistDir, "test-002.yaml"), []byte(rule2), 0644); err != nil {
			t.Fatal(err)
		}

		// Add a correlation rule
		corrRule := `correlations:
  - id: TEST-COR-001
    title: "Test correlation"
    description: "Test correlation rule"
    expr: kind == "file_access"
    window: "5m"
    group_by: ["machine_id"]
    count_distinct: "file_access.policy_name"
    threshold: 2
    severity: critical
    enabled: true
`
		if err := os.WriteFile(filepath.Join(tmpDir, "correlations.yaml"), []byte(corrRule), 0644); err != nil {
			t.Fatal(err)
		}

		// Load rules from directory
		config, err := LoadRulesDir(tmpDir)
		if err != nil {
			t.Fatalf("LoadRulesDir failed: %v", err)
		}

		// Verify all rules were loaded
		if len(config.Rules) != 2 {
			t.Errorf("expected 2 rules, got %d", len(config.Rules))
		}
		if len(config.Correlations) != 1 {
			t.Errorf("expected 1 correlation, got %d", len(config.Correlations))
		}

		// Verify rule IDs
		foundIDs := make(map[string]bool)
		for _, rule := range config.Rules {
			foundIDs[rule.ID] = true
		}
		if !foundIDs["TEST-001"] || !foundIDs["TEST-002"] {
			t.Errorf("expected rules TEST-001 and TEST-002, got %v", foundIDs)
		}
	})

	// Test case 2: Duplicate rule IDs across files
	t.Run("duplicate rule IDs", func(t *testing.T) {
		dupDir := filepath.Join(tmpDir, "duplicates")
		if err := os.MkdirAll(dupDir, 0755); err != nil {
			t.Fatal(err)
		}

		rule1 := `rules:
  - id: DUP-001
    title: "First rule"
    expr: kind == "execution"
    severity: high
    enabled: true
`
		if err := os.WriteFile(filepath.Join(dupDir, "dup1.yaml"), []byte(rule1), 0644); err != nil {
			t.Fatal(err)
		}

		rule2 := `rules:
  - id: DUP-001
    title: "Duplicate rule"
    expr: kind == "file_access"
    severity: medium
    enabled: true
`
		if err := os.WriteFile(filepath.Join(dupDir, "dup2.yaml"), []byte(rule2), 0644); err != nil {
			t.Fatal(err)
		}

		// Should fail due to duplicate ID
		_, err := LoadRulesDir(dupDir)
		if err == nil {
			t.Fatal("expected error for duplicate rule ID, got nil")
		}
		// Check error message mentions both files
		errMsg := err.Error()
		if !contains(errMsg, "duplicate") || !contains(errMsg, "DUP-001") {
			t.Errorf("error message should mention duplicate ID DUP-001: %v", err)
		}
	})

	// Test case 3: Empty directory
	t.Run("empty directory", func(t *testing.T) {
		emptyDir := filepath.Join(tmpDir, "empty")
		if err := os.MkdirAll(emptyDir, 0755); err != nil {
			t.Fatal(err)
		}

		config, err := LoadRulesDir(emptyDir)
		if err != nil {
			t.Fatalf("LoadRulesDir failed on empty directory: %v", err)
		}

		if len(config.Rules) != 0 {
			t.Errorf("expected 0 rules in empty directory, got %d", len(config.Rules))
		}
	})

	// Test case 4: Non-existent directory
	t.Run("non-existent directory", func(t *testing.T) {
		_, err := LoadRulesDir("/nonexistent/path")
		if err == nil {
			t.Fatal("expected error for non-existent directory, got nil")
		}
	})

	// Test case 5: Path is a file, not directory
	t.Run("file instead of directory", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "testfile.yaml")
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		_, err := LoadRulesDir(testFile)
		if err == nil {
			t.Fatal("expected error when path is a file, got nil")
		}
	})

	// Test case 6: Invalid YAML in one file
	t.Run("invalid YAML", func(t *testing.T) {
		invalidDir := filepath.Join(tmpDir, "invalid")
		if err := os.MkdirAll(invalidDir, 0755); err != nil {
			t.Fatal(err)
		}

		invalidYAML := `rules:
  - id: INVALID-001
    title: "Invalid rule"
    expr: [this is not valid yaml
`
		if err := os.WriteFile(filepath.Join(invalidDir, "invalid.yaml"), []byte(invalidYAML), 0644); err != nil {
			t.Fatal(err)
		}

		_, err := LoadRulesDir(invalidDir)
		if err == nil {
			t.Fatal("expected error for invalid YAML, got nil")
		}
	})

	// Test case 7: Mixed valid and non-yaml files
	t.Run("mixed file types", func(t *testing.T) {
		mixedDir := filepath.Join(tmpDir, "mixed")
		if err := os.MkdirAll(mixedDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Create a valid YAML file
		rule := `rules:
  - id: MIXED-001
    title: "Mixed test rule"
    expr: kind == "execution"
    severity: high
    enabled: true
`
		if err := os.WriteFile(filepath.Join(mixedDir, "valid.yaml"), []byte(rule), 0644); err != nil {
			t.Fatal(err)
		}

		// Create non-YAML files (should be ignored)
		if err := os.WriteFile(filepath.Join(mixedDir, "readme.txt"), []byte("readme"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(mixedDir, "script.sh"), []byte("#!/bin/bash"), 0644); err != nil {
			t.Fatal(err)
		}

		config, err := LoadRulesDir(mixedDir)
		if err != nil {
			t.Fatalf("LoadRulesDir failed: %v", err)
		}

		if len(config.Rules) != 1 {
			t.Errorf("expected 1 rule (non-yaml files ignored), got %d", len(config.Rules))
		}
	})
}

func TestMerge(t *testing.T) {
	config1 := &RulesConfig{
		Rules: []*Rule{
			{ID: "R1", Title: "Rule 1", Expr: "true", Severity: "high", Enabled: true},
		},
		Correlations: []*CorrelationRule{
			{ID: "C1", Title: "Corr 1", Expr: "true", Window: 300, Threshold: 2, Severity: "high", Enabled: true},
		},
	}

	config2 := &RulesConfig{
		Rules: []*Rule{
			{ID: "R2", Title: "Rule 2", Expr: "true", Severity: "medium", Enabled: true},
		},
		Baselines: []*BaselineRule{
			{ID: "B1", Title: "Base 1", Expr: "true", Track: []string{"field"}, Severity: "low", Enabled: true},
		},
	}

	config1.Merge(config2)

	if len(config1.Rules) != 2 {
		t.Errorf("expected 2 rules after merge, got %d", len(config1.Rules))
	}
	if len(config1.Correlations) != 1 {
		t.Errorf("expected 1 correlation after merge, got %d", len(config1.Correlations))
	}
	if len(config1.Baselines) != 1 {
		t.Errorf("expected 1 baseline after merge, got %d", len(config1.Baselines))
	}
}

func TestLoad(t *testing.T) {
	tmpDir := t.TempDir()

	// Test 1: Load from file
	t.Run("load from file", func(t *testing.T) {
		ruleFile := filepath.Join(tmpDir, "rules.yaml")
		ruleContent := `rules:
  - id: LOAD-001
    title: "Test rule"
    expr: kind == "execution"
    severity: high
    enabled: true
`
		if err := os.WriteFile(ruleFile, []byte(ruleContent), 0644); err != nil {
			t.Fatal(err)
		}

		config, err := Load(ruleFile)
		if err != nil {
			t.Fatalf("Load failed for file: %v", err)
		}

		if len(config.Rules) != 1 {
			t.Errorf("expected 1 rule from file, got %d", len(config.Rules))
		}
	})

	// Test 2: Load from directory
	t.Run("load from directory", func(t *testing.T) {
		rulesDir := filepath.Join(tmpDir, "rules-dir")
		if err := os.MkdirAll(rulesDir, 0755); err != nil {
			t.Fatal(err)
		}

		rule1 := `rules:
  - id: LOAD-002
    title: "First dir rule"
    expr: kind == "execution"
    severity: high
    enabled: true
`
		if err := os.WriteFile(filepath.Join(rulesDir, "rule1.yaml"), []byte(rule1), 0644); err != nil {
			t.Fatal(err)
		}

		rule2 := `rules:
  - id: LOAD-003
    title: "Second dir rule"
    expr: kind == "file_access"
    severity: medium
    enabled: true
`
		if err := os.WriteFile(filepath.Join(rulesDir, "rule2.yaml"), []byte(rule2), 0644); err != nil {
			t.Fatal(err)
		}

		config, err := Load(rulesDir)
		if err != nil {
			t.Fatalf("Load failed for directory: %v", err)
		}

		if len(config.Rules) != 2 {
			t.Errorf("expected 2 rules from directory, got %d", len(config.Rules))
		}
	})

	// Test 3: Load from non-existent path
	t.Run("load from non-existent path", func(t *testing.T) {
		_, err := Load("/nonexistent/path")
		if err == nil {
			t.Fatal("expected error for non-existent path, got nil")
		}
	})
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
