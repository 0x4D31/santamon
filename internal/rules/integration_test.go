package rules

import (
	"testing"
)

func TestLoadProductionRules(t *testing.T) {
	// Load the actual production rules file
	cfg, err := LoadRulesFile("../../configs/rules.yaml")
	if err != nil {
		t.Fatalf("Failed to load production rules: %v", err)
	}

	t.Logf("Loaded from configs/rules.yaml:")
	t.Logf("  Rules: %d", len(cfg.Rules))
	t.Logf("  Correlations: %d", len(cfg.Correlations))
	t.Logf("  Baselines: %d", len(cfg.Baselines))

	// Verify we have the expected counts
	if len(cfg.Rules) == 0 {
		t.Error("Expected some simple rules")
	}
	if len(cfg.Correlations) == 0 {
		t.Error("Expected some correlation rules")
	}
	if len(cfg.Baselines) == 0 {
		t.Error("Expected some baseline rules")
	}

	// Try to compile them
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	err = engine.LoadRules(cfg)
	if err != nil {
		t.Fatalf("Failed to load rules into engine: %v", err)
	}

	t.Logf("Successfully compiled:")
	t.Logf("  Simple rules: %d", len(engine.rules))
	t.Logf("  Correlation rules: %d", len(engine.correlations))
	t.Logf("  Baseline rules: %d", len(engine.baselines))
}
