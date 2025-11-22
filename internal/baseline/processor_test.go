package baseline

import (
	"testing"
	"time"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
	"github.com/0x4d31/santamon/internal/events"
	"github.com/0x4d31/santamon/internal/rules"
	"github.com/0x4d31/santamon/internal/state"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNewProcessor(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	proc := NewProcessor(db)
	if proc == nil {
		t.Fatal("NewProcessor returned nil")
	}
	if proc.db != db {
		t.Error("Processor db not set correctly")
	}
}

func TestProcessNoBaselines(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	proc := NewProcessor(db)
	engine, _ := rules.NewEngine()

	msg := createTestMessage(t, "DECISION_UNKNOWN")
	eventMap, _ := events.ToMap(msg)
	events.BuildActivation(msg, eventMap)

	matches, err := proc.Process(msg, eventMap, nil, engine)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Expected 0 matches, got %d", len(matches))
	}
}

func TestProcessFirstOccurrence(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	proc := NewProcessor(db)
	engine, _ := rules.NewEngine()

	// Create a baseline rule
	baseline := &rules.BaselineRule{
		ID:       "TEST-001",
		Title:    "First test event",
		Expr:     "kind == \"execution\"",
		Track:    []string{"execution.target.executable.path"},
		Severity: "medium",
		Tags:     []string{"test"},
		Enabled:  true,
	}

	compiled, err := compileBaseline(t, engine, baseline)
	if err != nil {
		t.Fatalf("Failed to compile baseline: %v", err)
	}

	msg := createTestMessage(t, "DECISION_UNKNOWN")
	eventMap, _ := events.ToMap(msg)
	events.BuildActivation(msg, eventMap)

	// First occurrence should match
	matches, err := proc.Process(msg, eventMap, []*rules.CompiledBaseline{compiled}, engine)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("Expected 1 match, got %d", len(matches))
	}

	match := matches[0]
	if match.RuleID != "TEST-001" {
		t.Errorf("Expected rule ID TEST-001, got %s", match.RuleID)
	}
	if match.Title != "First test event" {
		t.Errorf("Expected title 'First test event', got %s", match.Title)
	}
	if match.Severity != "medium" {
		t.Errorf("Expected severity medium, got %s", match.Severity)
	}
	if match.Pattern == "" {
		t.Error("Pattern should not be empty")
	}
	if match.InLearning {
		t.Error("Should not be in learning period by default")
	}
}

func TestProcessSecondOccurrence(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	proc := NewProcessor(db)
	engine, _ := rules.NewEngine()

	baseline := &rules.BaselineRule{
		ID:       "TEST-002",
		Title:    "Second test",
		Expr:     "kind == \"execution\"",
		Track:    []string{"execution.target.executable.path"},
		Severity: "high",
		Tags:     []string{"test"},
		Enabled:  true,
	}

	compiled, err := compileBaseline(t, engine, baseline)
	if err != nil {
		t.Fatalf("Failed to compile baseline: %v", err)
	}

	msg := createTestMessage(t, "DECISION_UNKNOWN")
	eventMap, _ := events.ToMap(msg)
	events.BuildActivation(msg, eventMap)

	// First occurrence
	matches1, err := proc.Process(msg, eventMap, []*rules.CompiledBaseline{compiled}, engine)
	if err != nil {
		t.Fatalf("First process failed: %v", err)
	}
	if len(matches1) != 1 {
		t.Fatalf("Expected 1 match on first occurrence, got %d", len(matches1))
	}

	// Second occurrence with same pattern should NOT match
	matches2, err := proc.Process(msg, eventMap, []*rules.CompiledBaseline{compiled}, engine)
	if err != nil {
		t.Fatalf("Second process failed: %v", err)
	}
	if len(matches2) != 0 {
		t.Errorf("Expected 0 matches on second occurrence, got %d", len(matches2))
	}
}

func TestProcessLearningPeriod(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	proc := NewProcessor(db)
	engine, _ := rules.NewEngine()

	baseline := &rules.BaselineRule{
		ID:             "TEST-003",
		Title:          "Learning test",
		Expr:           "kind == \"execution\"",
		Track:          []string{"execution.target.executable.path"},
		Severity:       "low",
		Tags:           []string{"test"},
		Enabled:        true,
		LearningPeriod: 24 * time.Hour, // 24 hours
	}

	compiled, err := compileBaseline(t, engine, baseline)
	if err != nil {
		t.Fatalf("Failed to compile baseline: %v", err)
	}

	msg := createTestMessage(t, "DECISION_UNKNOWN")
	eventMap, _ := events.ToMap(msg)
	events.BuildActivation(msg, eventMap)

	matches, err := proc.Process(msg, eventMap, []*rules.CompiledBaseline{compiled}, engine)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("Expected 1 match, got %d", len(matches))
	}

	if !matches[0].InLearning {
		t.Error("Expected InLearning=true during learning period")
	}
}

func TestProcessMultipleTrackFields(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	proc := NewProcessor(db)
	engine, _ := rules.NewEngine()

	baseline := &rules.BaselineRule{
		ID:    "TEST-004",
		Title: "Multi-field test",
		Expr:  "kind == \"execution\"",
		Track: []string{
			"execution.target.executable.path",
			"execution.target.executable.hash.hash",
		},
		Severity: "medium",
		Tags:     []string{"test"},
		Enabled:  true,
	}

	compiled, err := compileBaseline(t, engine, baseline)
	if err != nil {
		t.Fatalf("Failed to compile baseline: %v", err)
	}

	msg := createTestMessage(t, "DECISION_UNKNOWN")
	eventMap, _ := events.ToMap(msg)
	events.BuildActivation(msg, eventMap)

	matches, err := proc.Process(msg, eventMap, []*rules.CompiledBaseline{compiled}, engine)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("Expected 1 match, got %d", len(matches))
	}

	// Pattern should include both fields
	pattern := matches[0].Pattern
	if pattern == "" {
		t.Error("Pattern should not be empty")
	}
	// Pattern format: field1=value1|field2=value2
	// Should contain both field names
	t.Logf("Pattern: %s", pattern)
}

func TestProcessFilterNotMatching(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	proc := NewProcessor(db)
	engine, _ := rules.NewEngine()

	// This filter will not match our test message
	baseline := &rules.BaselineRule{
		ID:       "TEST-005",
		Title:    "Non-matching filter",
		Expr:     `kind == "execution" && execution.target.executable.path == "/nonexistent"`,
		Track:    []string{"execution.target.executable.path"},
		Severity: "high",
		Tags:     []string{"test"},
		Enabled:  true,
	}

	compiled, err := compileBaseline(t, engine, baseline)
	if err != nil {
		t.Fatalf("Failed to compile baseline: %v", err)
	}

	msg := createTestMessage(t, "DECISION_UNKNOWN")
	eventMap, _ := events.ToMap(msg)
	events.BuildActivation(msg, eventMap)

	matches, err := proc.Process(msg, eventMap, []*rules.CompiledBaseline{compiled}, engine)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if len(matches) != 0 {
		t.Errorf("Expected 0 matches for non-matching filter, got %d", len(matches))
	}
}

func TestExtractPattern(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	proc := NewProcessor(db)

	tests := []struct {
		name        string
		eventMap    map[string]any
		trackFields []string
		expected    string
	}{
		{
			name: "single field",
			eventMap: map[string]any{
				"execution": map[string]any{
					"target": map[string]any{
						"executable": map[string]any{
							"path": "/usr/bin/curl",
						},
					},
				},
			},
			trackFields: []string{"execution.target.executable.path"},
			expected:    "execution.target.executable.path=/usr/bin/curl",
		},
		{
			name: "multiple fields",
			eventMap: map[string]any{
				"execution": map[string]any{
					"target": map[string]any{
						"executable": map[string]any{
							"path": "/usr/bin/curl",
							"hash": map[string]any{
								"hash": "abc123",
							},
						},
					},
				},
			},
			trackFields: []string{
				"execution.target.executable.path",
				"execution.target.executable.hash.hash",
			},
			expected: "execution.target.executable.path=/usr/bin/curl|execution.target.executable.hash.hash=abc123",
		},
		{
			name: "missing field",
			eventMap: map[string]any{
				"execution": map[string]any{},
			},
			trackFields: []string{"execution.nonexistent"},
			expected:    "execution.nonexistent=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := proc.extractPattern(tt.eventMap, tt.trackFields)
			if pattern != tt.expected {
				t.Errorf("Expected pattern %q, got %q", tt.expected, pattern)
			}
		})
	}
}

func TestProcessMultipleBaselines(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	proc := NewProcessor(db)
	engine, _ := rules.NewEngine()

	baseline1 := &rules.BaselineRule{
		ID:       "TEST-006",
		Title:    "First baseline",
		Expr:     "kind == \"execution\"",
		Track:    []string{"execution.target.executable.path"},
		Severity: "medium",
		Tags:     []string{"test"},
		Enabled:  true,
	}

	baseline2 := &rules.BaselineRule{
		ID:       "TEST-007",
		Title:    "Second baseline",
		Expr:     "kind == \"execution\"",
		Track:    []string{"execution.target.executable.hash.hash"},
		Severity: "high",
		Tags:     []string{"test"},
		Enabled:  true,
	}

	compiled1, err := compileBaseline(t, engine, baseline1)
	if err != nil {
		t.Fatalf("Failed to compile baseline1: %v", err)
	}

	compiled2, err := compileBaseline(t, engine, baseline2)
	if err != nil {
		t.Fatalf("Failed to compile baseline2: %v", err)
	}

	msg := createTestMessage(t, "DECISION_UNKNOWN")
	eventMap, _ := events.ToMap(msg)
	events.BuildActivation(msg, eventMap)

	matches, err := proc.Process(msg, eventMap, []*rules.CompiledBaseline{compiled1, compiled2}, engine)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	// Both baselines should match (different patterns)
	if len(matches) != 2 {
		t.Fatalf("Expected 2 matches, got %d", len(matches))
	}

	// Verify both rule IDs are present
	ruleIDs := map[string]bool{}
	for _, match := range matches {
		ruleIDs[match.RuleID] = true
	}
	if !ruleIDs["TEST-006"] || !ruleIDs["TEST-007"] {
		t.Error("Expected both TEST-006 and TEST-007 in matches")
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

func createTestMessage(t *testing.T, decisionStr string) *santapb.SantaMessage {
	t.Helper()
	now := timestamppb.Now()

	decision := santapb.Execution_DECISION_UNKNOWN
	if decisionStr == "DECISION_DENY" {
		decision = santapb.Execution_DECISION_DENY
	} else if decisionStr == "DECISION_ALLOW" {
		decision = santapb.Execution_DECISION_ALLOW
	}

	return &santapb.SantaMessage{
		EventTime:       now,
		ProcessedTime:   now,
		MachineId:       proto.String("test-machine"),
		BootSessionUuid: proto.String("test-boot-session"),
		Event: &santapb.SantaMessage_Execution{
			Execution: &santapb.Execution{
				Decision: &decision,
				Instigator: &santapb.ProcessInfoLight{
					EffectiveUser: &santapb.UserInfo{
						Name: proto.String("testuser"),
					},
				},
				Target: &santapb.ProcessInfo{
					Executable: &santapb.FileInfo{
						Path: proto.String("/usr/bin/curl"),
						Hash: &santapb.Hash{
							Hash: proto.String("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
						},
					},
				},
			},
		},
	}
}

func compileBaseline(t *testing.T, engine *rules.Engine, baseline *rules.BaselineRule) (*rules.CompiledBaseline, error) {
	t.Helper()

	// Use the same compilation logic as engine.LoadRules
	ast, issues := engine.GetEnv().Compile(baseline.Expr)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}

	program, err := engine.GetEnv().Program(ast)
	if err != nil {
		return nil, err
	}

	return &rules.CompiledBaseline{
		Rule:    baseline,
		Program: program,
	}, nil
}
