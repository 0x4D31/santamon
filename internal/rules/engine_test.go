package rules

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
)

func TestNewEngine(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() failed: %v", err)
	}
	if engine == nil {
		t.Fatal("NewEngine() returned nil")
	}
	if engine.env == nil {
		t.Error("engine.env is nil")
	}
	if engine.rules == nil {
		t.Error("engine.rules is nil")
	}
	if engine.correlations == nil {
		t.Error("engine.correlations is nil")
	}
}

func TestLoadRules(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() failed: %v", err)
	}

	tests := []struct {
		name     string
		config   *RulesConfig
		wantErr  bool
		numRules int
		numCorrs int
	}{
		{
			name: "valid simple rule",
			config: &RulesConfig{
				Rules: []*Rule{
					{
						ID:       "TEST-001",
						Title:    "Test Rule",
						Expr:     "kind == \"execution\" && event.execution.decision == DECISION_ALLOW",
						Severity: "high",
						Enabled:  true,
					},
				},
			},
			wantErr:  false,
			numRules: 1,
			numCorrs: 0,
		},
		{
			name: "disabled rule should be skipped",
			config: &RulesConfig{
				Rules: []*Rule{
					{
						ID:       "TEST-002",
						Title:    "Disabled Rule",
						Expr:     "kind == \"execution\"",
						Severity: "low",
						Enabled:  false,
					},
				},
			},
			wantErr:  false,
			numRules: 0,
			numCorrs: 0,
		},
		{
			name: "invalid CEL expression",
			config: &RulesConfig{
				Rules: []*Rule{
					{
						ID:       "TEST-003",
						Title:    "Invalid Rule",
						Expr:     "invalid syntax +++",
						Severity: "medium",
						Enabled:  true,
					},
				},
			},
			wantErr:  true,
			numRules: 0,
			numCorrs: 0,
		},
		{
			name: "non-boolean expression",
			config: &RulesConfig{
				Rules: []*Rule{
					{
						ID:       "TEST-004",
						Title:    "Non-Boolean Rule",
						Expr:     "\"string_value\"",
						Severity: "high",
						Enabled:  true,
					},
				},
			},
			wantErr:  true,
			numRules: 0,
			numCorrs: 0,
		},
		{
			name: "mixed enabled and disabled",
			config: &RulesConfig{
				Rules: []*Rule{
					{
						ID:       "TEST-005",
						Title:    "Enabled",
						Expr:     "kind == \"execution\"",
						Severity: "high",
						Enabled:  true,
					},
					{
						ID:       "TEST-006",
						Title:    "Disabled",
						Expr:     "kind == \"file_access\"",
						Severity: "medium",
						Enabled:  false,
					},
					{
						ID:       "TEST-007",
						Title:    "Enabled 2",
						Expr:     "kind == \"xprotect\"",
						Severity: "critical",
						Enabled:  true,
					},
				},
			},
			wantErr:  false,
			numRules: 2,
			numCorrs: 0,
		},
		{
			name: "correlation rule",
			config: &RulesConfig{
				Correlations: []*CorrelationRule{
					{
						ID:        "TEST-CORR-001",
						Title:     "Test Correlation",
						Expr:      "kind == \"execution\" && event.execution.decision == DECISION_DENY",
						Window:    5 * time.Minute,
						Threshold: 3,
						Severity:  "medium",
						Enabled:   true,
					},
				},
			},
			wantErr:  false,
			numRules: 0,
			numCorrs: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.LoadRules(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(engine.rules) != tt.numRules {
					t.Errorf("got %d rules, want %d", len(engine.rules), tt.numRules)
				}
				if len(engine.correlations) != tt.numCorrs {
					t.Errorf("got %d correlations, want %d", len(engine.correlations), tt.numCorrs)
				}
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() failed: %v", err)
	}

	// Load test rules
	err = engine.LoadRules(&RulesConfig{
		Rules: []*Rule{
			{
				ID:       "EXEC-ALLOW",
				Title:    "Execution Allowed",
				Expr:     "kind == \"execution\" && event.execution.decision == DECISION_ALLOW",
				Severity: "low",
				Tags:     []string{"test"},
				Enabled:  true,
			},
			{
				ID:       "EXEC-DENY",
				Title:    "Execution Denied",
				Expr:     "kind == \"execution\" && event.execution.decision == DECISION_DENY",
				Severity: "high",
				Tags:     []string{"blocked"},
				Enabled:  true,
			},
			{
				ID:       "FILE-ACCESS",
				Title:    "File Access",
				Expr:     "kind == \"file_access\"",
				Severity: "medium",
				Enabled:  true,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules() failed: %v", err)
	}

	tests := []struct {
		name      string
		msg       *santapb.SantaMessage
		wantMatch []string // Rule IDs that should match
	}{
		{
			name: "execution allowed",
			msg: &santapb.SantaMessage{
				MachineId:       proto.String("test-machine"),
				BootSessionUuid: proto.String("boot-123"),
				EventTime:       timestamppb.New(time.Now()),
				Event: &santapb.SantaMessage_Execution{
					Execution: &santapb.Execution{
						Decision: santapb.Execution_DECISION_ALLOW.Enum(),
						Target: &santapb.ProcessInfo{
							Executable: &santapb.FileInfo{
								Path: proto.String("/bin/sh"),
							},
						},
					},
				},
			},
			wantMatch: []string{"EXEC-ALLOW"},
		},
		{
			name: "execution denied",
			msg: &santapb.SantaMessage{
				MachineId:       proto.String("test-machine"),
				BootSessionUuid: proto.String("boot-123"),
				EventTime:       timestamppb.New(time.Now()),
				Event: &santapb.SantaMessage_Execution{
					Execution: &santapb.Execution{
						Decision: santapb.Execution_DECISION_DENY.Enum(),
						Target: &santapb.ProcessInfo{
							Executable: &santapb.FileInfo{
								Path: proto.String("/tmp/malware"),
							},
						},
					},
				},
			},
			wantMatch: []string{"EXEC-DENY"},
		},
		{
			name: "file access",
			msg: &santapb.SantaMessage{
				MachineId:       proto.String("test-machine"),
				BootSessionUuid: proto.String("boot-123"),
				EventTime:       timestamppb.New(time.Now()),
				Event: &santapb.SantaMessage_FileAccess{
					FileAccess: &santapb.FileAccess{
						PolicyName: proto.String("TestPolicy"),
						Target: &santapb.FileInfoLight{
							Path: proto.String("/sensitive/file"),
						},
					},
				},
			},
			wantMatch: []string{"FILE-ACCESS"},
		},
		{
			name: "no matches",
			msg: &santapb.SantaMessage{
				MachineId:       proto.String("test-machine"),
				BootSessionUuid: proto.String("boot-123"),
				EventTime:       timestamppb.New(time.Now()),
				Event: &santapb.SantaMessage_Xprotect{
					Xprotect: &santapb.XProtect{},
				},
			},
			wantMatch: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Evaluate
			matches, err := engine.Evaluate(tt.msg)
			if err != nil {
				t.Fatalf("Evaluate() failed: %v", err)
			}

			// Check matches
			if len(matches) != len(tt.wantMatch) {
				t.Errorf("got %d matches, want %d", len(matches), len(tt.wantMatch))
			}

			// Verify specific rule IDs
			gotIDs := make(map[string]bool)
			for _, match := range matches {
				gotIDs[match.RuleID] = true
			}

			for _, wantID := range tt.wantMatch {
				if !gotIDs[wantID] {
					t.Errorf("expected rule %s to match, but it didn't", wantID)
				}
			}
		})
	}
}


func TestEvaluateEmpty(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() failed: %v", err)
	}

	// Load empty rules
	err = engine.LoadRules(&RulesConfig{
		Rules: []*Rule{},
	})
	if err != nil {
		t.Fatalf("LoadRules() failed: %v", err)
	}

	msg := &santapb.SantaMessage{
		MachineId:       proto.String("test-machine"),
		BootSessionUuid: proto.String("boot-123"),
		EventTime:       timestamppb.New(time.Now()),
		Event: &santapb.SantaMessage_Execution{
			Execution: &santapb.Execution{},
		},
	}

	matches, err := engine.Evaluate(msg)
	if err != nil {
		t.Fatalf("Evaluate() failed: %v", err)
	}

	if matches != nil && len(matches) != 0 {
		t.Errorf("expected nil or empty matches, got %d matches", len(matches))
	}
}

func TestCompileExpression(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() failed: %v", err)
	}

	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{
			name:    "valid boolean expression",
			expr:    "kind == \"execution\" && event.execution.decision == DECISION_ALLOW",
			wantErr: false,
		},
		{
			name:    "simple boolean",
			expr:    "true",
			wantErr: false,
		},
		{
			name:    "complex expression",
			expr:    "kind == \"execution\"",
			wantErr: false,
		},
		{
			name:    "invalid syntax",
			expr:    "invalid +++",
			wantErr: true,
		},
		{
			name:    "non-boolean return",
			expr:    "\"string\"",
			wantErr: true,
		},
		{
			name:    "non-boolean return - number",
			expr:    "123",
			wantErr: true,
		},
		{
			name:    "undefined variable",
			expr:    "undefined_field == \"value\"",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := engine.compileExpression("test", tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetCorrelations(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() failed: %v", err)
	}

	// Initially empty
	corrs := engine.GetCorrelations()
	if corrs == nil || len(corrs) != 0 {
		t.Errorf("expected empty correlations, got %v", corrs)
	}

	// Load some correlations
	err = engine.LoadRules(&RulesConfig{
		Correlations: []*CorrelationRule{
			{
				ID:        "CORR-001",
				Title:     "Test",
				Expr:      "kind == \"execution\"",
				Window:    5 * time.Minute,
				Threshold: 3,
				Severity:  "high",
				Enabled:   true,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules() failed: %v", err)
	}

	corrs = engine.GetCorrelations()
	if len(corrs) != 1 {
		t.Errorf("expected 1 correlation, got %d", len(corrs))
	}
}

func BenchmarkEvaluate(b *testing.B) {
	engine, err := NewEngine()
	if err != nil {
		b.Fatalf("NewEngine() failed: %v", err)
	}

	// Load realistic rules
	err = engine.LoadRules(&RulesConfig{
		Rules: []*Rule{
			{
				ID:       "BENCH-001",
				Title:    "Unsigned execution from Downloads",
				Expr:     "kind == \"execution\" && event.execution.target.executable.path.contains(\"/Downloads/\") && (!has(event.execution.target.code_signature.team_id) || event.execution.target.code_signature.team_id == \"\")",
				Severity: "high",
				Enabled:  true,
			},
			{
				ID:       "BENCH-002",
				Title:    "Chrome cookie access",
				Expr:     "kind == \"file_access\" && event.file_access.policy_name == \"ChromeCookies\"",
				Severity: "high",
				Enabled:  true,
			},
			{
				ID:       "BENCH-003",
				Title:    "XProtect detection",
				Expr:     "kind == \"xprotect\" && has(event.xprotect.detected)",
				Severity: "critical",
				Enabled:  true,
			},
		},
	})
	if err != nil {
		b.Fatalf("LoadRules() failed: %v", err)
	}

	msg := &santapb.SantaMessage{
		MachineId:       proto.String("bench-machine"),
		BootSessionUuid: proto.String("boot-456"),
		EventTime:       timestamppb.New(time.Now()),
		Event: &santapb.SantaMessage_Execution{
			Execution: &santapb.Execution{
				Decision: santapb.Execution_DECISION_ALLOW.Enum(),
				Target: &santapb.ProcessInfo{
					Executable: &santapb.FileInfo{
						Path: proto.String("/Applications/Test.app"),
					},
					CodeSignature: &santapb.CodeSignature{
						TeamId: proto.String("ABCD1234"),
					},
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.Evaluate(msg)
		if err != nil {
			b.Fatalf("Evaluate() failed: %v", err)
		}
	}
}
