package correlation

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
	"github.com/0x4d31/santamon/internal/rules"
	"github.com/0x4d31/santamon/internal/state"
)

func TestNewWindowManager(t *testing.T) {
	db, err := state.Open(t.TempDir()+"/test.db", 1000, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	wm := NewWindowManager(db, 100, time.Minute)
	if wm == nil {
		t.Fatal("NewWindowManager returned nil")
	}
	if wm.db == nil {
		t.Error("WindowManager.db is nil")
	}
	if wm.maxEvents != 100 {
		t.Errorf("maxEvents = %d, want 100", wm.maxEvents)
	}
	if wm.gcInterval != time.Minute {
		t.Errorf("gcInterval = %v, want 1m", wm.gcInterval)
	}
}

func TestProcessNoCorrelations(t *testing.T) {
	db, err := state.Open(t.TempDir()+"/test.db", 1000, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	wm := NewWindowManager(db, 100, time.Minute)
	msg := createTestMessage("test-machine", "DECISION_DENY")

	// Empty correlations
	matches, err := wm.Process(msg, []*rules.CompiledCorrelation{})
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if matches != nil && len(matches) != 0 {
		t.Errorf("expected nil or empty matches, got %d", len(matches))
	}
}

func TestProcessSimpleThreshold(t *testing.T) {
	// Use unique temp file for each test run to avoid state pollution
	db, err := state.Open(t.TempDir()+"/test.db", 1000, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	engine, err := rules.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Create correlation rule: trigger on 3 denied executions
	err = engine.LoadRules(&rules.RulesConfig{
		Correlations: []*rules.CorrelationRule{
			{
				ID:        "TEST-CORR-001",
				Title:     "Repeated denials",
				Expr:      "kind == \"execution\" && event.execution.decision == DECISION_DENY",
				Window:    5 * time.Minute,
				Threshold: 3,
				Severity:  "high",
				Tags:      []string{"persistence"},
				Enabled:   true,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	wm := NewWindowManager(db, 100, time.Minute)
	correlations := engine.GetCorrelations()

	// Send 2 events - should not trigger
	for i := 0; i < 2; i++ {
		msg := createTestMessage("machine-1", "DECISION_DENY")

		matches, err := wm.Process(msg, correlations)
		if err != nil {
			t.Fatalf("Process failed: %v", err)
		}
		if len(matches) != 0 {
			t.Errorf("iteration %d: expected no matches, got %d", i, len(matches))
		}
	}

	// Send 3rd event - should trigger
	msg := createTestMessage("machine-1", "DECISION_DENY")

	matches, err := wm.Process(msg, correlations)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	match := matches[0]
	if match.RuleID != "TEST-CORR-001" {
		t.Errorf("RuleID = %s, want TEST-CORR-001", match.RuleID)
	}
	if match.Count != 3 {
		t.Errorf("Count = %d, want 3", match.Count)
	}
	if match.Severity != "high" {
		t.Errorf("Severity = %s, want high", match.Severity)
	}
	if len(match.Tags) != 1 || match.Tags[0] != "persistence" {
		t.Errorf("Tags = %v, want [persistence]", match.Tags)
	}

	// Send 4th event - should not trigger (window was cleared after match)
	msg = createTestMessage("machine-1", "DECISION_DENY")

	matches, err = wm.Process(msg, correlations)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected no matches after window clear, got %d", len(matches))
	}
}

func TestProcessGroupBy(t *testing.T) {
	db, err := state.Open(t.TempDir()+"/test.db", 1000, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	engine, err := rules.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Group by hash and user - different groups should track separately
	err = engine.LoadRules(&rules.RulesConfig{
		Correlations: []*rules.CorrelationRule{
			{
				ID:    "TEST-GROUP-001",
				Title: "Grouped by hash and user",
				Expr:  "kind == \"execution\" && event.execution.decision == DECISION_DENY",
				GroupBy: []string{
					"execution.target.executable.hash.hash",
					"execution.instigator.effective_user.name",
				},
				Window:    5 * time.Minute,
				Threshold: 3,
				Severity:  "medium",
				Enabled:   true,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	wm := NewWindowManager(db, 100, time.Minute)
	correlations := engine.GetCorrelations()

	// Send events with different hash/user combinations
	testCases := []struct {
		hash          string
		user          string
		shouldTrigger bool
	}{
		{"hash1", "user1", false}, // 1st event for hash1+user1
		{"hash1", "user1", false}, // 2nd event for hash1+user1
		{"hash1", "user2", false}, // Different user, different group
		{"hash2", "user1", false}, // Different hash, different group
		{"hash1", "user1", true},  // 3rd event for hash1+user1 - TRIGGER!
		{"hash1", "user2", false}, // Still only 1 event for hash1+user2
		{"hash2", "user1", false}, // Still only 1 event for hash2+user1
	}

	for i, tc := range testCases {
		msg := createTestMessageWithHashUser(tc.hash, tc.user)

		matches, err := wm.Process(msg, correlations)
		if err != nil {
			t.Fatalf("case %d: Process failed: %v", i, err)
		}

		if tc.shouldTrigger {
			if len(matches) != 1 {
				t.Errorf("case %d (hash=%s, user=%s): expected 1 match, got %d", i, tc.hash, tc.user, len(matches))
			} else {
				// Verify group key contains both hash and user
				expectedKey := "execution.target.executable.hash.hash=" + tc.hash +
					"|execution.instigator.effective_user.name=" + tc.user
				if matches[0].GroupKey != expectedKey {
					t.Errorf("case %d: GroupKey = %s, want %s", i, matches[0].GroupKey, expectedKey)
				}
			}
		} else {
			if len(matches) != 0 {
				t.Errorf("case %d (hash=%s, user=%s): expected no matches, got %d, groupKey=%s",
					i, tc.hash, tc.user, len(matches), matches[0].GroupKey)
			}
		}
	}
}

func TestProcessCountDistinct(t *testing.T) {
	db, err := state.Open(t.TempDir()+"/test.db", 1000, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	engine, err := rules.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Count distinct hashes - trigger when 3 different binaries are denied
	err = engine.LoadRules(&rules.RulesConfig{
		Correlations: []*rules.CorrelationRule{
			{
				ID:            "TEST-DISTINCT-001",
				Title:         "Multiple binaries blocked",
				Expr:          "kind == \"execution\" && event.execution.decision == DECISION_DENY",
				Window:        5 * time.Minute,
				CountDistinct: "execution.target.executable.hash.hash",
				Threshold:     3,
				Severity:      "high",
				Enabled:       true,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	wm := NewWindowManager(db, 100, time.Minute)
	correlations := engine.GetCorrelations()

	// Send events with different hashes
	testCases := []struct {
		hash          string
		shouldTrigger bool
	}{
		{"hash1", false}, // 1 distinct hash
		{"hash1", false}, // Still 1 distinct hash (duplicate)
		{"hash2", false}, // 2 distinct hashes
		{"hash1", false}, // Still 2 distinct hashes
		{"hash3", true},  // 3 distinct hashes - TRIGGER!
	}

	for i, tc := range testCases {
		msg := createTestMessageWithHashUser(tc.hash, "user1")

		matches, err := wm.Process(msg, correlations)
		if err != nil {
			t.Fatalf("case %d: Process failed: %v", i, err)
		}

		if tc.shouldTrigger {
			if len(matches) != 1 {
				t.Errorf("case %d: expected 1 match, got %d", i, len(matches))
			} else if matches[0].Count != 3 {
				t.Errorf("case %d: Count = %d, want 3 distinct", i, matches[0].Count)
			}
		} else {
			if len(matches) != 0 {
				t.Errorf("case %d: expected no matches, got %d", i, len(matches))
			}
		}
	}
}

func TestProcessWindowExpiration(t *testing.T) {
	db, err := state.Open(t.TempDir()+"/test.db", 1000, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	engine, err := rules.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Very short window for testing
	err = engine.LoadRules(&rules.RulesConfig{
		Correlations: []*rules.CorrelationRule{
			{
				ID:        "TEST-WINDOW-001",
				Title:     "Short window test",
				Expr:      "kind == \"execution\" && event.execution.decision == DECISION_DENY",
				Window:    100 * time.Millisecond, // Very short window
				Threshold: 3,
				Severity:  "low",
				Enabled:   true,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	wm := NewWindowManager(db, 100, time.Minute)
	correlations := engine.GetCorrelations()

	// Send 2 events
	for i := 0; i < 2; i++ {
		msg := createTestMessage("machine-1", "DECISION_DENY")

		matches, err := wm.Process(msg, correlations)
		if err != nil {
			t.Fatalf("Process failed: %v", err)
		}
		if len(matches) != 0 {
			t.Errorf("expected no matches, got %d", len(matches))
		}
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Send 3rd event - should NOT trigger because previous events expired
	msg := createTestMessage("machine-1", "DECISION_DENY")

	matches, err := wm.Process(msg, correlations)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected no matches due to window expiration, got %d", len(matches))
	}
}

func TestProcessPrunesExpiredStoredEvents(t *testing.T) {
	db, err := state.Open(t.TempDir()+"/test.db", 1000, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	engine, err := rules.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	err = engine.LoadRules(&rules.RulesConfig{
		Correlations: []*rules.CorrelationRule{
			{
				ID:        "TEST-PRUNE-001",
				Title:     "Prune expired",
				Expr:      "kind == \"execution\" && event.execution.decision == DECISION_DENY",
				Window:    150 * time.Millisecond,
				Threshold: 5,
				Severity:  "low",
				Enabled:   true,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	wm := NewWindowManager(db, 100, time.Minute)
	correlations := engine.GetCorrelations()

	// First event enters the window
	msg := createTestMessageWithPath("/bin/old", "DECISION_DENY")
	if _, err := wm.Process(msg, correlations); err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	// Let the first event fall out of the window
	time.Sleep(200 * time.Millisecond)

	// Second event should replace stored state with only recent events
	msg = createTestMessageWithPath("/bin/new", "DECISION_DENY")
	if _, err := wm.Process(msg, correlations); err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	stored, err := db.GetWindowEvents("TEST-PRUNE-001", "_global")
	if err != nil {
		t.Fatalf("GetWindowEvents failed: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored event after pruning, got %d", len(stored))
	}
	if path := eventTargetPath(stored[0]); path != "/bin/new" {
		t.Fatalf("stored event path = %q, want /bin/new", path)
	}
}

func TestProcessBoundsStoredEvents(t *testing.T) {
	db, err := state.Open(t.TempDir()+"/test.db", 1000, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	engine, err := rules.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	err = engine.LoadRules(&rules.RulesConfig{
		Correlations: []*rules.CorrelationRule{
			{
				ID:        "TEST-BOUNDS-001",
				Title:     "Bound stored events",
				Expr:      "kind == \"execution\" && event.execution.decision == DECISION_DENY",
				Window:    5 * time.Minute,
				Threshold: 10,
				Severity:  "medium",
				Enabled:   true,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	// Limit stored events to 2
	wm := NewWindowManager(db, 2, time.Minute)
	correlations := engine.GetCorrelations()

	paths := []string{"/bin/one", "/bin/two", "/bin/three"}
	for _, p := range paths {
		msg := createTestMessageWithPath(p, "DECISION_DENY")
		if _, err := wm.Process(msg, correlations); err != nil {
			t.Fatalf("Process failed: %v", err)
		}
	}

	stored, err := db.GetWindowEvents("TEST-BOUNDS-001", "_global")
	if err != nil {
		t.Fatalf("GetWindowEvents failed: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("expected stored events to be bounded at 2, got %d", len(stored))
	}

	remaining := map[string]bool{
		"/bin/two":   false,
		"/bin/three": false,
	}
	for _, evt := range stored {
		p := eventTargetPath(evt)
		remaining[p] = true
	}
	for path, seen := range remaining {
		if !seen {
			t.Fatalf("expected path %s to remain in bounded window", path)
		}
	}
}

func TestProcessFilterExpression(t *testing.T) {
	db, err := state.Open(t.TempDir()+"/test.db", 1000, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	engine, err := rules.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Only track DENIED executions from /tmp
	err = engine.LoadRules(&rules.RulesConfig{
		Correlations: []*rules.CorrelationRule{
			{
				ID:        "TEST-FILTER-001",
				Title:     "Denials from /tmp",
				Expr:      "kind == \"execution\" && event.execution.decision == DECISION_DENY && event.execution.target.executable.path.startsWith(\"/tmp/\")",
				Window:    5 * time.Minute,
				Threshold: 2,
				Severity:  "critical",
				Enabled:   true,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	wm := NewWindowManager(db, 100, time.Minute)
	correlations := engine.GetCorrelations()

	// Send events with different paths and decisions
	testCases := []struct {
		path     string
		decision string
		counted  bool
	}{
		{"/tmp/malware", "DECISION_DENY", true},  // Matches filter
		{"/bin/sh", "DECISION_DENY", false},      // Wrong path
		{"/tmp/script", "DECISION_ALLOW", false}, // Wrong decision
		{"/tmp/another", "DECISION_DENY", true},  // Matches - should trigger!
	}

	matchFound := false
	for i, tc := range testCases {
		msg := createTestMessageWithPath(tc.path, tc.decision)

		matches, err := wm.Process(msg, correlations)
		if err != nil {
			t.Fatalf("case %d: Process failed: %v", i, err)
		}

		if len(matches) > 0 {
			matchFound = true
			if !tc.counted {
				t.Errorf("case %d: unexpected match", i)
			}
			if matches[0].Count != 2 {
				t.Errorf("case %d: Count = %d, want 2", i, matches[0].Count)
			}
		}
	}

	if !matchFound {
		t.Error("expected correlation to trigger, but it didn't")
	}
}

func TestProcessMultipleCorrelations(t *testing.T) {
	db, err := state.Open(t.TempDir()+"/test.db", 1000, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	engine, err := rules.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Multiple correlation rules running simultaneously
	err = engine.LoadRules(&rules.RulesConfig{
		Correlations: []*rules.CorrelationRule{
			{
				ID:        "CORR-DENY",
				Title:     "Multiple denials",
				Expr:      "kind == \"execution\" && event.execution.decision == DECISION_DENY",
				Window:    5 * time.Minute,
				Threshold: 2,
				Severity:  "high",
				Enabled:   true,
			},
			{
				ID:        "CORR-ALLOW",
				Title:     "Multiple allows",
				Expr:      "kind == \"execution\" && event.execution.decision == DECISION_ALLOW",
				Window:    5 * time.Minute,
				Threshold: 2,
				Severity:  "low",
				Enabled:   true,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	wm := NewWindowManager(db, 100, time.Minute)
	correlations := engine.GetCorrelations()

	// Send mix of allowed and denied events
	decisions := []string{
		"DECISION_DENY",
		"DECISION_ALLOW",
		"DECISION_DENY",  // Should trigger CORR-DENY
		"DECISION_ALLOW", // Should trigger CORR-ALLOW
	}

	denyTriggered := false
	allowTriggered := false

	for i, decision := range decisions {
		msg := createTestMessage("machine-1", decision)

		matches, err := wm.Process(msg, correlations)
		if err != nil {
			t.Fatalf("iteration %d: Process failed: %v", i, err)
		}

		for _, match := range matches {
			if match.RuleID == "CORR-DENY" {
				denyTriggered = true
			}
			if match.RuleID == "CORR-ALLOW" {
				allowTriggered = true
			}
		}
	}

	if !denyTriggered {
		t.Error("CORR-DENY should have triggered")
	}
	if !allowTriggered {
		t.Error("CORR-ALLOW should have triggered")
	}
}

func TestExtractGroupKey(t *testing.T) {
	db, err := state.Open(t.TempDir()+"/test.db", 1000, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	wm := NewWindowManager(db, 100, time.Minute)

	event := map[string]any{
		"execution": map[string]any{
			"target": map[string]any{
				"executable": map[string]any{
					"hash": map[string]any{
						"hash": "abc123",
					},
				},
			},
			"instigator": map[string]any{
				"effective_user": map[string]any{
					"name": "testuser",
				},
			},
		},
	}

	tests := []struct {
		name    string
		groupBy []string
		want    string
	}{
		{
			name:    "single field",
			groupBy: []string{"execution.target.executable.hash.hash"},
			want:    "execution.target.executable.hash.hash=abc123",
		},
		{
			name: "multiple fields",
			groupBy: []string{
				"execution.target.executable.hash.hash",
				"execution.instigator.effective_user.name",
			},
			want: "execution.target.executable.hash.hash=abc123|execution.instigator.effective_user.name=testuser",
		},
		{
			name:    "missing field",
			groupBy: []string{"nonexistent.field"},
			want:    "nonexistent.field=",
		},
		{
			name:    "empty group_by",
			groupBy: []string{},
			want:    "_global",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wm.extractGroupKey(event, tt.groupBy)
			if got != tt.want {
				t.Errorf("extractGroupKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCountEvents(t *testing.T) {
	db, err := state.Open(t.TempDir()+"/test.db", 1000, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	wm := NewWindowManager(db, 100, time.Minute)

	events := []map[string]any{
		{"hash": "hash1", "user": "user1"},
		{"hash": "hash1", "user": "user2"},
		{"hash": "hash2", "user": "user1"},
		{"hash": "hash2", "user": "user1"}, // Duplicate
	}

	tests := []struct {
		name          string
		countDistinct string
		want          int
	}{
		{
			name:          "count all",
			countDistinct: "",
			want:          4,
		},
		{
			name:          "count distinct hashes",
			countDistinct: "hash",
			want:          2, // hash1, hash2
		},
		{
			name:          "count distinct users",
			countDistinct: "user",
			want:          2, // user1, user2
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &rules.CorrelationRule{
				CountDistinct: tt.countDistinct,
			}
			got := wm.countEvents(events, rule)
			if got != tt.want {
				t.Errorf("countEvents() = %d, want %d", got, tt.want)
			}
		})
	}
}

// Helper functions

func createTestMessage(machineID, decision string) *santapb.SantaMessage {
	return createTestMessageWithPath("/bin/test", decision)
}

func createTestMessageWithPath(path, decision string) *santapb.SantaMessage {
	var decisionEnum santapb.Execution_Decision
	if decision == "DECISION_ALLOW" {
		decisionEnum = santapb.Execution_DECISION_ALLOW
	} else {
		decisionEnum = santapb.Execution_DECISION_DENY
	}

	return &santapb.SantaMessage{
		MachineId:       proto.String("test-machine"),
		BootSessionUuid: proto.String("boot-123"),
		EventTime:       timestamppb.New(time.Now()),
		Event: &santapb.SantaMessage_Execution{
			Execution: &santapb.Execution{
				Decision: &decisionEnum,
				Target: &santapb.ProcessInfo{
					Executable: &santapb.FileInfo{
						Path: proto.String(path),
					},
				},
			},
		},
	}
}

func createTestMessageWithHashUser(hash, user string) *santapb.SantaMessage {
	decision := santapb.Execution_DECISION_DENY
	return &santapb.SantaMessage{
		MachineId:       proto.String("test-machine"),
		BootSessionUuid: proto.String("boot-123"),
		EventTime:       timestamppb.New(time.Now()),
		Event: &santapb.SantaMessage_Execution{
			Execution: &santapb.Execution{
				Decision: &decision,
				Instigator: &santapb.ProcessInfoLight{
					EffectiveUser: &santapb.UserInfo{
						Name: proto.String(user),
					},
				},
				Target: &santapb.ProcessInfo{
					Executable: &santapb.FileInfo{
						Path: proto.String("/bin/test"),
						Hash: &santapb.Hash{
							Hash: proto.String(hash),
						},
					},
				},
			},
		},
	}
}

func eventTargetPath(evt map[string]any) string {
	execMap, ok := evt["execution"].(map[string]any)
	if !ok {
		return ""
	}
	target, ok := execMap["target"].(map[string]any)
	if !ok {
		return ""
	}
	exe, ok := target["executable"].(map[string]any)
	if !ok {
		return ""
	}
	if path, ok := exe["path"].(string); ok {
		return path
	}
	return ""
}
