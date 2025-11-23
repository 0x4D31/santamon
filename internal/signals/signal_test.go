package signals

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
	"github.com/0x4d31/santamon/internal/correlation"
	"github.com/0x4d31/santamon/internal/rules"
	"github.com/0x4d31/santamon/internal/state"
)

func TestNewGenerator(t *testing.T) {
	hostID := "test-host"
	gen := NewGenerator(hostID, nil)

	if gen == nil {
		t.Fatal("NewGenerator returned nil")
	}
	if gen.hostID != hostID {
		t.Errorf("hostID = %v, want %v", gen.hostID, hostID)
	}
}

func TestFromRuleMatch(t *testing.T) {
	gen := NewGenerator("test-host", nil)
	ts := time.Now()

	msg := &santapb.SantaMessage{
		BootSessionUuid: proto.String("boot-123"),
		EventTime:       timestamppb.New(ts),
		Event: &santapb.SantaMessage_Execution{
			Execution: &santapb.Execution{
				Decision: santapb.Execution_DECISION_ALLOW.Enum(),
				Instigator: &santapb.ProcessInfoLight{
					Executable: &santapb.FileInfoLight{
						Path: proto.String("/usr/bin/curl"),
					},
				},
				Target: &santapb.ProcessInfo{
					CodeSignature: &santapb.CodeSignature{
						TeamId: proto.String("com.apple"),
					},
					Executable: &santapb.FileInfo{
						Path: proto.String("/bin/sh"),
						Hash: &santapb.Hash{
							Hash: proto.String("def456"),
						},
					},
				},
			},
		},
	}

	match := &rules.Match{
		RuleID:    "SM-001",
		Severity:  "high",
		Title:     "Test Detection",
		Tags:      []string{"T1539", "credential-access"},
		Message:   msg,
		Timestamp: ts,
	}

	signal := gen.FromRuleMatch(match)

	// Verify signal fields
	if signal == nil {
		t.Fatal("FromRuleMatch returned nil")
	}
	if signal.ID == "" {
		t.Error("Signal ID is empty")
	}
	if signal.TS != ts {
		t.Errorf("TS = %v, want %v", signal.TS, ts)
	}
	if signal.HostID != "test-host" {
		t.Errorf("HostID = %v, want test-host", signal.HostID)
	}
	if signal.RuleID != "SM-001" {
		t.Errorf("RuleID = %v, want SM-001", signal.RuleID)
	}
	if signal.Severity != "high" {
		t.Errorf("Severity = %v, want high", signal.Severity)
	}
	if signal.Title != "Test Detection" {
		t.Errorf("Title = %v, want Test Detection", signal.Title)
	}
	if len(signal.Tags) != 2 {
		t.Errorf("Tags length = %v, want 2", len(signal.Tags))
	}

	// Verify context fields
	if signal.Context["actor_path"] != "/usr/bin/curl" {
		t.Errorf("Context actor_path = %v, want /usr/bin/curl", signal.Context["actor_path"])
	}
	if signal.Context["target_path"] != "/bin/sh" {
		t.Errorf("Context target_path = %v, want /bin/sh", signal.Context["target_path"])
	}
	if signal.Context["target_sha256"] != "def456" {
		t.Errorf("Context target_sha256 = %v, want def456", signal.Context["target_sha256"])
	}
	if signal.Context["decision"] != "DECISION_ALLOW" {
		t.Errorf("Context decision = %v, want DECISION_ALLOW", signal.Context["decision"])
	}
}

func TestFromWindowMatch(t *testing.T) {
	gen := NewGenerator("test-host", nil)

	event1 := map[string]any{
		"path": "/usr/bin/curl",
		"ts":   "2025-01-01T00:00:00Z",
	}
	event2 := map[string]any{
		"path": "/usr/bin/wget",
		"ts":   "2025-01-01T00:01:00Z",
	}

	wmatch := &correlation.WindowMatch{
		RuleID:   "SM-WIN-001",
		Severity: "medium",
		Title:    "Suspicious Activity Pattern",
		GroupKey: "user:1000",
		Count:    2,
		Events:   []map[string]any{event1, event2},
	}

	signal := gen.FromWindowMatch(wmatch, "boot-456")

	// Verify signal fields
	if signal == nil {
		t.Fatal("FromWindowMatch returned nil")
	}
	if signal.ID == "" {
		t.Error("Signal ID is empty")
	}
	if signal.HostID != "test-host" {
		t.Errorf("HostID = %v, want test-host", signal.HostID)
	}
	if signal.RuleID != "SM-WIN-001" {
		t.Errorf("RuleID = %v, want SM-WIN-001", signal.RuleID)
	}
	if signal.Severity != "medium" {
		t.Errorf("Severity = %v, want medium", signal.Severity)
	}
	if signal.Title != "Suspicious Activity Pattern" {
		t.Errorf("Title = %v, want Suspicious Activity Pattern", signal.Title)
	}
	if len(signal.Tags) != 1 || signal.Tags[0] != "correlation" {
		t.Errorf("Tags = %v, want [correlation]", signal.Tags)
	}

	// Verify context fields
	if signal.Context["event_count"] != 2 {
		t.Errorf("Context event_count = %v, want 2", signal.Context["event_count"])
	}
	if signal.Context["window_type"] != "correlation" {
		t.Errorf("Context window_type = %v, want correlation", signal.Context["window_type"])
	}

	// Verify sample event is included
	if signal.Context["sample_event"] == nil {
		t.Error("Context sample_event is nil")
	}
}

func TestFromWindowMatchNoEvents(t *testing.T) {
	gen := NewGenerator("test-host", nil)

	wmatch := &correlation.WindowMatch{
		RuleID:   "SM-WIN-001",
		Severity: "low",
		Title:    "Empty Window",
		GroupKey: "empty",
		Count:    0,
		Events:   []map[string]any{},
	}

	signal := gen.FromWindowMatch(wmatch, "boot-789")

	if signal == nil {
		t.Fatal("FromWindowMatch returned nil")
	}

	// Should not have sample_event for empty window
	if signal.Context["sample_event"] != nil {
		t.Error("Context sample_event should be nil for empty window")
	}
}

func TestGenerateSignalIDDeterministic(t *testing.T) {
	gen := NewGenerator("test-host", nil)
	ts := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	// Generate ID twice with same inputs
	id1 := gen.generateSignalID("SM-001", ts, "test-host", "identifier")
	id2 := gen.generateSignalID("SM-001", ts, "test-host", "identifier")

	if id1 != id2 {
		t.Errorf("Signal IDs should be deterministic: %s != %s", id1, id2)
	}

	// Length should be 32 hex characters (16 bytes * 2)
	if len(id1) != 32 {
		t.Errorf("Signal ID length = %d, want 32", len(id1))
	}

	// Should be hex
	if !isHex(id1) {
		t.Errorf("Signal ID should be hex: %s", id1)
	}
}

func TestGenerateSignalIDUniqueness(t *testing.T) {
	gen := NewGenerator("test-host", nil)
	ts := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	// Different inputs should produce different IDs
	tests := []struct {
		name       string
		ruleID     string
		ts         time.Time
		host       string
		identifier string
	}{
		{"base", "SM-001", ts, "test-host", "id1"},
		{"different rule", "SM-002", ts, "test-host", "id1"},
		{"different timestamp", "SM-001", ts.Add(time.Hour), "test-host", "id1"},
		{"different host", "SM-001", ts, "other-host", "id1"},
		{"different identifier", "SM-001", ts, "test-host", "id2"},
	}

	ids := make(map[string]bool)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := gen.generateSignalID(tt.ruleID, tt.ts, tt.host, tt.identifier)
			if ids[id] {
				t.Errorf("Signal ID collision detected: %s", id)
			}
			ids[id] = true
		})
	}
}

func TestEnrichSignal(t *testing.T) {
	gen := NewGenerator("test-host", nil)

	sig := &state.Signal{
		ID:       "test-id",
		TS:       time.Now(),
		HostID:   "test-host",
		RuleID:   "SM-001",
		Severity: "high",
		Title:    "Test",
		Tags:     []string{"tag1"},
		Context: map[string]any{
			"existing_field": "value",
		},
	}

	enrichments := map[string]any{
		"first_seen": true,
		"reputation": "unknown",
		"threat_intel": map[string]any{
			"score": 75,
		},
	}

	gen.EnrichSignal(sig, enrichments)

	// Verify enrichments were added
	if sig.Context["first_seen"] != true {
		t.Errorf("Enrichment first_seen = %v, want true", sig.Context["first_seen"])
	}
	if sig.Context["reputation"] != "unknown" {
		t.Errorf("Enrichment reputation = %v, want unknown", sig.Context["reputation"])
	}
	if sig.Context["threat_intel"] == nil {
		t.Error("Enrichment threat_intel is nil")
	}

	// Verify existing field is preserved
	if sig.Context["existing_field"] != "value" {
		t.Error("Existing context field was lost")
	}
}

func TestEnrichSignalOverwrite(t *testing.T) {
	gen := NewGenerator("test-host", nil)

	sig := &state.Signal{
		ID: "test-id",
		Context: map[string]any{
			"field": "original",
		},
	}

	enrichments := map[string]any{
		"field": "overwritten",
	}

	gen.EnrichSignal(sig, enrichments)

	// Enrichment should overwrite existing value
	if sig.Context["field"] != "overwritten" {
		t.Errorf("Field = %v, want overwritten", sig.Context["field"])
	}
}

// Helper function to check if string is hex
func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func TestWindowMatchSingleEvent(t *testing.T) {
	gen := NewGenerator("test-host", nil)

	event := map[string]any{"test": "data"}
	wmatch := &correlation.WindowMatch{
		RuleID:   "SM-WIN-001",
		Severity: "low",
		Title:    "Single Event",
		GroupKey: "group1",
		Count:    1,
		Events:   []map[string]any{event},
	}

	signal := gen.FromWindowMatch(wmatch, "boot-123")

	// Should have sample_event for single event
	if signal.Context["sample_event"] == nil {
		t.Error("Should have sample_event for single event window")
	}
}

func TestFromWindowMatchWithDistinctValues(t *testing.T) {
	gen := NewGenerator("test-host", nil)

	// Simulate SM-COR-001: accessing multiple credential stores
	event1 := map[string]any{
		"file_access": map[string]any{
			"policy_name": "ChromeCookies",
			"instigator": map[string]any{
				"executable": map[string]any{
					"path": "/usr/bin/suspicious",
				},
			},
		},
	}
	event2 := map[string]any{
		"file_access": map[string]any{
			"policy_name": "SSHPrivateKeys",
			"instigator": map[string]any{
				"executable": map[string]any{
					"path": "/usr/bin/suspicious",
				},
			},
		},
	}
	event3 := map[string]any{
		"file_access": map[string]any{
			"policy_name": "KeychainDB",
			"instigator": map[string]any{
				"executable": map[string]any{
					"path": "/usr/bin/suspicious",
				},
			},
		},
	}

	rule := &rules.CorrelationRule{
		ID:            "SM-COR-001",
		CountDistinct: "event.file_access.policy_name",
		GroupBy:       []string{"event.file_access.instigator.executable.path"},
	}

	wmatch := &correlation.WindowMatch{
		RuleID:   "SM-COR-001",
		Severity: "critical",
		Title:    "Process touching multiple credential stores",
		GroupKey: "file_access.instigator.executable.path=/usr/bin/suspicious",
		Count:    3,
		Events:   []map[string]any{event1, event2, event3},
		Rule:     rule,
	}

	signal := gen.FromWindowMatch(wmatch, "boot-789")

	if signal == nil {
		t.Fatal("FromWindowMatch returned nil")
	}

	// Verify distinct_values are included
	distinctValues, ok := signal.Context["distinct_values"].([]string)
	if !ok {
		t.Fatalf("Context distinct_values should be []string, got %T", signal.Context["distinct_values"])
	}
	if len(distinctValues) != 3 {
		t.Errorf("Expected 3 distinct values, got %d: %v", len(distinctValues), distinctValues)
	}

	// Verify all expected policy names are present
	expectedPolicies := map[string]bool{
		"ChromeCookies":   false,
		"SSHPrivateKeys":  false,
		"KeychainDB":      false,
	}
	for _, val := range distinctValues {
		if _, exists := expectedPolicies[val]; exists {
			expectedPolicies[val] = true
		}
	}
	for policy, found := range expectedPolicies {
		if !found {
			t.Errorf("Expected policy %s not found in distinct_values: %v", policy, distinctValues)
		}
	}

	// Verify distinct_field is included
	if signal.Context["distinct_field"] != "event.file_access.policy_name" {
		t.Errorf("Context distinct_field = %v, want event.file_access.policy_name", signal.Context["distinct_field"])
	}

	// Verify grouped_by is included for easier reading
	groupedBy, ok := signal.Context["grouped_by"].(map[string]string)
	if !ok {
		t.Fatalf("Context grouped_by should be map[string]string, got %T", signal.Context["grouped_by"])
	}
	if len(groupedBy) != 1 {
		t.Errorf("Expected 1 grouped_by value, got %d: %v", len(groupedBy), groupedBy)
	}
	if groupedBy["file_access.instigator.executable.path"] != "/usr/bin/suspicious" {
		t.Errorf("grouped_by[file_access.instigator.executable.path] = %v, want /usr/bin/suspicious",
			groupedBy["file_access.instigator.executable.path"])
	}
}
