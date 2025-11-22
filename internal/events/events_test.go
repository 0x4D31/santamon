package events

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
)

func TestToMap(t *testing.T) {
	msg := &santapb.SantaMessage{
		MachineId:       proto.String("test-machine"),
		BootSessionUuid: proto.String("boot-123"),
		EventTime:       timestamppb.New(time.Now()),
		Event: &santapb.SantaMessage_Execution{
			Execution: &santapb.Execution{
				Decision: santapb.Execution_DECISION_ALLOW.Enum(),
				Args: [][]byte{
					[]byte("/usr/bin/curl"),
					[]byte("-fsSL"),
				},
				Envs: [][]byte{
					[]byte("PATH=/usr/bin"),
					[]byte("USER=test"),
				},
				Target: &santapb.ProcessInfo{
					Executable: &santapb.FileInfo{
						Path: proto.String("/bin/sh"),
					},
				},
			},
		},
	}

	eventMap, err := ToMap(msg)
	if err != nil {
		t.Fatalf("ToMap() failed: %v", err)
	}

	if eventMap == nil {
		t.Fatal("ToMap() returned nil map")
	}

	// Check that execution event is present
	if _, ok := eventMap["execution"]; !ok {
		t.Error("expected 'execution' key in eventMap")
	}

	exec, _ := eventMap["execution"].(map[string]any)
	if exec == nil {
		t.Fatal("execution map missing")
	}

	args, ok := exec["args"].([]string)
	if !ok {
		t.Fatalf("execution.args type = %T, want []string", exec["args"])
	}
	wantArgs := []string{"/usr/bin/curl", "-fsSL"}
	if len(args) != len(wantArgs) {
		t.Fatalf("execution.args length = %d, want %d", len(args), len(wantArgs))
	}
	for i, v := range wantArgs {
		if args[i] != v {
			t.Fatalf("execution.args[%d] = %q, want %q", i, args[i], v)
		}
	}

	envs, ok := exec["envs"].([]string)
	if !ok {
		t.Fatalf("execution.envs type = %T, want []string", exec["envs"])
	}
	wantEnvs := []string{"PATH=/usr/bin", "USER=test"}
	if len(envs) != len(wantEnvs) {
		t.Fatalf("execution.envs length = %d, want %d", len(envs), len(wantEnvs))
	}
	for i, v := range wantEnvs {
		if envs[i] != v {
			t.Fatalf("execution.envs[%d] = %q, want %q", i, envs[i], v)
		}
	}
}

func TestBuildActivation(t *testing.T) {
	ts := time.Now()
	msg := &santapb.SantaMessage{
		MachineId:       proto.String("test-machine"),
		BootSessionUuid: proto.String("boot-uuid"),
		EventTime:       timestamppb.New(ts),
		Event: &santapb.SantaMessage_Execution{
			Execution: &santapb.Execution{
				Decision: santapb.Execution_DECISION_ALLOW.Enum(),
				Mode:     santapb.Execution_MODE_MONITOR.Enum(),
				Reason:   santapb.Execution_REASON_BINARY.Enum(),
				Target: &santapb.ProcessInfo{
					Executable: &santapb.FileInfo{
						Path: proto.String("/bin/sh"),
					},
				},
			},
		},
	}

	eventMap, err := ToMap(msg)
	if err != nil {
		t.Fatalf("ToMap() failed: %v", err)
	}

	// Build activation
	BuildActivation(msg, eventMap)

	// Verify metadata fields were added
	tests := []struct {
		key   string
		check func(v any) bool
	}{
		{"machine_id", func(v any) bool { return v == "test-machine" }},
		{"boot_session_uuid", func(v any) bool { return v == "boot-uuid" }},
		{"kind", func(v any) bool { return v == "execution" }},
		{"event_time", func(v any) bool { _, ok := v.(time.Time); return ok }},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			v, ok := eventMap[tt.key]
			if !ok {
				t.Errorf("key %q not found in activation", tt.key)
				return
			}
			if !tt.check(v) {
				t.Errorf("key %q has unexpected value: %v", tt.key, v)
			}
		})
	}

	// Ensure convenience aliases are not injected
	for _, alias := range []string{"decision", "mode", "reason", "actor_team_id", "actor_signing_id", "actor_is_platform_binary", "target_team_id", "target_signing_id"} {
		if _, ok := eventMap[alias]; ok {
			t.Errorf("unexpected alias field %q present", alias)
		}
	}
}

func TestBuildActivationFileAccess(t *testing.T) {
	msg := &santapb.SantaMessage{
		MachineId:       proto.String("test-machine"),
		BootSessionUuid: proto.String("boot-uuid"),
		EventTime:       timestamppb.New(time.Now()),
		Event: &santapb.SantaMessage_FileAccess{
			FileAccess: &santapb.FileAccess{
				PolicyName:     proto.String("TestPolicy"),
				PolicyDecision: santapb.FileAccess_POLICY_DECISION_DENIED.Enum(),
				Instigator: &santapb.ProcessInfo{
					CodeSignature: &santapb.CodeSignature{
						TeamId:    proto.String("TEAMID123"),
						SigningId: proto.String("com.example.app"),
					},
					IsPlatformBinary: proto.Bool(false),
				},
				Target: &santapb.FileInfoLight{
					Path: proto.String("/sensitive/file"),
				},
			},
		},
	}

	eventMap, err := ToMap(msg)
	if err != nil {
		t.Fatalf("ToMap() failed: %v", err)
	}

	BuildActivation(msg, eventMap)

	// Verify file_access specific fields
	if kind, ok := eventMap["kind"].(string); !ok || kind != "file_access" {
		t.Errorf("kind = %v, want file_access", eventMap["kind"])
	}

	if _, ok := eventMap["actor_team_id"]; ok {
		t.Errorf("actor_team_id alias should not be present")
	}
	if _, ok := eventMap["actor_signing_id"]; ok {
		t.Errorf("actor_signing_id alias should not be present")
	}
	if _, ok := eventMap["actor_is_platform_binary"]; ok {
		t.Errorf("actor_is_platform_binary alias should not be present")
	}
}

func TestKind(t *testing.T) {
	tests := []struct {
		name string
		msg  *santapb.SantaMessage
		want string
	}{
		{
			name: "execution",
			msg: &santapb.SantaMessage{
				Event: &santapb.SantaMessage_Execution{
					Execution: &santapb.Execution{},
				},
			},
			want: "execution",
		},
		{
			name: "file_access",
			msg: &santapb.SantaMessage{
				Event: &santapb.SantaMessage_FileAccess{
					FileAccess: &santapb.FileAccess{},
				},
			},
			want: "file_access",
		},
		{
			name: "xprotect",
			msg: &santapb.SantaMessage{
				Event: &santapb.SantaMessage_Xprotect{
					Xprotect: &santapb.XProtect{},
				},
			},
			want: "xprotect",
		},
		{
			name: "tcc_modification",
			msg: &santapb.SantaMessage{
				Event: &santapb.SantaMessage_TccModification{
					TccModification: &santapb.TCCModification{},
				},
			},
			want: "tcc_modification",
		},
		{
			name: "launch_item",
			msg: &santapb.SantaMessage{
				Event: &santapb.SantaMessage_LaunchItem{
					LaunchItem: &santapb.LaunchItem{},
				},
			},
			want: "launch_item",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Kind(tt.msg)
			if got != tt.want {
				t.Errorf("Kind() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecision(t *testing.T) {
	tests := []struct {
		name string
		msg  *santapb.SantaMessage
		want string
	}{
		{
			name: "execution allow",
			msg: &santapb.SantaMessage{
				Event: &santapb.SantaMessage_Execution{
					Execution: &santapb.Execution{
						Decision: santapb.Execution_DECISION_ALLOW.Enum(),
					},
				},
			},
			want: "DECISION_ALLOW",
		},
		{
			name: "execution deny",
			msg: &santapb.SantaMessage{
				Event: &santapb.SantaMessage_Execution{
					Execution: &santapb.Execution{
						Decision: santapb.Execution_DECISION_DENY.Enum(),
					},
				},
			},
			want: "DECISION_DENY",
		},
		{
			name: "file_access denied",
			msg: &santapb.SantaMessage{
				Event: &santapb.SantaMessage_FileAccess{
					FileAccess: &santapb.FileAccess{
						PolicyDecision: santapb.FileAccess_POLICY_DECISION_DENIED.Enum(),
					},
				},
			},
			want: "POLICY_DECISION_DENIED",
		},
		{
			name: "no decision",
			msg: &santapb.SantaMessage{
				Event: &santapb.SantaMessage_Xprotect{
					Xprotect: &santapb.XProtect{},
				},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decision(tt.msg)
			if got != tt.want {
				t.Errorf("Decision() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractField(t *testing.T) {
	event := map[string]any{
		"execution": map[string]any{
			"target": map[string]any{
				"executable": map[string]any{
					"path": "/bin/sh",
					"hash": map[string]any{
						"hash": "abc123",
					},
				},
			},
		},
		"simple": "value",
		"number": float64(42),
	}

	tests := []struct {
		name  string
		field string
		want  string
	}{
		{
			name:  "simple field",
			field: "simple",
			want:  "value",
		},
		{
			name:  "nested path",
			field: "execution.target.executable.path",
			want:  "/bin/sh",
		},
		{
			name:  "deeply nested",
			field: "execution.target.executable.hash.hash",
			want:  "abc123",
		},
		{
			name:  "number converted to string",
			field: "number",
			want:  "42",
		},
		{
			name:  "missing field",
			field: "nonexistent",
			want:  "",
		},
		{
			name:  "partial path",
			field: "execution.missing.field",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractField(event, tt.field)
			if got != tt.want {
				t.Errorf("ExtractField(%q) = %q, want %q", tt.field, got, tt.want)
			}
		})
	}
}

func BenchmarkToMap(b *testing.B) {
	msg := &santapb.SantaMessage{
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
					CodeSignature: &santapb.CodeSignature{
						TeamId: proto.String("APPLE"),
					},
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ToMap(msg)
		if err != nil {
			b.Fatalf("ToMap() failed: %v", err)
		}
	}
}

func BenchmarkBuildActivation(b *testing.B) {
	msg := &santapb.SantaMessage{
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
	}

	eventMap, err := ToMap(msg)
	if err != nil {
		b.Fatalf("ToMap() failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildActivation(msg, eventMap)
	}
}
