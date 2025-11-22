package events

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
)

var (
	jsonMarshal = protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}
)

// EventTypes lists all Santa event types
// NOTE: This must be kept in sync with the protobuf message types
var EventTypes = []string{
	"execution",
	"fork",
	"exit",
	"close",
	"rename",
	"unlink",
	"link",
	"exchangedata",
	"disk",
	"bundle",
	"allowlist",
	"file_access",
	"codesigning_invalidated",
	"login_window_session",
	"login_logout",
	"screen_sharing",
	"open_ssh",
	"authentication",
	"clone",
	"copyfile",
	"gatekeeper_override",
	"launch_item",
	"tcc_modification",
	"xprotect",
}

// ToMap converts a SantaMessage to a map suitable for CEL evaluation.
func ToMap(msg *santapb.SantaMessage) (map[string]any, error) {
	data, err := jsonMarshal.Marshal(msg)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	decodeExecutionStringLists(result)
	return result, nil
}

// BuildActivation enriches the eventMap in-place with metadata fields needed for CEL evaluation.
// This modifies the input map to avoid unnecessary allocations.
// The eventMap must already contain the protobuf data from ToMap().
func BuildActivation(msg *santapb.SantaMessage, eventMap map[string]any) {
	// Add core metadata
	eventMap["machine_id"] = msg.GetMachineId()
	eventMap["boot_session_uuid"] = msg.GetBootSessionUuid()
	eventMap["kind"] = Kind(msg)

	// Add timestamps
	if ts := msg.GetEventTime(); ts != nil {
		eventMap["event_time"] = ts.AsTime()
	}
	if pt := msg.GetProcessedTime(); pt != nil {
		eventMap["processed_time"] = pt.AsTime()
	}

}

// Kind returns the lower-case event type name for a Santa message.
func Kind(msg *santapb.SantaMessage) string {
	switch msg.GetEvent().(type) {
	case *santapb.SantaMessage_Execution:
		return "execution"
	case *santapb.SantaMessage_Fork:
		return "fork"
	case *santapb.SantaMessage_Exit:
		return "exit"
	case *santapb.SantaMessage_Close:
		return "close"
	case *santapb.SantaMessage_Rename:
		return "rename"
	case *santapb.SantaMessage_Unlink:
		return "unlink"
	case *santapb.SantaMessage_Link:
		return "link"
	case *santapb.SantaMessage_Exchangedata:
		return "exchangedata"
	case *santapb.SantaMessage_Disk:
		return "disk"
	case *santapb.SantaMessage_Bundle:
		return "bundle"
	case *santapb.SantaMessage_Allowlist:
		return "allowlist"
	case *santapb.SantaMessage_FileAccess:
		return "file_access"
	case *santapb.SantaMessage_CodesigningInvalidated:
		return "codesigning_invalidated"
	case *santapb.SantaMessage_LoginWindowSession:
		return "login_window_session"
	case *santapb.SantaMessage_LoginLogout:
		return "login_logout"
	case *santapb.SantaMessage_ScreenSharing:
		return "screen_sharing"
	case *santapb.SantaMessage_OpenSsh:
		return "open_ssh"
	case *santapb.SantaMessage_Authentication:
		return "authentication"
	case *santapb.SantaMessage_Clone:
		return "clone"
	case *santapb.SantaMessage_Copyfile:
		return "copyfile"
	case *santapb.SantaMessage_GatekeeperOverride:
		return "gatekeeper_override"
	case *santapb.SantaMessage_LaunchItem:
		return "launch_item"
	case *santapb.SantaMessage_TccModification:
		return "tcc_modification"
	case *santapb.SantaMessage_Xprotect:
		return "xprotect"
	default:
		return "unknown"
	}
}

// Decision returns a string representation of the allow/deny outcome for the event.
func Decision(msg *santapb.SantaMessage) string {
	switch ev := msg.GetEvent().(type) {
	case *santapb.SantaMessage_Execution:
		return ev.Execution.GetDecision().String()
	case *santapb.SantaMessage_FileAccess:
		return ev.FileAccess.GetPolicyDecision().String()
	default:
		return ""
	}
}

// Mode returns the Santa mode (monitor/lockdown) when available.
func Mode(msg *santapb.SantaMessage) string {
	if ev, ok := msg.GetEvent().(*santapb.SantaMessage_Execution); ok {
		return ev.Execution.GetMode().String()
	}
	return ""
}

// Reason returns the Santa reason for execution events.
func Reason(msg *santapb.SantaMessage) string {
	if ev, ok := msg.GetEvent().(*santapb.SantaMessage_Execution); ok {
		return ev.Execution.GetReason().String()
	}
	return ""
}

// TargetSHA256 returns the hash identifier for the event target when available.
func TargetSHA256(msg *santapb.SantaMessage) string {
	switch ev := msg.GetEvent().(type) {
	case *santapb.SantaMessage_Execution:
		if target := ev.Execution.GetTarget(); target != nil {
			if exe := target.GetExecutable(); exe != nil {
				if hash := exe.GetHash(); hash != nil {
					return hash.GetHash()
				}
			}
		}
	case *santapb.SantaMessage_FileAccess:
		// FileAccess target doesn't include hash information.
		return ""
	}
	return ""
}

// TargetPath extracts a human-readable target path.
func TargetPath(msg *santapb.SantaMessage) string {
	switch ev := msg.GetEvent().(type) {
	case *santapb.SantaMessage_Execution:
		if target := ev.Execution.GetTarget(); target != nil {
			if exe := target.GetExecutable(); exe != nil {
				return exe.GetPath()
			}
		}
	case *santapb.SantaMessage_FileAccess:
		if tgt := ev.FileAccess.GetTarget(); tgt != nil {
			return tgt.GetPath()
		}
	case *santapb.SantaMessage_Xprotect:
		if det := ev.Xprotect.GetDetected(); det != nil {
			return det.GetDetectedPath()
		}
	}
	return ""
}

// ActorPath extracts the instigator path.
func ActorPath(msg *santapb.SantaMessage) string {
	switch ev := msg.GetEvent().(type) {
	case *santapb.SantaMessage_Execution:
		if inst := ev.Execution.GetInstigator(); inst != nil {
			if exe := inst.GetExecutable(); exe != nil {
				return exe.GetPath()
			}
		}
	case *santapb.SantaMessage_FileAccess:
		if inst := ev.FileAccess.GetInstigator(); inst != nil {
			if exe := inst.GetExecutable(); exe != nil {
				return exe.GetPath()
			}
		}
	}
	return ""
}

// ActorTeam extracts the instigator team identifier when available.
// NOTE: Only works for FileAccess events - Execution instigators use ProcessInfoLight which lacks code signature.
func ActorTeam(msg *santapb.SantaMessage) string {
	switch ev := msg.GetEvent().(type) {
	case *santapb.SantaMessage_FileAccess:
		if inst := ev.FileAccess.GetInstigator(); inst != nil {
			if cs := inst.GetCodeSignature(); cs != nil {
				return cs.GetTeamId()
			}
		}
	}
	return ""
}

// ActorSigningID extracts the instigator signing identifier.
// NOTE: Only works for FileAccess events - Execution instigators use ProcessInfoLight which lacks code signature.
func ActorSigningID(msg *santapb.SantaMessage) string {
	switch ev := msg.GetEvent().(type) {
	case *santapb.SantaMessage_FileAccess:
		if inst := ev.FileAccess.GetInstigator(); inst != nil {
			if cs := inst.GetCodeSignature(); cs != nil {
				return cs.GetSigningId()
			}
		}
	}
	return ""
}

// ActorIsPlatformBinary indicates whether the instigator is a platform binary.
func ActorIsPlatformBinary(msg *santapb.SantaMessage) bool {
	switch ev := msg.GetEvent().(type) {
	case *santapb.SantaMessage_FileAccess:
		if inst := ev.FileAccess.GetInstigator(); inst != nil {
			return inst.GetIsPlatformBinary()
		}
	case *santapb.SantaMessage_Execution:
		if inst := ev.Execution.GetInstigator(); inst != nil {
			// ProcessInfoLight for instigator in execution events doesn't have is_platform_binary
			// Could potentially check the target instead, but staying conservative
			return false
		}
	}
	return false
}

// TargetTeam extracts the target team identifier.
func TargetTeam(msg *santapb.SantaMessage) string {
	switch ev := msg.GetEvent().(type) {
	case *santapb.SantaMessage_Execution:
		if target := ev.Execution.GetTarget(); target != nil {
			if cs := target.GetCodeSignature(); cs != nil {
				return cs.GetTeamId()
			}
		}
	}
	return ""
}

// TargetSigningID extracts the target signing identifier.
func TargetSigningID(msg *santapb.SantaMessage) string {
	switch ev := msg.GetEvent().(type) {
	case *santapb.SantaMessage_Execution:
		if target := ev.Execution.GetTarget(); target != nil {
			if cs := target.GetCodeSignature(); cs != nil {
				return cs.GetSigningId()
			}
		}
	}
	return ""
}

// EventTime returns the event timestamp, or zero if missing.
func EventTime(msg *santapb.SantaMessage) time.Time {
	if ts := msg.GetEventTime(); ts != nil {
		return ts.AsTime()
	}
	return time.Time{}
}

// DecodedArgs returns decoded args for execution events, empty list otherwise.
// Args from Santa are already decoded as [][]byte, so we just convert to []string.
func DecodedArgs(msg *santapb.SantaMessage) []string {
	ev, ok := msg.GetEvent().(*santapb.SantaMessage_Execution)
	if !ok {
		return []string{}
	}

	args := ev.Execution.GetArgs()
	if len(args) == 0 {
		return []string{}
	}

	decoded := make([]string, len(args))
	for i, arg := range args {
		decoded[i] = string(arg)
	}
	return decoded
}

func decodeExecutionStringLists(m map[string]any) {
	execRaw, ok := m["execution"].(map[string]any)
	if !ok {
		return
	}

	if decoded, ok := decodeBase64List(execRaw["args"]); ok {
		execRaw["args"] = decoded
	}
	if decoded, ok := decodeBase64List(execRaw["envs"]); ok {
		execRaw["envs"] = decoded
	}
}

func decodeBase64List(raw any) ([]string, bool) {
	values, ok := raw.([]any)
	if !ok {
		return nil, false
	}

	if len(values) == 0 {
		return []string{}, true
	}

	decoded := make([]string, len(values))
	for i, v := range values {
		s, ok := v.(string)
		if !ok {
			decoded[i] = fmt.Sprint(v)
			continue
		}
		data, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			decoded[i] = s
			continue
		}
		decoded[i] = string(data)
	}
	return decoded, true
}

// ExtractField walks a dotted path within the event map and returns the value as string.
func ExtractField(event map[string]any, field string) string {
	parts := strings.Split(field, ".")
	var current any = event

	for _, part := range parts {
		if current == nil {
			return ""
		}

		obj, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = obj[part]
	}

	if current == nil {
		return ""
	}
	return toString(current)
}

func toString(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case fmt.Stringer:
		return val.String()
	case float64:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", val), "0"), ".")
	default:
		return fmt.Sprintf("%v", val)
	}
}

// KindFromMap returns the lower-case event type name for an event map
// produced by ToMap. It checks for known top-level keys.
func KindFromMap(evt map[string]any) string {
	if evt == nil {
		return "unknown"
	}
	// Check most common kinds first
	if _, ok := evt["execution"]; ok {
		return "execution"
	}
	if _, ok := evt["file_access"]; ok {
		return "file_access"
	}
	if _, ok := evt["xprotect"]; ok {
		return "xprotect"
	}
	if _, ok := evt["tcc_modification"]; ok {
		return "tcc_modification"
	}
	if _, ok := evt["launch_item"]; ok {
		return "launch_item"
	}
	if _, ok := evt["open_ssh"]; ok {
		return "open_ssh"
	}
	if _, ok := evt["authentication"]; ok {
		return "authentication"
	}
	if _, ok := evt["gatekeeper_override"]; ok {
		return "gatekeeper_override"
	}
	return "unknown"
}
