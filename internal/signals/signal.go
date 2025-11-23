package signals

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
	"github.com/0x4d31/santamon/internal/baseline"
	"github.com/0x4d31/santamon/internal/correlation"
	"github.com/0x4d31/santamon/internal/events"
	"github.com/0x4d31/santamon/internal/lineage"
	"github.com/0x4d31/santamon/internal/rules"
	"github.com/0x4d31/santamon/internal/state"
)

// Generator creates signals from rule matches
type Generator struct {
	hostID  string
	lineage *lineage.Store
}

// NewGenerator creates a new signal generator
func NewGenerator(hostID string, store *lineage.Store) *Generator {
	return &Generator{
		hostID:  hostID,
		lineage: store,
	}
}

// FromRuleMatch creates a signal from a rule match
func (g *Generator) FromRuleMatch(match *rules.Match) *state.Signal {
	ts := match.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	targetIdentifier := events.TargetSHA256(match.Message)
	if targetIdentifier == "" {
		targetIdentifier = events.TargetPath(match.Message)
	}

	signalID := g.generateSignalID(match.RuleID, ts, g.hostID, targetIdentifier)

	context := map[string]any{}
	appendMessageContext(context, match.Message)

	// Build event map if needed for extra context or full event inclusion
	var eventMap map[string]any
	if match.Rule != nil && (match.Rule.IncludeEvent || len(match.Rule.ExtraContext) > 0) {
		var err error
		eventMap, err = events.ToMap(match.Message)
		if err == nil {
			events.BuildActivation(match.Message, eventMap)
		}
	}

	// Include full event map when requested on the rule
	if match.Rule != nil && match.Rule.IncludeEvent && eventMap != nil {
		context["event"] = eventMap
	}

	// Include extra context fields when requested on the rule
	if match.Rule != nil && len(match.Rule.ExtraContext) > 0 && eventMap != nil {
		for _, field := range match.Rule.ExtraContext {
			if field == "" {
				continue
			}

			// Strip "event." prefix if present (config uses event.field.path, but map doesn't have that prefix)
			cleanField := strings.TrimPrefix(field, "event.")

			// Special-case execution.args to preserve the full list
			if cleanField == "execution.args" {
				if execRaw, ok := eventMap["execution"].(map[string]any); ok {
					if args, ok := execRaw["args"]; ok && args != nil {
						context["execution.args"] = args
						continue
					}
				}
			}

			if val := events.ExtractField(eventMap, cleanField); val != "" {
				context[cleanField] = val
			}
		}
	}

	// Include process tree / lineage when requested on the rule
	if g.lineage != nil && match.Rule != nil && match.Rule.IncludeProcessTree {
		if ev, ok := match.Message.GetEvent().(*santapb.SantaMessage_Execution); ok {
			if tgt := ev.Execution.GetTarget(); tgt != nil && tgt.GetId() != nil {
				key := lineage.FromProcessID(match.Message.GetBootSessionUuid(), tgt.GetId())
				chain := g.lineage.Lineage(key, 8)
				if len(chain) > 0 {
					context["process_tree"] = lineage.Serialize(chain)
				}
			}
		}
	}

	ruleDesc := ""
	if match.Rule != nil {
		ruleDesc = strings.TrimSpace(match.Rule.Description)
	}

	return &state.Signal{
		ID:              signalID,
		TS:              ts,
		HostID:          g.hostID,
		RuleID:          match.RuleID,
		RuleDescription: ruleDesc,
		Status:          "open",
		Severity:        match.Severity,
		Title:           match.Title,
		Tags:            match.Tags,
		Context:         context,
	}
}

// FromWindowMatch creates a signal from a correlation window match
func (g *Generator) FromWindowMatch(match *correlation.WindowMatch, bootUUID string) *state.Signal {
	now := time.Now()

	// Representative identifier for stable signal ID: use group key
	signalID := g.generateSignalID(match.RuleID, now, g.hostID, match.GroupKey)

	// Build context to mirror single-event signals, using a sample event
	ctx := map[string]any{
		"group_key":   match.GroupKey,
		"event_count": match.Count,
		"window_type": "correlation",
	}

	if len(match.Events) > 0 {
		sample := match.Events[len(match.Events)-1]
		ctx["sample_event"] = sample
		// Populate common fields using map extraction
		// actor_path
		ap := events.ExtractField(sample, "execution.instigator.executable.path")
		if ap == "" {
			ap = events.ExtractField(sample, "file_access.instigator.executable.path")
		}
		if ap != "" {
			ctx["actor_path"] = ap
		}
		// actor_team
		at := events.ExtractField(sample, "execution.instigator.code_signature.team_id")
		if at == "" {
			at = events.ExtractField(sample, "file_access.instigator.code_signature.team_id")
		}
		if at != "" {
			ctx["actor_team"] = at
		}
		// actor_signing_id
		asid := events.ExtractField(sample, "execution.instigator.code_signature.signing_id")
		if asid == "" {
			asid = events.ExtractField(sample, "file_access.instigator.code_signature.signing_id")
		}
		if asid != "" {
			ctx["actor_signing_id"] = asid
		}
		// target_path
		tp := events.ExtractField(sample, "execution.target.executable.path")
		if tp == "" {
			tp = events.ExtractField(sample, "file_access.target.path")
		}
		if tp != "" {
			ctx["target_path"] = tp
		}
		// target_sha256
		th := events.ExtractField(sample, "execution.target.executable.hash.hash")
		if th != "" {
			ctx["target_sha256"] = th
		}
		// decision
		dec := events.ExtractField(sample, "execution.decision")
		if dec == "" {
			dec = events.ExtractField(sample, "file_access.policy_decision")
		}
		if dec != "" {
			ctx["decision"] = dec
		}
		// kind
		ctx["kind"] = events.KindFromMap(sample)
	}

	// Use tags from the rule, and add "correlation" tag
	tags := make([]string, 0, len(match.Tags)+1)
	tags = append(tags, match.Tags...)
	tags = append(tags, "correlation")

	return &state.Signal{
		ID:              signalID,
		TS:              now,
		HostID:          g.hostID,
		RuleID:          match.RuleID,
		RuleDescription: strings.TrimSpace(match.Description),
		Status:          "open",
		Severity:        match.Severity,
		Title:           match.Title,
		Tags:            tags,
		Context:         ctx,
	}
}

// generateSignalID creates a deterministic signal ID
func (g *Generator) generateSignalID(ruleID string, ts time.Time, host, identifier string) string {
	// Create a deterministic ID based on rule, time, host, and identifier
	data := fmt.Sprintf("%s|%s|%s|%s",
		ruleID,
		ts.Format(time.RFC3339),
		host,
		identifier,
	)

	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:16]) // Use first 16 bytes for shorter ID
}

// FromBaselineMatch creates a signal from a baseline match
func (g *Generator) FromBaselineMatch(match *baseline.BaselineMatch) *state.Signal {
	ts := match.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	// Use pattern as identifier for stable signal ID
	signalID := g.generateSignalID(match.RuleID, ts, g.hostID, match.Pattern)

	// Build context similar to rule matches
	context := map[string]any{
		"pattern":     match.Pattern,
		"in_learning": match.InLearning,
	}

	appendMessageContext(context, match.Message)

	// Add "baseline" tag to differentiate from simple rules
	tags := make([]string, 0, len(match.Tags)+1)
	tags = append(tags, match.Tags...)
	tags = append(tags, "baseline")

	return &state.Signal{
		ID:              signalID,
		TS:              ts,
		HostID:          g.hostID,
		RuleID:          match.RuleID,
		RuleDescription: strings.TrimSpace(match.Description),
		Status:          "open",
		Severity:        match.Severity,
		Title:           match.Title,
		Tags:            tags,
		Context:         context,
	}
}

// EnrichSignal adds additional context to a signal
func (g *Generator) EnrichSignal(sig *state.Signal, enrichments map[string]any) {
	for k, v := range enrichments {
		sig.Context[k] = v
	}
}

func appendMessageContext(ctx map[string]any, msg *santapb.SantaMessage) {
	if ctx == nil || msg == nil {
		return
	}

	if v := events.ActorPath(msg); v != "" {
		ctx["actor_path"] = v
	}
	if v := events.ActorTeam(msg); v != "" {
		ctx["actor_team"] = v
	}
	if v := events.ActorSigningID(msg); v != "" {
		ctx["actor_signing_id"] = v
	}
	if v := events.TargetPath(msg); v != "" {
		ctx["target_path"] = v
	}
	if v := events.TargetTeam(msg); v != "" {
		ctx["target_team"] = v
	}
	if v := events.TargetSHA256(msg); v != "" {
		ctx["target_sha256"] = v
	}
	if v := events.Decision(msg); v != "" {
		ctx["decision"] = v
	}
	ctx["kind"] = events.Kind(msg)
}
