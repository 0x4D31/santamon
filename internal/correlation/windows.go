package correlation

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
	"github.com/0x4d31/santamon/internal/events"
	"github.com/0x4d31/santamon/internal/rules"
	"github.com/0x4d31/santamon/internal/state"
)

// WindowManager manages correlation windows
type WindowManager struct {
	db         *state.DB
	maxEvents  int
	gcInterval time.Duration
	lastGC     time.Time
}

// WindowMatch represents a correlation window that exceeded threshold
type WindowMatch struct {
	RuleID      string
	Title       string
	Severity    string
	Tags        []string
	Description string
	Count       int
	Events      []map[string]any
	GroupKey    string
	Rule        *rules.CorrelationRule // Keep reference to rule for signal generation
}

// NewWindowManager creates a new correlation window manager
func NewWindowManager(db *state.DB, maxEvents int, gcInterval time.Duration) *WindowManager {
	return &WindowManager{
		db:         db,
		maxEvents:  maxEvents,
		gcInterval: gcInterval,
		lastGC:     time.Now(),
	}
}

// Process evaluates an event against correlation rules.
func (wm *WindowManager) Process(msg *santapb.SantaMessage, correlationRules []*rules.CompiledCorrelation) ([]*WindowMatch, error) {
	if len(correlationRules) == 0 {
		return nil, nil
	}

	// Build typed activation with enum constants for CEL evaluation
	activation := rules.BuildActivation(msg)

	// Build event map for storage and grouping (correlation windows still use maps)
	eventMap, err := events.ToMap(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert message to map: %w", err)
	}
	events.BuildActivation(msg, eventMap)

	matches := make([]*WindowMatch, 0, 1) // Most events won't trigger correlations

	for _, rule := range correlationRules {
		result, _, err := rule.Program.Eval(activation)
		if err != nil {
			slog.Warn("correlation filter evaluation error", "rule_id", rule.Rule.ID, "error", err)
			continue
		}
		matched, ok := result.Value().(bool)
		if !ok {
			slog.Warn("correlation filter returned non-boolean", "rule_id", rule.Rule.ID)
			continue
		}
		if !matched {
			continue
		}

		groupKey := wm.extractGroupKey(eventMap, rule.Rule.GroupBy)

		if err := wm.db.StoreWindowEvent(rule.Rule.ID, groupKey, eventMap); err != nil {
			return nil, fmt.Errorf("failed to store window event: %w", err)
		}

		windowEvents, err := wm.db.GetWindowEvents(rule.Rule.ID, groupKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get window events: %w", err)
		}

		now := time.Now()
		recentEvents := make([]map[string]any, 0)
		for _, evt := range windowEvents {
			if withinWindow(evt, now, rule.Rule.Window) {
				recentEvents = append(recentEvents, evt)
			}
		}

		if wm.maxEvents > 0 && len(recentEvents) > wm.maxEvents {
			recentEvents = recentEvents[len(recentEvents)-wm.maxEvents:]
		}

		count := wm.countEvents(recentEvents, rule.Rule)

		if count >= rule.Rule.Threshold {
			matches = append(matches, &WindowMatch{
				RuleID:      rule.Rule.ID,
				Title:       rule.Rule.Title,
				Severity:    rule.Rule.Severity,
				Tags:        rule.Rule.Tags,
				Description: rule.Rule.Description,
				Count:       count,
				Events:      recentEvents,
				GroupKey:    groupKey,
				Rule:        rule.Rule, // Store rule for signal generation
			})

			if err := wm.db.ReplaceWindowEvents(rule.Rule.ID, groupKey, nil); err != nil {
				return nil, fmt.Errorf("failed to clear window: %w", err)
			}
		} else {
			if err := wm.db.ReplaceWindowEvents(rule.Rule.ID, groupKey, recentEvents); err != nil {
				return nil, fmt.Errorf("failed to persist window: %w", err)
			}
		}
	}

	// Periodic garbage collection
	if time.Since(wm.lastGC) >= wm.gcInterval {
		wm.lastGC = time.Now()
		// GC would clean old windows here
	}

	return matches, nil
}

// extractGroupKey builds a group key from event fields.
// If no groupBy fields are specified, returns "_global" to group all events together.
func (wm *WindowManager) extractGroupKey(event map[string]any, groupBy []string) string {
	if len(groupBy) == 0 {
		return "_global"
	}

	parts := make([]string, 0, len(groupBy))
	for _, field := range groupBy {
		// Strip "event." prefix if present (config uses event.field.path, but map doesn't have that prefix)
		cleanField := strings.TrimPrefix(field, "event.")
		value := events.ExtractField(event, cleanField)
		parts = append(parts, fmt.Sprintf("%s=%s", cleanField, value))
	}

	return strings.Join(parts, "|")
}

// countEvents counts events based on correlation rule configuration
func (wm *WindowManager) countEvents(windowEvents []map[string]any, rule *rules.CorrelationRule) int {
	if rule.CountDistinct != "" {
		// Count distinct values of a field
		seen := make(map[string]struct{})
		for _, evt := range windowEvents {
			// Strip "event." prefix if present (config uses event.field.path, but map doesn't have that prefix)
			cleanField := strings.TrimPrefix(rule.CountDistinct, "event.")
			value := events.ExtractField(evt, cleanField)
			if value != "" {
				seen[value] = struct{}{}
			}
		}
		return len(seen)
	}

	// Just count total events
	return len(windowEvents)
}

func withinWindow(event map[string]any, now time.Time, window time.Duration) bool {
	if window == 0 {
		return true
	}
	v, ok := event["event_time"]
	if !ok || v == nil {
		return false
	}
	var ts time.Time
	switch t := v.(type) {
	case time.Time:
		ts = t
	case string:
		// Try RFC3339Nano then RFC3339
		if parsed, err := time.Parse(time.RFC3339Nano, t); err == nil {
			ts = parsed
		} else if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			ts = parsed
		} else {
			return false
		}
	default:
		return false
	}
	return now.Sub(ts) <= window
}
