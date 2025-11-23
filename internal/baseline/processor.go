package baseline

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

// Processor evaluates baseline rules and tracks first-seen patterns
type Processor struct {
	db *state.DB
}

// BaselineMatch represents a baseline rule match (first occurrence)
type BaselineMatch struct {
	RuleID      string
	Title       string
	Severity    string
	Tags        []string
	Description string
	Pattern     string // The unique pattern that was seen
	Message     *santapb.SantaMessage
	Timestamp   time.Time
	InLearning  bool // Whether this occurred during learning period
}

// NewProcessor creates a new baseline processor
func NewProcessor(db *state.DB) *Processor {
	return &Processor{
		db: db,
	}
}

// Process evaluates an event against baseline rules.
func (p *Processor) Process(
	msg *santapb.SantaMessage,
	baselines []*rules.CompiledBaseline,
	engine *rules.Engine,
) ([]*BaselineMatch, error) {
	if len(baselines) == 0 {
		return nil, nil
	}

	// Build typed activation with enum constants for CEL evaluation.
	// Note: We use typed protobuf for CEL (fast, type-safe), but convert to map
	// for pattern extraction (flexible field access). ToMap is called lazily
	// only after filter matches (~1% of events) to minimize overhead.
	activation := rules.BuildActivation(msg)

	matches := make([]*BaselineMatch, 0, 1) // Most events won't match

	for _, baseline := range baselines {
		// Evaluate filter expression against typed protobuf
		result, _, err := baseline.Program.Eval(activation)
		if err != nil {
			slog.Warn("baseline filter evaluation error", "rule_id", baseline.Rule.ID, "error", err)
			continue
		}

		matched, ok := result.Value().(bool)
		if !ok {
			slog.Warn("baseline filter returned non-boolean", "rule_id", baseline.Rule.ID)
			continue
		}

		if !matched {
			continue
		}

		// Only convert to map after filter matches (lazy evaluation for performance).
		// Pattern extraction needs flattened map structure for flexible field access.
		eventMap, err := events.ToMap(msg)
		if err != nil {
			return nil, fmt.Errorf("failed to convert message to map: %w", err)
		}
		events.BuildActivation(msg, eventMap)

		// Extract pattern to track (use event map for field extraction)
		pattern := p.extractPattern(eventMap, baseline.Rule.Track)

		// Check if we've seen this pattern before
		isFirst, err := p.db.IsFirstSeen(baseline.Rule.ID, pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to check first seen for %s: %w", baseline.Rule.ID, err)
		}

		if isFirst {
			inLearning := engine.IsInLearningPeriod(baseline.Rule)

			if inLearning {
				slog.Debug("baseline match during learning period",
					"rule_id", baseline.Rule.ID,
					"pattern", pattern)
			}

			matches = append(matches, &BaselineMatch{
				RuleID:      baseline.Rule.ID,
				Title:       baseline.Rule.Title,
				Severity:    baseline.Rule.Severity,
				Tags:        baseline.Rule.Tags,
				Description: baseline.Rule.Description,
				Pattern:     pattern,
				Message:     msg,
				Timestamp:   events.EventTime(msg),
				InLearning:  inLearning,
			})
		}
	}

	return matches, nil
}

// extractPattern builds a unique pattern from tracked fields.
// The pattern is used to deduplicate baseline matches - only the first occurrence
// of each unique pattern triggers an alert.
func (p *Processor) extractPattern(event map[string]any, trackFields []string) string {
	parts := make([]string, 0, len(trackFields))

	for _, field := range trackFields {
		// Strip "event." prefix if present. Config uses event.field.path (consistent with CEL),
		// but the eventMap doesn't have that prefix (top-level keys are execution, file_access, etc.)
		cleanField := strings.TrimPrefix(field, "event.")
		value := events.ExtractField(event, cleanField)
		// Include field name in pattern for clarity
		parts = append(parts, fmt.Sprintf("%s=%s", cleanField, value))
	}

	return strings.Join(parts, "|")
}
