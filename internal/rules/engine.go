package rules

import (
	"fmt"
	"time"

	"github.com/google/cel-go/cel"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
	"github.com/0x4d31/santamon/internal/events"
	"github.com/0x4d31/santamon/internal/logutil"
)

// santaEnums maps Santa protobuf enum names to their integer values
// These are registered as CEL constants for use in rules
var santaEnums = map[string]int64{
	// Execution.Decision
	"DECISION_UNKNOWN":        0,
	"DECISION_ALLOW":          1,
	"DECISION_DENY":           2,
	"DECISION_ALLOW_COMPILER": 3,

	// FileAccess.PolicyDecision
	"POLICY_DECISION_UNKNOWN":                  0,
	"POLICY_DECISION_DENIED":                   1,
	"POLICY_DECISION_DENIED_INVALID_SIGNATURE": 2,
	"POLICY_DECISION_ALLOWED_AUDIT_ONLY":       3,

	// LaunchItem.Action
	"ACTION_UNKNOWN": 0,
	"ACTION_ADD":     1,
	"ACTION_REMOVE":  2,

	// LaunchItem.ItemType
	"ITEM_TYPE_UNKNOWN":    0,
	"ITEM_TYPE_USER_ITEM":  1,
	"ITEM_TYPE_APP":        2,
	"ITEM_TYPE_LOGIN_ITEM": 3,
	"ITEM_TYPE_AGENT":      4,
	"ITEM_TYPE_DAEMON":     5,

	// TCCModification.AuthorizationRight
	"AUTHORIZATION_RIGHT_UNKNOWN":          0,
	"AUTHORIZATION_RIGHT_DENIED":           1,
	"AUTHORIZATION_RIGHT_ALLOWED":          2,
	"AUTHORIZATION_RIGHT_LIMITED":          3,
	"AUTHORIZATION_RIGHT_ADD_MODIFY_ADDED": 4,
	"AUTHORIZATION_RIGHT_SESSION_PID":      5,
	"AUTHORIZATION_RIGHT_LEARN_MORE":       6,

	// TCCModification.AuthorizationReason
	"AUTHORIZATION_REASON_UNKNOWN":                 0,
	"AUTHORIZATION_REASON_NONE":                    1,
	"AUTHORIZATION_REASON_ERROR":                   2,
	"AUTHORIZATION_REASON_USER_CONSENT":            3,
	"AUTHORIZATION_REASON_USER_SET":                4,
	"AUTHORIZATION_REASON_SYSTEM_SET":              5,
	"AUTHORIZATION_REASON_SERVICE_POLICY":          6,
	"AUTHORIZATION_REASON_MDM_POLICY":              7,
	"AUTHORIZATION_REASON_SERVICE_OVERRIDE_POLICY": 8,
	"AUTHORIZATION_REASON_MISSING_USAGE_STRING":    9,
	"AUTHORIZATION_REASON_PROMPT_TIMEOUT":          10,
	"AUTHORIZATION_REASON_PREFLIGHT_UNKNOWN":       11,
	"AUTHORIZATION_REASON_ENTITLED":                12,
	"AUTHORIZATION_REASON_APP_TYPE_POLICY":         13,
	"AUTHORIZATION_REASON_PROMPT_CANCEL":           14,
}

// Engine evaluates detection rules against events
type Engine struct {
	rules        []*CompiledRule
	correlations []*CompiledCorrelation
	baselines    []*CompiledBaseline
	env          *cel.Env
	startTime    time.Time // For learning period calculation
}

// CompiledRule is a rule ready for evaluation
type CompiledRule struct {
	Rule    *Rule
	Program cel.Program
}

// CompiledCorrelation holds a correlation rule plus its compiled CEL program.
type CompiledCorrelation struct {
    Rule    *CorrelationRule
    Program cel.Program
}

// Match represents a rule match
type Match struct {
	RuleID    string
	Title     string
	Severity  string
	Tags      []string
	Message   *santapb.SantaMessage
	Timestamp time.Time
	Rule      *Rule
}

// NewEngine creates a new rules engine
func NewEngine() (*Engine, error) {
	// Get the file descriptor for Santa messages
	msgDesc := (&santapb.SantaMessage{}).ProtoReflect().Descriptor()
	fileDesc := msgDesc.ParentFile()

	// Build CEL environment options
	envOpts := []cel.EnvOption{
		cel.TypeDescs(fileDesc),
		cel.Variable("event", cel.ObjectType(string(msgDesc.FullName()))),
		cel.Variable("kind", cel.StringType),
		cel.Variable("machine_id", cel.StringType),
		cel.Variable("boot_session_uuid", cel.StringType),
		cel.Variable("decoded_args", cel.ListType(cel.StringType)),
	}

	// Register Santa enum constants
	for name := range santaEnums {
		envOpts = append(envOpts, cel.Variable(name, cel.IntType))
	}

	// Register Santa protobuf types with CEL
	env, err := cel.NewEnv(envOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	return &Engine{
		rules:        make([]*CompiledRule, 0),
		correlations: make([]*CompiledCorrelation, 0),
		baselines:    make([]*CompiledBaseline, 0),
		env:          env,
		startTime:    time.Now(),
	}, nil
}

// LoadRules compiles rules from the rules configuration
func (e *Engine) LoadRules(rules *RulesConfig) error {
	// Pre-allocate slices with capacity to avoid reallocations
	enabledRules := 0
	enabledCorrs := 0
	enabledBaselines := 0
	for _, r := range rules.Rules {
		if r.Enabled {
			enabledRules++
		}
	}
	for _, c := range rules.Correlations {
		if c.Enabled {
			enabledCorrs++
		}
	}
	for _, b := range rules.Baselines {
		if b.Enabled {
			enabledBaselines++
		}
	}

	e.rules = make([]*CompiledRule, 0, enabledRules)
	e.correlations = make([]*CompiledCorrelation, 0, enabledCorrs)
	e.baselines = make([]*CompiledBaseline, 0, enabledBaselines)

	// Compile each enabled rule
	for _, rule := range rules.Rules {
		if !rule.Enabled {
			continue
		}
		compiled, err := e.compileExpression(rule.ID, rule.Expr)
		if err != nil {
			return fmt.Errorf("failed to compile rule %s: %w", rule.ID, err)
		}
		e.rules = append(e.rules, &CompiledRule{
			Rule:    rule,
			Program: compiled,
		})
	}

	// Compile each enabled correlation rule
    for _, corr := range rules.Correlations {
        if !corr.Enabled {
            continue
        }
        compiled, err := e.compileExpression(corr.ID, corr.Expr)
        if err != nil {
            return fmt.Errorf("failed to compile correlation %s: %w", corr.ID, err)
        }
        e.correlations = append(e.correlations, &CompiledCorrelation{Rule: corr, Program: compiled})
    }

	// Compile each enabled baseline rule
	for _, baseline := range rules.Baselines {
		if !baseline.Enabled {
			continue
		}
		compiled, err := e.compileExpression(baseline.ID, baseline.Expr)
		if err != nil {
			return fmt.Errorf("failed to compile baseline %s: %w", baseline.ID, err)
		}
		e.baselines = append(e.baselines, &CompiledBaseline{
			Rule:    baseline,
			Program: compiled,
		})
	}

	return nil
}

// compileExpression compiles a CEL expression into an executable program.
// Used for both simple rules and correlation rules.
func (e *Engine) compileExpression(ruleID, expr string) (cel.Program, error) {
	// Parse the CEL expression
	ast, issues := e.env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("CEL compilation error: %w", issues.Err())
	}

	// Validate that the expression returns a boolean
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("expression must return boolean, got %v", ast.OutputType())
	}

	// Create the executable program
	program, err := e.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("program creation error: %w", err)
	}

	return program, nil
}

// BuildActivation creates a CEL activation map from a Santa message with all required variables
func BuildActivation(msg *santapb.SantaMessage) map[string]any {
	activation := map[string]any{
		"event":             msg,
		"kind":              events.Kind(msg),
		"machine_id":        msg.GetMachineId(),
		"boot_session_uuid": msg.GetBootSessionUuid(),
		"decoded_args":      events.DecodedArgs(msg),
	}

	// Add enum constants to activation
	for name, value := range santaEnums {
		activation[name] = value
	}

	return activation
}

// Evaluate runs all rules against an event and returns matches.
func (e *Engine) Evaluate(msg *santapb.SantaMessage) ([]*Match, error) {
	if len(e.rules) == 0 {
		return nil, nil
	}

	activation := BuildActivation(msg)

	// Pre-allocate assuming ~5% match rate (tune based on real-world data)
	matches := make([]*Match, 0, max(1, len(e.rules)/20))

	// Evaluate each rule
	for _, compiled := range e.rules {
		result, _, err := compiled.Program.Eval(activation)
		if err != nil {
			// Log error but continue with other rules to avoid single rule failure breaking all detection
			logutil.Warn("rule evaluation error for %s: %v", compiled.Rule.ID, err)
			continue
		}

		// Check if rule matched
		matched, ok := result.Value().(bool)
		if !ok {
			logutil.Warn("rule %s returned non-boolean: %T", compiled.Rule.ID, result.Value())
			continue
		}

		if matched {
			matches = append(matches, &Match{
				RuleID:    compiled.Rule.ID,
				Title:     compiled.Rule.Title,
				Severity:  compiled.Rule.Severity,
				Tags:      compiled.Rule.Tags,
				Message:   msg,
				Timestamp: events.EventTime(msg),
				Rule:      compiled.Rule,
			})
		}
	}

	return matches, nil
}

// max returns the larger of two ints
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// GetCorrelations returns the compiled correlation rules
func (e *Engine) GetCorrelations() []*CompiledCorrelation {
	return e.correlations
}

// GetBaselines returns the compiled baseline rules
func (e *Engine) GetBaselines() []*CompiledBaseline {
	return e.baselines
}

// IsInLearningPeriod checks if a baseline rule is still in its learning period
func (e *Engine) IsInLearningPeriod(baseline *BaselineRule) bool {
	if baseline.LearningPeriod == 0 {
		return false
	}
	return time.Since(e.startTime) < baseline.LearningPeriod
}

// GetEnv returns the CEL environment (used for testing)
func (e *Engine) GetEnv() *cel.Env {
	return e.env
}
