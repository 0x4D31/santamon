package rules

import (
	"time"

	"github.com/google/cel-go/cel"
)

// BaselineRule detects first-occurrence or deviation from baseline
type BaselineRule struct {
	ID             string        `yaml:"id"`
	Title          string        `yaml:"title"`
	Description    string        `yaml:"description,omitempty"`
	Expr           string        `yaml:"expr"`             // Filter expression
	Track          []string      `yaml:"track"`            // Fields to track for uniqueness
	Severity       string        `yaml:"severity"`
	Tags           []string      `yaml:"tags,omitempty"`
	Enabled        bool          `yaml:"enabled"`
	LearningPeriod time.Duration `yaml:"learning_period,omitempty"` // Suppress alerts during learning
}

// CompiledBaseline holds a baseline rule plus its compiled CEL program
type CompiledBaseline struct {
	Rule    *BaselineRule
	Program cel.Program
}

// Validate checks a baseline rule
func (br *BaselineRule) Validate() error {
	if br.ID == "" {
		return ErrRequired("baseline ID")
	}
	if br.Title == "" {
		return ErrRequired("baseline title")
	}
	if br.Expr == "" {
		return ErrRequired("baseline expression")
	}
	if len(br.Track) == 0 {
		return ErrRequired("baseline track fields (at least one required)")
	}
	if br.Severity == "" {
		return ErrRequired("baseline severity")
	}
	if !ValidSeverities[br.Severity] {
		return ErrInvalidSeverity(br.Severity)
	}

	// Validate track fields are not empty
	for i, field := range br.Track {
		if field == "" {
			return ErrInvalidField("track", i)
		}
	}

	return nil
}
