package rules

// Severity levels for rules
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// ValidSeverities returns the set of valid severity levels
var ValidSeverities = map[string]bool{
	SeverityLow:      true,
	SeverityMedium:   true,
	SeverityHigh:     true,
	SeverityCritical: true,
}
