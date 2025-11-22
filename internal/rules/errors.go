package rules

import "fmt"

// Common validation errors

func ErrRequired(field string) error {
	return fmt.Errorf("%s is required", field)
}

func ErrInvalidSeverity(severity string) error {
	return fmt.Errorf("invalid severity: %s (must be low/medium/high/critical)", severity)
}

func ErrInvalidField(field string, index int) error {
	return fmt.Errorf("%s field %d is empty", field, index)
}

func ErrDuplicateID(id string) error {
	return fmt.Errorf("duplicate rule ID: %s", id)
}

func ErrDuplicateIDConflict(id string) error {
	return fmt.Errorf("duplicate rule ID: %s (conflicts with existing rule)", id)
}
