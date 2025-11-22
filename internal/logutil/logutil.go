package logutil

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// VerbosityLevel represents the logging verbosity
type VerbosityLevel int

const (
	// NormalLevel shows standard output (default)
	NormalLevel VerbosityLevel = iota
	// VerboseLevel shows additional details and timestamps
	VerboseLevel
)

// ANSI color codes
const (
	colorReset       = "\033[0m"
	colorRed         = "\033[91m"
	colorGreen       = "\033[92m"
	colorYellow      = "\033[93m"
	colorOrange      = "\033[38;5;208m"
	colorCyan        = "\033[96m"
	colorGray        = "\033[90m"
	colorDimGray     = "\033[38;5;240m" // Very dim gray for timestamps
	colorContextGray = "\033[38;5;8m"   // Dim gray for context
	colorBrightWhite = "\033[97m"       // Bright white for rule IDs
	colorNormalWhite = "\033[37m"       // Normal white for titles
	colorBold        = "\033[1m"
)

var (
	// CurrentVerbosity is the current verbosity level
	CurrentVerbosity = NormalLevel
	// ShowTimestamps controls whether timestamps are shown
	ShowTimestamps = false

	// Unicode symbols with colors
	checkMark = colorGreen + "✓" + colorReset  // green checkmark
	warnMark  = colorYellow + "⚠" + colorReset // yellow warning
	crossMark = colorRed + "✗" + colorReset    // red cross
	infoMark  = colorGray + "ℹ" + colorReset   // gray info

	// Severity icons (no color, just emoji)
	severityIcons = map[string]string{
		"critical": "🔴",
		"high":     "🟠",
		"medium":   "🟡",
		"low":      "🟢",
		"info":     "🔵",
	}

	// Severity text colors
	severityColors = map[string]string{
		"critical": colorRed,
		"high":     colorOrange,
		"medium":   colorYellow,
		"low":      colorGreen,
		"info":     colorCyan,
	}
)

func init() {
	// Simple, consistent log format without default timestamps;
	// we render our own prefixes instead.
	log.SetFlags(0)
	log.SetOutput(os.Stderr)
}

// SetVerbosity sets the current verbosity level
func SetVerbosity(level VerbosityLevel) {
	CurrentVerbosity = level
}

// SetTimestamps enables or disables timestamps
func SetTimestamps(enabled bool) {
	ShowTimestamps = enabled
}

func timestamp() string {
	if ShowTimestamps {
		return colorDimGray + time.Now().Format("15:04:05") + colorReset + " "
	}
	return ""
}

// timestampForSignals returns a timestamp for signals (only in verbose mode)
func timestampForSignals() string {
	if ShowTimestamps {
		return colorDimGray + time.Now().Format("15:04:05") + colorReset + " "
	}
	return ""
}

func Info(format string, args ...any) {
	if CurrentVerbosity < NormalLevel {
		return
	}
	msg := fmt.Sprintf(format, args...)
	log.Println(timestamp() + infoMark + " " + msg)
}

func Warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Println(timestamp() + warnMark + " " + msg)
}

func Error(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Println(timestamp() + crossMark + " " + msg)
}

func Success(format string, args ...any) {
	if CurrentVerbosity < NormalLevel {
		return
	}
	msg := fmt.Sprintf(format, args...)
	log.Println(timestamp() + checkMark + " " + msg)
}

// Verbose logs a message only in verbose mode
func Verbose(format string, args ...any) {
	if CurrentVerbosity < VerboseLevel {
		return
	}
	msg := fmt.Sprintf(format, args...)
	log.Println(timestamp() + infoMark + " " + msg)
}

func severityLabel(severity string) string {
	s := strings.ToLower(severity)
	color, ok := severityColors[s]
	if !ok {
		color = severityColors["info"]
		s = "info"
	}
	// Get icon for severity
	icon := severityIcons[s]
	if icon == "" {
		icon = "•"
	}
	return icon + " " + color + colorBold + strings.ToUpper(severity) + colorReset
}

// Signal formats any detection signal (simple, correlation, baseline).
// kind is "rule", "correlation", or "baseline" (no longer displayed in output).
// extra contains context information that will be displayed on a second line (only in verbose mode).
func Signal(kind, ruleID, severity, title, extra string) {
	// Add blank line before each signal in verbose mode for better separation
	if CurrentVerbosity >= VerboseLevel {
		fmt.Println()
	}

	// Format: [timestamp] ICON SEVERITY  RULE_ID: Title
	ts := timestampForSignals()
	sev := severityLabel(severity)

	// Get severity color for the colon
	s := strings.ToLower(severity)
	sevColor, ok := severityColors[s]
	if !ok {
		sevColor = severityColors["info"]
	}

	// Rule ID in bright white bold, colon in severity color
	ruleIDStyled := colorBrightWhite + colorBold + ruleID + colorReset
	colonStyled := sevColor + colorBold + ":" + colorReset

	// Calculate spaces needed after styled rule ID and colon for alignment (12 chars total)
	spacesNeeded := 12 - len(ruleID) - 1 // -1 for the colon
	if spacesNeeded < 0 {
		spacesNeeded = 0
	}
	ruleIDDisplay := ruleIDStyled + colonStyled + strings.Repeat(" ", spacesNeeded)

	// Title in normal white
	coloredTitle := colorNormalWhite + title + colorReset

	line := fmt.Sprintf("%s%s %s %s", ts, sev, ruleIDDisplay, coloredTitle)
	log.Println(line)

	// Context line: only show in verbose mode
	if extra != "" && CurrentVerbosity >= VerboseLevel {
		indent := "         "
		if ShowTimestamps {
			indent = "          " // account for HH:MM:SS timestamp
		}
		log.Printf("%s%s└─ %s%s\n", indent, colorContextGray, extra, colorReset)
	}
}

// SignalContext formats signal context information for the second line
func SignalContext(context map[string]string) string {
	if len(context) == 0 {
		return ""
	}

	var parts []string
	for k, v := range context {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, " ")
}
