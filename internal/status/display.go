package status

import (
	"fmt"
	"strings"
)

var lastStatusLength int = 0
var suppressed bool

// SetJSONMode suppresses status output entirely when enabled, so it never
// corrupts machine-readable output (e.g. --json) sharing the same stdout.
func SetJSONMode(enabled bool) {
	suppressed = enabled
}

// ShowStatus displays a dynamic status message that can be cleared
func ShowStatus(message string) {
	if suppressed {
		return
	}

	// Clear previous status line
	if lastStatusLength > 0 {
		fmt.Print("\r" + strings.Repeat(" ", lastStatusLength) + "\r")
	}

	// Show new status with color
	statusMessage := fmt.Sprintf("\r[*] %s", message)
	fmt.Print(statusMessage)
	lastStatusLength = len(statusMessage)
}

// ClearStatus clears the current status line
func ClearStatus() {
	if suppressed {
		return
	}
	if lastStatusLength > 0 {
		fmt.Print("\r" + strings.Repeat(" ", lastStatusLength) + "\r")
		lastStatusLength = 0
	}
}

// ShowStatusDone shows completion and clears
func ShowStatusDone(message string) {
	ClearStatus()
	fmt.Printf("[✓] %s\n", message)
}
