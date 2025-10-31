package ui

import (
	"fmt"
	"strings"
)

var lastStatusLength int = 0

// ShowStatus displays a dynamic status message that can be cleared
func ShowStatus(message string) {
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
