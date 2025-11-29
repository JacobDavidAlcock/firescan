package types

import "time"

// Color constants for terminal output - exactly as in original
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// State holds the global configuration for the console session - exactly as in original
type State struct {
	ProjectID string `yaml:"projectId"`
	APIKey    string `yaml:"apiKey"`
	Token     string `yaml:"-"`
	// Store credentials for automatic token refresh
	Email    string `yaml:"-"`
	Password string `yaml:"-"`
	// Store user info for verification status
	UserID        string `yaml:"-"`
	EmailVerified bool   `yaml:"-"`
}

// Finding represents a discovered vulnerability - exactly as in original
type Finding struct {
	Timestamp string `json:"timestamp"`
	Severity  string `json:"severity"`
	Type      string `json:"type"`
	Path      string `json:"path"`
	Status    string `json:"status"`
}

// Job represents a task for a worker - exactly as in original
type Job struct {
	Type string
	Path string
}

// ScanError represents an error that occurred during scanning
type ScanError struct {
	Timestamp string
	JobType   string
	Path      string
	Message   string
}

// SavedSession represents a saved authentication session - exactly as in original
type SavedSession struct {
	Name      string    `yaml:"name"`
	ProjectID string    `yaml:"projectID"`
	APIKey    string    `yaml:"apiKey"`
	Email     string    `yaml:"email"`
	Password  string    `yaml:"password"`
	SavedAt   time.Time `yaml:"savedAt"`
}

// SessionsFile represents the saved sessions file structure - exactly as in original
type SessionsFile struct {
	Sessions []SavedSession `yaml:"sessions"`
}
