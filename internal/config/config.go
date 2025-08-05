package config

import (
	"os"
	"sync"

	"firescan/internal/types"

	"gopkg.in/yaml.v3"
)

var (
	currentState types.State
	stateMutex   sync.RWMutex
)

// GetState returns a copy of the current state
func GetState() types.State {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	return currentState
}

// GetProjectID returns the current project ID
func GetProjectID() string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	return currentState.ProjectID
}

// GetAPIKey returns the current API key
func GetAPIKey() string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	return currentState.APIKey
}

// GetToken returns the current token
func GetToken() string {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	return currentState.Token
}

// GetAuthInfo returns current auth information
func GetAuthInfo() (email, password, userID string, emailVerified bool) {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	return currentState.Email, currentState.Password, currentState.UserID, currentState.EmailVerified
}

// SetProjectID sets the project ID
func SetProjectID(projectID string) {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	currentState.ProjectID = projectID
}

// SetAPIKey sets the API key
func SetAPIKey(apiKey string) {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	currentState.APIKey = apiKey
}

// SetToken sets the authentication token
func SetToken(token string) {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	currentState.Token = token
}

// SetAuthInfo sets authentication information
func SetAuthInfo(email, password, userID string, emailVerified bool) {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	currentState.Email = email
	currentState.Password = password
	currentState.UserID = userID
	currentState.EmailVerified = emailVerified
}

// UpdateTokenInfo updates token and related user info
func UpdateTokenInfo(token, userID string, emailVerified bool) {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	currentState.Token = token
	currentState.UserID = userID
	currentState.EmailVerified = emailVerified
}

// ClearAuth clears authentication information
func ClearAuth() {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	currentState.Token = ""
	currentState.Email = ""
	currentState.Password = ""
	currentState.UserID = ""
	currentState.EmailVerified = false
}

// LoadFromFile loads configuration from a YAML file
func LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	
	stateMutex.Lock()
	defer stateMutex.Unlock()
	
	return yaml.Unmarshal(data, &currentState)
}

// LoadFromSession loads configuration from a saved session
func LoadFromSession(session types.SavedSession) {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	
	currentState.ProjectID = session.ProjectID
	currentState.APIKey = session.APIKey
	currentState.Email = session.Email
	currentState.Password = session.Password
}

// MaskString hides the middle of a string for secure display
func MaskString(s string, prefixLen, suffixLen int) string {
	if len(s) < prefixLen+suffixLen {
		return "..."
	}
	return s[:prefixLen] + "..." + s[len(s)-suffixLen:]
}