package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"firescan/internal/types"

	"gopkg.in/yaml.v3"
)

var sessionsFilePath = "firescan_sessions.yaml"

// SaveSession saves the current session
func SaveSession(sessionName string) error {
	state := GetState()
	
	if state.ProjectID == "" || state.APIKey == "" {
		return fmt.Errorf("no configuration to save (projectID and apiKey required)")
	}
	
	session := types.SavedSession{
		Name:      sessionName,
		ProjectID: state.ProjectID,
		APIKey:    state.APIKey,
		Email:     state.Email,
		Password:  state.Password,
		SavedAt:   time.Now(),
	}
	
	return saveSessionToFile(session)
}

// saveSessionToFile saves a session to the sessions file
func saveSessionToFile(session types.SavedSession) error {
	// Load existing sessions
	sessions, err := loadSavedSessions()
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load existing sessions: %v", err)
	}
	
	// Remove any existing session with the same name
	var filteredSessions []types.SavedSession
	for _, s := range sessions.Sessions {
		if s.Name != session.Name {
			filteredSessions = append(filteredSessions, s)
		}
	}
	
	// Add the new session
	filteredSessions = append(filteredSessions, session)
	
	// Keep only the last 10 sessions
	if len(filteredSessions) > 10 {
		filteredSessions = filteredSessions[len(filteredSessions)-10:]
	}
	
	sessions.Sessions = filteredSessions
	
	// Save to file
	data, err := yaml.Marshal(sessions)
	if err != nil {
		return fmt.Errorf("failed to marshal sessions: %v", err)
	}
	
	err = os.WriteFile(sessionsFilePath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write sessions file: %v", err)
	}
	
	return nil
}

// loadSavedSessions loads saved sessions from file
func loadSavedSessions() (*types.SessionsFile, error) {
	data, err := os.ReadFile(sessionsFilePath)
	if err != nil {
		return &types.SessionsFile{Sessions: []types.SavedSession{}}, err
	}
	
	var sessions types.SessionsFile
	err = yaml.Unmarshal(data, &sessions)
	if err != nil {
		return &types.SessionsFile{Sessions: []types.SavedSession{}}, err
	}
	
	return &sessions, nil
}

// ResumeSession shows session selection and loads the chosen session
func ResumeSession() error {
	sessions, err := loadSavedSessions()
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no saved sessions found")
		}
		return fmt.Errorf("failed to load sessions: %v", err)
	}
	
	if len(sessions.Sessions) == 0 {
		return fmt.Errorf("no saved sessions available")
	}
	
	fmt.Println("\n--- Available Sessions ---")
	for i, session := range sessions.Sessions {
		fmt.Printf("%d. %s (Project: %s, Email: %s, Saved: %s)\n", 
			i+1, session.Name, session.ProjectID, 
			MaskString(session.Email, 2, 0), 
			session.SavedAt.Format("2006-01-02 15:04"))
	}
	fmt.Println("--------------------------")
	
	fmt.Print("Select session number (1-" + fmt.Sprintf("%d", len(sessions.Sessions)) + "): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	
	var selection int
	_, err = fmt.Sscanf(input, "%d", &selection)
	if err != nil || selection < 1 || selection > len(sessions.Sessions) {
		return fmt.Errorf("invalid selection")
	}
	
	selectedSession := sessions.Sessions[selection-1]
	
	// Load the session into current state
	LoadFromSession(selectedSession)
	
	// Try to authenticate with stored credentials if available
	if selectedSession.Email != "" && selectedSession.Password != "" {
		fmt.Printf("[*] Attempting to authenticate with stored credentials for %s...\n", selectedSession.Email)
		
		// Import auth package functions
		// Note: This will be handled in the main application
		fmt.Printf("✓ Session '%s' loaded. You may need to authenticate manually.\n", selectedSession.Name)
		return nil
	}
	
	fmt.Printf("✓ Session '%s' loaded. ProjectID and API Key have been set.\n", selectedSession.Name)
	return nil
}

// PromptForSessionName prompts user for session name
func PromptForSessionName(defaultName string) string {
	fmt.Print("Enter a name for this session: ")
	reader := bufio.NewReader(os.Stdin)
	sessionName, _ := reader.ReadString('\n')
	sessionName = strings.TrimSpace(sessionName)
	
	if sessionName == "" {
		sessionName = defaultName
	}
	
	return sessionName
}