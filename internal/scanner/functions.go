package scanner

import (
	"fmt"
	"strings"
	"time"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/types"
)

// CheckFunction checks a Cloud Function for accessibility
func CheckFunction(job types.Job, results chan<- types.Finding) {
	parts := strings.Split(job.Path, "/")
	region, funcName := parts[0], parts[1]

	state := config.GetState()
	url := fmt.Sprintf("https://%s-%s.cloudfunctions.net/%s", region, state.ProjectID, funcName)

	resp, err := auth.MakeAuthenticatedRequest("GET", url, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		results <- types.Finding{
			Timestamp: time.Now().Format(time.RFC3339),
			Severity:  "Medium",
			Type:      "Function",
			Path:      url,
			Status:    "Publicly Invokable",
		}
	} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
		results <- types.Finding{
			Timestamp: time.Now().Format(time.RFC3339),
			Severity:  "Informational",
			Type:      "Function",
			Path:      url,
			Status:    "Exists (Auth Required)",
		}
	}
}