package scanner

import (
	"fmt"
	"strings"
	"time"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/httpclient"
	"firescan/internal/types"
)

// CheckFunction checks a Cloud Function for accessibility
func CheckFunction(job types.Job, results chan<- types.Finding, errors chan<- types.ScanError) {
	parts := strings.Split(job.Path, "/")
	region, funcName := parts[0], parts[1]

	state := config.GetState()
	url := fmt.Sprintf("https://%s-%s.cloudfunctions.net/%s", region, state.ProjectID, funcName)

	// 1. Check Unauthenticated (Public Access)
	// We use httpclient directly to avoid adding Authorization header
	resp, err := httpclient.Get(url)
	if resp != nil {
		defer resp.Body.Close()
	}
	
	if err == nil && resp.StatusCode == 200 {
		results <- types.Finding{
			Timestamp: time.Now().Format(time.RFC3339),
			Severity:  "Medium",
			Type:      "Function",
			Path:      url,
			Status:    "Publicly Invokable",
		}
		return
	}

	// 2. Check Authenticated (if unauth failed)
	// Only if we have a token
	if state.Token != "" {
		respAuth, errAuth := auth.MakeAuthenticatedRequest("GET", url, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
		if respAuth != nil {
			defer respAuth.Body.Close()
		}
		if errAuth != nil {
			// Don't report auth errors as scan errors, just debug log
			return
		}

		if respAuth.StatusCode == 200 {
			results <- types.Finding{
				Timestamp: time.Now().Format(time.RFC3339),
				Severity:  "Informational",
				Type:      "Function",
				Path:      url,
				Status:    "Exists (Auth Required)",
			}
		} else if respAuth.StatusCode == 403 {
			// It exists but we don't have access
			results <- types.Finding{
				Timestamp: time.Now().Format(time.RFC3339),
				Severity:  "Informational",
				Type:      "Function",
				Path:      url,
				Status:    "Exists (Access Denied)",
			}
		}
	}
}
