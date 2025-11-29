package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"firescan/internal/config"
	"firescan/internal/httpclient"
	"firescan/internal/types"
)

// CheckRTDB checks a Realtime Database path for readability
func CheckRTDB(job types.Job, results chan<- types.Finding, errors chan<- types.ScanError) {
	state := config.GetState()
	
	// Check both legacy and new database URL formats
	databases := []string{state.ProjectID, fmt.Sprintf("%s-default-rtdb", state.ProjectID)}
	
	for _, dbName := range databases {
		url := fmt.Sprintf("https://%s.firebaseio.com/%s.json?auth=%s", dbName, job.Path, state.Token)

		resp, err := httpclient.Get(url)
		if resp != nil {
			defer resp.Body.Close()
		}
		if err != nil {
			// Only report error if it's the primary database or if we're sure it exists
			// For now, let's just log debug or ignore connection errors for the guess
			continue
		}
		
		// If 404, the database might not exist at this subdomain, continue to next
		if resp.StatusCode == http.StatusNotFound {
			continue
		}

		var body interface{}
		json.NewDecoder(resp.Body).Decode(&body)
		if body != nil {
			if errorMap, ok := body.(map[string]interface{}); ok {
				if _, isError := errorMap["error"]; isError {
					continue
				}
			}
			results <- types.Finding{
				Timestamp: time.Now().Format(time.RFC3339),
				Severity:  "High",
				Type:      "RTDB",
				Path:      fmt.Sprintf("https://%s.firebaseio.com/%s.json", dbName, job.Path),
				Status:    "Readable",
			}
			return // Found it, stop checking other subdomains
		}
	}
}

// ExtractRTDBNode extracts data from a Realtime Database node
func ExtractRTDBNode(path string) (interface{}, error) {
	state := config.GetState()
	url := fmt.Sprintf("https://%s.firebaseio.com/%s.json?auth=%s", state.ProjectID, path, state.Token)

	resp, err := httpclient.Get(url)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data (HTTP %d)", resp.StatusCode)
	}
	var body interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body != nil {
		if errorMap, ok := body.(map[string]interface{}); ok {
			if errMsg, isError := errorMap["error"]; isError {
				return nil, fmt.Errorf("could not read node: %v", errMsg)
			}
		}
		return body, nil
	}
	return nil, fmt.Errorf("no data found at node")
}
