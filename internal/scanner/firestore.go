package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/types"
)

// CheckFirestore checks a Firestore collection for readability
func CheckFirestore(job types.Job, results chan<- types.Finding) {
	state := config.GetState()
	url := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s", state.ProjectID, job.Path)

	// Use authenticated request with token refresh capability
	resp, err := auth.MakeAuthenticatedRequest("GET", url, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if _, ok := body["documents"]; ok {
		results <- types.Finding{
			Timestamp: time.Now().Format(time.RFC3339),
			Severity:  "High",
			Type:      "Firestore",
			Path:      job.Path,
			Status:    "Readable",
		}
	}
}

// ExtractFirestoreCollection extracts data from a Firestore collection
func ExtractFirestoreCollection(path string) (interface{}, error) {
	state := config.GetState()
	url := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s", state.ProjectID, path)

	resp, err := auth.MakeAuthenticatedRequest("GET", url, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data (HTTP %d)", resp.StatusCode)
	}
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if docs, ok := body["documents"]; ok {
		return docs, nil
	}
	return nil, fmt.Errorf("no documents found or permission denied")
}