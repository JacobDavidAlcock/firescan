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
	url := fmt.Sprintf("https://%s.firebaseio.com/%s.json?auth=%s", state.ProjectID, job.Path, state.Token)

	resp, err := httpclient.Get(url)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		errors <- types.ScanError{
			Timestamp: time.Now().Format(time.RFC3339),
			JobType:   "RTDB",
			Path:      job.Path,
			Message:   err.Error(),
		}
		return
	}
	var body interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body != nil {
		if errorMap, ok := body.(map[string]interface{}); ok {
			if _, isError := errorMap["error"]; isError {
				return
			}
		}
		results <- types.Finding{
			Timestamp: time.Now().Format(time.RFC3339),
			Severity:  "High",
			Type:      "RTDB",
			Path:      job.Path,
			Status:    "Readable",
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
