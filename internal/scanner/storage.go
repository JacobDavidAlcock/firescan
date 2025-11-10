package scanner

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/types"
)

// CheckCloudStorage checks if Cloud Storage bucket is listable
func CheckCloudStorage(results chan<- types.Finding, errors chan<- types.ScanError, wg *sync.WaitGroup) {
	defer wg.Done()
	state := config.GetState()
	bucketName := fmt.Sprintf("%s.appspot.com", state.ProjectID)
	url := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o", bucketName)

	resp, err := auth.MakeAuthenticatedRequest("GET", url, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		errors <- types.ScanError{
			Timestamp: time.Now().Format(time.RFC3339),
			JobType:   "Storage",
			Path:      bucketName,
			Message:   err.Error(),
		}
		return
	}

	if resp.StatusCode != http.StatusOK {
		// 404 means bucket doesn't exist, 403 means access is properly denied
		// Both are expected behaviors and should not be reported as errors
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusForbidden {
			errors <- types.ScanError{
				Timestamp: time.Now().Format(time.RFC3339),
				JobType:   "Storage",
				Path:      bucketName,
				Message:   fmt.Sprintf("HTTP %d", resp.StatusCode),
			}
		}
		return
	}

	results <- types.Finding{
		Timestamp: time.Now().Format(time.RFC3339),
		Severity:  "Critical",
		Type:      "Storage",
		Path:      bucketName,
		Status:    "Listable",
	}
}
