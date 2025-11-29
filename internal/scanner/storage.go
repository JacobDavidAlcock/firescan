package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/httpclient"
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

// CheckStoragePath checks if a specific path in Cloud Storage is accessible
func CheckStoragePath(job types.Job, results chan<- types.Finding, errors chan<- types.ScanError) {
	state := config.GetState()
	
	// Check both legacy and new bucket domains
	buckets := []string{
		fmt.Sprintf("%s.appspot.com", state.ProjectID),
		fmt.Sprintf("%s.firebasestorage.app", state.ProjectID),
	}

	encodedPath := url.QueryEscape(job.Path)

	for _, bucketName := range buckets {
		url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o/%s", bucketName, encodedPath)

		// Check Unauthenticated first
		resp, err := httpclient.Get(url)
		if resp != nil {
			defer resp.Body.Close()
		}
		
		// If 404, the bucket might not exist or the file doesn't exist.
		// If the bucket doesn't exist, we should try the next one.
		// But how to distinguish "bucket not found" from "file not found"?
		// GCS returns 404 for both.
		// However, if we get 200, we found it!
		
		if err == nil && resp.StatusCode == 200 {
			results <- types.Finding{
				Timestamp: time.Now().Format(time.RFC3339),
				Severity:  "High",
				Type:      "Storage",
				Path:      url,
				Status:    "Publicly Readable",
			}
			return
		}

		// Check Authenticated
		if state.Token != "" {
			respAuth, errAuth := auth.MakeAuthenticatedRequest("GET", url, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
			if respAuth != nil {
				defer respAuth.Body.Close()
			}
			if errAuth == nil && respAuth.StatusCode == 200 {
				results <- types.Finding{
					Timestamp: time.Now().Format(time.RFC3339),
					Severity:  "Medium",
					Type:      "Storage",
					Path:      url,
					Status:    "Readable (Auth Required)",
				}
				return
			}
		}
	}
}
