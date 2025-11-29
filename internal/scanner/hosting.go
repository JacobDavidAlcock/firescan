package scanner

import (
	"fmt"
	"sync"
	"time"

	"firescan/internal/config"
	"firescan/internal/httpclient"
	"firescan/internal/types"
)

// CheckHostingConfig checks if sensitive files are publicly accessible on Firebase Hosting
func CheckHostingConfig(results chan<- types.Finding, errors chan<- types.ScanError, wg *sync.WaitGroup) {
	defer wg.Done()
	state := config.GetState()
	baseURL := fmt.Sprintf("https://%s.web.app", state.ProjectID)

	sensitiveFiles := []string{
		"/firebase.json",
		"/.git/HEAD",
		"/.env",
		"/package.json",
		"/node_modules/package.json",
		"/src/config.js",
		"/src/config.ts",
		"/webpack.config.js",
		"/README.md",
	}

	for _, file := range sensitiveFiles {
		url := baseURL + file
		resp, err := httpclient.Get(url)
		if resp != nil {
			defer resp.Body.Close()
		}
		if err != nil {
			// Don't report connection errors for every file, just log debug if needed
			continue
		}
		
		if resp.StatusCode == 200 {
			results <- types.Finding{
				Timestamp: time.Now().Format(time.RFC3339),
				Severity:  "Medium",
				Type:      "Hosting",
				Path:      url,
				Status:    "Publicly Accessible",
			}
		}
	}
}
