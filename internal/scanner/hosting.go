package scanner

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"firescan/internal/config"
	"firescan/internal/types"
)

// CheckHostingConfig checks if firebase.json is publicly accessible
func CheckHostingConfig(results chan<- types.Finding, errors chan<- types.ScanError, wg *sync.WaitGroup) {
	defer wg.Done()
	state := config.GetState()
	url := fmt.Sprintf("https://%s.web.app/firebase.json", state.ProjectID)

	resp, err := http.Get(url)
	if err != nil {
		errors <- types.ScanError{
			Timestamp: time.Now().Format(time.RFC3339),
			JobType:   "Hosting",
			Path:      url,
			Message:   err.Error(),
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		results <- types.Finding{
			Timestamp: time.Now().Format(time.RFC3339),
			Severity:  "Medium",
			Type:      "Hosting",
			Path:      url,
			Status:    "firebase.json is Public",
		}
	}
}