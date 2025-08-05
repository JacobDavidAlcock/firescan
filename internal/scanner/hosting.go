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
func CheckHostingConfig(results chan<- types.Finding, wg *sync.WaitGroup) {
	defer wg.Done()
	state := config.GetState()
	url := fmt.Sprintf("https://%s.web.app/firebase.json", state.ProjectID)

	resp, err := http.Get(url)
	if err != nil {
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