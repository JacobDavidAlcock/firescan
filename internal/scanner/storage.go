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
func CheckCloudStorage(results chan<- types.Finding, wg *sync.WaitGroup) {
	defer wg.Done()
	state := config.GetState()
	bucketName := fmt.Sprintf("%s.appspot.com", state.ProjectID)
	url := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o", bucketName)

	resp, err := auth.MakeAuthenticatedRequest("GET", url, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()
	results <- types.Finding{
		Timestamp: time.Now().Format(time.RFC3339),
		Severity:  "Critical",
		Type:      "Storage",
		Path:      bucketName,
		Status:    "Listable",
	}
}