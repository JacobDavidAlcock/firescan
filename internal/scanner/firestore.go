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
func CheckFirestore(job types.Job, results chan<- types.Finding, errors chan<- types.ScanError) {
	state := config.GetState()
	url := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s", state.ProjectID, job.Path)

	// Use authenticated request with token refresh capability
	resp, err := auth.MakeAuthenticatedRequest("GET", url, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		errors <- types.ScanError{
			Timestamp: time.Now().Format(time.RFC3339),
			JobType:   "Firestore",
			Path:      job.Path,
			Message:   err.Error(),
		}
		return
	}

	if resp.StatusCode != http.StatusOK {
		// Only report non-404 errors (404 just means collection doesn't exist)
		if resp.StatusCode != http.StatusNotFound {
			errors <- types.ScanError{
				Timestamp: time.Now().Format(time.RFC3339),
				JobType:   "Firestore",
				Path:      job.Path,
				Message:   fmt.Sprintf("HTTP %d", resp.StatusCode),
			}
		}
		return
	}

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
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
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

// ExtractFirestoreDocument extracts data from a specific Firestore document
func ExtractFirestoreDocument(path, documentId string) (interface{}, error) {
	state := config.GetState()
	url := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s/%s", state.ProjectID, path, documentId)

	resp, err := auth.MakeAuthenticatedRequest("GET", url, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch document (HTTP %d)", resp.StatusCode)
	}
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	return body, nil
}

// WriteFirestoreDocument writes data to a specific Firestore document
func WriteFirestoreDocument(path, documentId string, data map[string]interface{}) error {
	state := config.GetState()
	url := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s/%s", state.ProjectID, path, documentId)

	// Convert data to Firestore format
	firestoreData := convertToFirestoreFormat(data)

	jsonData, err := json.Marshal(map[string]interface{}{
		"fields": firestoreData,
	})
	if err != nil {
		return fmt.Errorf("error marshaling data: %v", err)
	}

	resp, err := auth.MakeAuthenticatedRequestWithBody("PATCH", url, string(jsonData), state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to write document (HTTP %d)", resp.StatusCode)
	}

	return nil
}

// convertToFirestoreFormat converts regular JSON to Firestore field format
func convertToFirestoreFormat(data map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range data {
		switch v := value.(type) {
		case string:
			result[key] = map[string]interface{}{
				"stringValue": v,
			}
		case float64:
			result[key] = map[string]interface{}{
				"doubleValue": v,
			}
		case int:
			result[key] = map[string]interface{}{
				"integerValue": fmt.Sprintf("%d", v),
			}
		case bool:
			result[key] = map[string]interface{}{
				"booleanValue": v,
			}
		case map[string]interface{}:
			result[key] = map[string]interface{}{
				"mapValue": map[string]interface{}{
					"fields": convertToFirestoreFormat(v),
				},
			}
		case []interface{}:
			arrayValues := make([]interface{}, len(v))
			for i, item := range v {
				switch itemVal := item.(type) {
				case string:
					arrayValues[i] = map[string]interface{}{"stringValue": itemVal}
				case float64:
					arrayValues[i] = map[string]interface{}{"doubleValue": itemVal}
				case int:
					arrayValues[i] = map[string]interface{}{"integerValue": fmt.Sprintf("%d", itemVal)}
				case bool:
					arrayValues[i] = map[string]interface{}{"booleanValue": itemVal}
				default:
					arrayValues[i] = map[string]interface{}{"stringValue": fmt.Sprintf("%v", itemVal)}
				}
			}
			result[key] = map[string]interface{}{
				"arrayValue": map[string]interface{}{
					"values": arrayValues,
				},
			}
		default:
			// Default to string representation
			result[key] = map[string]interface{}{
				"stringValue": fmt.Sprintf("%v", v),
			}
		}
	}

	return result
}
