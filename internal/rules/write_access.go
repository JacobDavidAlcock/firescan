package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/httpclient"
	"firescan/internal/safety"
	"firescan/internal/types"
)

// TestWriteAccess tests write permissions across Firebase services
func TestWriteAccess(mode types.ScanMode, services []string) ([]types.WriteTestResult, error) {
	// Write testing is only available in test mode and above
	if mode < types.TestMode {
		return nil, fmt.Errorf("write access testing requires test mode or higher")
	}

	// Warn user about write operations
	if !safety.WarnUser(mode) {
		return nil, fmt.Errorf("user declined to proceed with write testing")
	}

	var results []types.WriteTestResult

	// Setup cleanup
	state := config.GetState()
	cleanup := safety.NewTestCleanup(state.ProjectID)
	defer safety.PerformCleanup(cleanup)

	// Generate write test cases
	testCases := generateWriteTestCases(mode, services)

	// Run write tests
	for _, testCase := range testCases {
		result := runWriteTest(testCase, cleanup)
		results = append(results, result)
	}

	return results, nil
}

// generateWriteTestCases creates write test cases based on mode and services
func generateWriteTestCases(mode types.ScanMode, services []string) []types.WriteTestCase {
	var testCases []types.WriteTestCase

	for _, service := range services {
		switch service {
		case "firestore":
			testCases = append(testCases, generateFirestoreWriteTests(mode)...)
		case "rtdb":
			testCases = append(testCases, generateRTDBWriteTests(mode)...)
		case "storage":
			testCases = append(testCases, generateStorageWriteTests(mode)...)
		}
	}

	return testCases
}

// generateFirestoreWriteTests creates Firestore write test cases
func generateFirestoreWriteTests(mode types.ScanMode) []types.WriteTestCase {
	testPath := safety.GenerateSafeTestPath()
	testData := safety.GenerateSafeTestData()

	testCases := []types.WriteTestCase{
		{
			ID:          "firestore_create_document",
			Service:     "firestore",
			Path:        testPath + "/test-doc-create",
			Operation:   "create",
			TestData:    testData,
			Expected:    true,
			Description: "Test document creation in Firestore",
			SafetyLevel: types.TestMode,
		},
		{
			ID:          "firestore_update_document",
			Service:     "firestore",
			Path:        testPath + "/test-doc-update",
			Operation:   "update",
			TestData:    testData,
			Expected:    true,
			Description: "Test document update in Firestore",
			SafetyLevel: types.TestMode,
		},
		{
			ID:          "firestore_delete_document",
			Service:     "firestore",
			Path:        testPath + "/test-doc-delete",
			Operation:   "delete",
			TestData:    nil,
			Expected:    true,
			Description: "Test document deletion in Firestore",
			SafetyLevel: types.TestMode,
		},
	}

	// Audit mode - Add more aggressive tests
	if mode >= types.AuditMode {
		auditTests := []types.WriteTestCase{
			{
				ID:          "firestore_batch_write",
				Service:     "firestore",
				Path:        testPath + "/batch",
				Operation:   "batch_write",
				TestData:    map[string]interface{}{"batch_size": 10, "test_data": testData},
				Expected:    false, // May be restricted
				Description: "Test batch write operations",
				SafetyLevel: types.AuditMode,
			},
			{
				ID:          "firestore_admin_write",
				Service:     "firestore",
				Path:        "/admin" + testPath,
				Operation:   "create",
				TestData:    testData,
				Expected:    false, // Should be denied
				Description: "Test write access to admin paths",
				SafetyLevel: types.AuditMode,
			},
		}
		testCases = append(testCases, auditTests...)
	}

	return testCases
}

// generateRTDBWriteTests creates RTDB write test cases
func generateRTDBWriteTests(mode types.ScanMode) []types.WriteTestCase {
	testPath := safety.GenerateSafeTestPath()
	testData := safety.GenerateSafeTestData()

	return []types.WriteTestCase{
		{
			ID:          "rtdb_write_data",
			Service:     "rtdb",
			Path:        testPath,
			Operation:   "write",
			TestData:    testData,
			Expected:    true,
			Description: "Test data write to RTDB",
			SafetyLevel: types.TestMode,
		},
		{
			ID:          "rtdb_push_data",
			Service:     "rtdb",
			Path:        testPath + "/list",
			Operation:   "push",
			TestData:    testData,
			Expected:    true,
			Description: "Test data push to RTDB list",
			SafetyLevel: types.TestMode,
		},
		{
			ID:          "rtdb_delete_data",
			Service:     "rtdb",
			Path:        testPath,
			Operation:   "delete",
			TestData:    nil,
			Expected:    true,
			Description: "Test data deletion from RTDB",
			SafetyLevel: types.TestMode,
		},
	}
}

// generateStorageWriteTests creates Storage write test cases
func generateStorageWriteTests(mode types.ScanMode) []types.WriteTestCase {
	testFileName := fmt.Sprintf("firescan-test-%d.txt", time.Now().Unix())
	testFileData := []byte("FireScan test file - safe to delete")

	return []types.WriteTestCase{
		{
			ID:          "storage_upload_file",
			Service:     "storage",
			Path:        "test-uploads/" + testFileName,
			Operation:   "upload",
			TestData:    testFileData,
			Expected:    true,
			Description: "Test file upload to Storage",
			SafetyLevel: types.TestMode,
		},
		{
			ID:          "storage_delete_file",
			Service:     "storage",
			Path:        "test-uploads/" + testFileName,
			Operation:   "delete",
			TestData:    nil,
			Expected:    true,
			Description: "Test file deletion from Storage",
			SafetyLevel: types.TestMode,
		},
	}
}

// runWriteTest executes a single write test case
func runWriteTest(testCase types.WriteTestCase, cleanup *types.TestCleanup) types.WriteTestResult {
	startTime := time.Now()

	result := types.WriteTestResult{
		TestCase: testCase,
		Duration: 0,
	}

	// Add to cleanup tracker
	if testCase.Service == "storage" {
		safety.AddFileToCleanup(cleanup, testCase.Path)
	} else {
		safety.AddPathToCleanup(cleanup, testCase.Path)
	}

	// Execute the test based on service and operation
	switch testCase.Service {
	case "firestore":
		result = executeFirestoreWriteTest(testCase)
	case "rtdb":
		result = executeRTDBWriteTest(testCase)
	case "storage":
		result = executeStorageWriteTest(testCase)
	default:
		result.Error = fmt.Errorf("unknown service: %s", testCase.Service)
	}

	result.Duration = time.Since(startTime)
	return result
}

// executeFirestoreWriteTest executes Firestore write operations
func executeFirestoreWriteTest(testCase types.WriteTestCase) types.WriteTestResult {
	state := config.GetState()

	// Generate test document ID
	testDocID := fmt.Sprintf("firescan-test-%d", time.Now().Unix())
	url := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s/%s",
		state.ProjectID, testCase.Path, testDocID)

	var resp *http.Response
	var err error

	switch testCase.Operation {
	case "create":
		// Convert test data to Firestore format
		firestoreData := convertToFirestoreFormat(testCase.TestData)
		jsonData, marshalErr := json.Marshal(map[string]interface{}{
			"fields": firestoreData,
		})
		if marshalErr != nil {
			return types.WriteTestResult{
				TestCase: testCase,
				Success:  false,
				Error:    fmt.Errorf("failed to marshal test data: %v", marshalErr),
			}
		}

		// POST to create document
		resp, err = auth.MakeAuthenticatedRequestWithBody("POST",
			fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s",
				state.ProjectID, testCase.Path),
			string(jsonData), state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)

	case "update":
		// First create a document to update
		firestoreData := convertToFirestoreFormat(testCase.TestData)
		jsonData, marshalErr := json.Marshal(map[string]interface{}{
			"fields": firestoreData,
		})
		if marshalErr != nil {
			return types.WriteTestResult{
				TestCase: testCase,
				Success:  false,
				Error:    fmt.Errorf("failed to marshal test data: %v", marshalErr),
			}
		}

		// PATCH to update document
		resp, err = auth.MakeAuthenticatedRequestWithBody("PATCH", url, string(jsonData),
			state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)

	case "delete":
		// First create a document to delete
		firestoreData := convertToFirestoreFormat(map[string]interface{}{"test": "data"})
		jsonData, _ := json.Marshal(map[string]interface{}{
			"fields": firestoreData,
		})

		// Create the document first
		createResp, createErr := auth.MakeAuthenticatedRequestWithBody("POST",
			fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s",
				state.ProjectID, testCase.Path),
			string(jsonData), state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
		if createResp != nil {
			createResp.Body.Close()
		}
		if createErr != nil {
			return types.WriteTestResult{
				TestCase: testCase,
				Success:  false,
				Error:    fmt.Errorf("failed to create document for delete test: %v", createErr),
			}
		}

		// Now try to delete it
		resp, err = auth.MakeAuthenticatedRequest("DELETE", url,
			state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)

	default:
		return types.WriteTestResult{
			TestCase: testCase,
			Success:  false,
			Error:    fmt.Errorf("unknown Firestore operation: %s", testCase.Operation),
		}
	}

	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return types.WriteTestResult{
			TestCase: testCase,
			Success:  false,
			Error:    fmt.Errorf("request failed: %v", err),
		}
	}

	// Parse response
	var responseData map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&responseData)

	// Check if operation was successful
	success := resp.StatusCode >= 200 && resp.StatusCode < 300

	result := types.WriteTestResult{
		TestCase: testCase,
		Success:  success,
		Response: responseData,
	}

	if !success {
		result.Error = fmt.Errorf("operation failed with HTTP %d", resp.StatusCode)
	}

	return result
}

// executeRTDBWriteTest executes RTDB write operations
func executeRTDBWriteTest(testCase types.WriteTestCase) types.WriteTestResult {
	state := config.GetState()

	// Generate test path
	testPath := fmt.Sprintf("%s/firescan-test-%d", testCase.Path, time.Now().Unix())
	url := fmt.Sprintf("https://%s.firebaseio.com/%s.json?auth=%s", state.ProjectID, testPath, state.Token)

	var resp *http.Response
	var err error

	switch testCase.Operation {
	case "create", "update":
		// Convert test data to JSON
		var jsonData []byte
		if testCase.TestData != nil {
			jsonData, err = json.Marshal(testCase.TestData)
		} else {
			jsonData, err = json.Marshal(map[string]interface{}{
				"test":      "data",
				"timestamp": time.Now().Unix(),
			})
		}

		if err != nil {
			return types.WriteTestResult{
				TestCase: testCase,
				Success:  false,
				Error:    fmt.Errorf("failed to marshal test data: %v", err),
			}
		}

		// PUT to create/update data
		req, reqErr := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
		if reqErr != nil {
			return types.WriteTestResult{
				TestCase: testCase,
				Success:  false,
				Error:    fmt.Errorf("failed to create request: %v", reqErr),
			}
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err = httpclient.Do(req)

	case "delete":
		// First create data to delete
		createData, _ := json.Marshal(map[string]interface{}{"test": "data"})
		createReq, _ := http.NewRequest("PUT", url, bytes.NewBuffer(createData))
		createReq.Header.Set("Content-Type", "application/json")
		createResp, createErr := httpclient.Do(createReq)
		if createResp != nil {
			createResp.Body.Close()
		}
		if createErr != nil {
			return types.WriteTestResult{
				TestCase: testCase,
				Success:  false,
				Error:    fmt.Errorf("failed to create data for delete test: %v", createErr),
			}
		}

		// DELETE to remove data
		req, reqErr := http.NewRequest("DELETE", url, nil)
		if reqErr != nil {
			return types.WriteTestResult{
				TestCase: testCase,
				Success:  false,
				Error:    fmt.Errorf("failed to create delete request: %v", reqErr),
			}
		}

		resp, err = httpclient.Do(req)

	default:
		return types.WriteTestResult{
			TestCase: testCase,
			Success:  false,
			Error:    fmt.Errorf("unknown RTDB operation: %s", testCase.Operation),
		}
	}

	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return types.WriteTestResult{
			TestCase: testCase,
			Success:  false,
			Error:    fmt.Errorf("request failed: %v", err),
		}
	}

	// Parse response
	var responseData interface{}
	json.NewDecoder(resp.Body).Decode(&responseData)

	// Check if operation was successful
	success := resp.StatusCode >= 200 && resp.StatusCode < 300

	result := types.WriteTestResult{
		TestCase: testCase,
		Success:  success,
		Response: responseData,
	}

	if !success {
		result.Error = fmt.Errorf("operation failed with HTTP %d", resp.StatusCode)
	}

	return result
}

// executeStorageWriteTest executes Storage write operations
func executeStorageWriteTest(testCase types.WriteTestCase) types.WriteTestResult {
	state := config.GetState()
	bucketName := fmt.Sprintf("%s.appspot.com", state.ProjectID)

	// Generate test file name
	testFileName := fmt.Sprintf("firescan-test-%d.txt", time.Now().Unix())
	objectPath := fmt.Sprintf("%s/%s", testCase.Path, testFileName)

	var resp *http.Response
	var err error

	switch testCase.Operation {
	case "upload", "create":
		// Create test file content
		testContent := []byte("FireScan security test file - safe to delete")

		// Upload using simple upload (not multipart for simplicity)
		uploadURL := fmt.Sprintf("https://storage.googleapis.com/upload/storage/v1/b/%s/o?uploadType=media&name=%s",
			bucketName, objectPath)

		resp, err = auth.MakeAuthenticatedRequestWithBody("POST", uploadURL, string(testContent),
			state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)

	case "delete":
		// First upload a file to delete
		testContent := []byte("FireScan test file")
		uploadURL := fmt.Sprintf("https://storage.googleapis.com/upload/storage/v1/b/%s/o?uploadType=media&name=%s",
			bucketName, objectPath)

		createResp, createErr := auth.MakeAuthenticatedRequestWithBody("POST", uploadURL, string(testContent),
			state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
		if createResp != nil {
			createResp.Body.Close()
		}
		if createErr != nil {
			return types.WriteTestResult{
				TestCase: testCase,
				Success:  false,
				Error:    fmt.Errorf("failed to create file for delete test: %v", createErr),
			}
		}

		// Now delete it
		deleteURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o/%s",
			bucketName, objectPath)

		resp, err = auth.MakeAuthenticatedRequest("DELETE", deleteURL,
			state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)

	case "update":
		// First upload a file
		testContent := []byte("Original content")
		uploadURL := fmt.Sprintf("https://storage.googleapis.com/upload/storage/v1/b/%s/o?uploadType=media&name=%s",
			bucketName, objectPath)

		createResp, createErr := auth.MakeAuthenticatedRequestWithBody("POST", uploadURL, string(testContent),
			state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
		if createResp != nil {
			createResp.Body.Close()
		}
		if createErr != nil {
			return types.WriteTestResult{
				TestCase: testCase,
				Success:  false,
				Error:    fmt.Errorf("failed to create file for update test: %v", createErr),
			}
		}

		// Update metadata
		metadataURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o/%s",
			bucketName, objectPath)

		metadata := map[string]interface{}{
			"metadata": map[string]string{
				"updated":   "true",
				"timestamp": fmt.Sprintf("%d", time.Now().Unix()),
			},
		}
		metadataJSON, _ := json.Marshal(metadata)

		resp, err = auth.MakeAuthenticatedRequestWithBody("PATCH", metadataURL, string(metadataJSON),
			state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)

	default:
		return types.WriteTestResult{
			TestCase: testCase,
			Success:  false,
			Error:    fmt.Errorf("unknown Storage operation: %s", testCase.Operation),
		}
	}

	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return types.WriteTestResult{
			TestCase: testCase,
			Success:  false,
			Error:    fmt.Errorf("request failed: %v", err),
		}
	}

	// Parse response
	var responseData map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&responseData)

	// Check if operation was successful
	success := resp.StatusCode >= 200 && resp.StatusCode < 300

	result := types.WriteTestResult{
		TestCase: testCase,
		Success:  success,
		Response: responseData,
	}

	if !success {
		result.Error = fmt.Errorf("operation failed with HTTP %d", resp.StatusCode)
	}

	return result
}
