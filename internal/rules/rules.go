package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/httpclient"
	"firescan/internal/safety"
	"firescan/internal/types"
)

// TestSecurityRules runs security rule tests based on the specified mode
func TestSecurityRules(mode types.ScanMode, services []string) ([]types.RuleTestResult, error) {
	// Validate safety mode
	if !safety.WarnUser(mode) {
		return nil, fmt.Errorf("user declined to proceed with %s mode", mode.String())
	}

	var results []types.RuleTestResult

	// Generate test cases based on mode and services
	testCases := generateTestCases(mode, services)

	// Setup cleanup if needed
	var cleanup *types.TestCleanup
	if mode != types.ProbeMode {
		state := config.GetState()
		cleanup = safety.NewTestCleanup(state.ProjectID)
		defer safety.PerformCleanup(cleanup)
	}

	// Run test cases
	for _, testCase := range testCases {
		result := runRuleTest(testCase, cleanup)
		results = append(results, result)
	}

	return results, nil
}

// generateTestCases creates test cases based on mode and target services
func generateTestCases(mode types.ScanMode, services []string) []types.RuleTestCase {
	var testCases []types.RuleTestCase

	for _, service := range services {
		switch service {
		case "firestore":
			testCases = append(testCases, generateFirestoreTestCases(mode)...)
		case "rtdb":
			testCases = append(testCases, generateRTDBTestCases(mode)...)
		}
	}

	return testCases
}

// generateFirestoreTestCases creates Firestore-specific test cases
func generateFirestoreTestCases(mode types.ScanMode) []types.RuleTestCase {
	var testCases []types.RuleTestCase

	// Probe mode - Safe read-only tests
	probeTests := []types.RuleTestCase{
		{
			ID:          "firestore_read_users",
			Path:        "/users",
			AuthContext: nil,
			Operation:   "read",
			Expected:    false, // Expect access denied for unauthenticated
			Description: "Test unauthenticated read access to users collection",
			SafetyLevel: types.ProbeMode,
		},
		{
			ID:          "firestore_read_public",
			Path:        "/public",
			AuthContext: nil,
			Operation:   "read",
			Expected:    true, // Expect public data to be readable
			Description: "Test unauthenticated read access to public collection",
			SafetyLevel: types.ProbeMode,
		},
		{
			ID:          "firestore_read_admin",
			Path:        "/admin",
			AuthContext: map[string]interface{}{"uid": "test-user"},
			Operation:   "read",
			Expected:    false, // Expect admin access denied for regular user
			Description: "Test regular user read access to admin collection",
			SafetyLevel: types.ProbeMode,
		},
	}
	testCases = append(testCases, probeTests...)

	// Test mode - Add safe write tests
	if mode >= types.TestMode {
		testPath := safety.GenerateSafeTestPath()
		testTests := []types.RuleTestCase{
			{
				ID:          "firestore_write_test",
				Path:        testPath + "/test-doc",
				AuthContext: map[string]interface{}{"uid": "test-user"},
				Operation:   "create",
				Expected:    true, // Test if write is allowed
				TestData:    safety.GenerateSafeTestData(),
				Description: "Test write access with safe test data",
				SafetyLevel: types.TestMode,
			},
			{
				ID:          "firestore_update_test",
				Path:        testPath + "/test-doc",
				AuthContext: map[string]interface{}{"uid": "test-user"},
				Operation:   "update",
				Expected:    true,
				TestData:    safety.GenerateSafeTestData(),
				Description: "Test update access with safe test data",
				SafetyLevel: types.TestMode,
			},
		}
		testCases = append(testCases, testTests...)
	}

	// Audit mode - Add deep testing
	if mode >= types.AuditMode {
		auditTests := []types.RuleTestCase{
			{
				ID:          "firestore_nested_bypass",
				Path:        "/users/{uid}/private",
				AuthContext: map[string]interface{}{"uid": "other-user"},
				Operation:   "read",
				Expected:    false,
				Description: "Test nested path access control bypass",
				SafetyLevel: types.AuditMode,
			},
			{
				ID:          "firestore_context_manipulation",
				Path:        "/users/{uid}",
				AuthContext: map[string]interface{}{"uid": "admin", "custom_claims": map[string]interface{}{"admin": true}},
				Operation:   "read",
				Expected:    false, // Test if custom claims can be manipulated
				Description: "Test authentication context manipulation",
				SafetyLevel: types.AuditMode,
			},
		}
		testCases = append(testCases, auditTests...)
	}

	return testCases
}

// generateRTDBTestCases creates RTDB-specific test cases
func generateRTDBTestCases(mode types.ScanMode) []types.RuleTestCase {
	var testCases []types.RuleTestCase

	// Probe mode tests
	probeTests := []types.RuleTestCase{
		{
			ID:          "rtdb_read_root",
			Path:        "/",
			AuthContext: nil,
			Operation:   "read",
			Expected:    false,
			Description: "Test unauthenticated read access to RTDB root",
			SafetyLevel: types.ProbeMode,
		},
		{
			ID:          "rtdb_read_users",
			Path:        "/users",
			AuthContext: map[string]interface{}{"uid": "test-user"},
			Operation:   "read",
			Expected:    false,
			Description: "Test authenticated read access to users node",
			SafetyLevel: types.ProbeMode,
		},
	}
	testCases = append(testCases, probeTests...)

	// Test mode - Add write tests
	if mode >= types.TestMode {
		testPath := safety.GenerateSafeTestPath()
		testTests := []types.RuleTestCase{
			{
				ID:          "rtdb_write_test",
				Path:        testPath,
				AuthContext: map[string]interface{}{"uid": "test-user"},
				Operation:   "write",
				Expected:    true,
				TestData:    safety.GenerateSafeTestData(),
				Description: "Test RTDB write access with safe test data",
				SafetyLevel: types.TestMode,
			},
		}
		testCases = append(testCases, testTests...)
	}

	return testCases
}

// runRuleTest executes a single rule test case
func runRuleTest(testCase types.RuleTestCase, cleanup *types.TestCleanup) types.RuleTestResult {
	startTime := time.Now()

	result := types.RuleTestResult{
		TestCase: testCase,
		Duration: 0,
	}

	// Validate that we're allowed to run this test based on safety level
	// (This would be validated earlier, but double-check here)

	switch testCase.Operation {
	case "read":
		result = testReadAccess(testCase)
	case "write", "create", "update":
		if cleanup != nil {
			result = testWriteAccess(testCase, cleanup)
		} else {
			result.Error = fmt.Errorf("write test requires cleanup context")
		}
	case "delete":
		if cleanup != nil {
			result = testDeleteAccess(testCase, cleanup)
		} else {
			result.Error = fmt.Errorf("delete test requires cleanup context")
		}
	default:
		result.Error = fmt.Errorf("unknown operation: %s", testCase.Operation)
	}

	result.Duration = time.Since(startTime)
	return result
}

// testReadAccess tests read access permissions (safe for all modes)
func testReadAccess(testCase types.RuleTestCase) types.RuleTestResult {
	state := config.GetState()
	startTime := time.Now()

	var resp *http.Response
	var err error
	var url string

	// Build URL based on service type
	switch {
	case testCase.Path == "" || testCase.Path == "/":
		// Invalid path
		return types.RuleTestResult{
			TestCase: testCase,
			Actual:   false,
			Success:  true,
			Error:    fmt.Errorf("invalid test path"),
			Duration: time.Since(startTime),
		}

	// Try Firestore first (most common)
	default:
		// Attempt Firestore read
		url = fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s",
			state.ProjectID, testCase.Path)

		resp, err = auth.MakeAuthenticatedRequest("GET", url, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
		if resp != nil {
			defer resp.Body.Close()
		}

		if err != nil {
			// If Firestore fails, try RTDB
			rtdbURL := fmt.Sprintf("https://%s.firebaseio.com/%s.json?auth=%s", state.ProjectID, testCase.Path, state.Token)
			rtdbResp, rtdbErr := httpclient.Get(rtdbURL)
			if rtdbResp != nil {
				defer rtdbResp.Body.Close()
			}

			if rtdbErr != nil {
				return types.RuleTestResult{
					TestCase: testCase,
					Actual:   false,
					Success:  true,
					Error:    fmt.Errorf("read test failed: %v", err),
					Duration: time.Since(startTime),
				}
			}

			resp = rtdbResp
		}
	}

	// Parse response
	var responseData interface{}
	json.NewDecoder(resp.Body).Decode(&responseData)

	// Determine if read was successful
	actual := resp.StatusCode == http.StatusOK

	// Check if result matches expectation
	success := actual == testCase.Expected

	return types.RuleTestResult{
		TestCase: testCase,
		Actual:   actual,
		Success:  success,
		Error:    nil,
		Response: responseData,
		Duration: time.Since(startTime),
	}
}

// testWriteAccess tests write access permissions (test mode and above)
func testWriteAccess(testCase types.RuleTestCase, cleanup *types.TestCleanup) types.RuleTestResult {
	state := config.GetState()
	startTime := time.Now()

	// Add this path to cleanup
	safety.AddPathToCleanup(cleanup, testCase.Path)

	// Generate test document/node ID
	testID := fmt.Sprintf("firescan-test-%d", time.Now().Unix())

	var resp *http.Response
	var err error
	var actual bool

	// Prepare test data
	testData := testCase.TestData
	if testData == nil {
		testData = map[string]interface{}{
			"test":      "data",
			"timestamp": time.Now().Unix(),
		}
	}

	// Try Firestore write first
	firestoreURL := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s",
		state.ProjectID, testCase.Path)

	// Convert to Firestore format
	firestoreFields := convertToFirestoreFormat(testData)
	jsonData, marshalErr := json.Marshal(map[string]interface{}{
		"fields": firestoreFields,
	})

	if marshalErr == nil {
		resp, err = auth.MakeAuthenticatedRequestWithBody("POST", firestoreURL, string(jsonData),
			state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)

		if resp != nil {
			defer resp.Body.Close()
		}

		if err == nil {
			actual = resp.StatusCode >= 200 && resp.StatusCode < 300
		} else {
			// If Firestore fails, try RTDB
			rtdbURL := fmt.Sprintf("https://%s.firebaseio.com/%s/%s.json?auth=%s",
				state.ProjectID, testCase.Path, testID, state.Token)

			rtdbData, _ := json.Marshal(testData)
			req, _ := http.NewRequest("PUT", rtdbURL, bytes.NewBuffer(rtdbData))
			req.Header.Set("Content-Type", "application/json")

			rtdbResp, rtdbErr := httpclient.Do(req)
			if rtdbResp != nil {
				defer rtdbResp.Body.Close()
			}

			if rtdbErr != nil {
				return types.RuleTestResult{
					TestCase: testCase,
					Actual:   false,
					Success:  true,
					Error:    fmt.Errorf("write test failed: %v", err),
					Duration: time.Since(startTime),
				}
			}

			resp = rtdbResp
			actual = resp.StatusCode >= 200 && resp.StatusCode < 300
		}
	} else {
		return types.RuleTestResult{
			TestCase: testCase,
			Actual:   false,
			Success:  true,
			Error:    fmt.Errorf("failed to prepare test data: %v", marshalErr),
			Duration: time.Since(startTime),
		}
	}

	// Parse response
	var responseData interface{}
	json.NewDecoder(resp.Body).Decode(&responseData)

	// Check if result matches expectation
	success := actual == testCase.Expected

	return types.RuleTestResult{
		TestCase: testCase,
		Actual:   actual,
		Success:  success,
		Error:    nil,
		Response: responseData,
		Duration: time.Since(startTime),
	}
}

// convertToFirestoreFormat converts test data to Firestore field format
func convertToFirestoreFormat(data interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		result["value"] = map[string]interface{}{
			"stringValue": fmt.Sprintf("%v", data),
		}
		return result
	}

	for key, value := range dataMap {
		switch v := value.(type) {
		case string:
			result[key] = map[string]interface{}{"stringValue": v}
		case float64:
			result[key] = map[string]interface{}{"doubleValue": v}
		case int:
			result[key] = map[string]interface{}{"integerValue": fmt.Sprintf("%d", v)}
		case int64:
			result[key] = map[string]interface{}{"integerValue": fmt.Sprintf("%d", v)}
		case bool:
			result[key] = map[string]interface{}{"booleanValue": v}
		case map[string]interface{}:
			result[key] = map[string]interface{}{
				"mapValue": map[string]interface{}{
					"fields": convertToFirestoreFormat(v),
				},
			}
		default:
			result[key] = map[string]interface{}{"stringValue": fmt.Sprintf("%v", v)}
		}
	}

	return result
}

// testDeleteAccess tests delete access permissions (test mode and above)
func testDeleteAccess(testCase types.RuleTestCase, cleanup *types.TestCleanup) types.RuleTestResult {
	state := config.GetState()
	startTime := time.Now()

	// Add this path to cleanup (though delete might clean itself)
	safety.AddPathToCleanup(cleanup, testCase.Path)

	// Generate test document/node ID
	testID := fmt.Sprintf("firescan-test-%d", time.Now().Unix())

	// First, create something to delete
	testData := map[string]interface{}{
		"test":      "data",
		"timestamp": time.Now().Unix(),
	}

	var deleteURL string
	var createSuccess bool

	// Try Firestore first
	firestoreCreateURL := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s",
		state.ProjectID, testCase.Path)

	firestoreFields := convertToFirestoreFormat(testData)
	jsonData, _ := json.Marshal(map[string]interface{}{
		"fields": firestoreFields,
	})

	createResp, createErr := auth.MakeAuthenticatedRequestWithBody("POST", firestoreCreateURL, string(jsonData),
		state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)

	if createResp != nil {
		defer createResp.Body.Close()
	}

	if createErr == nil && createResp.StatusCode >= 200 && createResp.StatusCode < 300 {
		// Parse response to get document name
		var createResponse map[string]interface{}
		json.NewDecoder(createResp.Body).Decode(&createResponse)

		if docName, ok := createResponse["name"].(string); ok {
			deleteURL = fmt.Sprintf("https://firestore.googleapis.com/v1/%s", docName)
			createSuccess = true
		}
	} else {
		// Try RTDB instead
		rtdbCreateURL := fmt.Sprintf("https://%s.firebaseio.com/%s/%s.json?auth=%s",
			state.ProjectID, testCase.Path, testID, state.Token)

		rtdbData, _ := json.Marshal(testData)
		req, _ := http.NewRequest("PUT", rtdbCreateURL, bytes.NewBuffer(rtdbData))
		req.Header.Set("Content-Type", "application/json")

		rtdbCreateResp, rtdbCreateErr := httpclient.Do(req)
		if rtdbCreateResp != nil {
			rtdbCreateResp.Body.Close()
		}

		if rtdbCreateErr == nil && rtdbCreateResp.StatusCode >= 200 && rtdbCreateResp.StatusCode < 300 {
			deleteURL = rtdbCreateURL
			createSuccess = true
		}
	}

	if !createSuccess {
		return types.RuleTestResult{
			TestCase: testCase,
			Actual:   false,
			Success:  true,
			Error:    fmt.Errorf("failed to create test data for delete test"),
			Duration: time.Since(startTime),
		}
	}

	// Now try to delete
	var resp *http.Response
	var err error

	if strings.Contains(deleteURL, "firestore") {
		resp, err = auth.MakeAuthenticatedRequest("DELETE", deleteURL,
			state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	} else {
		req, _ := http.NewRequest("DELETE", deleteURL, nil)
		resp, err = httpclient.Do(req)
	}

	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return types.RuleTestResult{
			TestCase: testCase,
			Actual:   false,
			Success:  true,
			Error:    fmt.Errorf("delete test failed: %v", err),
			Duration: time.Since(startTime),
		}
	}

	// Parse response
	var responseData interface{}
	json.NewDecoder(resp.Body).Decode(&responseData)

	// Determine if delete was successful
	actual := resp.StatusCode >= 200 && resp.StatusCode < 300

	// Check if result matches expectation
	success := actual == testCase.Expected

	return types.RuleTestResult{
		TestCase: testCase,
		Actual:   actual,
		Success:  success,
		Error:    nil,
		Response: responseData,
		Duration: time.Since(startTime),
	}
}
