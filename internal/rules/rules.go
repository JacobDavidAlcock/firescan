package rules

import (
	"fmt"
	"time"

	"firescan/internal/config"
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
	// This would implement actual read testing logic
	// For now, return a mock result
	return types.RuleTestResult{
		TestCase: testCase,
		Actual:   false, // Mock result
		Success:  true,
		Error:    nil,
		Response: map[string]interface{}{"status": "access_denied"},
	}
}

// testWriteAccess tests write access permissions (test mode and above)
func testWriteAccess(testCase types.RuleTestCase, cleanup *types.TestCleanup) types.RuleTestResult {
	// Add this path to cleanup
	safety.AddPathToCleanup(cleanup, testCase.Path)
	
	// This would implement actual write testing logic
	// For now, return a mock result
	return types.RuleTestResult{
		TestCase: testCase,
		Actual:   true, // Mock result - write succeeded
		Success:  true,
		Error:    nil,
		Response: map[string]interface{}{"status": "write_successful", "test_data_created": true},
	}
}

// testDeleteAccess tests delete access permissions (test mode and above)
func testDeleteAccess(testCase types.RuleTestCase, cleanup *types.TestCleanup) types.RuleTestResult {
	// Add this path to cleanup (though delete might clean itself)
	safety.AddPathToCleanup(cleanup, testCase.Path)
	
	// This would implement actual delete testing logic
	// For now, return a mock result
	return types.RuleTestResult{
		TestCase: testCase,
		Actual:   false, // Mock result - delete denied
		Success:  true,
		Error:    nil,
		Response: map[string]interface{}{"status": "delete_denied"},
	}
}