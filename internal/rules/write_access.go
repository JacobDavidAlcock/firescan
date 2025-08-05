package rules

import (
	"fmt"
	"time"

	"firescan/internal/config"
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
	// This would implement actual Firestore write testing
	// For now, return mock results
	
	switch testCase.Operation {
	case "create":
		return types.WriteTestResult{
			TestCase: testCase,
			Success:  true,
			Error:    nil,
			Response: map[string]interface{}{"document_created": true, "path": testCase.Path},
		}
	case "update":
		return types.WriteTestResult{
			TestCase: testCase,
			Success:  true,
			Error:    nil,
			Response: map[string]interface{}{"document_updated": true, "path": testCase.Path},
		}
	case "delete":
		return types.WriteTestResult{
			TestCase: testCase,
			Success:  true,
			Error:    nil,
			Response: map[string]interface{}{"document_deleted": true, "path": testCase.Path},
		}
	default:
		return types.WriteTestResult{
			TestCase: testCase,
			Success:  false,
			Error:    fmt.Errorf("unknown Firestore operation: %s", testCase.Operation),
		}
	}
}

// executeRTDBWriteTest executes RTDB write operations
func executeRTDBWriteTest(testCase types.WriteTestCase) types.WriteTestResult {
	// This would implement actual RTDB write testing
	// For now, return mock results
	
	return types.WriteTestResult{
		TestCase: testCase,
		Success:  true,
		Error:    nil,
		Response: map[string]interface{}{"rtdb_operation": testCase.Operation, "path": testCase.Path},
	}
}

// executeStorageWriteTest executes Storage write operations
func executeStorageWriteTest(testCase types.WriteTestCase) types.WriteTestResult {
	// This would implement actual Storage write testing
	// For now, return mock results
	
	return types.WriteTestResult{
		TestCase: testCase,
		Success:  true,
		Error:    nil,
		Response: map[string]interface{}{"storage_operation": testCase.Operation, "file": testCase.Path},
	}
}