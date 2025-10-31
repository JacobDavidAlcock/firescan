package rules

import (
	"testing"

	"firescan/internal/types"
)

func TestTestWriteAccess_ModeValidation(t *testing.T) {
	tests := []struct {
		name        string
		mode        types.ScanMode
		services    []string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "probe mode - should fail",
			mode:        types.ProbeMode,
			services:    []string{"firestore"},
			shouldError: true,
			errorMsg:    "write access testing requires test mode or higher",
		},
		{
			name:        "test mode - should work",
			mode:        types.TestMode,
			services:    []string{"firestore"},
			shouldError: false,
		},
		{
			name:        "audit mode - should work",
			mode:        types.AuditMode,
			services:    []string{"firestore"},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := TestWriteAccess(tt.mode, tt.services)

			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if err.Error() != tt.errorMsg {
					t.Errorf("Expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
			}
		})
	}
}

func TestWriteTestCase_Validation(t *testing.T) {
	tests := []struct {
		name     string
		testCase types.WriteTestCase
		valid    bool
	}{
		{
			name: "valid firestore create",
			testCase: types.WriteTestCase{
				ID:          "test1",
				Service:     "firestore",
				Path:        "users",
				Operation:   "create",
				Expected:    true,
				Description: "Test create access",
				SafetyLevel: types.TestMode,
			},
			valid: true,
		},
		{
			name: "valid rtdb update",
			testCase: types.WriteTestCase{
				ID:          "test2",
				Service:     "rtdb",
				Path:        "data",
				Operation:   "update",
				Expected:    false,
				Description: "Test update access",
				SafetyLevel: types.TestMode,
			},
			valid: true,
		},
		{
			name: "valid storage upload",
			testCase: types.WriteTestCase{
				ID:          "test3",
				Service:     "storage",
				Path:        "files",
				Operation:   "upload",
				Expected:    true,
				Description: "Test upload access",
				SafetyLevel: types.TestMode,
			},
			valid: true,
		},
		{
			name: "invalid service",
			testCase: types.WriteTestCase{
				ID:          "test4",
				Service:     "invalid",
				Path:        "data",
				Operation:   "create",
				SafetyLevel: types.TestMode,
			},
			valid: false,
		},
		{
			name: "empty path",
			testCase: types.WriteTestCase{
				ID:          "test5",
				Service:     "firestore",
				Path:        "",
				Operation:   "create",
				SafetyLevel: types.TestMode,
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate service
			validServices := map[string]bool{"firestore": true, "rtdb": true, "storage": true}
			if !validServices[tt.testCase.Service] && tt.valid {
				t.Errorf("Invalid service: %s", tt.testCase.Service)
			}

			// Validate path
			if tt.testCase.Path == "" && tt.valid {
				t.Error("Expected valid test case to have non-empty path")
			}

			// Validate operation
			validOps := map[string]bool{
				"create": true, "update": true, "delete": true,
				"upload": true, // storage specific
			}
			if tt.testCase.Operation != "" && !validOps[tt.testCase.Operation] && tt.valid {
				t.Errorf("Invalid operation: %s", tt.testCase.Operation)
			}
		})
	}
}

func TestGenerateTestCases(t *testing.T) {
	tests := []struct {
		name     string
		services []string
		mode     types.ScanMode
		minCount int
	}{
		{
			name:     "firestore only",
			services: []string{"firestore"},
			mode:     types.TestMode,
			minCount: 1,
		},
		{
			name:     "rtdb only",
			services: []string{"rtdb"},
			mode:     types.TestMode,
			minCount: 1,
		},
		{
			name:     "storage only",
			services: []string{"storage"},
			mode:     types.TestMode,
			minCount: 1,
		},
		{
			name:     "all services",
			services: []string{"firestore", "rtdb", "storage"},
			mode:     types.TestMode,
			minCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testCases := generateWriteTestCases(tt.mode, tt.services)

			if len(testCases) < tt.minCount {
				t.Errorf("Expected at least %d test cases, got %d", tt.minCount, len(testCases))
			}

			// Verify all test cases have required fields
			for i, tc := range testCases {
				if tc.ID == "" {
					t.Errorf("Test case %d missing ID", i)
				}
				if tc.Service == "" {
					t.Errorf("Test case %d missing Service", i)
				}
				if tc.Path == "" {
					t.Errorf("Test case %d missing Path", i)
				}
				if tc.Operation == "" {
					t.Errorf("Test case %d missing Operation", i)
				}
			}
		})
	}
}
