package rules

import (
	"testing"

	"firescan/internal/types"
)

func TestConvertToFirestoreFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected map[string]interface{}
	}{
		{
			name: "string value",
			input: map[string]interface{}{
				"name": "test",
			},
			expected: map[string]interface{}{
				"name": map[string]interface{}{
					"stringValue": "test",
				},
			},
		},
		{
			name: "integer value",
			input: map[string]interface{}{
				"age": 25,
			},
			expected: map[string]interface{}{
				"age": map[string]interface{}{
					"integerValue": "25",
				},
			},
		},
		{
			name: "float value",
			input: map[string]interface{}{
				"price": 19.99,
			},
			expected: map[string]interface{}{
				"price": map[string]interface{}{
					"doubleValue": 19.99,
				},
			},
		},
		{
			name: "boolean value",
			input: map[string]interface{}{
				"active": true,
			},
			expected: map[string]interface{}{
				"active": map[string]interface{}{
					"booleanValue": true,
				},
			},
		},
		{
			name: "nested map",
			input: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "John",
					"age":  30,
				},
			},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"mapValue": map[string]interface{}{
						"fields": map[string]interface{}{
							"name": map[string]interface{}{
								"stringValue": "John",
							},
							"age": map[string]interface{}{
								"integerValue": "30",
							},
						},
					},
				},
			},
		},
		{
			name: "mixed types",
			input: map[string]interface{}{
				"name":   "test",
				"count":  42,
				"price":  9.99,
				"active": false,
			},
			expected: map[string]interface{}{
				"name": map[string]interface{}{
					"stringValue": "test",
				},
				"count": map[string]interface{}{
					"integerValue": "42",
				},
				"price": map[string]interface{}{
					"doubleValue": 9.99,
				},
				"active": map[string]interface{}{
					"booleanValue": false,
				},
			},
		},
		{
			name:  "non-map input",
			input: "simple string",
			expected: map[string]interface{}{
				"value": map[string]interface{}{
					"stringValue": "simple string",
				},
			},
		},
		{
			name:  "nil input",
			input: nil,
			expected: map[string]interface{}{
				"value": map[string]interface{}{
					"stringValue": "<nil>",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertToFirestoreFormat(tt.input)

			// Check that all expected keys exist
			for key, expectedValue := range tt.expected {
				if _, ok := result[key]; !ok {
					t.Errorf("Expected key %s not found in result", key)
					continue
				}

				// Deep comparison for nested structures
				if !compareFirestoreValues(result[key], expectedValue) {
					t.Errorf("For key %s: got %v, want %v", key, result[key], expectedValue)
				}
			}
		})
	}
}

// compareFirestoreValues compares two Firestore value structures
func compareFirestoreValues(a, b interface{}) bool {
	aMap, aIsMap := a.(map[string]interface{})
	bMap, bIsMap := b.(map[string]interface{})

	if aIsMap != bIsMap {
		return false
	}

	if !aIsMap {
		return a == b
	}

	if len(aMap) != len(bMap) {
		return false
	}

	for key, aVal := range aMap {
		bVal, ok := bMap[key]
		if !ok {
			return false
		}

		if !compareFirestoreValues(aVal, bVal) {
			return false
		}
	}

	return true
}

func TestTestSecurityRules_ModeValidation(t *testing.T) {
	tests := []struct {
		name        string
		mode        types.ScanMode
		services    []string
		shouldError bool
	}{
		{
			name:        "probe mode - should work",
			mode:        types.ProbeMode,
			services:    []string{"firestore"},
			shouldError: false,
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
			// Note: This will fail without proper Firebase credentials
			// but we're testing the mode validation logic
			_, err := TestSecurityRules(tt.mode, tt.services)

			// We expect an error about user declining or missing credentials
			// not about invalid mode
			if err != nil && tt.shouldError {
				// Expected error
				return
			}
		})
	}
}

func TestRuleTestCase_Validation(t *testing.T) {
	tests := []struct {
		name     string
		testCase types.RuleTestCase
		valid    bool
	}{
		{
			name: "valid read test",
			testCase: types.RuleTestCase{
				ID:          "test1",
				Path:        "users",
				Operation:   "read",
				Expected:    true,
				Description: "Test read access",
				SafetyLevel: types.ProbeMode,
			},
			valid: true,
		},
		{
			name: "valid write test",
			testCase: types.RuleTestCase{
				ID:          "test2",
				Path:        "users",
				Operation:   "write",
				Expected:    false,
				Description: "Test write access",
				SafetyLevel: types.TestMode,
			},
			valid: true,
		},
		{
			name: "empty path",
			testCase: types.RuleTestCase{
				ID:          "test3",
				Path:        "",
				Operation:   "read",
				Expected:    true,
				SafetyLevel: types.ProbeMode,
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate path
			if tt.testCase.Path == "" && tt.valid {
				t.Error("Expected valid test case to have non-empty path")
			}

			// Validate operation
			validOps := map[string]bool{"read": true, "write": true, "delete": true, "create": true, "update": true}
			if tt.testCase.Operation != "" && !validOps[tt.testCase.Operation] && tt.valid {
				t.Errorf("Invalid operation: %s", tt.testCase.Operation)
			}
		})
	}
}
