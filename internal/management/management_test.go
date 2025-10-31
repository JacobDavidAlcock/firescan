package management

import (
	"testing"

	"firescan/internal/types"
)

func TestMaskAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard API key",
			input:    "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			expected: "AIza****XXXX",
		},
		{
			name:     "short key",
			input:    "short",
			expected: "****",
		},
		{
			name:     "empty key",
			input:    "",
			expected: "****",
		},
		{
			name:     "exact 8 chars",
			input:    "12345678",
			expected: "****",
		},
		{
			name:     "9 chars",
			input:    "123456789",
			expected: "1234****6789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskAPIKey(tt.input)
			if result != tt.expected {
				t.Errorf("maskAPIKey(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTestAPIKeyRestrictions_UnrestrictedKey(t *testing.T) {
	state := types.State{
		ProjectID: "test-project",
	}

	// Test unrestricted key (no restrictions field)
	keys := []interface{}{
		map[string]interface{}{
			"keyString": "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			"name":      "projects/test/keys/key1",
		},
	}

	results := testAPIKeyRestrictions(keys, state, types.ProbeMode)

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	result := results[0]
	if result.Severity != "High" {
		t.Errorf("Expected severity 'High', got '%s'", result.Severity)
	}

	if result.Details["unrestricted"] != true {
		t.Error("Expected unrestricted flag to be true")
	}

	if result.Finding == "" {
		t.Error("Expected finding message for unrestricted key")
	}
}

func TestTestAPIKeyRestrictions_WildcardReferrer(t *testing.T) {
	state := types.State{
		ProjectID: "test-project",
	}

	// Test key with wildcard referrer restriction
	keys := []interface{}{
		map[string]interface{}{
			"keyString": "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			"name":      "projects/test/keys/key1",
			"restrictions": map[string]interface{}{
				"browserKeyRestrictions": map[string]interface{}{
					"allowedReferrers": []interface{}{"*"},
				},
			},
		},
	}

	results := testAPIKeyRestrictions(keys, state, types.ProbeMode)

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	result := results[0]
	if result.Severity != "Medium" {
		t.Errorf("Expected severity 'Medium', got '%s'", result.Severity)
	}

	weaknesses, ok := result.Details["weaknesses"].([]string)
	if !ok || len(weaknesses) == 0 {
		t.Error("Expected weaknesses to be reported")
	}

	foundWildcard := false
	for _, w := range weaknesses {
		if w == "Wildcard referrer restriction allows any domain" {
			foundWildcard = true
			break
		}
	}
	if !foundWildcard {
		t.Error("Expected wildcard referrer weakness to be detected")
	}
}

func TestTestAPIKeyRestrictions_BroadIPRange(t *testing.T) {
	state := types.State{
		ProjectID: "test-project",
	}

	// Test key with overly broad IP restriction
	keys := []interface{}{
		map[string]interface{}{
			"keyString": "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			"name":      "projects/test/keys/key1",
			"restrictions": map[string]interface{}{
				"serverKeyRestrictions": map[string]interface{}{
					"allowedIps": []interface{}{"0.0.0.0/0"},
				},
			},
		},
	}

	results := testAPIKeyRestrictions(keys, state, types.ProbeMode)

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	result := results[0]
	weaknesses, ok := result.Details["weaknesses"].([]string)
	if !ok || len(weaknesses) == 0 {
		t.Error("Expected weaknesses to be reported")
	}

	foundBroadIP := false
	for _, w := range weaknesses {
		if w == "IP restriction allows all addresses" {
			foundBroadIP = true
			break
		}
	}
	if !foundBroadIP {
		t.Error("Expected broad IP range weakness to be detected")
	}
}

func TestTestAPIKeyRestrictions_NoAPIRestrictions(t *testing.T) {
	state := types.State{
		ProjectID: "test-project",
	}

	// Test key with no API service restrictions
	keys := []interface{}{
		map[string]interface{}{
			"keyString": "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			"name":      "projects/test/keys/key1",
			"restrictions": map[string]interface{}{
				"browserKeyRestrictions": map[string]interface{}{
					"allowedReferrers": []interface{}{"https://example.com/*"},
				},
				// No apiTargets field
			},
		},
	}

	results := testAPIKeyRestrictions(keys, state, types.ProbeMode)

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	result := results[0]
	weaknesses, ok := result.Details["weaknesses"].([]string)
	if !ok || len(weaknesses) == 0 {
		t.Error("Expected weaknesses to be reported")
	}

	foundNoAPI := false
	for _, w := range weaknesses {
		if w == "No API service restrictions - key can access all Firebase/GCP APIs" {
			foundNoAPI = true
			break
		}
	}
	if !foundNoAPI {
		t.Error("Expected no API restrictions weakness to be detected")
	}
}

func TestTestAPIKeyRestrictions_ProperRestrictions(t *testing.T) {
	state := types.State{
		ProjectID: "test-project",
	}

	// Test key with proper restrictions
	keys := []interface{}{
		map[string]interface{}{
			"keyString": "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			"name":      "projects/test/keys/key1",
			"restrictions": map[string]interface{}{
				"browserKeyRestrictions": map[string]interface{}{
					"allowedReferrers": []interface{}{"https://example.com/*"},
				},
				"apiTargets": []interface{}{
					map[string]interface{}{"service": "firestore.googleapis.com"},
					map[string]interface{}{"service": "identitytoolkit.googleapis.com"},
				},
			},
		},
	}

	results := testAPIKeyRestrictions(keys, state, types.ProbeMode)

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	result := results[0]
	if result.Severity != "Info" {
		t.Errorf("Expected severity 'Info', got '%s'", result.Severity)
	}

	weaknesses, ok := result.Details["weaknesses"].([]string)
	if ok && len(weaknesses) > 0 {
		t.Errorf("Expected no weaknesses, got %v", weaknesses)
	}
}

func TestTestAPIKeyRestrictions_AndroidRestrictions(t *testing.T) {
	state := types.State{
		ProjectID: "test-project",
	}

	// Test key with Android app restrictions
	keys := []interface{}{
		map[string]interface{}{
			"keyString": "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			"name":      "projects/test/keys/key1",
			"restrictions": map[string]interface{}{
				"androidKeyRestrictions": map[string]interface{}{
					"allowedApplications": []interface{}{
						map[string]interface{}{
							"packageName":     "com.example.app",
							"sha1Fingerprint": "AA:BB:CC:DD:EE:FF",
						},
					},
				},
				"apiTargets": []interface{}{
					map[string]interface{}{"service": "firestore.googleapis.com"},
				},
			},
		},
	}

	results := testAPIKeyRestrictions(keys, state, types.ProbeMode)

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	result := results[0]
	restrictionTypes, ok := result.Details["restriction_types"].([]string)
	if !ok {
		t.Fatal("Expected restriction_types in details")
	}

	foundAndroid := false
	for _, rt := range restrictionTypes {
		if rt == "Android App" {
			foundAndroid = true
			break
		}
	}
	if !foundAndroid {
		t.Error("Expected Android App restriction type to be detected")
	}
}

func TestTestAPIKeyRestrictions_iOSRestrictions(t *testing.T) {
	state := types.State{
		ProjectID: "test-project",
	}

	// Test key with iOS app restrictions
	keys := []interface{}{
		map[string]interface{}{
			"keyString": "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			"name":      "projects/test/keys/key1",
			"restrictions": map[string]interface{}{
				"iosKeyRestrictions": map[string]interface{}{
					"allowedBundleIds": []interface{}{"com.example.app"},
				},
				"apiTargets": []interface{}{
					map[string]interface{}{"service": "firestore.googleapis.com"},
				},
			},
		},
	}

	results := testAPIKeyRestrictions(keys, state, types.ProbeMode)

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	result := results[0]
	restrictionTypes, ok := result.Details["restriction_types"].([]string)
	if !ok {
		t.Fatal("Expected restriction_types in details")
	}

	foundiOS := false
	for _, rt := range restrictionTypes {
		if rt == "iOS App" {
			foundiOS = true
			break
		}
	}
	if !foundiOS {
		t.Error("Expected iOS App restriction type to be detected")
	}
}

func TestTestAPIKeyRestrictions_MultipleKeys(t *testing.T) {
	state := types.State{
		ProjectID: "test-project",
	}

	// Test multiple keys with different restriction levels
	keys := []interface{}{
		map[string]interface{}{
			"keyString": "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			"name":      "projects/test/keys/key1",
			// No restrictions
		},
		map[string]interface{}{
			"keyString": "AIzaSyDYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
			"name":      "projects/test/keys/key2",
			"restrictions": map[string]interface{}{
				"browserKeyRestrictions": map[string]interface{}{
					"allowedReferrers": []interface{}{"https://example.com/*"},
				},
				"apiTargets": []interface{}{
					map[string]interface{}{"service": "firestore.googleapis.com"},
				},
			},
		},
	}

	results := testAPIKeyRestrictions(keys, state, types.ProbeMode)

	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}

	// First key should be unrestricted (High severity)
	if results[0].Severity != "High" {
		t.Errorf("Expected first key severity 'High', got '%s'", results[0].Severity)
	}

	// Second key should be properly restricted (Info severity)
	if results[1].Severity != "Info" {
		t.Errorf("Expected second key severity 'Info', got '%s'", results[1].Severity)
	}
}

func TestTestAPIKeyRestrictions_WebAppConfigFormat(t *testing.T) {
	state := types.State{
		ProjectID: "test-project",
	}

	// Test web app config format (different structure)
	keys := map[string]interface{}{
		"apiKey": "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	}

	results := testAPIKeyRestrictions(keys, state, types.ProbeMode)

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Web app config format doesn't include restrictions, so should be flagged as unrestricted
	result := results[0]
	if result.Severity != "High" {
		t.Errorf("Expected severity 'High' for web app config without restrictions, got '%s'", result.Severity)
	}
}

func TestGetAPIBaseURL(t *testing.T) {
	tests := []struct {
		apiVersion string
		expected   string
	}{
		{"firebase", "https://firebase.googleapis.com"},
		{"cloudresourcemanager", "https://cloudresourcemanager.googleapis.com"},
		{"iam", "https://iam.googleapis.com"},
		{"apikeys", "https://apikeys.googleapis.com"},
	}

	for _, tt := range tests {
		t.Run(tt.apiVersion, func(t *testing.T) {
			result := getAPIBaseURL(tt.apiVersion)
			if result != tt.expected {
				t.Errorf("getAPIBaseURL(%s) = %s, want %s", tt.apiVersion, result, tt.expected)
			}
		})
	}
}
