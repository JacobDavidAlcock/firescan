package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/safety"
	"firescan/internal/types"
)

// ManagementSecurityResult represents Firebase Management API security test results
type ManagementSecurityResult struct {
	TestType    string
	Endpoint    string
	Method      string
	Severity    string
	Finding     string
	Details     map[string]interface{}
	SafetyLevel types.ScanMode
	Error       error
}

// TestManagementAPISecurity performs comprehensive Firebase Management API security testing
func TestManagementAPISecurity(mode types.ScanMode) ([]ManagementSecurityResult, error) {
	if !safety.WarnUser(mode) {
		return nil, fmt.Errorf("user declined to proceed with Management API testing")
	}

	var results []ManagementSecurityResult
	state := config.GetState()

	fmt.Printf("[*] Firebase Management API Security Testing (%s mode)\n", mode.String())

	// Test 1: Project Configuration Exposure (SAFE - Read-only)
	projectResults := testProjectConfiguration(state, mode)
	results = append(results, projectResults...)

	// Test 2: IAM Members Enumeration (SAFE - Read-only)
	iamResults := testIAMMembers(state, mode)
	results = append(results, iamResults...)

	// Test 3: Service Account Enumeration (SAFE - Read-only)
	saResults := testServiceAccounts(state, mode)
	results = append(results, saResults...)

	// Test 4: API Keys Enumeration (SAFE - Read-only)
	keyResults := testAPIKeysEnumeration(state, mode)
	results = append(results, keyResults...)

	// Test 5: Firebase Service Configuration (SAFE - Read-only)
	serviceResults := testServiceConfiguration(state, mode)
	results = append(results, serviceResults...)

	// Test 6: Security & Access Testing (SAFE - Read-only)
	securityResults := testSecurityConfiguration(state, mode)
	results = append(results, securityResults...)

	// Test 7: Billing & Quota Information (SAFE - Read-only)
	billingResults := testBillingConfiguration(state, mode)
	results = append(results, billingResults...)

	return results, nil
}

// testProjectConfiguration tests project configuration exposure
func testProjectConfiguration(state types.State, mode types.ScanMode) []ManagementSecurityResult {
	var results []ManagementSecurityResult

	endpoints := []struct {
		path        string
		description string
		apiVersion  string
	}{
		{
			path:        fmt.Sprintf("/v1/projects/%s", state.ProjectID),
			description: "Project metadata and configuration",
			apiVersion:  "firebase",
		},
		{
			path:        fmt.Sprintf("/v1/projects/%s/webApps", state.ProjectID),
			description: "Web application configurations",
			apiVersion:  "firebase",
		},
		{
			path:        fmt.Sprintf("/v1/projects/%s/androidApps", state.ProjectID),
			description: "Android application configurations",
			apiVersion:  "firebase",
		},
		{
			path:        fmt.Sprintf("/v1/projects/%s/iosApps", state.ProjectID),
			description: "iOS application configurations",
			apiVersion:  "firebase",
		},
		{
			path:        fmt.Sprintf("/v1/projects/%s/availableLocations", state.ProjectID),
			description: "Available deployment locations",
			apiVersion:  "firebase",
		},
	}

	for _, endpoint := range endpoints {
		result := testManagementEndpoint(endpoint.path, endpoint.description, endpoint.apiVersion, "GET", state, mode)
		if result.Finding != "" {
			showManagementFinding(result)
		}
		results = append(results, result)
	}

	return results
}

// testIAMMembers tests IAM member enumeration
func testIAMMembers(state types.State, mode types.ScanMode) []ManagementSecurityResult {
	var results []ManagementSecurityResult

	endpoints := []struct {
		path        string
		description string
		apiVersion  string
	}{
		{
			path:        fmt.Sprintf("/v1/projects/%s:getIamPolicy", state.ProjectID),
			description: "Project IAM policy and members",
			apiVersion:  "cloudresourcemanager",
		},
		{
			path:        fmt.Sprintf("/v1/projects/%s:testIamPermissions", state.ProjectID),
			description: "Current user's IAM permissions",
			apiVersion:  "cloudresourcemanager",
		},
	}

	for _, endpoint := range endpoints {
		result := testManagementEndpoint(endpoint.path, endpoint.description, endpoint.apiVersion, "POST", state, mode)
		if result.Finding != "" {
			showManagementFinding(result)
		}
		results = append(results, result)
	}

	return results
}

// testServiceAccounts tests service account enumeration
func testServiceAccounts(state types.State, mode types.ScanMode) []ManagementSecurityResult {
	var results []ManagementSecurityResult

	endpoints := []struct {
		path        string
		description string
		apiVersion  string
		method      string
	}{
		{
			path:        fmt.Sprintf("/v1/projects/%s/serviceAccounts", state.ProjectID),
			description: "Service accounts enumeration",
			apiVersion:  "iam",
			method:      "GET",
		},
		{
			path:        fmt.Sprintf("/v1/projects/-/serviceAccounts/%s@%s.iam.gserviceaccount.com", state.ProjectID, state.ProjectID),
			description: "Default Firebase Admin SDK service account",
			apiVersion:  "iam", 
			method:      "GET",
		},
		{
			path:        fmt.Sprintf("/v1/projects/-/serviceAccounts/firebase-adminsdk@%s.iam.gserviceaccount.com", state.ProjectID),
			description: "Firebase Admin SDK service account",
			apiVersion:  "iam",
			method:      "GET", 
		},
	}

	for _, endpoint := range endpoints {
		result := testManagementEndpoint(endpoint.path, endpoint.description, endpoint.apiVersion, endpoint.method, state, mode)
		if result.Finding != "" {
			showManagementFinding(result)
		}
		results = append(results, result)
	}

	return results
}

// testAPIKeysEnumeration tests API key enumeration and configuration
func testAPIKeysEnumeration(state types.State, mode types.ScanMode) []ManagementSecurityResult {
	var results []ManagementSecurityResult

	endpoints := []struct {
		path        string
		description string
		apiVersion  string
	}{
		{
			path:        fmt.Sprintf("/v2/projects/%s/apiKeys", state.ProjectID),
			description: "API keys enumeration",
			apiVersion:  "apikeys",
		},
		{
			path:        fmt.Sprintf("/v1/projects/%s/webApps/-/config", state.ProjectID),
			description: "Web app configuration with API keys",
			apiVersion:  "firebase",
		},
	}

	for _, endpoint := range endpoints {
		result := testManagementEndpoint(endpoint.path, endpoint.description, endpoint.apiVersion, "GET", state, mode)
		if result.Finding != "" {
			showManagementFinding(result)
		}
		results = append(results, result)

		// If we found API keys, test their restrictions
		if result.Details != nil {
			if keys, ok := result.Details["api_keys"]; ok {
				keyResults := testAPIKeyRestrictions(keys, state, mode)
				for _, keyResult := range keyResults {
					if keyResult.Finding != "" {
						showManagementFinding(keyResult)
					}
				}
				results = append(results, keyResults...)
			}
		}
	}

	return results
}

// testServiceConfiguration tests Firebase service configurations
func testServiceConfiguration(state types.State, mode types.ScanMode) []ManagementSecurityResult {
	var results []ManagementSecurityResult

	endpoints := []struct {
		path        string
		description string
		apiVersion  string
	}{
		{
			path:        fmt.Sprintf("/v1/projects/%s/databases", state.ProjectID),
			description: "Firestore database configuration",
			apiVersion:  "firestore",
		},
		{
			path:        fmt.Sprintf("/v1/projects/%s/locations/-/buckets", state.ProjectID),
			description: "Storage bucket configuration",
			apiVersion:  "storage",
		},
		{
			path:        fmt.Sprintf("/v1/projects/%s/sites", state.ProjectID),
			description: "Hosting sites configuration",
			apiVersion:  "firebase",
		},
		{
			path:        fmt.Sprintf("/v1/projects/%s/tenants", state.ProjectID),
			description: "Authentication tenant configuration",
			apiVersion:  "identitytoolkit",
		},
	}

	for _, endpoint := range endpoints {
		result := testManagementEndpoint(endpoint.path, endpoint.description, endpoint.apiVersion, "GET", state, mode)
		if result.Finding != "" {
			showManagementFinding(result)
		}
		results = append(results, result)
	}

	return results
}

// testSecurityConfiguration tests security-related configurations
func testSecurityConfiguration(state types.State, mode types.ScanMode) []ManagementSecurityResult {
	var results []ManagementSecurityResult

	endpoints := []struct {
		path        string
		description string
		apiVersion  string
	}{
		{
			path:        fmt.Sprintf("/v1/projects/%s/config", state.ProjectID),
			description: "Authentication provider configuration",
			apiVersion:  "identitytoolkit",
		},
		{
			path:        fmt.Sprintf("/v1/projects/%s/oauthIdpConfigs", state.ProjectID),
			description: "OAuth identity provider configurations",
			apiVersion:  "identitytoolkit",
		},
		{
			path:        fmt.Sprintf("/v1/projects/%s/inboundSamlConfigs", state.ProjectID),
			description: "SAML identity provider configurations", 
			apiVersion:  "identitytoolkit",
		},
	}

	for _, endpoint := range endpoints {
		result := testManagementEndpoint(endpoint.path, endpoint.description, endpoint.apiVersion, "GET", state, mode)
		if result.Finding != "" {
			showManagementFinding(result)
		}
		results = append(results, result)
	}

	return results
}

// testBillingConfiguration tests billing and quota configurations
func testBillingConfiguration(state types.State, mode types.ScanMode) []ManagementSecurityResult {
	var results []ManagementSecurityResult

	endpoints := []struct {
		path        string
		description string
		apiVersion  string
	}{
		{
			path:        fmt.Sprintf("/v1/projects/%s/billingInfo", state.ProjectID),
			description: "Project billing information",
			apiVersion:  "cloudbilling",
		},
		{
			path:        fmt.Sprintf("/v1/services/firebase.googleapis.com/consumerQuotaMetrics", state.ProjectID),
			description: "Firebase API quota information",
			apiVersion:  "serviceusage",
		},
	}

	for _, endpoint := range endpoints {
		result := testManagementEndpoint(endpoint.path, endpoint.description, endpoint.apiVersion, "GET", state, mode)
		if result.Finding != "" {
			showManagementFinding(result)
		}
		results = append(results, result)
	}

	return results
}

// testManagementEndpoint tests a specific Management API endpoint
func testManagementEndpoint(path, description, apiVersion, method string, state types.State, mode types.ScanMode) ManagementSecurityResult {
	result := ManagementSecurityResult{
		TestType:    "Management API",
		Endpoint:    path,
		Method:      method,
		Details:     make(map[string]interface{}),
		SafetyLevel: mode,
	}

	// Construct the full URL based on API version
	baseURL := getAPIBaseURL(apiVersion)
	fullURL := baseURL + path

	result.Details["description"] = description
	result.Details["api_version"] = apiVersion

	// Make authenticated request
	var resp *http.Response
	var err error

	if method == "POST" {
		// For POST requests, we might need request bodies for some endpoints
		requestBody := getRequestBodyForEndpoint(path)
		resp, err = auth.MakeAuthenticatedRequestWithBody("POST", fullURL, requestBody, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	} else {
		resp, err = auth.MakeAuthenticatedRequest(method, fullURL, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	}

	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.Details["status_code"] = resp.StatusCode

	// Analyze response for security issues
	if resp.StatusCode == 200 {
		var responseData interface{}
		if err := json.NewDecoder(resp.Body).Decode(&responseData); err == nil {
			result.Details["response_data"] = responseData
			
			// Analyze response for sensitive information
			securityAnalysis := analyzeManagementResponse(responseData, description, path)
			if securityAnalysis.HasSensitiveData {
				result.Severity = securityAnalysis.Severity
				result.Finding = securityAnalysis.Finding
				result.Details["sensitive_data"] = securityAnalysis.SensitiveFields
			}
		}
	} else if resp.StatusCode == 403 {
		result.Details["access_denied"] = true
		// This is expected for many endpoints - not necessarily a finding
	} else if resp.StatusCode == 401 {
		result.Details["authentication_required"] = true
	}

	return result
}

// SecurityAnalysis represents the analysis of a management API response
type SecurityAnalysis struct {
	HasSensitiveData bool
	Severity         string
	Finding          string
	SensitiveFields  []string
}

// analyzeManagementResponse analyzes Management API responses for sensitive data
func analyzeManagementResponse(data interface{}, description, path string) SecurityAnalysis {
	analysis := SecurityAnalysis{
		SensitiveFields: []string{},
	}

	// Convert to map for analysis
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return analysis
	}

	// Check for different types of sensitive information
	sensitivePatterns := []struct {
		field    string
		severity string
		finding  string
	}{
		{"private_key", "High", "Private key exposed in Management API response"},
		{"client_secret", "High", "OAuth client secret exposed"},
		{"api_key", "Medium", "API key exposed in configuration"},
		{"service_account", "Medium", "Service account details exposed"}, 
		{"members", "Medium", "IAM members enumerated"},
		{"email", "Low", "Email addresses exposed"},
		{"projectId", "Low", "Project configuration details exposed"},
		{"billingAccountName", "Medium", "Billing account information exposed"},
	}

	for _, pattern := range sensitivePatterns {
		if containsFieldRecursive(dataMap, pattern.field) {
			analysis.HasSensitiveData = true
			analysis.SensitiveFields = append(analysis.SensitiveFields, pattern.field)
			
			// Use the highest severity found
			if analysis.Severity == "" || (pattern.severity == "High" || (pattern.severity == "Medium" && analysis.Severity == "Low")) {
				analysis.Severity = pattern.severity
				analysis.Finding = pattern.finding
			}
		}
	}

	// Special analysis for specific endpoints
	if strings.Contains(path, "serviceAccounts") {
		analysis.HasSensitiveData = true
		analysis.Severity = "High"
		analysis.Finding = "Service account enumeration successful - potential privilege escalation"
	} else if strings.Contains(path, "getIamPolicy") {
		analysis.HasSensitiveData = true
		analysis.Severity = "Medium" 
		analysis.Finding = "IAM policy enumerated - project access control exposed"
	} else if strings.Contains(path, "apiKeys") {
		analysis.HasSensitiveData = true
		analysis.Severity = "Medium"
		analysis.Finding = "API keys enumerated - potential API abuse"
	}

	return analysis
}

// containsFieldRecursive checks if a field exists anywhere in the data structure
func containsFieldRecursive(data map[string]interface{}, field string) bool {
	for key, value := range data {
		if strings.Contains(strings.ToLower(key), strings.ToLower(field)) {
			return true
		}
		
		// Recurse into nested objects
		if nestedMap, ok := value.(map[string]interface{}); ok {
			if containsFieldRecursive(nestedMap, field) {
				return true
			}
		}
		
		// Check arrays of objects
		if array, ok := value.([]interface{}); ok {
			for _, item := range array {
				if itemMap, ok := item.(map[string]interface{}); ok {
					if containsFieldRecursive(itemMap, field) {
						return true
					}
				}
			}
		}
	}
	return false
}

// testAPIKeyRestrictions tests API key restrictions and configurations
func testAPIKeyRestrictions(keys interface{}, state types.State, mode types.ScanMode) []ManagementSecurityResult {
	var results []ManagementSecurityResult

	// This would analyze API key restrictions, allowed origins, etc.
	result := ManagementSecurityResult{
		TestType:    "API Key Security",
		Details:     make(map[string]interface{}),
		SafetyLevel: mode,
	}

	result.Details["api_keys_analyzed"] = keys
	result.Finding = "API key restriction analysis - placeholder for detailed key security testing"
	result.Severity = "Info"

	results = append(results, result)
	return results
}

// Helper functions
func getAPIBaseURL(apiVersion string) string {
	switch apiVersion {
	case "firebase":
		return "https://firebase.googleapis.com"
	case "cloudresourcemanager":
		return "https://cloudresourcemanager.googleapis.com"
	case "iam":
		return "https://iam.googleapis.com"
	case "apikeys":
		return "https://apikeys.googleapis.com"
	case "firestore":
		return "https://firestore.googleapis.com"
	case "storage":
		return "https://storage.googleapis.com"
	case "identitytoolkit":
		return "https://identitytoolkit.googleapis.com"
	case "cloudbilling":
		return "https://cloudbilling.googleapis.com"
	case "serviceusage":
		return "https://serviceusage.googleapis.com"
	default:
		return "https://firebase.googleapis.com"
	}
}

func getRequestBodyForEndpoint(path string) string {
	if strings.Contains(path, "testIamPermissions") {
		return `{"permissions": ["firebase.projects.get", "resourcemanager.projects.get", "iam.serviceAccounts.list"]}`
	}
	return ""
}

// showManagementFinding displays a Management API finding immediately
func showManagementFinding(result ManagementSecurityResult) {
	if result.Finding == "" {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	// Determine color based on severity
	severityColor := types.ColorCyan
	switch result.Severity {
	case "High":
		severityColor = types.ColorRed
	case "Medium":  
		severityColor = types.ColorYellow
	case "Low":
		severityColor = types.ColorGreen
	}

	fmt.Printf("\n[%s%s%s] %s%sVulnerability Found!%s\n  ├── Timestamp: %s\n  ├── Severity:  %s%s%s\n  ├── Type:      %s\n  └── Endpoint:  %s\n",
		types.ColorRed, types.ColorBold, "Management", types.ColorGreen, types.ColorBold, types.ColorReset,
		timestamp,
		severityColor, result.Severity, types.ColorReset,
		result.TestType,
		result.Endpoint)
		
	fmt.Printf("  └── Details:   %s\n", result.Finding)
}