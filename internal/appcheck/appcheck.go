package appcheck

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

// Provider represents different App Check providers
type Provider struct {
	Name        string
	Enabled     bool
	ConfigURL   string
	TestURL     string
	Description string
}

// Result represents App Check test results
type Result struct {
	Provider     string
	Enabled      bool
	HasDebugMode bool
	Accessible   bool
	Error        error
	Details      map[string]interface{}
	SafetyLevel  types.ScanMode
}

// GetAppCheckProviders returns list of App Check providers to test
func GetAppCheckProviders() []Provider {
	return []Provider{
		{
			Name:        "Play Integrity",
			ConfigURL:   "https://firebaseappcheck.googleapis.com/v1/projects/{projectId}/apps/{appId}:exchangePlayIntegrityToken",
			TestURL:     "https://firebaseappcheck.googleapis.com/v1/projects/{projectId}/apps",
			Description: "Google Play Integrity API for Android apps",
		},
		{
			Name:        "DeviceCheck",
			ConfigURL:   "https://firebaseappcheck.googleapis.com/v1/projects/{projectId}/apps/{appId}:exchangeDeviceCheckToken",
			TestURL:     "https://firebaseappcheck.googleapis.com/v1/projects/{projectId}/apps",
			Description: "Apple DeviceCheck for iOS apps",
		},
		{
			Name:        "reCAPTCHA",
			ConfigURL:   "https://firebaseappcheck.googleapis.com/v1/projects/{projectId}/apps/{appId}:exchangeRecaptchaToken",
			TestURL:     "https://firebaseappcheck.googleapis.com/v1/projects/{projectId}/apps",
			Description: "reCAPTCHA Enterprise for web apps",
		},
		{
			Name:        "Debug Provider",
			ConfigURL:   "https://firebaseappcheck.googleapis.com/v1/projects/{projectId}/apps/{appId}:exchangeDebugToken",
			TestURL:     "https://firebaseappcheck.googleapis.com/v1/projects/{projectId}/debugTokens",
			Description: "Debug tokens for development (SECURITY RISK in production)",
		},
	}
}

// TestAppCheck performs comprehensive App Check security testing
func TestAppCheck(mode types.ScanMode) ([]Result, error) {
	if !safety.WarnUser(mode) {
		return nil, fmt.Errorf("user declined to proceed with App Check testing")
	}

	results := make([]Result, 0, 10)
	state := config.GetState()
	providers := GetAppCheckProviders()

	// Test each App Check provider
	for _, provider := range providers {
		result := testAppCheckProvider(provider, mode, state)
		results = append(results, result)
	}

	// Test for debug tokens in production (critical security issue)
	if mode >= types.TestMode {
		debugResult := testDebugTokensInProduction(state)
		results = append(results, debugResult)
	}

	// Test App Check bypass techniques
	if mode >= types.AuditMode {
		bypassResults := testAppCheckBypass(state)
		results = append(results, bypassResults...)
	}

	return results, nil
}

// testAppCheckProvider tests a specific App Check provider
func testAppCheckProvider(provider Provider, mode types.ScanMode, state types.State) Result {
	result := Result{
		Provider:    provider.Name,
		SafetyLevel: mode,
		Details:     make(map[string]interface{}),
	}

	// Replace project ID in URLs
	testURL := strings.ReplaceAll(provider.TestURL, "{projectId}", state.ProjectID)
	result.Details["test_url"] = testURL

	// Test if App Check is configured
	resp, err := auth.MakeAuthenticatedRequest("GET", testURL, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.Accessible = resp.StatusCode == 200

	// Parse response for App Check configuration
	if resp.StatusCode == 200 {
		var appCheckConfig map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&appCheckConfig); err == nil {
			result.Details["config"] = appCheckConfig
			result.Enabled = true

			// Check for debug mode indicators
			if provider.Name == "Debug Provider" {
				result.HasDebugMode = true
			}
		}
	}

	return result
}

// testDebugTokensInProduction checks for debug tokens in production (critical vulnerability)
func testDebugTokensInProduction(state types.State) Result {
	result := Result{
		Provider:    "Debug Token Security Check",
		SafetyLevel: types.TestMode,
		Details:     make(map[string]interface{}),
	}

	debugTokenURL := fmt.Sprintf("https://firebaseappcheck.googleapis.com/v1/projects/%s/debugTokens", state.ProjectID)
	result.Details["test_url"] = debugTokenURL

	resp, err := auth.MakeAuthenticatedRequest("GET", debugTokenURL, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.Accessible = resp.StatusCode == 200

	if resp.StatusCode == 200 {
		var debugTokens map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&debugTokens); err == nil {
			result.Details["debug_tokens"] = debugTokens
			result.HasDebugMode = true
			result.Details["security_risk"] = "Debug tokens found in production environment"
		}
	}

	return result
}

// testAppCheckBypass tests various App Check bypass techniques
func testAppCheckBypass(state types.State) []Result {
	var results []Result

	// Test 1: Direct API access without App Check token
	bypassResult1 := Result{
		Provider:    "Direct API Bypass Test",
		SafetyLevel: types.AuditMode,
		Details:     make(map[string]interface{}),
	}

	// Test direct access to Firebase APIs without App Check headers
	rtdbURL := fmt.Sprintf("https://%s-default-rtdb.firebaseio.com/.json", state.ProjectID)
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", rtdbURL, nil)
	if err != nil {
		bypassResult1.Error = err
		results = append(results, bypassResult1)
		return results
	}
	// Intentionally NOT adding App Check headers

	resp, err := client.Do(req)
	if err != nil {
		bypassResult1.Error = err
	} else {
		defer resp.Body.Close()
		bypassResult1.Accessible = resp.StatusCode == 200
		bypassResult1.Details["bypass_successful"] = resp.StatusCode == 200
		bypassResult1.Details["status_code"] = resp.StatusCode
	}
	results = append(results, bypassResult1)

	// Test 2: Invalid App Check token acceptance
	bypassResult2 := Result{
		Provider:    "Invalid Token Test",
		SafetyLevel: types.AuditMode,
		Details:     make(map[string]interface{}),
	}

	req2, err := http.NewRequest("GET", rtdbURL, nil)
	if err != nil {
		bypassResult2.Error = err
		results = append(results, bypassResult2)
		return results
	}
	req2.Header.Set("X-Firebase-AppCheck", "invalid-token-12345")

	resp2, err := client.Do(req2)
	if err != nil {
		bypassResult2.Error = err
	} else {
		defer resp2.Body.Close()
		bypassResult2.Accessible = resp2.StatusCode == 200
		bypassResult2.Details["invalid_token_accepted"] = resp2.StatusCode == 200
		bypassResult2.Details["status_code"] = resp2.StatusCode
	}
	results = append(results, bypassResult2)

	return results
}

// FormatAppCheckResults formats App Check test results for display
func FormatAppCheckResults(results []Result) {
	fmt.Printf("\n%s=== Firebase App Check Security Analysis ===%s\n", types.ColorCyan, types.ColorReset)

	for _, result := range results {
		status := "✓"
		statusColor := types.ColorGreen

		if result.Error != nil {
			status = "✗"
			statusColor = types.ColorRed
		} else if result.HasDebugMode && result.Provider != "Debug Token Security Check" {
			status = "⚠"
			statusColor = types.ColorYellow
		}

		fmt.Printf("%s%s %s%s\n", statusColor, status, result.Provider, types.ColorReset)
		fmt.Printf("  Enabled: %v\n", result.Enabled)
		fmt.Printf("  Accessible: %v\n", result.Accessible)

		if result.HasDebugMode {
			fmt.Printf("  %sWARNING: Debug mode detected%s\n", types.ColorYellow, types.ColorReset)
		}

		if result.Error != nil {
			fmt.Printf("  Error: %v\n", result.Error)
		}

		if len(result.Details) > 0 {
			fmt.Printf("  Details: %v\n", result.Details)
		}

		fmt.Println()
	}
}
