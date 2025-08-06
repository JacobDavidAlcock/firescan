package unauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"firescan/internal/config"
	"firescan/internal/types"
)

// UnauthTestResult represents unauthenticated test results
type UnauthTestResult struct {
	Service     string
	Endpoint    string
	Method      string
	Accessible  bool
	HasData     bool
	DataSample  interface{}
	StatusCode  int
	Error       error
	Description string
}

// TestUnauthenticated performs comprehensive unauthenticated access testing
// Automatically uses whatever credentials are available (projectID, API key, or both)
func TestUnauthenticated(mode types.ScanMode) ([]UnauthTestResult, error) {
	var results []UnauthTestResult
	state := config.GetState()

	if state.ProjectID == "" {
		return nil, fmt.Errorf("project ID required for unauthenticated testing")
	}

	// Determine what credentials we have available
	hasAPIKey := state.APIKey != ""
	
	// Test RTDB access (works with projectID only)
	rtdbResults := testRTDBUnauth(state, hasAPIKey)
	results = append(results, rtdbResults...)

	// Test Firestore access (better with API key)
	firestoreResults := testFirestoreUnauth(state, hasAPIKey)
	results = append(results, firestoreResults...)

	// Test Storage access (works with projectID only)
	storageResults := testStorageUnauth(state, hasAPIKey)
	results = append(results, storageResults...)

	// Test Cloud Functions access (works with projectID only)
	functionsResults := testFunctionsUnauth(state, hasAPIKey)
	results = append(results, functionsResults...)

	// Test Hosting access (works with projectID only)
	hostingResults := testHostingUnauth(state, hasAPIKey)
	results = append(results, hostingResults...)

	// Test Remote Config access (requires API key)
	if hasAPIKey {
		configResults := testRemoteConfigUnauth(state, hasAPIKey)
		results = append(results, configResults...)
	}

	// Test Auth API endpoints (requires API key)
	if hasAPIKey {
		authResults := testAuthAPIUnauth(state)
		results = append(results, authResults...)
	}

	// Test RTDB Advanced vulnerabilities (works with projectID only)
	rtdbAdvResults := testRTDBAdvancedUnauth(state, hasAPIKey)
	results = append(results, rtdbAdvResults...)

	// Test FCM security (works with projectID, enhanced with API key)
	fcmResults := testFCMUnauth(state, hasAPIKey)
	results = append(results, fcmResults...)

	// Test Firebase Services enumeration (works with projectID only)
	servicesResults := testServicesUnauth(state, hasAPIKey)
	results = append(results, servicesResults...)

	// Test App Check configuration (works with projectID only)
	appCheckResults := testAppCheckUnauth(state, hasAPIKey)
	results = append(results, appCheckResults...)

	// Test Storage security basics (works with projectID only)
	storageSecResults := testStorageSecurityUnauth(state, hasAPIKey)
	results = append(results, storageSecResults...)

	return results, nil
}

// showUnauthFinding displays a finding immediately in the same format as normal scans
func showUnauthFinding(result UnauthTestResult) {
	// Determine severity and type
	severity := "Medium"
	findingType := "Public Access"
	
	if result.HasData {
		severity = "High"
		findingType = "Data Exposure"
	}
	
	// Use same format as normal scanner
	severityColor := types.ColorYellow
	if severity == "High" {
		severityColor = types.ColorRed
	}
	
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	fmt.Printf("\n[%s%s%s] %s%sVulnerability Found!%s\n  ├── Timestamp: %s\n  ├── Severity:  %s%s%s\n  ├── Type:      %s\n  └── Path:      %s\n",
		types.ColorRed, types.ColorBold, result.Service, types.ColorGreen, types.ColorBold, types.ColorReset,
		timestamp,
		severityColor, severity, types.ColorReset,
		findingType,
		result.Endpoint)
		
	if result.HasData && result.DataSample != nil {
		fmt.Printf("  └── Data:      %v\n", result.DataSample)
	}
}

// testRTDBUnauth tests RTDB without authentication
func testRTDBUnauth(state types.State, hasAPIKey bool) []UnauthTestResult {
	var results []UnauthTestResult
	
	endpoints := []struct {
		path        string
		description string
	}{
		{"/.json", "Root database access"},
		{"/users.json", "Users collection"},
		{"/public.json", "Public data"},
		{"/config.json", "Configuration data"},
		{"/posts.json", "Posts collection"},
		{"/messages.json", "Messages collection"},
		{"/.settings/rules.json", "Security rules exposure"},
	}

	for _, endpoint := range endpoints {
		var url string
		if hasAPIKey {
			url = fmt.Sprintf("https://%s-default-rtdb.firebaseio.com%s?key=%s", state.ProjectID, endpoint.path, state.APIKey)
		} else {
			url = fmt.Sprintf("https://%s-default-rtdb.firebaseio.com%s", state.ProjectID, endpoint.path)
		}
		result := makeUnauthenticatedRequest("RTDB", url, "GET", endpoint.description)
		if hasAPIKey {
			result.Description += " (with API key)"
		}
		
		// Show finding immediately if it's a security issue
		if result.HasData || result.Accessible {
			showUnauthFinding(result)
		}
		
		results = append(results, result)
	}

	return results
}

// testFirestoreUnauth tests Firestore without authentication
func testFirestoreUnauth(state types.State, hasAPIKey bool) []UnauthTestResult {
	var results []UnauthTestResult

	// Firestore REST API endpoints
	endpoints := []struct {
		path        string
		description string
	}{
		{"/documents", "Document root access"},
		{"/documents/users", "Users collection"},
		{"/documents/public", "Public collection"},
		{"/documents/posts", "Posts collection"},
		{"/documents/config", "Config documents"},
		{":runQuery", "Query endpoint"},
		{":batchGet", "Batch get endpoint"},
	}

	baseURL := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)", state.ProjectID)
	
	for _, endpoint := range endpoints {
		var url string
		if hasAPIKey {
			url = fmt.Sprintf("%s/%s?key=%s", baseURL, endpoint.path, state.APIKey)
		} else {
			url = baseURL + "/" + endpoint.path
		}
		
		result := makeUnauthenticatedRequest("Firestore", url, "GET", endpoint.description)
		if hasAPIKey {
			result.Description += " (with API key)"
		}
		
		// Show finding immediately if it's a security issue
		if result.HasData || result.Accessible {
			showUnauthFinding(result)
		}
		
		results = append(results, result)
		
		// Also test POST for query endpoints (works better with API key)
		if endpoint.path == ":runQuery" || endpoint.path == ":batchGet" {
			postResult := makeUnauthenticatedRequest("Firestore", url, "POST", endpoint.description+" (POST)")
			if hasAPIKey {
				postResult.Description += " (with API key)"
			}
			
			// Show finding immediately if it's a security issue
			if postResult.HasData || postResult.Accessible {
				showUnauthFinding(postResult)
			}
			
			results = append(results, postResult)
		}
	}

	return results
}

// testStorageUnauth tests Storage without authentication
func testStorageUnauth(state types.State, hasAPIKey bool) []UnauthTestResult {
	var results []UnauthTestResult

	buckets := []string{
		fmt.Sprintf("%s.appspot.com", state.ProjectID),
		fmt.Sprintf("%s.firebaseapp.com", state.ProjectID),
		fmt.Sprintf("gs://%s.appspot.com", state.ProjectID),
	}

	testPaths := []string{
		"",
		"/public",
		"/images",
		"/uploads",
		"/files",
		"/assets",
		"/config.json",
		"/firebase.json",
	}

	for _, bucket := range buckets {
		for _, path := range testPaths {
			url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o%s", bucket, path)
			description := fmt.Sprintf("Storage bucket %s path %s", bucket, path)
			result := makeUnauthenticatedRequest("Storage", url, "GET", description)
			
			// Show finding immediately if it's a security issue
			if result.HasData || result.Accessible {
				showUnauthFinding(result)
			}
			
			results = append(results, result)
		}
	}

	return results
}

// testFunctionsUnauth tests Cloud Functions without authentication
func testFunctionsUnauth(state types.State, hasAPIKey bool) []UnauthTestResult {
	var results []UnauthTestResult

	// Common function names to test
	functionNames := []string{
		"api",
		"webhook",
		"public",
		"healthCheck",
		"status",
		"hello",
		"test",
		"ping",
		"info",
		"version",
	}

	regions := []string{
		"us-central1",
		"us-east1", 
		"europe-west1",
		"asia-southeast1",
	}

	for _, region := range regions {
		for _, funcName := range functionNames {
			url := fmt.Sprintf("https://%s-%s.cloudfunctions.net/%s", region, state.ProjectID, funcName)
			description := fmt.Sprintf("Cloud Function %s in %s", funcName, region)
			result := makeUnauthenticatedRequest("Functions", url, "GET", description)
			
			// Show finding immediately if it's a security issue
			if result.HasData || result.Accessible {
				showUnauthFinding(result)
			}
			
			results = append(results, result)
		}
	}

	return results
}

// testHostingUnauth tests Firebase Hosting without authentication
func testHostingUnauth(state types.State, hasAPIKey bool) []UnauthTestResult {
	var results []UnauthTestResult

	hostingDomains := []string{
		fmt.Sprintf("%s.web.app", state.ProjectID),
		fmt.Sprintf("%s.firebaseapp.com", state.ProjectID),
	}

	testPaths := []string{
		"",
		"/api",
		"/config",
		"/admin",
		"/.well-known/security.txt",
		"/.well-known/assetlinks.json",
		"/firebase.json",
		"/firebase-config.js",
		"/__/firebase/init.js",
		"/manifest.json",
		"/sitemap.xml",
		"/robots.txt",
	}

	for _, domain := range hostingDomains {
		for _, path := range testPaths {
			url := fmt.Sprintf("https://%s%s", domain, path)
			description := fmt.Sprintf("Hosting %s path %s", domain, path)
			result := makeUnauthenticatedRequest("Hosting", url, "GET", description)
			
			// Show finding immediately if it's a security issue
			if result.HasData || result.Accessible {
				showUnauthFinding(result)
			}
			
			results = append(results, result)
		}
	}

	return results
}

// testRemoteConfigUnauth tests Remote Config without authentication
func testRemoteConfigUnauth(state types.State, hasAPIKey bool) []UnauthTestResult {
	var results []UnauthTestResult

	endpoints := []struct {
		url         string
		description string
	}{
		{
			fmt.Sprintf("https://firebaseremoteconfig.googleapis.com/v1/projects/%s/remoteConfig", state.ProjectID),
			"Remote Config settings",
		},
		{
			fmt.Sprintf("https://firebaseremoteconfig.googleapis.com/v1/projects/%s/namespaces/firebase:fetch", state.ProjectID),
			"Remote Config fetch",
		},
	}

	for _, endpoint := range endpoints {
		result := makeUnauthenticatedRequest("Remote Config", endpoint.url, "GET", endpoint.description)
		
		// Show finding immediately if it's a security issue
		if result.HasData || result.Accessible {
			showUnauthFinding(result)
		}
		
		results = append(results, result)
	}

	return results
}

// testAuthAPIUnauth tests Firebase Auth API endpoints (requires API key)
func testAuthAPIUnauth(state types.State) []UnauthTestResult {
	var results []UnauthTestResult

	endpoints := []struct {
		path        string
		description string
	}{
		{
			fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=%s", state.APIKey),
			"User signup endpoint",
		},
		{
			fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s", state.APIKey),
			"Password login endpoint",
		},
		{
			fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInAnonymously?key=%s", state.APIKey),
			"Anonymous login endpoint",
		},
		{
			fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=%s", state.APIKey),
			"Account lookup endpoint",
		},
		{
			fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=%s", state.APIKey),
			"OAuth provider discovery",
		},
		{
			fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key=%s", state.APIKey),
			"Password reset endpoint",
		},
		{
			fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=%s", state.APIKey),
			"Email verification endpoint",
		},
	}

	for _, endpoint := range endpoints {
		result := makeUnauthenticatedRequest("Firebase Auth", endpoint.path, "POST", endpoint.description+" (with API key)")
		
		// Show finding immediately if it's a security issue
		if result.HasData || result.Accessible {
			showUnauthFinding(result)
		}
		
		results = append(results, result)
	}

	return results
}

// makeUnauthenticatedRequest makes an HTTP request without authentication
func makeUnauthenticatedRequest(service, url, method, description string) UnauthTestResult {
	result := UnauthTestResult{
		Service:     service,
		Endpoint:    url,
		Method:      method,
		Description: description,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		result.Error = err
		return result
	}

	// Add common headers that might help with testing
	req.Header.Set("User-Agent", "FireScan-Security-Scanner")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Accessible = resp.StatusCode == 200

	// Check if we got data
	if resp.StatusCode == 200 {
		var data interface{}
		if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
			result.HasData = true
			
			// Store a sample of the data (truncated for display)
			if dataStr, ok := data.(string); ok && len(dataStr) > 100 {
				result.DataSample = dataStr[:100] + "..."
			} else if dataMap, ok := data.(map[string]interface{}); ok {
				// Limit the sample to avoid huge outputs
				sample := make(map[string]interface{})
				count := 0
				for k, v := range dataMap {
					if count >= 3 {
						sample["..."] = "truncated"
						break
					}
					sample[k] = v
					count++
				}
				result.DataSample = sample
			} else {
				result.DataSample = data
			}
		}
	}

	return result
}

// CountUnauthFindings counts the security findings from unauthenticated testing
func CountUnauthFindings(results []UnauthTestResult) int {
	count := 0
	for _, result := range results {
		if result.HasData || result.Accessible {
			count++
		}
	}
	return count
}

// testRTDBAdvancedUnauth tests RTDB advanced vulnerabilities without authentication
func testRTDBAdvancedUnauth(state types.State, hasAPIKey bool) []UnauthTestResult {
	var results []UnauthTestResult

	// Test path traversal vulnerabilities  
	exploitPaths := []string{
		"/../admin",
		"/users/../config", 
		"/public/%2e%2e/private",
		"/data/..",
		"/.settings/rules",
		"/.indexOn",
	}

	for _, path := range exploitPaths {
		result := makeUnauthenticatedRequest("RTDB Advanced", fmt.Sprintf("https://%s-default-rtdb.firebaseio.com%s.json", state.ProjectID, path), "GET", fmt.Sprintf("Path traversal test: %s", path))
		
		// Only show if it's actually accessible (security finding)
		if result.Accessible {
			showUnauthFinding(result)
		}
		
		results = append(results, result)
	}

	// Test rule structure exposure
	rulesResult := makeUnauthenticatedRequest("RTDB Advanced", fmt.Sprintf("https://%s-default-rtdb.firebaseio.com/.settings/rules.json", state.ProjectID), "GET", "Security rules exposure")
	if rulesResult.HasData {
		showUnauthFinding(rulesResult)
	}
	results = append(results, rulesResult)

	return results
}

// testFCMUnauth tests FCM and push notification security without authentication
func testFCMUnauth(state types.State, hasAPIKey bool) []UnauthTestResult {
	var results []UnauthTestResult

	// Test FCM configuration exposure in web resources
	configEndpoints := []struct {
		url         string
		description string
	}{
		{fmt.Sprintf("https://%s.web.app/firebase-messaging-sw.js", state.ProjectID), "FCM service worker keys"},
		{fmt.Sprintf("https://%s.web.app/manifest.json", state.ProjectID), "Web app manifest with FCM config"},
		{fmt.Sprintf("https://%s.web.app/.well-known/firebase-messaging-sw.js", state.ProjectID), "Well-known FCM service worker"},
		{fmt.Sprintf("https://%s.firebaseapp.com/firebase-messaging-sw.js", state.ProjectID), "Firebase app FCM service worker"},
		{fmt.Sprintf("https://%s.firebaseapp.com/manifest.json", state.ProjectID), "Firebase app manifest"},
	}

	for _, endpoint := range configEndpoints {
		result := makeUnauthenticatedRequest("FCM Security", endpoint.url, "GET", endpoint.description)
		
		// Check for FCM keys/sensitive data in the response
		if result.Accessible && result.DataSample != nil {
			dataStr := fmt.Sprintf("%v", result.DataSample)
			if containsFCMKeys(dataStr) {
				result.HasData = true
				result.Description += " - Contains FCM keys/configuration"
				showUnauthFinding(result)
			}
		}
		
		results = append(results, result)
	}

	// Test FCM topic information (enhanced with API key)
	if hasAPIKey {
		commonTopics := []string{"news", "updates", "notifications", "all", "general", "test"}
		for _, topic := range commonTopics {
			topicURL := fmt.Sprintf("https://iid.googleapis.com/iid/info/%s?key=%s", topic, state.APIKey)
			result := makeUnauthenticatedRequest("FCM Security", topicURL, "GET", fmt.Sprintf("Topic information: %s", topic))
			
			if result.Accessible && result.HasData {
				showUnauthFinding(result)
			}
			
			results = append(results, result)
		}
	}

	// Test Dynamic Links configuration
	dynamicLinksEndpoints := []struct {
		url         string
		description string
	}{
		{fmt.Sprintf("https://%s.page.link/.well-known/firebase-dynamic-links", state.ProjectID), "Dynamic Links configuration"},
		{fmt.Sprintf("https://%s.web.app/.well-known/firebase-dynamic-links", state.ProjectID), "Web app dynamic links config"},
	}

	for _, endpoint := range dynamicLinksEndpoints {
		result := makeUnauthenticatedRequest("FCM Security", endpoint.url, "GET", endpoint.description)
		
		if result.Accessible {
			showUnauthFinding(result)
		}
		
		results = append(results, result)
	}

	return results
}

// containsFCMKeys checks if response contains FCM-related sensitive data
func containsFCMKeys(data string) bool {
	sensitivePatterns := []string{
		"messagingSenderId",
		"senderId", 
		"AAAA", // FCM server key pattern
		"APA91b", // FCM token pattern
		"firebase-messaging",
		"vapidKey",
		"serverKey",
	}
	
	for _, pattern := range sensitivePatterns {
		if strings.Contains(data, pattern) {
			return true
		}
	}
	return false
}

// testServicesUnauth tests Firebase services enumeration without authentication
func testServicesUnauth(state types.State, hasAPIKey bool) []UnauthTestResult {
	var results []UnauthTestResult

	// Test common Firebase service endpoints
	serviceEndpoints := []struct {
		url         string
		description string
	}{
		{fmt.Sprintf("https://%s.web.app/.well-known/remoteconfig", state.ProjectID), "Remote Config public endpoint"},
		{fmt.Sprintf("https://%s.web.app/.well-known/firebase-extensions", state.ProjectID), "Extensions configuration"},
		{fmt.Sprintf("https://%s.firebaseapp.com/.well-known/remoteconfig", state.ProjectID), "Firebase app Remote Config"},
		{fmt.Sprintf("https://%s.page.link/.well-known/assetlinks.json", state.ProjectID), "Dynamic Links asset links"},
		{fmt.Sprintf("https://%s.web.app/firebase-config.json", state.ProjectID), "Firebase configuration file"},
	}

	for _, endpoint := range serviceEndpoints {
		result := makeUnauthenticatedRequest("Services", endpoint.url, "GET", endpoint.description)
		
		if result.Accessible && result.HasData {
			showUnauthFinding(result)
		}
		
		results = append(results, result)
	}

	return results
}

// testAppCheckUnauth tests App Check configuration without authentication
func testAppCheckUnauth(state types.State, hasAPIKey bool) []UnauthTestResult {
	var results []UnauthTestResult

	// Test App Check configuration endpoints
	appCheckEndpoints := []struct {
		url         string
		description string
	}{
		{fmt.Sprintf("https://%s.web.app/.well-known/app-check", state.ProjectID), "App Check configuration"},
		{fmt.Sprintf("https://%s.firebaseapp.com/.well-known/app-check", state.ProjectID), "Firebase app App Check config"},
		{fmt.Sprintf("https://%s.web.app/recaptcha-config.json", state.ProjectID), "reCAPTCHA configuration"},
		{fmt.Sprintf("https://%s.web.app/app-attest-config.json", state.ProjectID), "App Attest configuration"},
	}

	for _, endpoint := range appCheckEndpoints {
		result := makeUnauthenticatedRequest("App Check", endpoint.url, "GET", endpoint.description)
		
		if result.Accessible {
			// Check if response contains sensitive App Check data
			if result.DataSample != nil {
				dataStr := fmt.Sprintf("%v", result.DataSample)
				if strings.Contains(dataStr, "debug") || strings.Contains(dataStr, "token") || strings.Contains(dataStr, "key") {
					result.HasData = true
					result.Description += " - Contains App Check configuration"
				}
			}
			
			if result.HasData {
				showUnauthFinding(result)
			}
		}
		
		results = append(results, result)
	}

	return results
}

// testStorageSecurityUnauth tests Firebase Storage security basics without authentication
func testStorageSecurityUnauth(state types.State, hasAPIKey bool) []UnauthTestResult {
	var results []UnauthTestResult

	// Test Storage security configuration endpoints
	storageEndpoints := []struct {
		url         string
		description string
	}{
		{fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s.appspot.com", state.ProjectID), "Storage bucket metadata"},
		{fmt.Sprintf("https://%s.web.app/.well-known/storage-cors", state.ProjectID), "Storage CORS configuration"},
		{fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s.appspot.com/o?alt=media", state.ProjectID), "Public storage objects"},
		{fmt.Sprintf("https://%s.appspot.com/.well-known/security.txt", state.ProjectID), "Security configuration"},
	}

	for _, endpoint := range storageEndpoints {
		result := makeUnauthenticatedRequest("Storage Security", endpoint.url, "GET", endpoint.description)
		
		if result.Accessible && result.HasData {
			showUnauthFinding(result)
		}
		
		results = append(results, result)
	}

	// Test common public file patterns
	commonFiles := []string{"config.json", "firebase-config.js", "manifest.json", "robots.txt", ".env", "debug.log"}
	for _, file := range commonFiles {
		fileURL := fmt.Sprintf("https://storage.googleapis.com/%s.appspot.com/%s", state.ProjectID, file)
		result := makeUnauthenticatedRequest("Storage Security", fileURL, "GET", fmt.Sprintf("Public file: %s", file))
		
		if result.Accessible && result.HasData {
			showUnauthFinding(result)
		}
		
		results = append(results, result)
	}

	return results
}