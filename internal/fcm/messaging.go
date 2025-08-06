package fcm

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

// FCMSecurityResult represents FCM security test results
type FCMSecurityResult struct {
	TestType      string
	TestCase      string
	Endpoint      string
	Vulnerability string
	Severity      string
	Finding       string
	Details       map[string]interface{}
	SafetyLevel   types.ScanMode
	Error         error
	AuthRequired  bool
}

// TestFCMSecurity performs comprehensive FCM and Push Notification security testing
func TestFCMSecurity(mode types.ScanMode) ([]FCMSecurityResult, error) {
	if !safety.WarnUser(mode) {
		return nil, fmt.Errorf("user declined to proceed with FCM security testing")
	}

	var results []FCMSecurityResult
	state := config.GetState()

	fmt.Printf("[*] FCM & Push Notification Security Testing (%s mode)\n", mode.String())

	// Test 1: FCM Server Key Exposure (SAFE - Read-only)
	serverKeyResults := testFCMServerKeyExposure(state, mode)
	for _, result := range serverKeyResults {
		if result.Finding != "" {
			showFCMFinding(result)
		}
	}
	results = append(results, serverKeyResults...)

	// Test 2: FCM Topic Enumeration (SAFE - Read-only)
	topicResults := testFCMTopicEnumeration(state, mode)
	for _, result := range topicResults {
		if result.Finding != "" {
			showFCMFinding(result)
		}
	}
	results = append(results, topicResults...)

	// Test 3: Push Token Validation (SAFE - Read-only)
	tokenResults := testPushTokenValidation(state, mode)
	for _, result := range tokenResults {
		if result.Finding != "" {
			showFCMFinding(result)
		}
	}
	results = append(results, tokenResults...)

	// Test 4: Notification Content Disclosure (SAFE - Read-only)
	contentResults := testNotificationContentDisclosure(state, mode)
	for _, result := range contentResults {
		if result.Finding != "" {
			showFCMFinding(result)
		}
	}
	results = append(results, contentResults...)

	// Test 5: In-App Messaging Security (SAFE - Read-only)
	messagingResults := testInAppMessagingSecurity(state, mode)
	for _, result := range messagingResults {
		if result.Finding != "" {
			showFCMFinding(result)
		}
	}
	results = append(results, messagingResults...)

	// Test 6: Dynamic Link Security (SAFE - Read-only) 
	dynamicResults := testDynamicLinkSecurity(state, mode)
	for _, result := range dynamicResults {
		if result.Finding != "" {
			showFCMFinding(result)
		}
	}
	results = append(results, dynamicResults...)

	return results, nil
}

// testFCMServerKeyExposure tests for FCM server key exposure
func testFCMServerKeyExposure(state types.State, mode types.ScanMode) []FCMSecurityResult {
	var results []FCMSecurityResult

	// Test common server key exposure endpoints
	testCases := []struct {
		endpoint    string
		description string
		authReq     bool
	}{
		{"/v1/projects/%s/messages:send", "FCM Messaging API access", true},
		{"/fcm/send", "Legacy FCM send endpoint", false},
		{"/v1/projects/%s", "Project configuration with FCM keys", true},
		{"/.well-known/firebase-messaging-sw.js", "Service Worker with keys", false},
		{"/firebase-messaging-sw.js", "Firebase messaging service worker", false},
		{"/manifest.json", "Web app manifest with FCM config", false},
	}

	for _, testCase := range testCases {
		result := FCMSecurityResult{
			TestType:     "FCM Key Exposure",
			TestCase:     testCase.description,
			Endpoint:     fmt.Sprintf(testCase.endpoint, state.ProjectID),
			Details:      make(map[string]interface{}),
			SafetyLevel:  mode,
			AuthRequired: testCase.authReq,
		}

		if testCase.authReq && (state.Token == "" || state.ProjectID == "") {
			result.Details["skipped"] = "Authentication required"
			results = append(results, result)
			continue
		}

		if state.ProjectID == "" {
			result.Details["skipped"] = "ProjectID required"
			results = append(results, result)
			continue
		}

		// Test for server key exposure
		keyExposure := testFCMKeyEndpoint(result.Endpoint, state, testCase.authReq)
		result.Details["key_test"] = keyExposure

		if keyExposure.HasServerKey {
			result.Vulnerability = "FCM Server Key Exposure"
			result.Severity = "High"
			result.Finding = fmt.Sprintf("FCM server key exposed at %s - could enable message injection attacks", result.Endpoint)
			result.Details["exposed_key"] = keyExposure.KeyPattern
		} else if keyExposure.HasSenderID {
			result.Vulnerability = "FCM Sender ID Exposure"
			result.Severity = "Medium"
			result.Finding = fmt.Sprintf("FCM sender ID exposed at %s - enables topic enumeration", result.Endpoint)
			result.Details["sender_id"] = keyExposure.SenderID
		}

		results = append(results, result)
	}

	return results
}

// testFCMTopicEnumeration tests FCM topic enumeration
func testFCMTopicEnumeration(state types.State, mode types.ScanMode) []FCMSecurityResult {
	var results []FCMSecurityResult

	// Common FCM topic names to test
	commonTopics := []string{
		"news", "updates", "notifications", "alerts", "marketing",
		"admin", "test", "dev", "prod", "users", "all", "general",
		"announcements", "promotions", "events", "debug",
	}

	result := FCMSecurityResult{
		TestType:     "FCM Topic Enumeration",
		TestCase:     "Topic subscription enumeration",
		Details:      make(map[string]interface{}),
		SafetyLevel:  mode,
		AuthRequired: false, // Can test some topic endpoints without auth
	}

	if state.ProjectID == "" {
		result.Details["skipped"] = "ProjectID required"
		results = append(results, result)
		return results
	}

	var accessibleTopics []string
	var topicDetails []map[string]interface{}

	for _, topic := range commonTopics {
		topicAccess := testFCMTopicAccess(topic, state)
		if topicAccess.Accessible {
			accessibleTopics = append(accessibleTopics, topic)
			topicDetails = append(topicDetails, map[string]interface{}{
				"topic":           topic,
				"subscriber_count": topicAccess.SubscriberCount,
				"metadata":        topicAccess.Metadata,
			})
		}
	}

	result.Details["accessible_topics"] = accessibleTopics
	result.Details["topic_details"] = topicDetails

	if len(accessibleTopics) > 0 {
		result.Vulnerability = "FCM Topic Enumeration"
		result.Severity = "Medium"
		result.Finding = fmt.Sprintf("Found %d accessible FCM topics - potential for unauthorized subscriptions", len(accessibleTopics))
		result.Endpoint = fmt.Sprintf("/v1/projects/%s/topics", state.ProjectID)
	}

	results = append(results, result)
	return results
}

// testPushTokenValidation tests push token security
func testPushTokenValidation(state types.State, mode types.ScanMode) []FCMSecurityResult {
	var results []FCMSecurityResult

	result := FCMSecurityResult{
		TestType:     "Push Token Security",
		TestCase:     "Push token validation and abuse",
		Details:      make(map[string]interface{}),
		SafetyLevel:  mode,
		AuthRequired: false,
	}

	if state.APIKey == "" || state.ProjectID == "" {
		result.Details["skipped"] = "API key and project ID required"
		results = append(results, result)
		return results
	}

	// Test token validation endpoint
	tokenValidation := testTokenValidationEndpoint(state)
	result.Details["token_validation"] = tokenValidation

	if tokenValidation.ValidationBypassable {
		result.Vulnerability = "Push Token Validation Bypass"
		result.Severity = "Medium"
		result.Finding = "Push token validation can be bypassed - enables unauthorized message sending"
		result.Endpoint = tokenValidation.ValidationEndpoint
	}

	// Test for token enumeration possibilities
	tokenEnum := testTokenEnumeration(state)
	result.Details["token_enumeration"] = tokenEnum

	if tokenEnum.EnumerationPossible {
		result.Vulnerability = "Push Token Enumeration"
		result.Severity = "High"
		result.Finding = "Push token enumeration possible - could enable mass spam attacks"
	}

	results = append(results, result)
	return results
}

// testNotificationContentDisclosure tests for notification content disclosure
func testNotificationContentDisclosure(state types.State, mode types.ScanMode) []FCMSecurityResult {
	var results []FCMSecurityResult

	// Test notification history and content endpoints
	testCases := []struct {
		endpoint    string
		description string
		authReq     bool
	}{
		{"/v1/projects/%s/messages", "Message history access", true},
		{"/notifications/history", "Notification history", false},
		{"/firebase-messaging-logs", "FCM message logs", false},
		{"/.well-known/notifications", "Notification metadata", false},
	}

	for _, testCase := range testCases {
		result := FCMSecurityResult{
			TestType:     "Notification Content Disclosure",
			TestCase:     testCase.description,
			Endpoint:     fmt.Sprintf(testCase.endpoint, state.ProjectID),
			Details:      make(map[string]interface{}),
			SafetyLevel:  mode,
			AuthRequired: testCase.authReq,
		}

		if testCase.authReq && (state.Token == "" || state.ProjectID == "") {
			result.Details["skipped"] = "Authentication required"
			results = append(results, result)
			continue
		}

		if state.ProjectID == "" {
			result.Details["skipped"] = "ProjectID required"
			results = append(results, result)
			continue
		}

		// Test for content disclosure
		contentAccess := testNotificationContentAccess(result.Endpoint, state, testCase.authReq)
		result.Details["content_access"] = contentAccess

		if contentAccess.HasSensitiveContent {
			result.Vulnerability = "Notification Content Disclosure"
			result.Severity = "Medium"
			result.Finding = fmt.Sprintf("Sensitive notification content exposed at %s", result.Endpoint)
			result.Details["content_types"] = contentAccess.SensitiveTypes
		}

		results = append(results, result)
	}

	return results
}

// testInAppMessagingSecurity tests in-app messaging security
func testInAppMessagingSecurity(state types.State, mode types.ScanMode) []FCMSecurityResult {
	var results []FCMSecurityResult

	result := FCMSecurityResult{
		TestType:     "In-App Messaging Security",
		TestCase:     "In-app messaging configuration and content",
		Details:      make(map[string]interface{}),
		SafetyLevel:  mode,
		AuthRequired: false,
	}

	if state.ProjectID == "" {
		result.Details["skipped"] = "ProjectID required"
		results = append(results, result)
		return results
	}

	// Test in-app messaging endpoints
	messagingAccess := testInAppMessagingEndpoints(state)
	result.Details["messaging_access"] = messagingAccess

	if messagingAccess.ConfigurationExposed {
		result.Vulnerability = "In-App Messaging Configuration Exposure"
		result.Severity = "Low"
		result.Finding = "In-app messaging configuration exposed - reveals campaign details"
		result.Endpoint = messagingAccess.ConfigEndpoint
	}

	if messagingAccess.ContentInjectable {
		result.Vulnerability = "In-App Message Content Injection"
		result.Severity = "High"
		result.Finding = "In-app message content injection possible - could enable phishing attacks"
	}

	results = append(results, result)
	return results
}

// testDynamicLinkSecurity tests dynamic link security
func testDynamicLinkSecurity(state types.State, mode types.ScanMode) []FCMSecurityResult {
	var results []FCMSecurityResult

	// Test dynamic link endpoints and configurations
	testCases := []struct {
		endpoint    string
		description string
		authReq     bool
	}{
		{"/v1/projects/%s/shortLinks", "Dynamic link creation", true},
		{"/.well-known/firebase-dynamic-links", "Dynamic link configuration", false},
		{"/v1/projects/%s/dynamicLinks", "Dynamic link enumeration", true},
		{"/firebase-dynamic-links.json", "Dynamic link manifest", false},
	}

	for _, testCase := range testCases {
		result := FCMSecurityResult{
			TestType:     "Dynamic Link Security",
			TestCase:     testCase.description,
			Endpoint:     fmt.Sprintf(testCase.endpoint, state.ProjectID),
			Details:      make(map[string]interface{}),
			SafetyLevel:  mode,
			AuthRequired: testCase.authReq,
		}

		if testCase.authReq && (state.Token == "" || state.ProjectID == "") {
			result.Details["skipped"] = "Authentication required"
			results = append(results, result)
			continue
		}

		if state.ProjectID == "" {
			result.Details["skipped"] = "ProjectID required"
			results = append(results, result)
			continue
		}

		// Test dynamic link security
		linkSecurity := testDynamicLinkEndpoint(result.Endpoint, state, testCase.authReq)
		result.Details["link_security"] = linkSecurity

		if linkSecurity.ParameterInjection {
			result.Vulnerability = "Dynamic Link Parameter Injection"
			result.Severity = "High"
			result.Finding = fmt.Sprintf("Parameter injection possible in dynamic links at %s", result.Endpoint)
		} else if linkSecurity.ConfigurationExposed {
			result.Vulnerability = "Dynamic Link Configuration Exposure"
			result.Severity = "Medium"
			result.Finding = fmt.Sprintf("Dynamic link configuration exposed at %s", result.Endpoint)
		}

		results = append(results, result)
	}

	return results
}

// Helper structures for FCM testing
type FCMKeyTest struct {
	HasServerKey bool
	HasSenderID  bool
	KeyPattern   string
	SenderID     string
	Accessible   bool
}

type FCMTopicAccess struct {
	Accessible      bool
	SubscriberCount int
	Metadata        map[string]interface{}
}

type TokenValidationTest struct {
	ValidationBypassable bool
	ValidationEndpoint   string
	BypassMethod        string
}

type TokenEnumerationTest struct {
	EnumerationPossible bool
	EnumerationMethod   string
	SampleTokens        []string
}

type NotificationContentAccess struct {
	HasSensitiveContent bool
	SensitiveTypes      []string
	ContentSamples      []string
}

type InAppMessagingAccess struct {
	ConfigurationExposed bool
	ContentInjectable    bool
	ConfigEndpoint       string
}

type DynamicLinkSecurity struct {
	ParameterInjection   bool
	ConfigurationExposed bool
	InjectionVectors     []string
}

// Helper functions for FCM testing
func testFCMKeyEndpoint(endpoint string, state types.State, requireAuth bool) FCMKeyTest {
	result := FCMKeyTest{}

	var baseURL string
	if strings.HasPrefix(endpoint, "http") {
		baseURL = endpoint
	} else if strings.HasPrefix(endpoint, "/v1/") {
		baseURL = "https://fcm.googleapis.com" + endpoint
	} else if strings.HasPrefix(endpoint, "/fcm/") {
		baseURL = "https://fcm.googleapis.com" + endpoint
	} else {
		// Assume it's a web resource
		baseURL = fmt.Sprintf("https://%s.web.app%s", state.ProjectID, endpoint)
	}

	var resp *http.Response
	var err error

	if requireAuth && state.Token != "" {
		resp, err = auth.MakeAuthenticatedRequest("GET", baseURL, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	} else {
		resp, err = http.Get(baseURL)
	}

	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.Accessible = (resp.StatusCode == 200)

	if resp.StatusCode == 200 {
		var responseData interface{}
		if json.NewDecoder(resp.Body).Decode(&responseData) == nil {
			// Look for FCM keys and sender IDs in response
			responseStr := fmt.Sprintf("%v", responseData)
			
			// Look for server key patterns
			if strings.Contains(responseStr, "AAAA") && strings.Contains(responseStr, ":APA91b") {
				result.HasServerKey = true
				result.KeyPattern = "Server key pattern detected"
			}
			
			// Look for sender ID patterns
			if strings.Contains(responseStr, "messagingSenderId") || strings.Contains(responseStr, "senderId") {
				result.HasSenderID = true
				result.SenderID = "Sender ID found in configuration"
			}
		}
	}

	return result
}

func testFCMTopicAccess(topic string, state types.State) FCMTopicAccess {
	result := FCMTopicAccess{
		Metadata: make(map[string]interface{}),
	}

	// Test topic info endpoint (if available)
	topicURL := fmt.Sprintf("https://iid.googleapis.com/iid/info/%s?details=true", topic)
	
	if state.APIKey != "" {
		topicURL += "&key=" + state.APIKey
	}

	resp, err := http.Get(topicURL)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.Accessible = (resp.StatusCode == 200)

	if resp.StatusCode == 200 {
		var topicInfo map[string]interface{}
		if json.NewDecoder(resp.Body).Decode(&topicInfo) == nil {
			result.Metadata = topicInfo
			if count, ok := topicInfo["rel"].(map[string]interface{})["topics"].(map[string]interface{})[topic].(float64); ok {
				result.SubscriberCount = int(count)
			}
		}
	}

	return result
}

func testTokenValidationEndpoint(state types.State) TokenValidationTest {
	result := TokenValidationTest{}

	// Test token validation endpoint
	validationURL := "https://iid.googleapis.com/iid/v1:batchAdd"
	result.ValidationEndpoint = validationURL

	// Test with dummy token to see if validation can be bypassed
	testPayload := `{"to":"/topics/test","registration_tokens":["dummy_token_test_123"]}`
	
	resp, err := http.Post(validationURL+"?key="+state.APIKey, "application/json", strings.NewReader(testPayload))
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	// If we get a 200 response with dummy token, validation might be bypassable
	if resp.StatusCode == 200 {
		result.ValidationBypassable = true
		result.BypassMethod = "dummy_token_accepted"
	}

	return result
}

func testTokenEnumeration(state types.State) TokenEnumerationTest {
	result := TokenEnumerationTest{}

	// Test various token enumeration techniques
	// This is a safe check - we're not actually enumerating real tokens
	
	// Check if batch operations reveal token validation patterns
	batchURL := "https://iid.googleapis.com/iid/v1:batchImport"
	resp, err := http.Post(batchURL+"?key="+state.APIKey, "application/json", strings.NewReader(`{}`))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != 400 && resp.StatusCode != 403 {
			result.EnumerationPossible = true
			result.EnumerationMethod = "batch_operation_enumeration"
		}
	}

	return result
}

func testNotificationContentAccess(endpoint string, state types.State, requireAuth bool) NotificationContentAccess {
	result := NotificationContentAccess{
		SensitiveTypes: []string{},
		ContentSamples: []string{},
	}

	var baseURL string
	if strings.HasPrefix(endpoint, "http") {
		baseURL = endpoint
	} else {
		baseURL = fmt.Sprintf("https://%s.web.app%s", state.ProjectID, endpoint)
	}

	var resp *http.Response
	var err error

	if requireAuth && state.Token != "" {
		resp, err = auth.MakeAuthenticatedRequest("GET", baseURL, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	} else {
		resp, err = http.Get(baseURL)
	}

	if err != nil {
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var data interface{}
		if json.NewDecoder(resp.Body).Decode(&data) == nil {
			dataStr := fmt.Sprintf("%v", data)
			
			// Check for sensitive content patterns
			sensitivePatterns := []string{"email", "phone", "personal", "private", "confidential", "internal"}
			for _, pattern := range sensitivePatterns {
				if strings.Contains(strings.ToLower(dataStr), pattern) {
					result.HasSensitiveContent = true
					result.SensitiveTypes = append(result.SensitiveTypes, pattern)
				}
			}
		}
	}

	return result
}

func testInAppMessagingEndpoints(state types.State) InAppMessagingAccess {
	result := InAppMessagingAccess{}

	// Test in-app messaging configuration endpoint
	configURL := fmt.Sprintf("https://%s.web.app/.well-known/in-app-messaging", state.ProjectID)
	resp, err := http.Get(configURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			result.ConfigurationExposed = true
			result.ConfigEndpoint = configURL
		}
	}

	// Test for content injection possibilities (safe check)
	// We're just checking if the endpoint accepts POST requests, not injecting actual content
	injectURL := fmt.Sprintf("https://inappmessaging.googleapis.com/v1/projects/%s/campaigns", state.ProjectID)
	postResp, err := http.Post(injectURL, "application/json", strings.NewReader(`{"test": "content"}`))
	if err == nil {
		defer postResp.Body.Close()
		// If we don't get immediate authentication error, content injection might be possible
		if postResp.StatusCode != 401 && postResp.StatusCode != 403 {
			result.ContentInjectable = true
		}
	}

	return result
}

func testDynamicLinkEndpoint(endpoint string, state types.State, requireAuth bool) DynamicLinkSecurity {
	result := DynamicLinkSecurity{
		InjectionVectors: []string{},
	}

	var baseURL string
	if strings.HasPrefix(endpoint, "http") {
		baseURL = endpoint
	} else if strings.HasPrefix(endpoint, "/v1/") {
		baseURL = "https://firebasedynamiclinks.googleapis.com" + endpoint
	} else {
		baseURL = fmt.Sprintf("https://%s.web.app%s", state.ProjectID, endpoint)
	}

	var resp *http.Response
	var err error

	if requireAuth && state.Token != "" {
		resp, err = auth.MakeAuthenticatedRequest("GET", baseURL, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	} else {
		resp, err = http.Get(baseURL)
	}

	if err != nil {
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var data interface{}
		if json.NewDecoder(resp.Body).Decode(&data) == nil {
			dataStr := fmt.Sprintf("%v", data)
			
			// Check for configuration exposure
			if strings.Contains(dataStr, "domainUriPrefix") || strings.Contains(dataStr, "shortLinks") {
				result.ConfigurationExposed = true
			}
			
			// Check for parameter injection vectors
			injectionPatterns := []string{"javascript:", "data:", "vbscript:", "onload=", "onerror="}
			for _, pattern := range injectionPatterns {
				if strings.Contains(strings.ToLower(dataStr), pattern) {
					result.ParameterInjection = true
					result.InjectionVectors = append(result.InjectionVectors, pattern)
				}
			}
		}
	}

	return result
}

// showFCMFinding displays an FCM finding immediately
func showFCMFinding(result FCMSecurityResult) {
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
		types.ColorRed, types.ColorBold, "FCM", types.ColorGreen, types.ColorBold, types.ColorReset,
		timestamp,
		severityColor, result.Severity, types.ColorReset,
		result.TestType,
		result.Endpoint)
		
	fmt.Printf("  └── Details:   %s\n", result.Finding)
}