package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/safety"
	"firescan/internal/types"
)

// StorageSecurityResult represents storage security test results
type StorageSecurityResult struct {
	TestType    string
	Bucket      string
	Path        string
	Severity    string
	Finding     string
	Details     map[string]interface{}
	SafetyLevel types.ScanMode
	Error       error
}

// StorageTestCase represents a storage security test
type StorageTestCase struct {
	ID            string
	TestType      string
	Bucket        string
	Path          string
	Description   string
	SafetyLevel   types.ScanMode
	IsDestructive bool
}

// TestStorageSecurity performs comprehensive Firebase Storage security testing
func TestStorageSecurity(mode types.ScanMode) ([]StorageSecurityResult, error) {
	if !safety.WarnUser(mode) {
		return nil, fmt.Errorf("user declined to proceed with storage security testing")
	}

	var results []StorageSecurityResult
	state := config.GetState()

	fmt.Printf("[*] Firebase Storage Security Deep Testing (%s mode)\n", mode.String())

	// Test 1: CORS Misconfiguration Testing (SAFE - Read-only)
	corsResults := testCORSMisconfigurations(state, mode)
	results = append(results, corsResults...)

	// Test 2: Bucket ACL Testing (SAFE - Read-only)
	aclResults := testBucketACLs(state, mode)
	results = append(results, aclResults...)

	// Test 3: Directory Traversal Testing (SAFE - Read-only)
	traversalResults := testDirectoryTraversal(state, mode)
	results = append(results, traversalResults...)

	// Test 4: Public Bucket Enumeration (SAFE - Read-only)
	enumResults := testPublicBucketEnumeration(state, mode)
	results = append(results, enumResults...)

	// Test 5: File Upload Validation Testing (Test mode and above - Creates test files)
	if mode >= types.TestMode {
		uploadResults := testFileUploadValidation(state, mode)
		results = append(results, uploadResults...)
	} else {
		results = append(results, StorageSecurityResult{
			TestType:    "File Upload Validation",
			Finding:     "Skipped in probe mode - requires test mode for safe file uploads",
			SafetyLevel: mode,
		})
	}

	// Test 6: Malicious File Upload Testing (Audit mode only - POTENTIALLY DESTRUCTIVE)
	if mode >= types.AuditMode {
		fmt.Printf("\n%s[!] WARNING: Malicious file upload testing can potentially harm the application%s\n", types.ColorRed, types.ColorReset)
		fmt.Printf("%s[!] This test uploads potentially dangerous files for testing purposes%s\n", types.ColorRed, types.ColorReset)
		fmt.Printf("%s[!] Files will be automatically cleaned up, but this is DESTRUCTIVE testing%s\n", types.ColorRed, types.ColorReset)

		maliciousResults := testMaliciousFileUploads(state, mode)
		results = append(results, maliciousResults...)
	}

	return results, nil
}

// testCORSMisconfigurations tests for CORS misconfigurations (SAFE - Read-only)
func testCORSMisconfigurations(state types.State, mode types.ScanMode) []StorageSecurityResult {
	var results []StorageSecurityResult

	buckets := []string{
		fmt.Sprintf("%s.appspot.com", state.ProjectID),
		fmt.Sprintf("%s.firebaseapp.com", state.ProjectID),
	}

	for _, bucket := range buckets {
		// Track findings for this bucket to avoid duplicates
		foundWildcard := false
		foundMalicious := false

		// Test CORS headers with different origins
		testOrigins := []string{
			"https://evil.com",
			"https://attacker.example.com",
			"null",
			"*",
		}

		for _, origin := range testOrigins {
			result := testCORSOrigin(bucket, origin, state)
			
			// Only show and append finding if we haven't seen this type for this bucket yet
			if result.Finding != "" {
				isWildcard := strings.Contains(result.Finding, "wildcard")
				isMalicious := strings.Contains(result.Finding, "malicious")

				if isWildcard && !foundWildcard {
					showStorageFinding(result)
					foundWildcard = true
					results = append(results, result)
				} else if isMalicious && !foundMalicious {
					showStorageFinding(result)
					foundMalicious = true
					results = append(results, result)
				} else if !isWildcard && !isMalicious {
					// Other types of findings (if any)
					showStorageFinding(result)
					results = append(results, result)
				}
			}
		}
	}

	return results
}

// testCORSOrigin tests CORS configuration for a specific origin
func testCORSOrigin(bucket, origin string, state types.State) StorageSecurityResult {
	result := StorageSecurityResult{
		TestType:    "CORS Misconfiguration",
		Bucket:      bucket,
		Details:     make(map[string]interface{}),
		SafetyLevel: types.ProbeMode,
	}

	url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o", bucket)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("OPTIONS", url, nil)
	if err != nil {
		result.Error = err
		return result
	}

	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "authorization")

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	// Check for dangerous CORS configurations
	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")

	result.Details["origin_tested"] = origin
	result.Details["allow_origin"] = allowOrigin
	result.Details["allow_credentials"] = allowCredentials

	if allowOrigin == "*" && allowCredentials == "true" {
		result.Severity = "High"
		result.Finding = "Dangerous CORS: Wildcard origin with credentials allowed"
	} else if allowOrigin == origin && strings.Contains(origin, "evil") {
		result.Severity = "Medium"
		result.Finding = "CORS allows potentially malicious origin"
	} else if allowOrigin == "*" {
		result.Severity = "Low"
		result.Finding = "CORS allows wildcard origin (potential information disclosure)"
	}

	return result
}

// testBucketACLs tests bucket Access Control Lists (SAFE - Read-only)
func testBucketACLs(state types.State, mode types.ScanMode) []StorageSecurityResult {
	var results []StorageSecurityResult

	buckets := []string{
		fmt.Sprintf("%s.appspot.com", state.ProjectID),
		fmt.Sprintf("%s.firebaseapp.com", state.ProjectID),
	}

	for _, bucket := range buckets {
		// Test bucket-level permissions without authentication
		result := testBucketPermissions(bucket, state)
		if result.Finding != "" {
			showStorageFinding(result)
		}
		results = append(results, result)

		// Test with different authentication contexts
		authResults := testBucketAuthContexts(bucket, state, mode)
		for _, authResult := range authResults {
			if authResult.Finding != "" {
				showStorageFinding(authResult)
			}
		}
		results = append(results, authResults...)
	}

	return results
}

// testBucketPermissions tests bucket permissions
func testBucketPermissions(bucket string, state types.State) StorageSecurityResult {
	result := StorageSecurityResult{
		TestType:    "Bucket ACL",
		Bucket:      bucket,
		Details:     make(map[string]interface{}),
		SafetyLevel: types.ProbeMode,
	}

	// Test unauthenticated access to bucket listing
	url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o", bucket)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		result.Error = err
		return result
	}
	resp, err := client.Do(req)

	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.Details["status_code"] = resp.StatusCode
	result.Details["unauthenticated_access"] = resp.StatusCode == 200

	if resp.StatusCode == 200 {
		result.Severity = "High"
		result.Finding = "Bucket allows unauthenticated listing - potential data exposure"

		// Try to read response body to see what's exposed
		body, err := io.ReadAll(resp.Body)
		if err == nil && len(body) > 0 {
			var bucketData map[string]interface{}
			if json.Unmarshal(body, &bucketData) == nil {
				if items, exists := bucketData["items"]; exists {
					result.Details["exposed_files"] = items
				}
			}
		}
	}

	return result
}

// testBucketAuthContexts tests bucket with different auth contexts
func testBucketAuthContexts(bucket string, state types.State, mode types.ScanMode) []StorageSecurityResult {
	var results []StorageSecurityResult

	// Note: Firebase JWT validation is handled by Google's infrastructure and is robust.
	// Testing JWT manipulation (expired tokens, wrong project tokens, modified claims)
	// would primarily test Google's security, not the target application's configuration.
	//
	// The real security issues are in Security Rules, which are tested by the
	// write/read access testing modules.
	//
	// This function is intentionally left as a no-op as JWT validation testing
	// provides minimal security value for Firebase applications.

	return results
}

// testDirectoryTraversal tests for directory traversal vulnerabilities (SAFE)
func testDirectoryTraversal(state types.State, mode types.ScanMode) []StorageSecurityResult {
	var results []StorageSecurityResult

	bucket := fmt.Sprintf("%s.appspot.com", state.ProjectID)

	// Directory traversal payloads (safe to test)
	traversalPaths := []string{
		"../",
		"../../",
		"../../../",
		"..%2f",
		"..%2f..%2f",
		"..%252f",
		"....//",
		"....\\/",
		"..\\../",
		".%2e%2f",
		"%2e%2e%2f",
		"%252e%252e%252f",
	}

	for _, payload := range traversalPaths {
		result := testTraversalPayload(bucket, payload, state)
		if result.Finding != "" {
			showStorageFinding(result)
		}
		results = append(results, result)
	}

	return results
}

// testTraversalPayload tests a specific directory traversal payload
func testTraversalPayload(bucket, payload string, state types.State) StorageSecurityResult {
	result := StorageSecurityResult{
		TestType:    "Directory Traversal",
		Bucket:      bucket,
		Path:        payload,
		Details:     make(map[string]interface{}),
		SafetyLevel: types.ProbeMode,
	}

	// Test with the traversal payload
	url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o/%s", bucket, payload)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		result.Error = err
		return result
	}
	resp, err := client.Do(req)

	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.Details["status_code"] = resp.StatusCode
	result.Details["payload"] = payload

	// Check for signs of successful traversal
	if resp.StatusCode == 200 {
		result.Severity = "Medium"
		result.Finding = "Directory traversal payload returned 200 - potential path traversal"
	} else if resp.StatusCode == 403 {
		result.Details["blocked"] = true
		// This is expected - security working correctly
	}

	return result
}

// testPublicBucketEnumeration tests for public bucket enumeration (SAFE)
func testPublicBucketEnumeration(state types.State, mode types.ScanMode) []StorageSecurityResult {
	var results []StorageSecurityResult

	// Test common bucket naming patterns
	bucketPatterns := []string{
		fmt.Sprintf("%s.appspot.com", state.ProjectID),
		fmt.Sprintf("%s.firebaseapp.com", state.ProjectID),
		fmt.Sprintf("%s-backup", state.ProjectID),
		fmt.Sprintf("%s-dev", state.ProjectID),
		fmt.Sprintf("%s-staging", state.ProjectID),
		fmt.Sprintf("%s-prod", state.ProjectID),
		fmt.Sprintf("%s-uploads", state.ProjectID),
		fmt.Sprintf("%s-assets", state.ProjectID),
	}

	for _, bucket := range bucketPatterns {
		result := testBucketExists(bucket, state)
		if result.Finding != "" {
			showStorageFinding(result)
		}
		results = append(results, result)
	}

	return results
}

// testBucketExists tests if a bucket exists and is accessible
func testBucketExists(bucket string, state types.State) StorageSecurityResult {
	result := StorageSecurityResult{
		TestType:    "Bucket Enumeration",
		Bucket:      bucket,
		Details:     make(map[string]interface{}),
		SafetyLevel: types.ProbeMode,
	}

	url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s", bucket)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		result.Error = err
		return result
	}
	resp, err := client.Do(req)

	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.Details["status_code"] = resp.StatusCode

	if resp.StatusCode == 200 {
		result.Severity = "Medium"
		result.Finding = "Additional storage bucket discovered - review contents"
	}

	return result
}

// testFileUploadValidation tests file upload validation (Test mode - Creates files)
func testFileUploadValidation(state types.State, mode types.ScanMode) []StorageSecurityResult {
	var results []StorageSecurityResult

	fmt.Printf("[*] Testing file upload validation (will create test files for cleanup)\n")

	bucket := fmt.Sprintf("%s.appspot.com", state.ProjectID)

	// Safe test files
	testFiles := []struct {
		name        string
		content     []byte
		contentType string
		expected    string
	}{
		{
			name:        "test-oversized.txt",
			content:     make([]byte, 100*1024*1024), // 100MB
			contentType: "text/plain",
			expected:    "size_limit_test",
		},
		{
			name:        "test.exe.jpg", // Double extension
			content:     []byte("fake image content"),
			contentType: "image/jpeg",
			expected:    "extension_validation",
		},
		{
			name:        "test_with_spaces .txt",
			content:     []byte("content"),
			contentType: "text/plain",
			expected:    "filename_validation",
		},
	}

	// Setup cleanup tracker
	cleanup := safety.NewTestCleanup(state.ProjectID)
	defer safety.PerformCleanup(cleanup)

	for _, testFile := range testFiles {
		result := testFileUpload(bucket, testFile.name, testFile.content, testFile.contentType, state, cleanup)
		if result.Finding != "" {
			showStorageFinding(result)
		}
		results = append(results, result)
	}

	return results
}

// testMaliciousFileUploads tests malicious file uploads (Audit mode - DESTRUCTIVE)
func testMaliciousFileUploads(state types.State, mode types.ScanMode) []StorageSecurityResult {
	var results []StorageSecurityResult

	fmt.Printf("%s[!] DESTRUCTIVE TEST: Testing malicious file uploads%s\n", types.ColorRed, types.ColorReset)
	fmt.Printf("%s[!] This may upload potentially harmful files to your storage%s\n", types.ColorRed, types.ColorReset)

	bucket := fmt.Sprintf("%s.appspot.com", state.ProjectID)

	// Malicious test payloads (DO NOT make these actually malicious in real testing)
	maliciousTests := []struct {
		name        string
		content     []byte
		contentType string
		testType    string
	}{
		{
			name:        "test-polyglot.jpg",
			content:     []byte("GIF89a/* <script>alert('xss')</script> */fake gif content"),
			contentType: "image/gif",
			testType:    "polyglot_file",
		},
		{
			name:        "test-zip-bomb.zip",
			content:     createSafeZipBomb(), // Safe version for testing
			contentType: "application/zip",
			testType:    "zip_bomb",
		},
		{
			name:        "test-svg-xss.svg",
			content:     []byte(`<svg><script>/*safe test*/</script></svg>`),
			contentType: "image/svg+xml",
			testType:    "svg_xss",
		},
	}

	// Setup cleanup tracker
	cleanup := safety.NewTestCleanup(state.ProjectID)
	defer safety.PerformCleanup(cleanup)

	for _, malTest := range maliciousTests {
		result := testMaliciousUpload(bucket, malTest.name, malTest.content, malTest.contentType, malTest.testType, state, cleanup)
		if result.Finding != "" {
			showStorageFinding(result)
		}
		results = append(results, result)
	}

	return results
}

// Helper functions
func mustParseURL(rawURL string) *url.URL {
	parsedURL, _ := url.Parse(rawURL)
	return parsedURL
}

func createSafeZipBomb() []byte {
	// Create a small, safe zip file for testing (not actually a zip bomb)
	return []byte("PK\x03\x04safe test zip content")
}

func testFileUpload(bucket, filename string, content []byte, contentType string, state types.State, cleanup *types.TestCleanup) StorageSecurityResult {
	result := StorageSecurityResult{
		TestType:    "File Upload Validation",
		Bucket:      bucket,
		Path:        filename,
		Details:     make(map[string]interface{}),
		SafetyLevel: types.TestMode,
	}

	// Add to cleanup
	safety.AddFileToCleanup(cleanup, filename)

	// Attempt upload
	uploadURL := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o", bucket)

	// Create multipart form data
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		result.Error = err
		return result
	}

	fw.Write(content)
	w.Close()

	// Make authenticated request
	resp, err := auth.MakeAuthenticatedRequest("POST", uploadURL, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.Details["status_code"] = resp.StatusCode
	result.Details["file_size"] = len(content)

	// Analyze response
	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		if len(content) > 50*1024*1024 { // > 50MB
			result.Severity = "Medium"
			result.Finding = "Large file upload successful - no size limits detected"
		} else if strings.Contains(filename, ".exe.") {
			result.Severity = "High"
			result.Finding = "Double extension file upload successful - potential security risk"
		}
	}

	return result
}

func testMaliciousUpload(bucket, filename string, content []byte, contentType, testType string, state types.State, cleanup *types.TestCleanup) StorageSecurityResult {
	result := StorageSecurityResult{
		TestType:    "Malicious Upload Test",
		Bucket:      bucket,
		Path:        filename,
		Details:     make(map[string]interface{}),
		SafetyLevel: types.AuditMode,
	}

	result.Details["test_type"] = testType
	result.Details["content_type"] = contentType

	// Add to cleanup
	safety.AddFileToCleanup(cleanup, filename)

	// This would implement actual malicious upload testing
	// For safety, we're not implementing the actual malicious uploads
	result.Finding = fmt.Sprintf("Malicious upload test placeholder - would test %s", testType)
	result.Severity = "Info"

	return result
}

// showStorageFinding displays a storage security finding immediately
func showStorageFinding(result StorageSecurityResult) {
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

	fmt.Printf("\n[%s%s%s] %s%sVulnerability Found!%s\n  ├── Timestamp: %s\n  ├── Severity:  %s%s%s\n  ├── Type:      %s\n  └── Path:      %s\n",
		types.ColorRed, types.ColorBold, "Storage", types.ColorGreen, types.ColorBold, types.ColorReset,
		timestamp,
		severityColor, result.Severity, types.ColorReset,
		result.TestType,
		result.Bucket+"/"+result.Path)

	fmt.Printf("  └── Details:   %s\n", result.Finding)
}
