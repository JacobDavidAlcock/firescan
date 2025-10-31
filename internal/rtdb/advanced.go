package rtdb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/safety"
	"firescan/internal/status"
	"firescan/internal/types"
)

// RTDBAdvancedResult represents RTDB advanced security test results
type RTDBAdvancedResult struct {
	TestType      string
	TestCase      string
	Path          string
	Vulnerability string
	Severity      string
	Finding       string
	Details       map[string]interface{}
	SafetyLevel   types.ScanMode
	Error         error
	AuthRequired  bool
}

// TestRTDBAdvancedSecurity performs comprehensive RTDB advanced security testing
func TestRTDBAdvancedSecurity(mode types.ScanMode) ([]RTDBAdvancedResult, error) {
	if !safety.WarnUser(mode) {
		return nil, fmt.Errorf("user declined to proceed with RTDB advanced testing")
	}

	var results []RTDBAdvancedResult
	state := config.GetState()

	fmt.Printf("[*] RTDB Advanced Security Testing (%s mode)\n", mode.String())

	// Test 1: Rule Precedence Conflicts (SAFE - Read-only)
	precedenceResults := testRulePrecedenceConflicts(state, mode)
	for _, result := range precedenceResults {
		if result.Finding != "" {
			showRTDBFinding(result)
		}
	}
	results = append(results, precedenceResults...)

	// Test 2: Validation Rule Bypasses (SAFE - Read-only analysis)
	validationResults := testValidationRuleBypasses(state, mode)
	for _, result := range validationResults {
		if result.Finding != "" {
			showRTDBFinding(result)
		}
	}
	results = append(results, validationResults...)

	// Test 3: Path Rule Exploitation (SAFE - Read-only)
	pathResults := testPathRuleExploitation(state, mode)
	for _, result := range pathResults {
		if result.Finding != "" {
			showRTDBFinding(result)
		}
	}
	results = append(results, pathResults...)

	// Test 4: Rule Indexing Bypasses (SAFE - Read-only)
	indexResults := testRuleIndexingBypasses(state, mode)
	for _, result := range indexResults {
		if result.Finding != "" {
			showRTDBFinding(result)
		}
	}
	results = append(results, indexResults...)

	// Test 5: Delta Sync Rule Testing (SAFE - Read-only)
	deltaResults := testDeltaSyncRules(state, mode)
	for _, result := range deltaResults {
		if result.Finding != "" {
			showRTDBFinding(result)
		}
	}
	results = append(results, deltaResults...)

	// Clear any remaining status at the end
	status.ClearStatus()

	return results, nil
}

// testRulePrecedenceConflicts tests for rule precedence vulnerabilities
func testRulePrecedenceConflicts(state types.State, mode types.ScanMode) []RTDBAdvancedResult {
	var results []RTDBAdvancedResult

	// Test common precedence conflict patterns
	testCases := []struct {
		path        string
		description string
		authReq     bool
	}{
		{"/users", "Parent-child rule conflicts in user data", true},
		{"/users/$uid/private", "Private data rule precedence", true},
		{"/admin", "Administrative path rule conflicts", true},
		{"/public", "Public data with restrictive child rules", false},
		{"/config", "Configuration data rule conflicts", false},
		{"/metadata", "Metadata rule precedence issues", false},
	}

	for _, testCase := range testCases {
		status.ShowStatus(fmt.Sprintf("Testing RTDB rule precedence: %s", testCase.description))

		result := RTDBAdvancedResult{
			TestType:     "Rule Precedence",
			TestCase:     testCase.description,
			Path:         testCase.path,
			Details:      make(map[string]interface{}),
			SafetyLevel:  mode,
			AuthRequired: testCase.authReq,
		}

		// Test parent rule vs child rule conflicts
		parentPath := testCase.path
		childPath := testCase.path + "/restricted"

		if testCase.authReq && (state.Token == "" || state.ProjectID == "") {
			result.Details["skipped"] = "Authentication required"
			results = append(results, result)
			continue
		}

		if !testCase.authReq && state.ProjectID == "" {
			result.Details["skipped"] = "ProjectID required"
			results = append(results, result)
			continue
		}

		// Test parent access
		parentAccess := testRTDBAccess(parentPath, state, testCase.authReq)
		childAccess := testRTDBAccess(childPath, state, testCase.authReq)

		result.Details["parent_access"] = parentAccess
		result.Details["child_access"] = childAccess

		// Analyze for precedence conflicts
		if analyzeRulePrecedenceVulnerability(parentAccess, childAccess) {
			result.Vulnerability = "Rule Precedence Conflict"
			result.Severity = "Medium"
			result.Finding = fmt.Sprintf("Rule precedence conflict detected - parent access differs from child access at %s", testCase.path)
			result.Details["vulnerability_type"] = "precedence_conflict"
		}

		results = append(results, result)
	}

	return results
}

// testValidationRuleBypasses tests for validation rule bypass vulnerabilities
func testValidationRuleBypasses(state types.State, mode types.ScanMode) []RTDBAdvancedResult {
	var results []RTDBAdvancedResult

	testCases := []struct {
		path        string
		description string
		authReq     bool
	}{
		{"/users/$uid/profile", "User profile validation bypasses", true},
		{"/posts", "Post validation rule testing", true},
		{"/comments", "Comment validation bypasses", true},
		{"/settings", "Settings validation rules", false},
		{"/public_data", "Public data validation", false},
	}

	for _, testCase := range testCases {
		result := RTDBAdvancedResult{
			TestType:     "Validation Bypass",
			TestCase:     testCase.description,
			Path:         testCase.path,
			Details:      make(map[string]interface{}),
			SafetyLevel:  mode,
			AuthRequired: testCase.authReq,
		}

		if testCase.authReq && (state.Token == "" || state.ProjectID == "") {
			result.Details["skipped"] = "Authentication required"
			results = append(results, result)
			continue
		}

		if !testCase.authReq && state.ProjectID == "" {
			result.Details["skipped"] = "ProjectID required"
			results = append(results, result)
			continue
		}

		// Test for validation rule bypasses by checking rule structure
		ruleAnalysis := analyzeValidationRules(testCase.path, state, testCase.authReq)
		result.Details["rule_analysis"] = ruleAnalysis

		if ruleAnalysis.HasValidationBypass {
			result.Vulnerability = "Validation Rule Bypass"
			result.Severity = "High"
			result.Finding = fmt.Sprintf("Validation rule bypass detected at %s - write operations may bypass validation", testCase.path)
			result.Details["bypass_type"] = ruleAnalysis.BypassType
		}

		results = append(results, result)
	}

	return results
}

// testPathRuleExploitation tests for path-based rule exploitation
func testPathRuleExploitation(state types.State, mode types.ScanMode) []RTDBAdvancedResult {
	var results []RTDBAdvancedResult

	// Test path traversal and manipulation techniques
	exploitPaths := []struct {
		path        string
		description string
		technique   string
		authReq     bool
	}{
		{"/../admin", "Path traversal to admin", "path_traversal", false},
		{"/users/../config", "Config access via user path", "lateral_traversal", true},
		{"/public/%2e%2e/private", "URL encoded path traversal", "encoded_traversal", false},
		{"/data/..", "Parent directory access", "parent_access", false},
		{"/users/$uid/../other_user", "User data lateral access", "lateral_access", true},
	}

	for _, exploit := range exploitPaths {
		result := RTDBAdvancedResult{
			TestType:     "Path Exploitation",
			TestCase:     exploit.description,
			Path:         exploit.path,
			Details:      make(map[string]interface{}),
			SafetyLevel:  mode,
			AuthRequired: exploit.authReq,
		}

		result.Details["technique"] = exploit.technique

		if exploit.authReq && (state.Token == "" || state.ProjectID == "") {
			result.Details["skipped"] = "Authentication required"
			results = append(results, result)
			continue
		}

		if state.ProjectID == "" {
			result.Details["skipped"] = "ProjectID required"
			results = append(results, result)
			continue
		}

		// Test the exploit path
		accessResult := testRTDBAccess(exploit.path, state, exploit.authReq)
		result.Details["access_result"] = accessResult

		if accessResult.Accessible && !accessResult.ExpectedDenied {
			result.Vulnerability = "Path Rule Exploitation"
			result.Severity = "High"
			result.Finding = fmt.Sprintf("Path exploitation successful at %s using %s technique", exploit.path, exploit.technique)
			result.Details["exploitation_successful"] = true
		}

		results = append(results, result)
	}

	return results
}

// testRuleIndexingBypasses tests for rule indexing optimization bypasses
func testRuleIndexingBypasses(state types.State, mode types.ScanMode) []RTDBAdvancedResult {
	var results []RTDBAdvancedResult

	// Test indexing rule bypass techniques
	testCases := []struct {
		path        string
		description string
		technique   string
		authReq     bool
	}{
		{"/indexed_data", "Query without required index", "missing_index", false},
		{"/ordered_data", "Ordering bypass without index", "order_bypass", false},
		{"/filtered_data", "Filter bypass via indexing", "filter_bypass", true},
		{"/limited_data", "Limit bypass through indexing", "limit_bypass", true},
	}

	for _, testCase := range testCases {
		result := RTDBAdvancedResult{
			TestType:     "Indexing Bypass",
			TestCase:     testCase.description,
			Path:         testCase.path,
			Details:      make(map[string]interface{}),
			SafetyLevel:  mode,
			AuthRequired: testCase.authReq,
		}

		result.Details["technique"] = testCase.technique

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

		// Test indexing bypass
		indexBypass := testIndexingBypass(testCase.path, testCase.technique, state, testCase.authReq)
		result.Details["bypass_result"] = indexBypass

		if indexBypass.BypassSuccessful {
			result.Vulnerability = "Rule Indexing Bypass"
			result.Severity = "Medium"
			result.Finding = fmt.Sprintf("Indexing rule bypass detected at %s using %s", testCase.path, testCase.technique)
		}

		results = append(results, result)
	}

	return results
}

// testDeltaSyncRules tests delta sync rule bypasses
func testDeltaSyncRules(state types.State, mode types.ScanMode) []RTDBAdvancedResult {
	var results []RTDBAdvancedResult

	testCases := []struct {
		path        string
		description string
		authReq     bool
	}{
		{"/live_data", "Live data delta sync rules", true},
		{"/user_presence", "User presence delta sync", true},
		{"/chat_messages", "Chat message delta sync", true},
		{"/notifications", "Notification delta sync", false},
	}

	for _, testCase := range testCases {
		result := RTDBAdvancedResult{
			TestType:     "Delta Sync Rules",
			TestCase:     testCase.description,
			Path:         testCase.path,
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

		// Test delta sync rule bypasses
		deltaBypass := testDeltaSyncBypass(testCase.path, state, testCase.authReq)
		result.Details["delta_test"] = deltaBypass

		if deltaBypass.HasBypass {
			result.Vulnerability = "Delta Sync Rule Bypass"
			result.Severity = "Medium"
			result.Finding = fmt.Sprintf("Delta sync rule bypass detected at %s", testCase.path)
		}

		results = append(results, result)
	}

	return results
}

// Helper structures and functions
type RTDBAccessResult struct {
	Accessible     bool
	HasData        bool
	StatusCode     int
	ResponseSize   int
	ExpectedDenied bool
	Error          error
}

type ValidationAnalysis struct {
	HasValidationBypass bool
	BypassType          string
	RuleStructure       map[string]interface{}
}

type IndexingBypassResult struct {
	BypassSuccessful bool
	IndexRequired    bool
	QueryWorked      bool
}

type DeltaSyncTest struct {
	HasBypass  bool
	ListenerOk bool
	SyncIssues []string
}

// testRTDBAccess tests access to an RTDB path
func testRTDBAccess(path string, state types.State, requireAuth bool) RTDBAccessResult {
	result := RTDBAccessResult{}

	// Construct RTDB URL
	url := fmt.Sprintf("https://%s-default-rtdb.firebaseio.com%s.json", state.ProjectID, path)

	var resp *http.Response
	var err error

	if requireAuth && state.Token != "" {
		// Make authenticated request
		resp, err = auth.MakeAuthenticatedRequest("GET", url, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	} else {
		// Make unauthenticated request
		resp, err = http.Get(url)
	}

	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Accessible = (resp.StatusCode == 200)

	// Check if we have data
	if resp.StatusCode == 200 {
		var data interface{}
		if json.NewDecoder(resp.Body).Decode(&data) == nil {
			result.HasData = (data != nil)
		}
	}

	return result
}

// analyzeRulePrecedenceVulnerability analyzes rule precedence conflicts
func analyzeRulePrecedenceVulnerability(parentAccess, childAccess RTDBAccessResult) bool {
	// If parent is accessible but child is not (or vice versa), there might be a precedence issue
	if parentAccess.Accessible != childAccess.Accessible {
		return true
	}

	// If both accessible but different data patterns
	if parentAccess.Accessible && childAccess.Accessible {
		if parentAccess.HasData != childAccess.HasData {
			return true
		}
	}

	return false
}

// analyzeValidationRules analyzes validation rule structure
func analyzeValidationRules(path string, state types.State, requireAuth bool) ValidationAnalysis {
	analysis := ValidationAnalysis{
		RuleStructure: make(map[string]interface{}),
	}

	// Try to access rules endpoint to analyze structure
	rulesURL := fmt.Sprintf("https://%s-default-rtdb.firebaseio.com/.settings/rules.json", state.ProjectID)

	var resp *http.Response
	var err error

	if requireAuth && state.Token != "" {
		resp, err = auth.MakeAuthenticatedRequest("GET", rulesURL, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	} else {
		resp, err = http.Get(rulesURL)
	}

	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		var rules map[string]interface{}
		if json.NewDecoder(resp.Body).Decode(&rules) == nil {
			analysis.RuleStructure = rules

			// Analyze for common validation bypass patterns
			if ruleStr, ok := rules["rules"].(string); ok {
				if strings.Contains(ruleStr, ".validate") && !strings.Contains(ruleStr, ".write") {
					analysis.HasValidationBypass = true
					analysis.BypassType = "missing_write_rule"
				}
			}
		}
	}

	return analysis
}

// testIndexingBypass tests for indexing rule bypasses
func testIndexingBypass(path, technique string, state types.State, requireAuth bool) IndexingBypassResult {
	result := IndexingBypassResult{}

	// Test different query patterns that might bypass indexing rules
	queryURL := fmt.Sprintf("https://%s-default-rtdb.firebaseio.com%s.json?orderBy=\"$key\"&limitToFirst=1", state.ProjectID, path)

	var resp *http.Response
	var err error

	if requireAuth && state.Token != "" {
		resp, err = auth.MakeAuthenticatedRequest("GET", queryURL, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	} else {
		resp, err = http.Get(queryURL)
	}

	if err == nil {
		defer resp.Body.Close()
		result.QueryWorked = (resp.StatusCode == 200)
		result.BypassSuccessful = result.QueryWorked && technique == "missing_index"
	}

	return result
}

// testDeltaSyncBypass tests for delta sync rule issues
func testDeltaSyncBypass(path string, state types.State, requireAuth bool) DeltaSyncTest {
	result := DeltaSyncTest{
		SyncIssues: []string{},
	}

	// Test basic listener endpoint
	listenerURL := fmt.Sprintf("https://%s-default-rtdb.firebaseio.com%s.json?print=silent", state.ProjectID, path)

	var resp *http.Response
	var err error

	if requireAuth && state.Token != "" {
		resp, err = auth.MakeAuthenticatedRequest("GET", listenerURL, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	} else {
		resp, err = http.Get(listenerURL)
	}

	if err == nil {
		defer resp.Body.Close()
		result.ListenerOk = (resp.StatusCode == 200)

		// If listener works but should be restricted, it's a bypass
		if result.ListenerOk && strings.Contains(path, "private") {
			result.HasBypass = true
			result.SyncIssues = append(result.SyncIssues, "unrestricted_delta_access")
		}
	}

	return result
}

// showRTDBFinding displays an RTDB finding immediately
func showRTDBFinding(result RTDBAdvancedResult) {
	if result.Finding == "" {
		return
	}

	// Clear any status message before showing finding
	status.ClearStatus()

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
		types.ColorRed, types.ColorBold, "RTDB", types.ColorGreen, types.ColorBold, types.ColorReset,
		timestamp,
		severityColor, result.Severity, types.ColorReset,
		result.TestType,
		result.Path)

	fmt.Printf("  └── Details:   %s\n", result.Finding)
}
