package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// GetAuthToken authenticates and returns token, userID, emailVerified status, and error
func GetAuthToken(email, password, apiKey string, createAccount bool) (string, string, bool, error) {
	if createAccount {
		token, userID, emailVerified, err := SignUp(email, password, apiKey)
		if err != nil {
			if strings.Contains(err.Error(), "EMAIL_EXISTS") {
				fmt.Println("[*] Test account already exists, attempting to log in...")
				return SignIn(email, password, apiKey)
			}
			return "", "", false, err
		}
		return token, userID, emailVerified, nil
	}
	return SignIn(email, password, apiKey)
}

// SignUp creates a new Firebase account
func SignUp(email, password, apiKey string) (string, string, bool, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=%s", apiKey)
	payload := map[string]string{"email": email, "password": password, "returnSecureToken": "true"}
	return executeAuthRequestWithUserInfo(url, payload)
}

// SignIn authenticates with existing Firebase account
func SignIn(email, password, apiKey string) (string, string, bool, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s", apiKey)
	payload := map[string]string{"email": email, "password": password, "returnSecureToken": "true"}
	return executeAuthRequestWithUserInfo(url, payload)
}

// executeAuthRequest performs basic auth request (legacy function)
func executeAuthRequest(url string, payload map[string]string) (string, error) {
	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != http.StatusOK {
		if errData, ok := result["error"].(map[string]interface{}); ok {
			return "", fmt.Errorf("auth API error: %s (HTTP %d)", errData["message"], resp.StatusCode)
		}
		return "", fmt.Errorf("unexpected auth API error (HTTP %d)", resp.StatusCode)
	}
	if idToken, ok := result["idToken"].(string); ok {
		return idToken, nil
	}
	return "", fmt.Errorf("could not find idToken in auth response")
}

// executeAuthRequestWithUserInfo performs auth request and returns user info
func executeAuthRequestWithUserInfo(url string, payload map[string]string) (string, string, bool, error) {
	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return "", "", false, err
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != http.StatusOK {
		if errData, ok := result["error"].(map[string]interface{}); ok {
			return "", "", false, fmt.Errorf("auth API error: %s (HTTP %d)", errData["message"], resp.StatusCode)
		}
		return "", "", false, fmt.Errorf("unexpected auth API error (HTTP %d)", resp.StatusCode)
	}
	
	idToken, hasToken := result["idToken"].(string)
	if !hasToken {
		return "", "", false, fmt.Errorf("could not find idToken in auth response")
	}
	
	userID, _ := result["localId"].(string)
	emailVerified, _ := result["emailVerified"].(bool)
	
	return idToken, userID, emailVerified, nil
}

// MakeAuthenticatedRequest creates an authenticated HTTP request with automatic token refresh
func MakeAuthenticatedRequest(method, url, token, email, password, apiKey string, updateTokenFunc func(string, string, bool)) (*http.Response, error) {
	client := &http.Client{Timeout: 10000000000} // 10 seconds in nanoseconds

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Println("\n[*] Token expired. Attempting to refresh...")

		if email != "" && password != "" {
			newToken, userID, emailVerified, err := SignIn(email, password, apiKey)
			if err != nil {
				return resp, fmt.Errorf("token refresh failed: %v", err)
			}
			fmt.Println("✓ Token refreshed successfully.")
			
			// Update token via callback
			if updateTokenFunc != nil {
				updateTokenFunc(newToken, userID, emailVerified)
			}
			
			req.Header.Set("Authorization", "Bearer "+newToken)
			return client.Do(req)
		}
		return resp, fmt.Errorf("token expired, but no credentials available to refresh")
	}
	return resp, nil
}

// CheckEmailVerificationStatus checks if an email is verified
func CheckEmailVerificationStatus(idToken, apiKey string) (bool, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=%s", apiKey)
	payload := map[string]string{
		"idToken": idToken,
	}
	
	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		if errData, ok := result["error"].(map[string]interface{}); ok {
			return false, fmt.Errorf("user lookup API error: %s (HTTP %d)", errData["message"], resp.StatusCode)
		}
		return false, fmt.Errorf("unexpected user lookup API error (HTTP %d)", resp.StatusCode)
	}
	
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	
	if users, ok := result["users"].([]interface{}); ok && len(users) > 0 {
		if user, ok := users[0].(map[string]interface{}); ok {
			if emailVerified, ok := user["emailVerified"].(bool); ok {
				return emailVerified, nil
			}
		}
	}
	
	return false, nil
}

// SendEmailVerification sends a verification email
func SendEmailVerification(idToken, apiKey string) error {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=%s", apiKey)
	payload := map[string]string{
		"requestType": "VERIFY_EMAIL",
		"idToken":     idToken,
	}
	
	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		if errData, ok := result["error"].(map[string]interface{}); ok {
			return fmt.Errorf("verification email API error: %s (HTTP %d)", errData["message"], resp.StatusCode)
		}
		return fmt.Errorf("unexpected verification email API error (HTTP %d)", resp.StatusCode)
	}
	
	return nil
}

// EnumerateAuthProviders checks which authentication providers are enabled
func EnumerateAuthProviders(apiKey string) map[string]bool {
	fmt.Println("[*] Enumerating Authentication Providers by probing...")
	providers := []string{"password", "google.com", "facebook.com", "twitter.com", "github.com"}
	results := make(map[string]bool)
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	for _, provider := range providers {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			enabled := probeAuthProvider(p, apiKey)
			
			mu.Lock()
			results[p] = enabled
			mu.Unlock()
			
			status := "Disabled"
			if enabled {
				status = "Enabled"
			}
			fmt.Printf("  ├── Provider: %-20s Status: %s\n", p, status)
		}(provider)
	}
	wg.Wait()
	
	return results
}

// probeAuthProvider tests if a specific auth provider is enabled
func probeAuthProvider(provider, apiKey string) bool {
	var url string
	var payload map[string]string

	switch provider {
	case "password":
		url = fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=%s", apiKey)
		payload = map[string]string{"email": "test@example.com", "password": "password"}
	default: // For OAuth providers like google.com, facebook.com, etc.
		url = fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key=%s", apiKey)
		payload = map[string]string{
			"postBody":   "id_token=dummy&providerId=" + provider,
			"requestUri": "http://localhost",
		}
	}

	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if errData, ok := result["error"].(map[string]interface{}); ok {
		if msg, ok := errData["message"].(string); ok {
			// If the operation is not allowed, it's definitively disabled.
			if strings.Contains(msg, "OPERATION_NOT_ALLOWED") {
				return false
			}
			// For OAuth, specific errors indicate it's enabled but our dummy token is bad.
			if strings.Contains(msg, "INVALID_IDP_RESPONSE") || strings.Contains(msg, "INVALID_ID_TOKEN") {
				return true
			}
			// For password, EMAIL_EXISTS is a sign it's enabled.
			if provider == "password" && strings.Contains(msg, "EMAIL_EXISTS") {
				return true
			}
			// Any other error likely means it's not configured correctly or disabled.
			return false
		}
	}
	// If there's no error field at all, the request was successful, meaning it's enabled.
	return true
}