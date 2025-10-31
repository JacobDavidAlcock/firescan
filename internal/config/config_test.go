package config

import (
	"sync"
	"testing"
)

func TestSetAndGetProjectID(t *testing.T) {
	// Reset state
	stateMutex.Lock()
	currentState.ProjectID = ""
	stateMutex.Unlock()

	testID := "test-project-123"
	SetProjectID(testID)

	result := GetProjectID()
	if result != testID {
		t.Errorf("GetProjectID() = %s, want %s", result, testID)
	}
}

func TestSetAndGetAPIKey(t *testing.T) {
	// Reset state
	stateMutex.Lock()
	currentState.APIKey = ""
	stateMutex.Unlock()

	testKey := "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	SetAPIKey(testKey)

	result := GetAPIKey()
	if result != testKey {
		t.Errorf("GetAPIKey() = %s, want %s", result, testKey)
	}
}

func TestSetAndGetToken(t *testing.T) {
	// Reset state
	stateMutex.Lock()
	currentState.Token = ""
	stateMutex.Unlock()

	testToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"
	SetToken(testToken)

	result := GetToken()
	if result != testToken {
		t.Errorf("GetToken() = %s, want %s", result, testToken)
	}
}

func TestSetAndGetAuthInfo(t *testing.T) {
	// Reset state
	stateMutex.Lock()
	currentState.Email = ""
	currentState.Password = ""
	currentState.UserID = ""
	currentState.EmailVerified = false
	stateMutex.Unlock()

	testEmail := "test@example.com"
	testPassword := "password123"
	testUserID := "user123"
	testVerified := true

	SetAuthInfo(testEmail, testPassword, testUserID, testVerified)

	email, password, userID, verified := GetAuthInfo()
	if email != testEmail {
		t.Errorf("GetAuthInfo() email = %s, want %s", email, testEmail)
	}
	if password != testPassword {
		t.Errorf("GetAuthInfo() password = %s, want %s", password, testPassword)
	}
	if userID != testUserID {
		t.Errorf("GetAuthInfo() userID = %s, want %s", userID, testUserID)
	}
	if verified != testVerified {
		t.Errorf("GetAuthInfo() verified = %v, want %v", verified, testVerified)
	}
}

func TestGetState(t *testing.T) {
	// Set up test state
	stateMutex.Lock()
	currentState.ProjectID = "test-project"
	currentState.APIKey = "test-key"
	currentState.Token = "test-token"
	stateMutex.Unlock()

	state := GetState()
	if state.ProjectID != "test-project" {
		t.Errorf("GetState().ProjectID = %s, want test-project", state.ProjectID)
	}
	if state.APIKey != "test-key" {
		t.Errorf("GetState().APIKey = %s, want test-key", state.APIKey)
	}
	if state.Token != "test-token" {
		t.Errorf("GetState().Token = %s, want test-token", state.Token)
	}
}

func TestClearAuth(t *testing.T) {
	// Set up auth state
	SetAuthInfo("test@example.com", "password", "user123", true)
	SetToken("test-token")

	// Clear auth
	ClearAuth()

	// Verify cleared
	email, password, userID, verified := GetAuthInfo()
	if email != "" {
		t.Errorf("After ClearAuth(), email = %s, want empty", email)
	}
	if password != "" {
		t.Errorf("After ClearAuth(), password = %s, want empty", password)
	}
	if userID != "" {
		t.Errorf("After ClearAuth(), userID = %s, want empty", userID)
	}
	if verified {
		t.Errorf("After ClearAuth(), verified = %v, want false", verified)
	}

	token := GetToken()
	if token != "" {
		t.Errorf("After ClearAuth(), token = %s, want empty", token)
	}
}

func TestMaskString(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		prefixLen  int
		suffixLen  int
		wantPrefix string
		wantSuffix string
	}{
		{
			name:       "standard masking",
			input:      "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			prefixLen:  4,
			suffixLen:  4,
			wantPrefix: "AIza",
			wantSuffix: "XXXX",
		},
		{
			name:       "short string",
			input:      "short",
			prefixLen:  4,
			suffixLen:  4,
			wantPrefix: "",
			wantSuffix: "",
		},
		{
			name:       "empty string",
			input:      "",
			prefixLen:  4,
			suffixLen:  4,
			wantPrefix: "",
			wantSuffix: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskString(tt.input, tt.prefixLen, tt.suffixLen)

			if tt.wantPrefix != "" {
				if len(result) < tt.prefixLen {
					t.Errorf("Result too short to contain prefix")
					return
				}
				if result[:tt.prefixLen] != tt.wantPrefix {
					t.Errorf("Prefix = %s, want %s", result[:tt.prefixLen], tt.wantPrefix)
				}
			}

			if tt.wantSuffix != "" {
				if len(result) < tt.suffixLen {
					t.Errorf("Result too short to contain suffix")
					return
				}
				if result[len(result)-tt.suffixLen:] != tt.wantSuffix {
					t.Errorf("Suffix = %s, want %s", result[len(result)-tt.suffixLen:], tt.wantSuffix)
				}
			}
		})
	}
}

func TestConcurrentAccess(t *testing.T) {
	// Test thread safety with concurrent reads and writes
	var wg sync.WaitGroup
	iterations := 100

	// Concurrent writes
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			SetProjectID("project-" + string(rune(id)))
			SetAPIKey("key-" + string(rune(id)))
			SetToken("token-" + string(rune(id)))
		}(i)
	}

	// Concurrent reads
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = GetProjectID()
			_ = GetAPIKey()
			_ = GetToken()
			_ = GetState()
		}()
	}

	wg.Wait()
	// If we get here without deadlock or panic, thread safety is working
}

func TestUpdateTokenInfo(t *testing.T) {
	// Reset state
	ClearAuth()

	testToken := "new-token"
	testUserID := "new-user"
	testVerified := true

	UpdateTokenInfo(testToken, testUserID, testVerified)

	token := GetToken()
	if token != testToken {
		t.Errorf("After UpdateTokenInfo(), token = %s, want %s", token, testToken)
	}

	_, _, userID, verified := GetAuthInfo()
	if userID != testUserID {
		t.Errorf("After UpdateTokenInfo(), userID = %s, want %s", userID, testUserID)
	}
	if verified != testVerified {
		t.Errorf("After UpdateTokenInfo(), verified = %v, want %v", verified, testVerified)
	}
}
