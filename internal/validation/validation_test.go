package validation

import (
	"testing"
)

func TestValidateProjectID(t *testing.T) {
	tests := []struct {
		name      string
		projectID string
		wantError bool
	}{
		{
			name:      "valid project ID",
			projectID: "my-firebase-project",
			wantError: false,
		},
		{
			name:      "valid with numbers",
			projectID: "project-123",
			wantError: false,
		},
		{
			name:      "minimum length",
			projectID: "proj12",
			wantError: false,
		},
		{
			name:      "maximum length",
			projectID: "this-is-a-very-long-project",
			wantError: false,
		},
		{
			name:      "empty string",
			projectID: "",
			wantError: true,
		},
		{
			name:      "too short",
			projectID: "proj",
			wantError: true,
		},
		{
			name:      "too long",
			projectID: "this-is-a-very-long-project-id-that-exceeds-limit",
			wantError: true,
		},
		{
			name:      "uppercase letters",
			projectID: "My-Project",
			wantError: true,
		},
		{
			name:      "starts with hyphen",
			projectID: "-myproject",
			wantError: true,
		},
		{
			name:      "ends with hyphen",
			projectID: "myproject-",
			wantError: true,
		},
		{
			name:      "contains underscore",
			projectID: "my_project",
			wantError: true,
		},
		{
			name:      "contains special chars",
			projectID: "my-project!",
			wantError: true,
		},
		{
			name:      "contains spaces",
			projectID: "my project",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProjectID(tt.projectID)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateProjectID() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		apiKey    string
		wantError bool
	}{
		{
			name:      "valid API key",
			apiKey:    "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			wantError: false,
		},
		{
			name:      "empty string",
			apiKey:    "",
			wantError: true,
		},
		{
			name:      "wrong prefix",
			apiKey:    "BIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			wantError: true,
		},
		{
			name:      "too short",
			apiKey:    "AIzaSyDXXX",
			wantError: true,
		},
		{
			name:      "too long",
			apiKey:    "AIzaSyDXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			wantError: true,
		},
		{
			name:      "no prefix",
			apiKey:    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAPIKey(tt.apiKey)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateAPIKey() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateJWT(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		wantError bool
	}{
		{
			name:      "valid JWT structure",
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantError: false,
		},
		{
			name:      "empty string",
			token:     "",
			wantError: true,
		},
		{
			name:      "only two parts",
			token:     "header.payload",
			wantError: true,
		},
		{
			name:      "four parts",
			token:     "header.payload.signature.extra",
			wantError: true,
		},
		{
			name:      "empty part",
			token:     "header..signature",
			wantError: true,
		},
		{
			name:      "invalid base64",
			token:     "!!!invalid!!!.!!!invalid!!!.!!!invalid!!!",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJWT(tt.token)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateJWT() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		wantError bool
	}{
		{
			name:      "valid email",
			email:     "user@example.com",
			wantError: false,
		},
		{
			name:      "valid with subdomain",
			email:     "user@mail.example.com",
			wantError: false,
		},
		{
			name:      "valid with plus",
			email:     "user+tag@example.com",
			wantError: false,
		},
		{
			name:      "valid with dots",
			email:     "first.last@example.com",
			wantError: false,
		},
		{
			name:      "empty string",
			email:     "",
			wantError: true,
		},
		{
			name:      "no @ symbol",
			email:     "userexample.com",
			wantError: true,
		},
		{
			name:      "no domain",
			email:     "user@",
			wantError: true,
		},
		{
			name:      "no local part",
			email:     "@example.com",
			wantError: true,
		},
		{
			name:      "multiple @ symbols",
			email:     "user@@example.com",
			wantError: true,
		},
		{
			name:      "invalid characters",
			email:     "user name@example.com",
			wantError: true,
		},
		{
			name:      "no TLD",
			email:     "user@example",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateEmail() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateJSON(t *testing.T) {
	tests := []struct {
		name      string
		jsonStr   string
		wantError bool
	}{
		{
			name:      "valid object",
			jsonStr:   `{"key": "value"}`,
			wantError: false,
		},
		{
			name:      "valid array",
			jsonStr:   `["item1", "item2"]`,
			wantError: false,
		},
		{
			name:      "valid nested",
			jsonStr:   `{"user": {"name": "John", "age": 30}}`,
			wantError: false,
		},
		{
			name:      "valid with numbers",
			jsonStr:   `{"count": 42, "price": 19.99}`,
			wantError: false,
		},
		{
			name:      "valid with boolean",
			jsonStr:   `{"active": true, "deleted": false}`,
			wantError: false,
		},
		{
			name:      "valid with null",
			jsonStr:   `{"value": null}`,
			wantError: false,
		},
		{
			name:      "empty string",
			jsonStr:   "",
			wantError: true,
		},
		{
			name:      "invalid JSON",
			jsonStr:   `{key: value}`,
			wantError: true,
		},
		{
			name:      "unclosed brace",
			jsonStr:   `{"key": "value"`,
			wantError: true,
		},
		{
			name:      "trailing comma",
			jsonStr:   `{"key": "value",}`,
			wantError: true,
		},
		{
			name:      "single quotes",
			jsonStr:   `{'key': 'value'}`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJSON(tt.jsonStr)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateJSON() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantError bool
	}{
		{
			name:      "valid relative path",
			path:      "data/file.txt",
			wantError: false,
		},
		{
			name:      "valid absolute path",
			path:      "/data/file.txt",
			wantError: false,
		},
		{
			name:      "empty string",
			path:      "",
			wantError: true,
		},
		{
			name:      "path traversal with ..",
			path:      "../../../etc/passwd",
			wantError: true,
		},
		{
			name:      "path traversal in middle",
			path:      "data/../../../etc/passwd",
			wantError: true,
		},
		{
			name:      "suspicious path - etc/passwd",
			path:      "/etc/passwd",
			wantError: true, // ValidatePath checks for suspicious paths (detected on Linux)
		},
		{
			name:      "suspicious path - windows system32",
			path:      "C:/Windows/System32/config",
			wantError: true, // ValidatePath checks for suspicious paths (detected on Linux)
		},
		{
			name:      "suspicious path - etc/shadow",
			path:      "/etc/shadow",
			wantError: true, // ValidatePath checks for suspicious paths (detected on Linux)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidatePath(tt.path)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidatePath() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateFirebasePath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantError bool
	}{
		{
			name:      "valid simple path",
			path:      "users",
			wantError: false,
		},
		{
			name:      "valid nested path",
			path:      "users/123/posts",
			wantError: false,
		},
		{
			name:      "valid with leading slash",
			path:      "/users",
			wantError: false,
		},
		{
			name:      "empty string",
			path:      "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFirebasePath(tt.path)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateFirebasePath() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}
