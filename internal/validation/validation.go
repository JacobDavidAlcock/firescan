package validation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// ValidateProjectID validates Firebase project ID format
// Project IDs must be 6-30 characters, lowercase letters, numbers, or hyphens
func ValidateProjectID(projectID string) error {
	if projectID == "" {
		return fmt.Errorf("project ID cannot be empty")
	}

	if len(projectID) < 6 || len(projectID) > 30 {
		return fmt.Errorf("project ID must be 6-30 characters long (got %d)", len(projectID))
	}

	// Firebase project IDs can only contain lowercase letters, numbers, and hyphens
	re := regexp.MustCompile(`^[a-z0-9-]+$`)
	if !re.MatchString(projectID) {
		return fmt.Errorf("project ID can only contain lowercase letters, numbers, and hyphens")
	}

	// Cannot start or end with hyphen
	if strings.HasPrefix(projectID, "-") || strings.HasSuffix(projectID, "-") {
		return fmt.Errorf("project ID cannot start or end with a hyphen")
	}

	return nil
}

// ValidateAPIKey validates Firebase Web API key format
// Firebase API keys typically start with "AIza" and are 39 characters long
func ValidateAPIKey(apiKey string) error {
	if apiKey == "" {
		return fmt.Errorf("API key cannot be empty")
	}

	if !strings.HasPrefix(apiKey, "AIza") {
		return fmt.Errorf("API key should start with 'AIza' (this appears to be an invalid Firebase API key)")
	}

	if len(apiKey) != 39 {
		return fmt.Errorf("API key should be 39 characters (got %d) - this may be invalid", len(apiKey))
	}

	return nil
}

// ValidateJWT validates JWT token format (basic structure check)
func ValidateJWT(token string) error {
	if token == "" {
		return fmt.Errorf("JWT token cannot be empty")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: should have 3 parts separated by dots (got %d)", len(parts))
	}

	// Validate each part is valid base64
	for i, part := range parts {
		if part == "" {
			return fmt.Errorf("invalid JWT: part %d is empty", i+1)
		}
		// JWT uses base64url encoding
		_, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			// Try standard base64 as fallback
			_, err = base64.RawStdEncoding.DecodeString(part)
			if err != nil {
				return fmt.Errorf("invalid JWT: part %d is not valid base64", i+1)
			}
		}
	}

	return nil
}

// ValidateEmail validates email format
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}

	// Basic email validation
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !re.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}

	return nil
}

// ValidateJSON validates that a string is valid JSON
func ValidateJSON(jsonStr string) error {
	if jsonStr == "" {
		return fmt.Errorf("JSON string cannot be empty")
	}

	var js json.RawMessage
	if err := json.Unmarshal([]byte(jsonStr), &js); err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}

	return nil
}

// ValidatePath validates and sanitizes file paths to prevent traversal attacks
func ValidatePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path cannot be empty")
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("path traversal not allowed (..) - potential security risk")
	}

	// Clean the path
	cleanPath := filepath.Clean(path)

	// Additional checks for suspicious patterns
	suspiciousPatterns := []string{
		"etc/passwd",
		"windows/system32",
		"/etc/shadow",
		"c:/windows",
	}

	lowerPath := strings.ToLower(cleanPath)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerPath, pattern) {
			return "", fmt.Errorf("suspicious path detected - potential security risk")
		}
	}

	return cleanPath, nil
}

// ValidateFirebasePath validates Firebase RTDB/Firestore paths
func ValidateFirebasePath(path string) error {
	if path == "" {
		return fmt.Errorf("Firebase path cannot be empty")
	}

	// Check for invalid characters
	invalidChars := []string{"#", "$", "[", "]", ".", "//"}
	for _, char := range invalidChars {
		if strings.Contains(path, char) {
			return fmt.Errorf("Firebase path contains invalid character: %s", char)
		}
	}

	return nil
}

// ValidateDocumentID validates Firestore document ID
func ValidateDocumentID(docID string) error {
	if docID == "" {
		return fmt.Errorf("document ID cannot be empty")
	}

	// Firestore document IDs must be valid UTF-8 characters
	// Cannot be "." or ".."
	if docID == "." || docID == ".." {
		return fmt.Errorf("document ID cannot be '.' or '..'")
	}

	// Check for invalid characters
	if strings.Contains(docID, "/") {
		return fmt.Errorf("document ID cannot contain forward slashes")
	}

	// Check length (Firestore limit is 1,500 bytes)
	if len(docID) > 1500 {
		return fmt.Errorf("document ID too long (max 1500 bytes)")
	}

	return nil
}

// ValidateCollectionPath validates Firestore collection path
func ValidateCollectionPath(path string) error {
	if path == "" {
		return fmt.Errorf("collection path cannot be empty")
	}

	// Split by slash to validate structure
	parts := strings.Split(path, "/")

	// Collection paths should have odd number of parts
	// e.g., "users" (1 part) or "users/user123/posts" (3 parts)
	if len(parts)%2 == 0 {
		return fmt.Errorf("invalid collection path: should be collection/document/collection format")
	}

	// Validate each part
	for i, part := range parts {
		if part == "" {
			return fmt.Errorf("collection path cannot have empty segments")
		}

		if i%2 == 0 {
			// This is a collection name
			if err := ValidateFirebasePath(part); err != nil {
				return fmt.Errorf("invalid collection name '%s': %v", part, err)
			}
		} else {
			// This is a document ID
			if err := ValidateDocumentID(part); err != nil {
				return fmt.Errorf("invalid document ID '%s': %v", part, err)
			}
		}
	}

	return nil
}

// ValidateConcurrency validates concurrency level
func ValidateConcurrency(concurrency int) error {
	if concurrency < 1 {
		return fmt.Errorf("concurrency must be at least 1 (got %d)", concurrency)
	}

	if concurrency > 1000 {
		return fmt.Errorf("concurrency too high (max 1000, got %d) - this could overwhelm the target", concurrency)
	}

	return nil
}

// ValidateWordlistName validates wordlist name
func ValidateWordlistName(name string) error {
	if name == "" {
		return fmt.Errorf("wordlist name cannot be empty")
	}

	// Wordlist names should be alphanumeric with underscores/hyphens
	re := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !re.MatchString(name) {
		return fmt.Errorf("wordlist name can only contain letters, numbers, underscores, and hyphens")
	}

	return nil
}
