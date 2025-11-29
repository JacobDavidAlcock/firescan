package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"firescan/internal/config"
	"firescan/internal/scanner"
	"firescan/internal/logger"
	"firescan/internal/auth"
	"firescan/internal/types"
	"os/exec"
)

func main() {
	// Initialize logger
	logger.Init("e2e.log", logger.DEBUG, true)

	// Load config
	configFile := "test-fixture/config.json"
	content, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("Error reading config: %v\n", err)
		os.Exit(1)
	}

	var cfg struct {
		ProjectID string `json:"projectId"`
		APIKey    string `json:"apiKey"`
	}
	if err := json.Unmarshal(content, &cfg); err != nil {
		fmt.Printf("Error parsing config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Running E2E test for project: %s\n", cfg.ProjectID)

	// Set global config state
	config.SetProjectID(cfg.ProjectID)
	config.SetAPIKey(cfg.APIKey)

	// Check for unauth flag
	unauthMode := false
	for _, arg := range os.Args {
		if arg == "--unauth" {
			unauthMode = true
			break
		}
	}

	if unauthMode {
		fmt.Println("Running in UNAUTHENTICATED mode...")
		config.SetToken("")
	} else {
		// Authenticate
		fmt.Println("Authenticating...")
		token, userID, emailVerified, err := auth.GetAuthToken("test@example.com", "password123", cfg.APIKey, true)
		if err != nil {
			fmt.Printf("Authentication failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Got token: %s... (UserID: %s, Verified: %v)\n", token[:10], userID, emailVerified)
		config.SetToken(token)
		config.SetAuthInfo("test@example.com", "password123", userID, emailVerified)
		fmt.Println("Authenticated successfully.")
	}

	// Run Scan
	options := scanner.ScanOptions{
		List:          "test-fixture/wordlist.txt",
		AllScan:       true,
		RTDBTest:      true,
		FirestoreTest: true,
		StorageTest:   true,
		FunctionsTest: true,
		HostingTest:   true,
		AuthTest:      true, // Enable Auth Test
		JSONOutput:    false,
		Concurrency:   50,
		RateLimit:     0,
	}

	fmt.Println("Starting scan...")
	findings, err := scanner.RunScan(options)
	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
		os.Exit(1)
	}

	// Verify Findings
	fmt.Printf("Scan completed. Found %d issues.\n", len(findings))
	
	expectedFindings := map[string]bool{
		"rtdb:insecure_node": false,
		"firestore:insecure_collection": false,
		"storage:insecure": false,
		"function:publicFunction": false,
		"auth:password": false, // Expect password auth to be enabled
	}
	success := true

	for _, f := range findings {
		fmt.Printf("- [%s] %s: %s\n", f.Severity, f.Type, f.Path)
		
		// Simple check
		if f.Type == "RTDB" && strings.Contains(f.Path, "insecure_node") {
			expectedFindings["rtdb:insecure_node"] = true
		}
		if f.Type == "Firestore" && strings.Contains(f.Path, "insecure_collection") {
			expectedFindings["firestore:insecure_collection"] = true
		}
		if f.Type == "Storage" && (strings.Contains(f.Path, "insecure/secret.txt") || strings.Contains(f.Path, "insecure%2Fsecret.txt")) { 
			expectedFindings["storage:insecure"] = true
		}
		// Check for function
		if f.Type == "Function" && (f.Status == "Publicly Invokable" || f.Status == "Exists (Auth Required)") {
			if strings.Contains(f.Path, "publicFunction") {
				expectedFindings["function:publicFunction"] = true
			}
		}
		// Check for Auth
		if f.Type == "Auth" && f.Path == "password" && f.Status == "Enabled" {
			expectedFindings["auth:password"] = true
		}

		// Check for False Positives (Secure resources that should NOT be reported as vulnerable)
		// Note: "Exists (Auth Required)" is acceptable for private functions if we are authenticated,
		// but "Publicly Invokable" or "Readable" would be a failure.
		
		// Use stricter matching to avoid matching "insecure_node" with "secure_node"
		if f.Type == "RTDB" && strings.Contains(f.Path, "/secure_node.json") {
			fmt.Printf("❌ False Positive: Found secure RTDB node '%s'\n", f.Path)
			success = false
		}
		if f.Type == "Firestore" && f.Path == "secure_collection" {
			fmt.Printf("❌ False Positive: Found secure Firestore collection '%s'\n", f.Path)
			success = false
		}
		if f.Type == "Storage" && (strings.Contains(f.Path, "/secure/secret.txt") || strings.Contains(f.Path, "/secure%2Fsecret.txt")) {
			if f.Status == "Publicly Readable" {
				fmt.Printf("❌ False Positive: Found secure Storage object '%s'\n", f.Path)
				success = false
			}
		}
		if f.Type == "Function" && strings.Contains(f.Path, "privateFunction") {
			if f.Status == "Publicly Invokable" {
				fmt.Printf("❌ False Positive: Found private Function '%s' as Publicly Invokable\n", f.Path)
				success = false
			}
		}
	}

	// Report results
	for k, v := range expectedFindings {
		if !v {
			fmt.Printf("❌ Missing expected finding: %s\n", k)
			success = false
		} else {
			fmt.Printf("✅ Found expected finding: %s\n", k)
		}
	}

	if success {
		fmt.Println("E2E Test PASSED")
	} else {
		fmt.Println("E2E Test FAILED")
		os.Exit(1)
	}

	// Verify JSON Output from CLI
	fmt.Println("\nVerifying CLI JSON Output...")
	if err := verifyJSONOutput(); err != nil {
		fmt.Printf("❌ JSON Verification Failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ CLI JSON Output Verified")
}

func verifyJSONOutput() error {
	// Build the command
	cmd := exec.Command("go", "run", "cmd/firescan/main.go", "--config", "test-fixture/config.json", "scan", "--unauth", "--json", "--rtdb", "--firestore", "--functions", "--storage", "-l", "test-fixture/wordlist.txt")
	
	// Capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to run firescan cli: %v\nOutput: %s", err, string(output))
	}

	// Parse JSON
	var findings []types.Finding
	// scanner.Finding is not exported? It is types.Finding.
	// But types is internal. We can't import internal packages from cmd/e2e if we respect Go rules, 
	// but here we are in the same module.
	// cmd/e2e/main.go imports firescan/internal/scanner which returns types.Finding.
	// So we can use types.Finding if we import firescan/internal/types.
	
	// We need to import "os/exec" and "firescan/internal/types"
	
	if err := json.Unmarshal(output, &findings); err != nil {
		return fmt.Errorf("failed to parse JSON output: %v\nOutput start: %s", err, string(output)[:min(len(output), 200)])
	}

	if len(findings) == 0 {
		return fmt.Errorf("no findings returned in JSON output")
	}

	// Verify we have at least one expected finding
	found := false
	for _, f := range findings {
		if f.Type == "RTDB" && strings.Contains(f.Path, "insecure_node") {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("expected RTDB finding not found in JSON output")
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
