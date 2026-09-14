package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/logger"
	"firescan/internal/scanner"
	"firescan/internal/types"
	"os/exec"
)

type testConfig struct {
	ProjectID string `json:"projectId"`
	APIKey    string `json:"apiKey"`
}

func main() {
	// Initialize logger
	if err := logger.Init("e2e.log", logger.DEBUG, true); err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	cfg, err := loadTestConfig("test-fixture/config.json")
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Running E2E test for project: %s\n", cfg.ProjectID)

	// Set global config state
	config.SetProjectID(cfg.ProjectID)
	config.SetAPIKey(cfg.APIKey)

	if err := setupAuth(cfg.APIKey, hasArg(os.Args, "--unauth")); err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Starting scan...")
	findings, err := runTestScan()
	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Scan completed. Found %d issues.\n", len(findings))

	if verifyFindings(findings) {
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

// loadTestConfig reads and parses the e2e test fixture config.
func loadTestConfig(path string) (testConfig, error) {
	var cfg testConfig
	content, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("error reading config: %w", err)
	}
	if err := json.Unmarshal(content, &cfg); err != nil {
		return cfg, fmt.Errorf("error parsing config: %w", err)
	}
	return cfg, nil
}

// hasArg reports whether target is present in args.
func hasArg(args []string, target string) bool {
	for _, arg := range args {
		if arg == target {
			return true
		}
	}
	return false
}

// setupAuth authenticates against the test project, or clears the token when unauthMode is set.
func setupAuth(apiKey string, unauthMode bool) error {
	if unauthMode {
		fmt.Println("Running in UNAUTHENTICATED mode...")
		config.SetToken("")
		return nil
	}

	fmt.Println("Authenticating...")
	token, userID, emailVerified, err := auth.GetAuthToken("test@example.com", "password123", apiKey, true)
	if err != nil {
		return err
	}
	fmt.Printf("Got token: %s... (UserID: %s, Verified: %v)\n", token[:10], userID, emailVerified)
	config.SetToken(token)
	config.SetAuthInfo("test@example.com", "password123", userID, emailVerified)
	fmt.Println("Authenticated successfully.")
	return nil
}

// runTestScan runs a full scan against the test fixture project.
func runTestScan() ([]types.Finding, error) {
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
	return scanner.RunScan(options)
}

// verifyFindings checks that every expected finding was reported and that no
// known-secure fixture resource was flagged as a false positive.
func verifyFindings(findings []types.Finding) bool {
	expectedFindings := map[string]bool{
		"rtdb:insecure_node":            false,
		"firestore:insecure_collection": false,
		"storage:insecure":              false,
		"function:publicFunction":       false,
		"auth:password":                 false, // Expect password auth to be enabled
	}
	success := true

	for _, f := range findings {
		fmt.Printf("- [%s] %s: %s\n", f.Severity, f.Type, f.Path)
		markExpectedFinding(f, expectedFindings)
		if isFalsePositive(f) {
			success = false
		}
	}

	for k, v := range expectedFindings {
		if !v {
			fmt.Printf("❌ Missing expected finding: %s\n", k)
			success = false
		} else {
			fmt.Printf("✅ Found expected finding: %s\n", k)
		}
	}

	return success
}

// markExpectedFinding flags an expected finding as seen if f matches it.
func markExpectedFinding(f types.Finding, expected map[string]bool) {
	switch {
	case f.Type == "RTDB" && strings.Contains(f.Path, "insecure_node"):
		expected["rtdb:insecure_node"] = true
	case f.Type == "Firestore" && strings.Contains(f.Path, "insecure_collection"):
		expected["firestore:insecure_collection"] = true
	case f.Type == "Storage" && (strings.Contains(f.Path, "insecure/secret.txt") || strings.Contains(f.Path, "insecure%2Fsecret.txt")):
		expected["storage:insecure"] = true
	case f.Type == "Function" && strings.Contains(f.Path, "publicFunction") &&
		(f.Status == "Publicly Invokable" || f.Status == "Exists (Auth Required)"):
		expected["function:publicFunction"] = true
	case f.Type == "Auth" && f.Path == "password" && f.Status == "Enabled":
		expected["auth:password"] = true
	}
}

// isFalsePositive reports (and logs) whether f is a known-secure fixture
// resource that was incorrectly flagged as vulnerable.
//
// Note: "Exists (Auth Required)" is acceptable for private functions if we
// are authenticated, but "Publicly Invokable" or "Readable" would be a failure.
// Use stricter matching to avoid matching "insecure_node" with "secure_node".
func isFalsePositive(f types.Finding) bool {
	switch {
	case f.Type == "RTDB" && strings.Contains(f.Path, "/secure_node.json"):
		fmt.Printf("❌ False Positive: Found secure RTDB node '%s'\n", f.Path)
		return true
	case f.Type == "Firestore" && f.Path == "secure_collection":
		fmt.Printf("❌ False Positive: Found secure Firestore collection '%s'\n", f.Path)
		return true
	case f.Type == "Storage" &&
		(strings.Contains(f.Path, "/secure/secret.txt") || strings.Contains(f.Path, "/secure%2Fsecret.txt")) &&
		f.Status == "Publicly Readable":
		fmt.Printf("❌ False Positive: Found secure Storage object '%s'\n", f.Path)
		return true
	case f.Type == "Function" && strings.Contains(f.Path, "privateFunction") && f.Status == "Publicly Invokable":
		fmt.Printf("❌ False Positive: Found private Function '%s' as Publicly Invokable\n", f.Path)
		return true
	default:
		return false
	}
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
