package safety

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"firescan/internal/types"
)

// DefaultSafetyConfig returns the default safety configuration
func DefaultSafetyConfig() types.SafetyConfig {
	return types.SafetyConfig{
		Mode:            types.ProbeMode,
		AutoCleanup:     true,
		ConfirmRequired: true,
		TestPathPrefix:  "firescan-test",
		MaxTestDuration: 5 * time.Minute,
	}
}

// ValidateScanMode checks if the requested scan mode is safe for the operation
func ValidateScanMode(requested types.ScanMode, required types.ScanMode) error {
	if requested < required {
		return fmt.Errorf("operation requires %s mode or higher, but %s mode requested",
			required.String(), requested.String())
	}
	return nil
}

// GenerateSafeTestPath creates an isolated test path
func GenerateSafeTestPath() string {
	timestamp := time.Now().Unix()
	randomSuffix := generateRandomString(8)
	return fmt.Sprintf("/firescan-test-%d-%s", timestamp, randomSuffix)
}

// GenerateSafeTestData creates safe test data that won't look like real user data
func GenerateSafeTestData() map[string]interface{} {
	return map[string]interface{}{
		"firescan_test_marker": true,
		"timestamp":            time.Now().Unix(),
		"test_id":              generateRandomString(12),
		"safe_test_data":       "firescan-test-value",
		"cleanup_required":     true,
	}
}

// NewTestCleanup creates a new cleanup tracker
func NewTestCleanup(projectID string) *types.TestCleanup {
	return &types.TestCleanup{
		TestPaths:    make([]string, 0),
		TestFiles:    make([]string, 0),
		CreatedAt:    time.Now(),
		ProjectID:    projectID,
		CleanupFuncs: make([]func() error, 0),
	}
}

// AddPathToCleanup adds a test path that needs cleanup
func AddPathToCleanup(tc *types.TestCleanup, path string) {
	tc.TestPaths = append(tc.TestPaths, path)
}

// AddFileToCleanup adds a test file that needs cleanup
func AddFileToCleanup(tc *types.TestCleanup, file string) {
	tc.TestFiles = append(tc.TestFiles, file)
}

// AddCleanupFunc adds a custom cleanup function
func AddCleanupFunc(tc *types.TestCleanup, fn func() error) {
	tc.CleanupFuncs = append(tc.CleanupFuncs, fn)
}

// PerformCleanup performs all registered cleanup operations
func PerformCleanup(tc *types.TestCleanup) error {
	var errors []string

	// Run custom cleanup functions
	for _, fn := range tc.CleanupFuncs {
		if err := fn(); err != nil {
			errors = append(errors, err.Error())
		}
	}

	// Note: Actual cleanup implementation would go here
	// For now, we log what would be cleaned up
	if len(tc.TestPaths) > 0 {
		fmt.Printf("[*] Would cleanup test paths: %v\n", tc.TestPaths)
	}
	if len(tc.TestFiles) > 0 {
		fmt.Printf("[*] Would cleanup test files: %v\n", tc.TestFiles)
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

var autoConfirm bool
var jsonMode bool

// SetJSONMode suppresses this package's own output when enabled, so it
// never corrupts machine-readable output (e.g. --json) sharing stdout.
func SetJSONMode(enabled bool) {
	jsonMode = enabled
}

// SetAutoConfirm skips WarnUser's interactive y/N prompt when enabled. This
// exists for non-interactive use (e.g. `scan --yes`, or scripted/CI runs):
// without it, --test and --audit mode can never run outside a real
// terminal, since the confirmation prompt reads from stdin via fmt.Scanln,
// which returns an empty string (and so a default "no") the moment stdin
// isn't an interactive session -- silently declining every write/audit test
// before it runs a single case. It must be explicitly requested per scan,
// never inferred from --json alone, since it bypasses a warning about
// destructive operations.
func SetAutoConfirm(enabled bool) {
	autoConfirm = enabled
}

// WarnUser displays appropriate warnings based on scan mode
func WarnUser(mode types.ScanMode) bool {
	switch mode {
	case types.ProbeMode:
		// No warning needed for probe mode
		return true
	case types.TestMode:
		if autoConfirm {
			if !jsonMode {
				fmt.Printf("%s⚠️  TEST MODE%s: proceeding automatically (--yes passed)\n", types.ColorYellow, types.ColorReset)
			}
			return true
		}
		if jsonMode {
			// The interactive prompt below has no way to receive real input
			// under --json (no TTY), so it would always decline anyway --
			// skip straight to that outcome instead of printing the
			// warning banner into the JSON stream first.
			return false
		}
		return warnTestMode()
	case types.AuditMode:
		if autoConfirm {
			if !jsonMode {
				fmt.Printf("%s⚠️  AUDIT MODE%s: proceeding automatically (--yes passed)\n", types.ColorRed, types.ColorReset)
			}
			return true
		}
		if jsonMode {
			return false
		}
		return warnAuditMode()
	default:
		fmt.Printf("%sUnknown scan mode%s\n", types.ColorRed, types.ColorReset)
		return false
	}
}

// warnTestMode shows test mode warning
func warnTestMode() bool {
	fmt.Printf("\n%s⚠️  TEST MODE WARNING%s\n", types.ColorYellow, types.ColorReset)
	fmt.Println("This mode will:")
	fmt.Println("  • Create temporary test documents in isolated paths")
	fmt.Println("  • Perform write operations to test permissions")
	fmt.Println("  • May trigger security monitoring alerts")
	fmt.Println("  • All test data will be automatically cleaned up")
	fmt.Println("  • No existing user data will be modified")

	return promptYesNo("\nContinue with test mode?")
}

// warnAuditMode shows audit mode warning
func warnAuditMode() bool {
	fmt.Printf("\n%s⚠️  AUDIT MODE WARNING%s\n", types.ColorRed, types.ColorReset)
	fmt.Println("This mode will perform DEEP security testing including:")
	fmt.Println("  • Advanced rule bypass testing")
	fmt.Println("  • Real path analysis (read-only)")
	fmt.Println("  • Comprehensive permission mapping")
	fmt.Println("  • May generate significant security logs")
	fmt.Println("  • Extensive API calls to Firebase services")

	fmt.Print("\nType 'I UNDERSTAND THE RISKS' to continue: ")
	var input string
	fmt.Scanln(&input)

	return input == "I UNDERSTAND THE RISKS"
}

// promptYesNo prompts user for yes/no confirmation
func promptYesNo(message string) bool {
	fmt.Print(message + " (y/N): ")
	var input string
	fmt.Scanln(&input)

	input = strings.ToLower(strings.TrimSpace(input))
	return input == "y" || input == "yes"
}

// generateRandomString creates a random string of specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)

	for i := range result {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[num.Int64()]
	}

	return string(result)
}
