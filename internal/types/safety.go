package types

import "time"

// ScanMode defines the safety level of scanning operations
type ScanMode int

const (
	// ProbeMode - Default, 100% safe, read-only operations
	ProbeMode ScanMode = iota
	// TestMode - Safe write testing with automatic cleanup
	TestMode
	// AuditMode - Deep testing with explicit user confirmation
	AuditMode
)

func (sm ScanMode) String() string {
	switch sm {
	case ProbeMode:
		return "probe"
	case TestMode:
		return "test"
	case AuditMode:
		return "audit"
	default:
		return "unknown"
	}
}

// SafetyConfig holds safety-related configuration
type SafetyConfig struct {
	Mode            ScanMode
	AutoCleanup     bool
	ConfirmRequired bool
	TestPathPrefix  string
	MaxTestDuration time.Duration
}

// TestCleanup manages cleanup of test data
type TestCleanup struct {
	TestPaths    []string
	TestFiles    []string
	CreatedAt    time.Time
	ProjectID    string
	CleanupFuncs []func() error
}

// RuleTestCase represents a security rule test case
type RuleTestCase struct {
	ID          string
	Path        string
	AuthContext map[string]interface{}
	Operation   string // "read", "write", "create", "update", "delete"
	Expected    bool
	TestData    interface{}
	Description string
	SafetyLevel ScanMode // Minimum safety level required
}

// RuleTestResult represents the result of a rule test
type RuleTestResult struct {
	TestCase    RuleTestCase
	Actual      bool
	Success     bool
	Error       error
	Response    interface{}
	Duration    time.Duration
	CleanupDone bool
}

// WriteTestCase represents a write access test case
type WriteTestCase struct {
	ID          string
	Service     string // "firestore", "rtdb", "storage"
	Path        string
	Operation   string // "create", "update", "delete", "upload"
	TestData    interface{}
	Expected    bool
	Description string
	SafetyLevel ScanMode
}

// WriteTestResult represents the result of a write test
type WriteTestResult struct {
	TestCase    WriteTestCase
	Success     bool
	Error       error
	Response    interface{}
	Duration    time.Duration
	CleanupDone bool
}

// ServiceEnumResult represents discovered Firebase services
type ServiceEnumResult struct {
	Service     string
	Endpoint    string
	Accessible  bool
	HasData     bool
	DataSample  interface{}
	Error       error
	SafetyLevel ScanMode // Level at which this was discovered
}
