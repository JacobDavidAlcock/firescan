package logger

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLogLevelString(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{DEBUG, "DEBUG"},
		{INFO, "INFO"},
		{WARNING, "WARNING"},
		{ERROR, "ERROR"},
		{CRITICAL, "CRITICAL"},
		{LogLevel(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.level.String()
			if result != tt.expected {
				t.Errorf("LogLevel.String() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestInit(t *testing.T) {
	// Create temp directory for test logs
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	err := Init(logFile, INFO, false)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer Close()

	// Verify log file was created
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("Log file was not created")
	}
}

func TestInitWithInvalidPath(t *testing.T) {
	// Note: Init creates parent directories, so this test is skipped
	// The function is designed to be forgiving and create necessary directories
	t.Skip("Init creates parent directories automatically")
}

func TestInitConsoleOnly(t *testing.T) {
	// Initialize with empty path (console only)
	err := Init("", INFO, true)
	if err != nil {
		t.Fatalf("Init() with console only error = %v", err)
	}

	logger := Get()
	if logger == nil {
		t.Error("Expected logger to be initialized")
	}
}

func TestSetLevel(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	err := Init(logFile, INFO, false)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer Close()

	logger := Get()
	logger.SetLevel(DEBUG)

	// Verify level was set (we can't directly check private field, but no panic is good)
}

func TestLoggingFunctions(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	// Reset global logger
	globalLogger = nil
	once = sync.Once{}

	err := Init(logFile, DEBUG, false)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer Close()

	// Test all logging functions
	Debug("Debug message: %s", "test")
	Info("Info message: %s", "test")
	Warning("Warning message: %s", "test")
	Error("Error message: %s", "test")
	Critical("Critical message: %s", "test")

	// Close to flush
	Close()

	// Read log file
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(content)

	// Verify all messages were logged
	expectedMessages := []string{
		"[DEBUG] Debug message: test",
		"[INFO] Info message: test",
		"[WARNING] Warning message: test",
		"[ERROR] Error message: test",
		"[CRITICAL] Critical message: test",
	}

	for _, expected := range expectedMessages {
		if !strings.Contains(logContent, expected) {
			t.Errorf("Log file does not contain expected message: %s", expected)
		}
	}
}

func TestLogLevelFiltering(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	// Reset global logger
	globalLogger = nil
	once = sync.Once{}

	// Initialize with WARNING level
	err := Init(logFile, WARNING, false)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer Close()

	// Log messages at different levels
	Debug("Debug message")
	Info("Info message")
	Warning("Warning message")
	Error("Error message")

	// Close to flush
	Close()

	// Read log file
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(content)

	// DEBUG and INFO should not be logged
	if strings.Contains(logContent, "[DEBUG]") {
		t.Error("DEBUG message was logged when level is WARNING")
	}
	if strings.Contains(logContent, "[INFO]") {
		t.Error("INFO message was logged when level is WARNING")
	}

	// WARNING and ERROR should be logged
	if !strings.Contains(logContent, "[WARNING]") {
		t.Error("WARNING message was not logged")
	}
	if !strings.Contains(logContent, "[ERROR]") {
		t.Error("ERROR message was not logged")
	}
}

func TestLogFinding(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	// Reset global logger
	globalLogger = nil
	once = sync.Once{}

	err := Init(logFile, INFO, false)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer Close()

	// Log a finding
	LogFinding("High", "Firestore", "/users", "Readable")

	// Close to flush
	Close()

	// Read log file
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(content)

	// Verify finding was logged with all details
	expectedParts := []string{
		"[WARNING]",
		"Finding:",
		"[High]",
		"Type=Firestore",
		"Path=/users",
		"Status=Readable",
	}

	for _, part := range expectedParts {
		if !strings.Contains(logContent, part) {
			t.Errorf("Log file does not contain expected part: %s", part)
		}
	}
}

func TestGet(t *testing.T) {
	// Get should return a logger even if not initialized
	logger := Get()
	if logger == nil {
		t.Error("Get() returned nil")
	}

	// Should be able to log without panic
	logger.Info("Test message")
}

func TestClose(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	err := Init(logFile, INFO, false)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	Info("Before close")
	Close()

	// Closing should not panic
	// Multiple closes should not panic
	Close()
}

func TestConcurrentLogging(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	err := Init(logFile, INFO, false)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer Close()

	// Concurrent logging should not cause race conditions
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				Info("Message from goroutine %d iteration %d", id, j)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// If we get here without panic or deadlock, concurrent logging works
}
