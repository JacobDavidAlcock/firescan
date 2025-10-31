package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
	CRITICAL
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARNING:
		return "WARNING"
	case ERROR:
		return "ERROR"
	case CRITICAL:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Logger represents a structured logger
type Logger struct {
	level      LogLevel
	fileLogger *log.Logger
	console    bool
	logFile    *os.File
	mu         sync.Mutex
}

var (
	globalLogger *Logger
	once         sync.Once
)

// Init initializes the global logger
// If logPath is empty, only console logging is enabled
func Init(logPath string, level LogLevel, enableConsole bool) error {
	var initErr error
	once.Do(func() {
		globalLogger = &Logger{
			level:   level,
			console: enableConsole,
		}

		if logPath != "" {
			// Create log directory if it doesn't exist
			logDir := filepath.Dir(logPath)
			if err := os.MkdirAll(logDir, 0755); err != nil {
				initErr = fmt.Errorf("failed to create log directory: %v", err)
				return
			}

			// Open log file
			file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				initErr = fmt.Errorf("failed to open log file: %v", err)
				return
			}

			globalLogger.logFile = file

			// Create multi-writer if console is enabled
			var writer io.Writer
			if enableConsole {
				writer = io.MultiWriter(file, os.Stdout)
			} else {
				writer = file
			}

			globalLogger.fileLogger = log.New(writer, "", 0)
		} else if enableConsole {
			globalLogger.fileLogger = log.New(os.Stdout, "", 0)
		}
	})

	return initErr
}

// Get returns the global logger instance
func Get() *Logger {
	if globalLogger == nil {
		// Initialize with console-only, INFO level if not initialized
		Init("", INFO, true)
	}
	return globalLogger
}

// Close closes the log file
func Close() {
	if globalLogger != nil && globalLogger.logFile != nil {
		globalLogger.logFile.Close()
	}
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// log writes a log message at the specified level
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Skip if message level is below configured level
	if level < l.level {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	levelStr := level.String()
	message := fmt.Sprintf(format, args...)

	logLine := fmt.Sprintf("[%s] [%s] %s", timestamp, levelStr, message)

	if l.fileLogger != nil {
		l.fileLogger.Println(logLine)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs an informational message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warning logs a warning message
func (l *Logger) Warning(format string, args ...interface{}) {
	l.log(WARNING, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// Critical logs a critical error message
func (l *Logger) Critical(format string, args ...interface{}) {
	l.log(CRITICAL, format, args...)
}

// Global convenience functions

// Debug logs a debug message using the global logger
func Debug(format string, args ...interface{}) {
	Get().Debug(format, args...)
}

// Info logs an informational message using the global logger
func Info(format string, args ...interface{}) {
	Get().Info(format, args...)
}

// Warning logs a warning message using the global logger
func Warning(format string, args ...interface{}) {
	Get().Warning(format, args...)
}

// Error logs an error message using the global logger
func Error(format string, args ...interface{}) {
	Get().Error(format, args...)
}

// Critical logs a critical error message using the global logger
func Critical(format string, args ...interface{}) {
	Get().Critical(format, args...)
}

// LogFinding logs a security finding
func LogFinding(severity, findingType, path, status string) {
	Get().log(WARNING, "Finding: [%s] Type=%s Path=%s Status=%s", severity, findingType, path, status)
}

// LogScanStart logs the start of a scan
func LogScanStart(scanType string, options map[string]interface{}) {
	Get().Info("Scan started: type=%s options=%v", scanType, options)
}

// LogScanComplete logs the completion of a scan
func LogScanComplete(scanType string, findingsCount int, errorsCount int, duration time.Duration) {
	Get().Info("Scan completed: type=%s findings=%d errors=%d duration=%v",
		scanType, findingsCount, errorsCount, duration)
}

// LogError logs an error with context
func LogError(context string, err error) {
	Get().Error("%s: %v", context, err)
}
