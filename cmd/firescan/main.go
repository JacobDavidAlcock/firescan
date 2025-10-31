package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/logger"
	"firescan/internal/types"
	"firescan/internal/ui"
)

func main() {
	os.Exit(run())
}

func run() int {
	// Handle startup flags like --config and --resume before entering the interactive loop.
	var configPath string
	var resumeSession bool
	var logFile string
	var logLevel string
	flag.StringVar(&configPath, "config", "", "Path to a YAML configuration file.")
	flag.BoolVar(&resumeSession, "resume", false, "Resume from a saved session.")
	flag.StringVar(&logFile, "log", "", "Path to log file (default: ./firescan.log).")
	flag.StringVar(&logLevel, "log-level", "info", "Log level: debug, info, warning, error, critical.")
	flag.Parse()

	// Initialize logger
	level := parseLogLevel(logLevel)
	if logFile == "" {
		// Default log file location
		homeDir, _ := os.UserHomeDir()
		logFile = filepath.Join(homeDir, ".firescan", "firescan.log")
	}
	if err := logger.Init(logFile, level, false); err != nil {
		fmt.Printf("⚠️  Warning: Failed to initialize logger: %v\n", err)
		fmt.Println("   Continuing without file logging...")
	} else {
		logger.Info("FireScan started")
	}
	defer logger.Close()

	if resumeSession {
		if err := handleResumeSession(); err != nil {
			fmt.Printf("❌ Error resuming session: %v\n", err)
			return 1
		}
	} else if configPath != "" {
		if err := config.LoadFromFile(configPath); err != nil {
			fmt.Printf("❌ Error loading config file: %v\n", err)
			return 1
		}
		fmt.Printf("✓ Configuration loaded from %s\n", configPath)
	}

	ui.PrintBanner()

	if err := ui.RunConsole(); err != nil {
		fmt.Printf("❌ Console error: %v\n", err)
		return 1
	}

	return 0
}

// handleResumeSession handles the --resume flag functionality
func handleResumeSession() error {
	if err := config.ResumeSession(); err != nil {
		return err
	}

	// Try to authenticate with stored credentials if available
	email, password, _, _ := config.GetAuthInfo()
	apiKey := config.GetAPIKey()

	if email != "" && password != "" && apiKey != "" {
		fmt.Printf("[*] Attempting to authenticate with stored credentials for %s...\n", email)
		token, userID, emailVerified, err := auth.SignIn(email, password, apiKey)
		if err != nil {
			fmt.Printf("⚠️  Warning: Auto-authentication failed: %v\n", err)
			fmt.Println("[*] Session loaded but you'll need to authenticate manually.")
		} else {
			config.SetAuthInfo(email, password, userID, emailVerified)
			config.SetToken(token)
			fmt.Printf("%s✓ Session resumed and authenticated successfully.%s\n", types.ColorGreen, types.ColorReset)
		}
	}

	return nil
}

// parseLogLevel parses log level string to LogLevel
func parseLogLevel(level string) logger.LogLevel {
	switch level {
	case "debug":
		return logger.DEBUG
	case "info":
		return logger.INFO
	case "warning":
		return logger.WARNING
	case "error":
		return logger.ERROR
	case "critical":
		return logger.CRITICAL
	default:
		return logger.INFO
	}
}
