package main

import (
	"flag"
	"fmt"
	"os"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/types"
	"firescan/internal/ui"
)

func main() {
	// Handle startup flags like --config and --resume before entering the interactive loop.
	var configPath string
	var resumeSession bool
	flag.StringVar(&configPath, "config", "", "Path to a YAML configuration file.")
	flag.BoolVar(&resumeSession, "resume", false, "Resume from a saved session.")
	flag.Parse()

	if resumeSession {
		err := handleResumeSession()
		if err != nil {
			fmt.Printf("❌ Error resuming session: %v\n", err)
			os.Exit(1)
		}
	} else if configPath != "" {
		err := config.LoadFromFile(configPath)
		if err != nil {
			fmt.Printf("❌ Error loading config file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Configuration loaded from %s\n", configPath)
	}

	ui.PrintBanner()

	err := ui.RunConsole()
	if err != nil {
		fmt.Printf("❌ Console error: %v\n", err)
		os.Exit(1)
	}
}

// handleResumeSession handles the --resume flag functionality
func handleResumeSession() error {
	err := config.ResumeSession()
	if err != nil {
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