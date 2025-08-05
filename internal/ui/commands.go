package ui

import (
	"encoding/json"
	"flag"
	"fmt"
	"regexp"
	"strings"
	"time"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/scanner"
	"firescan/internal/types"
	"firescan/internal/wordlist"
)

// HandleSet handles the 'set' command exactly as in original
func HandleSet(args []string) {
	if len(args) != 2 {
		fmt.Println("Usage: set <VARIABLE> <VALUE>")
		return
	}
	variable := strings.ToLower(args[0])
	value := args[1]

	switch variable {
	case "projectid":
		// Basic validation for Firebase project ID format.
		re := regexp.MustCompile(`^[a-z0-9-]{6,30}$`)
		if !re.MatchString(value) {
			fmt.Println("❌ Invalid projectID format. Must be 6-30 lowercase letters, numbers, or hyphens.")
			return
		}
		config.SetProjectID(value)
	case "apikey":
		config.SetAPIKey(value)
	case "token":
		config.SetToken(value)
	default:
		fmt.Printf("❌ Unknown variable: %s. Available: projectID, apiKey, token\n", variable)
		return
	}
	fmt.Printf("[*] %s => %s\n", variable, value)
}

// HandleShow handles the 'show' command exactly as in original
func HandleShow(args []string) {
	if len(args) == 0 || strings.ToLower(args[0]) != "options" {
		fmt.Println("Usage: show options")
		return
	}

	state := config.GetState()

	fmt.Println("\n--- Current Session Configuration ---")
	fmt.Printf("  projectID : %s\n", state.ProjectID)
	fmt.Printf("  apiKey    : %s\n", config.MaskString(state.APIKey, 4, 4))
	fmt.Printf("  token     : %s\n", config.MaskString(state.Token, 8, 8))
	fmt.Println("-----------------------------------")
}

// HandleAuth handles the 'auth' command exactly as in original
func HandleAuth(args []string) {
	if len(args) > 0 {
		if strings.ToLower(args[0]) == "logout" {
			config.ClearAuth()
			fmt.Println("[*] User logged out. Session credentials have been cleared.")
			return
		}
		if strings.ToLower(args[0]) == "show-token" {
			token := config.GetToken()
			if token == "" {
				fmt.Println("❌ No authentication token found. Please authenticate first using 'auth --create-account' or 'auth -e <email> -P <password>'.")
			} else {
				fmt.Printf("🔐 Current JWT Token:\n%s\n", token)
			}
			return
		}
		if strings.ToLower(args[0]) == "--enum-providers" {
			HandleEnumerateAuthProviders()
			return
		}
		if strings.ToLower(args[0]) == "status" {
			HandleAuthStatus()
			return
		}
		if strings.ToLower(args[0]) == "refresh" {
			HandleAuthRefresh()
			return
		}
	}

	authFlags := flag.NewFlagSet("auth", flag.ContinueOnError)
	email := authFlags.String("e", "", "Email for authentication")
	password := authFlags.String("P", "", "Password for authentication")
	createAccount := authFlags.Bool("create-account", false, "Create/use a test account")
	createAccountEmail := authFlags.String("email", "", "Email for account creation (use with --create-account, defaults to fire@scan.com)")

	authFlags.Parse(args)

	// Validate that --email flag is only used with --create-account
	if *createAccountEmail != "" && !*createAccount {
		fmt.Println("❌ Error: --email flag can only be used with --create-account.")
		return
	}

	apiKey := config.GetAPIKey()
	if apiKey == "" {
		fmt.Println("❌ Error: apiKey must be set before using the auth command.")
		return
	}

	var authEmail, authPassword string
	if *createAccount {
		// Use provided email or default to fire@scan.com
		if *createAccountEmail != "" {
			authEmail = *createAccountEmail
		} else {
			authEmail = "fire@scan.com"
		}
		authPassword = "password123"
		fmt.Printf("[*] Attempting to create/login with test account %s...\n", authEmail)
	} else if *email != "" && *password != "" {
		authEmail = *email
		authPassword = *password
		fmt.Printf("[*] Attempting to login with %s...\n", authEmail)
	} else {
		fmt.Println("Usage: auth [--create-account [--email <email>]] | [-e <email> -P <password>] | [logout] | [show-token] | [status] | [refresh] | [--enum-providers]")
		return
	}

	token, userID, emailVerified, err := auth.GetAuthToken(authEmail, authPassword, apiKey, *createAccount)
	if err != nil {
		fmt.Printf("❌ Authentication failed: %v\n", err)
		return
	}

	config.SetAuthInfo(authEmail, authPassword, userID, emailVerified)
	config.SetToken(token)

	// Send verification email for custom accounts if not already verified
	if *createAccount && *createAccountEmail != "" && *createAccountEmail != "fire@scan.com" {
		// Check current verification status by fetching fresh user info
		currentVerified, err := auth.CheckEmailVerificationStatus(token, apiKey)
		if err != nil {
			fmt.Printf("⚠️  Warning: Could not check verification status: %v\n", err)
			currentVerified = emailVerified // Fall back to signup response
		}
		
		if !currentVerified {
			fmt.Printf("[*] Sending email verification to %s...\n", authEmail)
			err = auth.SendEmailVerification(token, apiKey)
			if err != nil {
				fmt.Printf("⚠️  Warning: Failed to send verification email: %v\n", err)
			} else {
				fmt.Printf("%s✓ Verification email sent to %s%s\n", types.ColorYellow, authEmail, types.ColorReset)
			}
		} else {
			fmt.Printf("%s✓ Email %s is already verified%s\n", types.ColorGreen, authEmail, types.ColorReset)
		}
		
		// Update state with current verification status
		config.SetAuthInfo(authEmail, authPassword, userID, currentVerified)
	}

	fmt.Printf("%s✓ Successfully authenticated. Token has been set.%s\n", types.ColorGreen, types.ColorReset)
}

// HandleScan handles the 'scan' command exactly as in original
func HandleScan(args []string) {
	scanFlags := flag.NewFlagSet("scan", flag.ContinueOnError)
	list := scanFlags.String("l", "all", "Wordlist keyword (defaults to 'all') or file path.")
	allScan := scanFlags.Bool("all", false, "Run all enumeration modules with the 'all' wordlist.")
	rtdbTest := scanFlags.Bool("rtdb", false, "Enable Realtime Database enumeration.")
	firestoreTest := scanFlags.Bool("firestore", false, "Enable Firestore enumeration.")
	storageTest := scanFlags.Bool("storage", false, "Enable Cloud Storage enumeration.")
	functionsTest := scanFlags.Bool("functions", false, "Enable Cloud Functions enumeration.")
	hostingTest := scanFlags.Bool("hosting", false, "Check for public firebase.json config file.")
	jsonOutput := scanFlags.Bool("json", false, "Output results in JSON format.")
	concurrency := scanFlags.Int("c", 50, "Set concurrency.")

	scanFlags.Parse(args)

	if *allScan {
		*list = "all"
		*rtdbTest = true
		*firestoreTest = true
		*storageTest = true
		*functionsTest = true
		*hostingTest = true
	}

	if !(*rtdbTest || *firestoreTest || *storageTest || *functionsTest || *hostingTest) {
		fmt.Println("❌ Error: No scan type specified. Use a flag like --rtdb, --firestore, --all, etc.")
		return
	}

	state := config.GetState()
	if state.ProjectID == "" || state.Token == "" {
		fmt.Println("❌ Error: projectID and token must be set before scanning. Use 'set' and 'auth'.")
		return
	}

	options := scanner.ScanOptions{
		List:          *list,
		AllScan:       *allScan,
		RTDBTest:      *rtdbTest,
		FirestoreTest: *firestoreTest,
		StorageTest:   *storageTest,
		FunctionsTest: *functionsTest,
		HostingTest:   *hostingTest,
		JSONOutput:    *jsonOutput,
		Concurrency:   *concurrency,
	}

	findings, err := scanner.RunScan(options)
	if err != nil {
		fmt.Printf("❌ Error during scan: %v\n", err)
		return
	}

	if *jsonOutput {
		PrintJSON(findings)
	}
	fmt.Printf("\n\n✅ Scan complete. Found %d vulnerabilities.\n", len(findings))
}

// HandleExtract handles the 'extract' command exactly as in original
func HandleExtract(args []string) {
	extractFlags := flag.NewFlagSet("extract", flag.ContinueOnError)
	isFirestore := extractFlags.Bool("firestore", false, "Extract from a Firestore collection.")
	isRTDB := extractFlags.Bool("rtdb", false, "Extract from a Realtime Database node.")
	path := extractFlags.String("path", "", "The path/collection to extract.")

	extractFlags.Parse(args)

	if (!*isFirestore && !*isRTDB) || *path == "" {
		fmt.Println("Usage: extract [--firestore | --rtdb] --path <collection_or_node_path>")
		return
	}

	state := config.GetState()
	if state.ProjectID == "" || state.Token == "" {
		fmt.Println("❌ Error: projectID and token must be set before extracting. Use 'set' and 'auth'.")
		return
	}

	fmt.Printf("[*] Extracting data from path: %s\n", *path)

	var data interface{}
	var err error

	if *isFirestore {
		data, err = scanner.ExtractFirestoreCollection(*path)
	} else {
		data, err = scanner.ExtractRTDBNode(*path)
	}

	if err != nil {
		fmt.Printf("❌ Error extracting data: %v\n", err)
		return
	}

	prettyJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("❌ Error formatting JSON output: %v\n", err)
		return
	}

	fmt.Println(string(prettyJSON))
}

// HandleWordlist handles the 'wordlist' command exactly as in original
func HandleWordlist(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: wordlist <show|add> [options]")
		return
	}

	switch strings.ToLower(args[0]) {
	case "show":
		if len(args) == 1 {
			fmt.Println("[*] Available built-in wordlists:")
			for _, name := range wordlist.List() {
				fmt.Printf("  - %s\n", name)
			}
		} else {
			listName := args[1]
			if list, ok := wordlist.Get(listName); ok {
				fmt.Printf("[*] Contents of wordlist '%s':\n", listName)
				for _, item := range list {
					fmt.Printf("  %s\n", item)
				}
			} else {
				fmt.Printf("❌ Wordlist '%s' not found.\n", listName)
			}
		}
	case "add":
		if len(args) != 3 {
			fmt.Println("Usage: wordlist add <list_name> <word1,word2,...>")
			return
		}
		listName := args[1]
		words := strings.Split(args[2], ",")
		wordlist.Add(listName, words)
		fmt.Printf("✓ Successfully added session wordlist '%s' with %d words.\n", listName, len(words))
	default:
		fmt.Println("Usage: wordlist <show|add> [options]")
	}
}

// HandleMakeConfig handles the 'make-config' command exactly as in original
func HandleMakeConfig() {
	exampleConfig := `
# firescan configuration file
#
# Use this file to pre-load your settings at startup.
# Launch with: ./firescan --config /path/to/your/config.yaml

# Your Firebase Project ID (e.g., my-cool-app)
projectID: ""

# Your Firebase Web API Key (found in the firebaseConfig object in client-side JS)
apiKey: ""
`
	fmt.Println(exampleConfig)
}

// HandleSaveQuit handles the 'save-quit' command
func HandleSaveQuit() {
	state := config.GetState()
	
	if state.ProjectID == "" || state.APIKey == "" {
		fmt.Println("⚠️  Warning: No configuration to save (projectID and apiKey required).")
		return
	}
	
	sessionName := config.PromptForSessionName(fmt.Sprintf("%s-%d", state.ProjectID, time.Now().Unix()))
	
	err := config.SaveSession(sessionName)
	if err != nil {
		fmt.Printf("❌ Error saving session: %v\n", err)
		return
	}
	
	fmt.Printf("%s✓ Session '%s' saved successfully.%s\n", types.ColorGreen, sessionName, types.ColorReset)
}

// HandleEnumerateAuthProviders enumerates authentication providers
func HandleEnumerateAuthProviders() {
	apiKey := config.GetAPIKey()
	if apiKey == "" {
		fmt.Println("❌ Error: apiKey must be set to enumerate auth providers.")
		return
	}

	auth.EnumerateAuthProviders(apiKey)
}

// HandleAuthStatus shows current authentication status
func HandleAuthStatus() {
	email, _, userID, emailVerified := config.GetAuthInfo()
	token := config.GetToken()
	
	if token == "" {
		fmt.Println("❌ No active authentication session. Please authenticate first using 'auth --create-account' or 'auth -e <email> -P <password>'.")
		return
	}
	
	fmt.Println("\n--- Authentication Status ---")
	fmt.Printf("  Email         : %s\n", email)
	fmt.Printf("  User ID       : %s\n", userID)
	verificationStatus := "No"
	if emailVerified {
		verificationStatus = "Yes"
	}
	fmt.Printf("  Email Verified: %s\n", verificationStatus)
	fmt.Printf("  Token Active  : Yes\n")
	fmt.Println("-----------------------------")
}

// HandleAuthRefresh refreshes the authentication token
func HandleAuthRefresh() {
	email, password, _, _ := config.GetAuthInfo()
	apiKey := config.GetAPIKey()
	
	if email == "" || password == "" {
		fmt.Println("❌ Error: No stored credentials available for refresh. Please authenticate first.")
		return
	}
	
	if apiKey == "" {
		fmt.Println("❌ Error: apiKey must be set before refreshing token.")
		return
	}
	
	fmt.Printf("[*] Refreshing authentication token for %s...\n", email)
	
	newToken, userID, emailVerified, err := auth.SignIn(email, password, apiKey)
	if err != nil {
		fmt.Printf("❌ Token refresh failed: %v\n", err)
		return
	}
	
	config.SetAuthInfo(email, password, userID, emailVerified)
	config.SetToken(newToken)
	
	fmt.Printf("%s✓ Token refreshed successfully.%s\n", types.ColorGreen, types.ColorReset)
}