package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chzyer/readline"
	"gopkg.in/yaml.v3"
)

// --- State, Structs, and Constants ---
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// State holds the global configuration for the console session.
type State struct {
	ProjectID string `yaml:"projectID"`
	APIKey    string `yaml:"apiKey"`
	Token     string `yaml:"-"`
	// Store credentials for automatic token refresh
	Email    string `yaml:"-"`
	Password string `yaml:"-"`
}

// Finding represents a discovered vulnerability.
type Finding struct {
	Timestamp string `json:"timestamp"`
	Severity  string `json:"severity"`
	Type      string `json:"type"`
	Path      string `json:"path"`
	Status    string `json:"status"`
}

// Job represents a task for a worker.
type Job struct {
	Type string
	Path string
}

var currentState State       // Global state for the session
var stateMutex sync.RWMutex // Mutex to protect currentState from concurrent access

// --- Default Wordlists & Data ---
var defaultLists = map[string][]string{
	"users": {
		// Basic user terms
		"users", "user", "accounts", "account", "profiles", "profile", "members", "member",
		"admins", "admin", "administrators", "administrator", "guests", "guest", "clients", "client",
		"customers", "customer", "employees", "employee", "staff", "team", "teams",
		"subscribers", "subscriber", "principals", "principal", "tenants", "tenant",
		// Extended user terms
		"userProfiles", "userProfile", "userAccounts", "userAccount", "userInfo", "userInformation",
		"userData", "userDetails", "userSettings", "userPreferences", "userPrefs", "userConfig",
		"publicUsers", "privateUsers", "activeUsers", "inactiveUsers", "bannedUsers", "deletedUsers",
		"moderators", "moderator", "superusers", "superuser", "operators", "operator",
		"owners", "owner", "managers", "manager", "developers", "developer", "testers", "tester",
		"beta_users", "betaUsers", "vip_users", "vipUsers", "premium_users", "premiumUsers",
		"free_users", "freeUsers", "trial_users", "trialUsers", "paid_users", "paidUsers",
		// Authentication related
		"auth", "authentication", "authorization", "sessions", "session", "tokens", "token",
		"logins", "login", "logouts", "logout", "registrations", "registration", "signups", "signup",
		"signin", "signout", "passwords", "password", "credentials", "credential",
		// Roles and permissions
		"roles", "role", "permissions", "permission", "groups", "group", "access", "acl",
		"privileges", "privilege", "rights", "right", "policies", "policy",
	},
	"config": {
		// Basic config terms
		"config", "configuration", "configurations", "settings", "setting", "app_config", "appConfig",
		"app_settings", "appSettings", "env", "environment", "environments", "properties", "property",
		"secret", "secrets", "credential", "credentials", "key", "keys", "token", "tokens",
		"apikey", "apiKey", "api_key", "apiKeys", "api_keys",
		// Extended config terms
		"firebase_config", "firebaseConfig", "firebase_settings", "firebaseSettings",
		"database_config", "databaseConfig", "db_config", "dbConfig", "auth_config", "authConfig",
		"storage_config", "storageConfig", "function_config", "functionConfig",
		"hosting_config", "hostingConfig", "analytics_config", "analyticsConfig",
		"security_config", "securityConfig", "firebase_rules", "firebaseRules",
		"security_rules", "securityRules", "rules", "rule", "indexes", "index",
		// Environment and deployment
		"prod", "production", "dev", "development", "test", "testing", "stage", "staging",
		"local", "beta", "alpha", "demo", "sandbox", "preview", "build", "deploy", "deployment",
		// Sensitive data
		"private_key", "privateKey", "private_keys", "privateKeys", "public_key", "publicKey",
		"master_key", "masterKey", "encryption_key", "encryptionKey", "signing_key", "signingKey",
		"jwt_secret", "jwtSecret", "oauth_secret", "oauthSecret", "client_secret", "clientSecret",
		"database_url", "databaseUrl", "storage_bucket", "storageBucket", "project_id", "projectId",
	},
	"passwords": {
		// Basic password terms
		"password", "passwords", "pwd", "credential", "credentials", "cred", "secret", "secrets",
		"vault", "hash", "hashes", "secret_key", "secretKey", "private_key", "privateKey",
		"master_key", "masterKey", "pwd_hash", "pwdHash", "shadow", "salt", "salts",
		// Extended password terms
		"user_passwords", "userPasswords", "admin_passwords", "adminPasswords",
		"password_hash", "passwordHash", "password_hashes", "passwordHashes",
		"encrypted_passwords", "encryptedPasswords", "hashed_passwords", "hashedPasswords",
		"password_salt", "passwordSalt", "password_salts", "passwordSalts",
		"password_reset", "passwordReset", "password_resets", "passwordResets",
		"reset_tokens", "resetTokens", "reset_token", "resetToken",
		"recovery_codes", "recoveryCodes", "recovery_code", "recoveryCode",
		"backup_codes", "backupCodes", "backup_code", "backupCode",
		"verification_codes", "verificationCodes", "verification_code", "verificationCode",
		"otp", "otps", "totp", "totps", "mfa", "2fa", "twofa", "two_factor", "twoFactor",
		// Security related
		"security_questions", "securityQuestions", "security_answers", "securityAnswers",
		"pin", "pins", "passcode", "passcodes", "passphrase", "passphrases",
		"session_keys", "sessionKeys", "session_key", "sessionKey",
		"auth_tokens", "authTokens", "auth_token", "authToken",
		"access_tokens", "accessTokens", "access_token", "accessToken",
		"refresh_tokens", "refreshTokens", "refresh_token", "refreshToken",
	},
	"functions": {
		// Basic API/Function terms
		"api", "apis", "graphql", "webhook", "webhooks", "user", "users", "helloWorld", "hello",
		"payment", "payments", "charge", "charges", "message", "messages", "messaging",
		"login", "logout", "register", "registration", "signup", "signin", "signout",
		"checkout", "processPayment", "sendNotification", "notification", "notifications",
		"upload", "uploads", "download", "downloads", "trigger", "triggers", "cron", "background",
		// Extended function terms
		"createUser", "updateUser", "deleteUser", "getUser", "getUserById", "getUserByEmail",
		"authenticateUser", "authorizeUser", "validateUser", "verifyUser",
		"sendEmail", "sendSMS", "sendPushNotification", "emailVerification", "phoneVerification",
		"resetPassword", "changePassword", "updatePassword", "forgotPassword",
		"processOrder", "createOrder", "updateOrder", "deleteOrder", "getOrder", "getOrders",
		"addToCart", "removeFromCart", "updateCart", "getCart", "clearCart",
		"processRefund", "createRefund", "handlePayment", "validatePayment", "chargeCard",
		"subscribeUser", "unsubscribeUser", "updateSubscription", "cancelSubscription",
		"generateReport", "exportData", "importData", "backupData", "restoreData",
		"resizeImage", "compressImage", "uploadFile", "deleteFile", "getFileUrl",
		"logEvent", "trackAnalytics", "recordMetric", "auditLog", "errorLog",
		"sendWelcomeEmail", "sendPasswordReset", "sendInvitation", "sendReminder",
		"validateInput", "sanitizeInput", "hashPassword", "encryptData", "decryptData",
		"generateToken", "verifyToken", "refreshToken", "revokeToken",
		// Admin functions
		"adminPanel", "adminFunction", "adminOnly", "superAdmin", "moderateContent",
		"banUser", "unbanUser", "deleteAccount", "suspendUser", "activateUser",
		"bulkUpdate", "bulkDelete", "bulkInsert", "bulkImport", "bulkExport",
		"maintenance", "healthCheck", "systemStatus", "cleanup", "migration",
		// Business logic
		"calculateTax", "calculateShipping", "applyDiscount", "applyPromoCode",
		"inventoryUpdate", "stockCheck", "priceUpdate", "productSearch", "categorySearch",
		"userRecommendations", "contentModeration", "spamDetection", "fraudDetection",
		"geoLocation", "weatherData", "currencyConversion", "languageDetection",
	},
	"database": {
		// Database collections/nodes
		"users", "accounts", "profiles", "sessions", "tokens", "roles", "permissions",
		"products", "items", "inventory", "catalog", "categories", "brands", "manufacturers",
		"orders", "purchases", "transactions", "payments", "invoices", "receipts", "billing",
		"cart", "wishlist", "favorites", "bookmarks", "history", "activity", "logs",
		"posts", "articles", "blogs", "comments", "reviews", "ratings", "feedback",
		"messages", "notifications", "alerts", "announcements", "news", "updates",
		"files", "images", "videos", "documents", "uploads", "media", "assets",
		"settings", "config", "preferences", "options", "metadata", "cache", "tmp",
		"analytics", "metrics", "stats", "reports", "events", "tracking", "monitoring",
		"subscriptions", "memberships", "plans", "features", "licenses", "quotas",
		"geo", "locations", "addresses", "countries", "regions", "cities", "places",
		"contacts", "friends", "followers", "following", "connections", "relationships",
		"teams", "organizations", "companies", "departments", "groups", "projects",
		"tasks", "todos", "schedules", "calendars", "appointments", "bookings", "reservations",
		"support", "tickets", "issues", "bugs", "features", "requests", "feedback",
		"tests", "experiments", "ab_tests", "feature_flags", "toggles", "switches",
	},
	"storage": {
		// Storage buckets and folders
		"uploads", "images", "photos", "pictures", "avatars", "thumbnails", "gallery",
		"videos", "movies", "clips", "recordings", "streams", "media", "assets",
		"documents", "files", "pdfs", "docs", "sheets", "presentations", "archives",
		"backup", "backups", "exports", "dumps", "snapshots", "temp", "tmp", "cache",
		"public", "private", "shared", "protected", "secure", "encrypted", "compressed",
		"user_uploads", "admin_uploads", "system_files", "config_files", "log_files",
		"profile_pictures", "cover_photos", "product_images", "category_images",
		"audio", "music", "sounds", "podcasts", "voicemails", "recordings",
		"data", "datasets", "exports", "imports", "migrations", "seeds", "fixtures",
	},
	"security": {
		// Security and vulnerability related
		"security", "vulnerabilities", "exploits", "backdoors", "malware", "viruses",
		"injection", "xss", "csrf", "sqli", "nosqli", "rce", "lfi", "rfi", "xxe",
		"idor", "bola", "bfla", "ssrf", "ssti", "deserialization", "overflow",
		"authentication", "authorization", "session", "jwt", "oauth", "saml",
		"firewall", "waf", "ids", "ips", "antivirus", "encryption", "decryption",
		"certificates", "ssl", "tls", "https", "pki", "ca", "csr", "crl",
		"audit", "compliance", "gdpr", "hipaa", "pci", "sox", "iso27001",
		"penetration", "pentest", "vulnerability_scan", "security_scan", "assessment",
		"forensics", "incident", "response", "recovery", "disaster", "continuity",
		"monitoring", "alerting", "logging", "siem", "soar", "threat", "intelligence",
	},
	"all": {
		// Comprehensive list combining all categories and common variations
		// User-related
		"users", "user", "accounts", "account", "profiles", "profile", "members", "member",
		"admins", "admin", "administrators", "guests", "clients", "customers", "employees",
		"staff", "team", "teams", "subscribers", "principals", "tenants", "userProfiles",
		"userAccounts", "userData", "userSettings", "publicUsers", "privateUsers",
		"moderators", "superusers", "operators", "owners", "managers", "developers",
		// Configuration and secrets
		"config", "configuration", "settings", "app_config", "env", "environment",
		"properties", "secret", "secrets", "credential", "credentials", "key", "keys",
		"token", "tokens", "apikey", "api_key", "firebase_config", "database_config",
		"auth_config", "storage_config", "security_config", "rules", "indexes",
		"private_key", "public_key", "master_key", "jwt_secret", "oauth_secret",
		// Authentication and sessions
		"auth", "authentication", "authorization", "sessions", "session", "login",
		"logout", "signin", "signout", "register", "registration", "signup",
		"password", "passwords", "pwd", "hash", "salt", "vault", "otp", "mfa", "2fa",
		// Business data
		"products", "items", "inventory", "catalog", "categories", "orders", "purchases",
		"transactions", "payments", "invoices", "cart", "wishlist", "favorites",
		"posts", "articles", "blogs", "comments", "reviews", "ratings", "messages",
		"notifications", "alerts", "news", "analytics", "metrics", "stats", "reports",
		"events", "logs", "activity", "history", "tracking", "monitoring",
		// Files and media
		"files", "uploads", "images", "photos", "videos", "documents", "media",
		"assets", "thumbnails", "gallery", "backup", "exports", "temp", "cache",
		"public", "private", "shared", "protected", "avatars", "profile_pictures",
		// Functions and APIs
		"api", "apis", "graphql", "webhook", "webhooks", "functions", "endpoints",
		"helloWorld", "payment", "charge", "message", "processPayment", "sendNotification",
		"upload", "download", "trigger", "cron", "background", "createUser", "updateUser",
		"deleteUser", "getUser", "sendEmail", "resetPassword", "processOrder",
		// Database collections
		"data", "content", "metadata", "subscriptions", "memberships", "plans",
		"features", "licenses", "geo", "locations", "addresses", "contacts", "friends",
		"followers", "organizations", "companies", "projects", "tasks", "schedules",
		"support", "tickets", "issues", "bugs", "tests", "experiments", "ab_tests",
		// Development and testing
		"dev", "development", "prod", "production", "test", "testing", "stage",
		"staging", "beta", "alpha", "demo", "sandbox", "build", "deploy", "migration",
		// Security terms
		"security", "audit", "compliance", "vulnerability", "pentest", "firewall",
		"encryption", "certificates", "ssl", "monitoring", "incident", "forensics",
		// Common variations and typos
		"admin1", "test", "demo", "sample", "example", "default", "public", "www",
		"ftp", "mail", "email", "blog", "forum", "shop", "store", "portal", "dashboard",
		"panel", "console", "manager", "control", "system", "service", "application",
		"app", "mobile", "web", "site", "page", "home", "index", "main", "root",
		// Industry specific
		"books", "library", "reading", "courses", "lessons", "students", "teachers",
		"medical", "health", "hospital", "patient", "doctor", "clinic", "pharmacy",
		"finance", "bank", "trading", "investment", "insurance", "loan", "credit",
		"real_estate", "property", "rental", "lease", "hotel", "booking", "reservation",
		"restaurant", "food", "menu", "recipe", "delivery", "shipping", "logistics",
		"social", "feed", "timeline", "chat", "forum", "community", "gaming", "sports",
	},
}
var functionRegions = []string{"us-central1", "us-east1", "us-east4", "europe-west1", "europe-west2", "asia-east2", "asia-northeast1"}

// --- Main Application Loop ---

func main() {
	// Handle startup flags like --config before entering the interactive loop.
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to a YAML configuration file.")
	flag.Parse()

	if configPath != "" {
		err := loadConfigFromFile(configPath)
		if err != nil {
			fmt.Printf("❌ Error loading config file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Configuration loaded from %s\n", configPath)
	}

	printBanner()

	// Setup readline for a professional console experience.
	completer := readline.NewPrefixCompleter(
		readline.PcItem("set",
			readline.PcItem("projectid"),
			readline.PcItem("apikey"),
			readline.PcItem("token"),
		),
		readline.PcItem("show",
			readline.PcItem("options"),
		),
		readline.PcItem("auth",
			readline.PcItem("--create-account"),
			readline.PcItem("--email"),
			readline.PcItem("-e"),
			readline.PcItem("-P"),
			readline.PcItem("logout"),
			readline.PcItem("show-token"),
			readline.PcItem("--enum-providers"),
		),
		readline.PcItem("scan",
			readline.PcItem("--all"),
			readline.PcItem("-l",
				readline.PcItem("all"),
				readline.PcItem("users"),
				readline.PcItem("config"),
				readline.PcItem("passwords"),
				readline.PcItem("functions"),
				readline.PcItem("database"),
				readline.PcItem("storage"),
				readline.PcItem("security"),
			),
			readline.PcItem("--rtdb"),
			readline.PcItem("--firestore"),
			readline.PcItem("--storage"),
			readline.PcItem("--functions"),
			readline.PcItem("--hosting"),
			readline.PcItem("--json"),
			readline.PcItem("-c"),
		),
		readline.PcItem("extract",
			readline.PcItem("--firestore"),
			readline.PcItem("--rtdb"),
			readline.PcItem("--path"),
		),
		readline.PcItem("wordlist",
			readline.PcItem("show"),
			readline.PcItem("add"),
		),
		readline.PcItem("make-config"),
		readline.PcItem("help"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "firescan > ",
		HistoryFile:     "/tmp/firescan_history.tmp",
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		panic(err)
	}
	defer rl.Close()

	// This is the main REPL (Read-Evaluate-Print Loop).
	for {
		line, err := rl.Readline()
		if err == readline.ErrInterrupt || err == io.EOF {
			break
		}

		input := strings.Fields(line)
		if len(input) == 0 {
			continue
		}

		command := input[0]
		args := input[1:]

		switch strings.ToLower(command) {
		case "set":
			handleSet(args)
		case "show":
			handleShow(args)
		case "auth":
			handleAuth(args)
		case "scan":
			handleScan(args)
		case "extract":
			handleExtract(args)
		case "wordlist":
			handleWordlist(args)
		case "make-config":
			handleMakeConfig()
		case "help":
			printHelp()
		case "exit", "quit":
			return
		default:
			fmt.Println("❌ Unknown command. Type 'help' for a list of commands.")
		}
	}
}

// --- Command Handlers ---

func handleSet(args []string) {
	if len(args) != 2 {
		fmt.Println("Usage: set <VARIABLE> <VALUE>")
		return
	}
	variable := strings.ToLower(args[0])
	value := args[1]

	stateMutex.Lock()
	defer stateMutex.Unlock()

	switch variable {
	case "projectid":
		// Basic validation for Firebase project ID format.
		re := regexp.MustCompile(`^[a-z0-9-]{6,30}$`)
		if !re.MatchString(value) {
			fmt.Println("❌ Invalid projectID format. Must be 6-30 lowercase letters, numbers, or hyphens.")
			return
		}
		currentState.ProjectID = value
	case "apikey":
		currentState.APIKey = value
	case "token":
		currentState.Token = value
	default:
		fmt.Printf("❌ Unknown variable: %s. Available: projectID, apiKey, token\n", variable)
		return
	}
	fmt.Printf("[*] %s => %s\n", variable, value)
}

func handleShow(args []string) {
	if len(args) == 0 || strings.ToLower(args[0]) != "options" {
		fmt.Println("Usage: show options")
		return
	}

	stateMutex.RLock()
	defer stateMutex.RUnlock()

	fmt.Println("\n--- Current Session Configuration ---")
	fmt.Printf("  projectID : %s\n", currentState.ProjectID)
	fmt.Printf("  apiKey    : %s\n", maskString(currentState.APIKey, 4, 4))
	fmt.Printf("  token     : %s\n", maskString(currentState.Token, 8, 8))
	fmt.Println("-----------------------------------")
}

func handleAuth(args []string) {
	if len(args) > 0 {
		if strings.ToLower(args[0]) == "logout" {
			stateMutex.Lock()
			currentState.Token = ""
			currentState.Email = ""
			currentState.Password = ""
			stateMutex.Unlock()
			fmt.Println("[*] User logged out. Session credentials have been cleared.")
			return
		}
		if strings.ToLower(args[0]) == "show-token" {
			stateMutex.RLock()
			token := currentState.Token
			stateMutex.RUnlock()
			
			if token == "" {
				fmt.Println("❌ No authentication token found. Please authenticate first using 'auth --create-account' or 'auth -e <email> -P <password>'.")
			} else {
				fmt.Printf("🔐 Current JWT Token:\n%s\n", token)
			}
			return
		}
		if strings.ToLower(args[0]) == "--enum-providers" {
			handleEnumerateAuthProviders()
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

	stateMutex.RLock()
	apiKey := currentState.APIKey
	stateMutex.RUnlock()
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
		fmt.Println("Usage: auth [--create-account [--email <email>]] | [-e <email> -P <password>] | [logout] | [show-token] | [--enum-providers]")
		return
	}

	token, err := getAuthToken(authEmail, authPassword, *createAccount)
	if err != nil {
		fmt.Printf("❌ Authentication failed: %v\n", err)
		return
	}

	stateMutex.Lock()
	currentState.Token = token
	currentState.Email = authEmail
	currentState.Password = authPassword
	stateMutex.Unlock()

	fmt.Printf("%s✓ Successfully authenticated. Token has been set.%s\n", ColorGreen, ColorReset)
}

func handleScan(args []string) {
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

	stateMutex.RLock()
	if currentState.ProjectID == "" || currentState.Token == "" {
		stateMutex.RUnlock()
		fmt.Println("❌ Error: projectID and token must be set before scanning. Use 'set' and 'auth'.")
		return
	}
	stateMutex.RUnlock()

	wordlist, err := loadWordlist(*list)
	if err != nil {
		fmt.Printf("❌ Error loading wordlist: %v\n", err)
		return
	}

	jobs := make(chan Job, *concurrency)
	results := make(chan Finding)
	var wg sync.WaitGroup

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
	}

	totalChecks := 0
	if *rtdbTest {
		totalChecks += len(wordlist)
	}
	if *firestoreTest {
		totalChecks += len(wordlist)
	}
	if *functionsTest {
		totalChecks += len(wordlist) * len(functionRegions)
	}
	if *storageTest {
		totalChecks++
	}
	if *hostingTest {
		totalChecks++
	}

	findings := make([]Finding, 0)
	var foundCount int32
	var checkedCount int64

	doneUI := make(chan bool)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		spinners := []rune{'|', '/', '-', '\\'}
		i := 0
		for {
			select {
			case finding, ok := <-results:
				if !ok {
					doneUI <- true
					return
				}
				atomic.AddInt32(&foundCount, 1)
				if *jsonOutput {
					findings = append(findings, finding)
				} else {
					fmt.Printf("\r%80s\r", "")
					printFinding(finding)
				}
			case <-ticker.C:
				if !*jsonOutput {
					currentChecked := atomic.LoadInt64(&checkedCount)
					currentFound := atomic.LoadInt32(&foundCount)
					fmt.Printf("\r[%s%c%s] Scanning... [Checked: %d/%d | Found: %d]", ColorCyan, spinners[i%len(spinners)], ColorReset, currentChecked, totalChecks, currentFound)
					i++
				}
			}
		}
	}()

	go func() {
		for _, item := range wordlist {
			if *rtdbTest {
				jobs <- Job{Type: "rtdb", Path: item}
				atomic.AddInt64(&checkedCount, 1)
			}
			if *firestoreTest {
				jobs <- Job{Type: "firestore", Path: item}
				atomic.AddInt64(&checkedCount, 1)
			}
			if *functionsTest {
				for _, region := range functionRegions {
					jobs <- Job{Type: "function", Path: fmt.Sprintf("%s/%s", region, item)}
					atomic.AddInt64(&checkedCount, 1)
				}
			}
		}
		close(jobs)
	}()

	if *storageTest {
		wg.Add(1)
		go func() {
			checkCloudStorage(results, &wg)
			atomic.AddInt64(&checkedCount, 1)
		}()
	}
	if *hostingTest {
		wg.Add(1)
		go func() {
			checkHostingConfig(results, &wg)
			atomic.AddInt64(&checkedCount, 1)
		}()
	}

	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	close(results)
	<-doneUI

	if *jsonOutput {
		printJSON(findings)
	}
	fmt.Printf("\n\n✅ Scan complete. Found %d vulnerabilities.\n", foundCount)
}

func handleWordlist(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: wordlist <show|add> [options]")
		return
	}

	switch strings.ToLower(args[0]) {
	case "show":
		if len(args) == 1 {
			fmt.Println("[*] Available built-in wordlists:")
			for name := range defaultLists {
				fmt.Printf("  - %s\n", name)
			}
		} else {
			listName := args[1]
			if list, ok := defaultLists[listName]; ok {
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
		defaultLists[listName] = words
		fmt.Printf("✓ Successfully added session wordlist '%s' with %d words.\n", listName, len(words))
	default:
		fmt.Println("Usage: wordlist <show|add> [options]")
	}
}

func handleMakeConfig() {
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

func handleExtract(args []string) {
	extractFlags := flag.NewFlagSet("extract", flag.ContinueOnError)
	isFirestore := extractFlags.Bool("firestore", false, "Extract from a Firestore collection.")
	isRTDB := extractFlags.Bool("rtdb", false, "Extract from a Realtime Database node.")
	path := extractFlags.String("path", "", "The path/collection to extract.")

	extractFlags.Parse(args)

	if (!*isFirestore && !*isRTDB) || *path == "" {
		fmt.Println("Usage: extract [--firestore | --rtdb] --path <collection_or_node_path>")
		return
	}

	stateMutex.RLock()
	if currentState.ProjectID == "" || currentState.Token == "" {
		stateMutex.RUnlock()
		fmt.Println("❌ Error: projectID and token must be set before extracting. Use 'set' and 'auth'.")
		return
	}
	stateMutex.RUnlock()

	fmt.Printf("[*] Extracting data from path: %s\n", *path)

	var data interface{}
	var err error

	if *isFirestore {
		data, err = extractFirestoreCollection(*path)
	} else {
		data, err = extractRTDBNode(*path)
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

// --- Helper, Auth & Scanning Functions ---

func printBanner() {
	asciiArt := "                                                /===-_---~~~~~~~~~------____\n" +
		"                                               |===-~___                _,-'\n" +
		"                 -==\\\\                         `//~\\\\   ~~~~`---.___.-~~\n" +
		"             ______-==|                         | |  \\\\           _-~`\n" +
		"       __--~~~  ,-/-==\\\\                        | |   `\\        ,'\n" +
		"    _-~       /'    |  \\\\                      / /      \\      /\n" +
		"  .'        /       |   \\\\                   /' /        \\   /'\n" +
		" /  ____  /         |    `\\.__/-~~ ~ \\ _ _/'  /          \\/'\n" +
		"/-'~    ~~~~~---__  |     ~-/~         ( )   /'        _--~`\n" +
		"                  \\_|      /        _)   ;  ),   __--~~\n" +
		"                    '~~--_/      _-~/-  / \\   '-~ \\\n" +
		"                   {\\__--_/}    / \\\\_>- )<__\\      \\\n" +
		"                   /'   (_/  _-~  | |__>--<__|      |\n" +
		"                  |0  0 _/) )-~     | |__>--<__|      |\n" +
		"                  / /~ ,_/       / /__>---<__/      |\n" +
		"                 o o _//        /-~_>---<__-~      /\n" +
		"                 (^(~          /~_>---<__-      _-~\n" +
		"                ,/|           /__>--<__/     _-~\n" +
		"             ,//('(          |__>--<__|     /                  .----_\n" +
		"            ( ( '))          |__>--<__|    |                 /' _---_~\\\n" +
		"         `-)) )) (           |__>--<__|    |               /'  /     ~\\`\\\n" +
		"        ,/,'//( (             \\__>--<__\\    \\            /'  //        ||\n" +
		"      ,( ( ((, ))              ~-__>--<_~-_  ~--____---~' _/'/        /'\n" +
		"    `~/  )` ) ,/|                 ~-_~>--<_/-__       __-~ _/\n" +
		"  ._-~//( )/ )) `                    ~~-'_/_/ /~~~~~~~__--~\n" +
		"   ;'( ')/ ,)(                              ~~~~~~~~~~\n" +
		"  ' ') '( (/\n" +
		"    '   '  `"

	fireScanLogo := `
███████╗██╗██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
█████╗  ██║██████╔╝█████╗  ███████╗██║     ███████║██╔██╗ ██║
██╔══╝  ██║██╔══██╗██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
██║     ██║██║  ██║███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

              🔥 Firebase Security Auditor 🔥
`
	fmt.Println(ColorCyan + asciiArt + ColorReset)
	fmt.Println(ColorCyan + fireScanLogo + ColorReset)
}

func printHelp() {
	fmt.Println("\n--- FireScan Help Menu ---")
	fmt.Println("  set <var> <val>       Set a configuration variable (projectID, apiKey, token).")
	fmt.Println("  show options          Display the current configuration.")
	fmt.Println("  auth                  Authenticate to Firebase.")
	fmt.Println("    --create-account      Create/use a test account (defaults to fire@scan.com).")
	fmt.Println("    --email <email>       Email for account creation (use with --create-account).")
	fmt.Println("    -e <email>            Email for authentication.")
	fmt.Println("    -P <password>         Password for authentication.")
	fmt.Println("    logout                Clear the current session token.")
	fmt.Println("    show-token            Display the current JWT authentication token.")
	fmt.Println("    --enum-providers      List enabled authentication providers.")
	fmt.Println("  scan                  Run a scan with the current configuration.")
	fmt.Println("    --all                 Run all scan modules with the 'all' wordlist.")
	fmt.Println("    -l <list>             Wordlist: all, users, config, passwords, functions, database, storage, security, or file path.")
	fmt.Println("    --rtdb                Scan Realtime Database.")
	fmt.Println("    --firestore           Scan Firestore.")
	fmt.Println("    --storage             Scan Cloud Storage.")
	fmt.Println("    --functions           Scan Cloud Functions.")
	fmt.Println("    --hosting             Scan Hosting for public config.")
	fmt.Println("  extract               Dump data from a readable path.")
	fmt.Println("    --firestore --path <collection>")
	fmt.Println("    --rtdb --path <node>")
	fmt.Println("  wordlist <cmd> [opts] Manage wordlists for the current session.")
	fmt.Println("    show                  List available built-in wordlists.")
	fmt.Println("    show <name>           Show contents of a specific list.")
	fmt.Println("    add <name> <w1,w2>    Add a new session-only list.")
	fmt.Println("  make-config           Print an example configuration file.")
	fmt.Println("  help                  Display this help menu.")
	fmt.Println("  exit / quit           Close the application.")
	fmt.Println("--------------------------")
}

// generateCaseVariations takes a word and returns a slice with its lowercase, PascalCase, and UPPERCASE variations.
func generateCaseVariations(word string) []string {
	if len(word) == 0 {
		return []string{}
	}
	variationsSet := make(map[string]bool)
	variationsSet[strings.ToLower(word)] = true
	variationsSet[strings.ToUpper(string(word[0]))+strings.ToLower(word[1:])] = true
	variationsSet[strings.ToUpper(word)] = true
	result := make([]string, 0, len(variationsSet))
	for v := range variationsSet {
		result = append(result, v)
	}
	return result
}

func loadWordlist(listIdentifier string) ([]string, error) {
	var baseList []string
	if list, ok := defaultLists[listIdentifier]; ok {
		fmt.Printf("[*] Using built-in wordlist: %s\n", listIdentifier)
		baseList = list
	} else if listIdentifier != "" {
		fmt.Printf("[*] Using custom wordlist from: %s\n", listIdentifier)
		file, err := os.Open(listIdentifier)
		if err != nil {
			return nil, fmt.Errorf("could not find keyword or file at '%s'", listIdentifier)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			baseList = append(baseList, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	finalListSet := make(map[string]bool)
	for _, word := range baseList {
		variations := generateCaseVariations(word)
		for _, v := range variations {
			finalListSet[v] = true
		}
	}
	finalList := make([]string, 0, len(finalListSet))
	for v := range finalListSet {
		finalList = append(finalList, v)
	}
	return finalList, nil
}

func loadConfigFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(data, &currentState)
	return err
}

func getAuthToken(email, password string, createAccount bool) (string, error) {
	if createAccount {
		token, err := signUp(email, password, currentState.APIKey)
		if err != nil {
			if strings.Contains(err.Error(), "EMAIL_EXISTS") {
				fmt.Println("[*] Test account already exists, attempting to log in...")
				return signIn(email, password, currentState.APIKey)
			}
			return "", err
		}
		return token, nil
	}
	return signIn(email, password, currentState.APIKey)
}

func signUp(email, password, apiKey string) (string, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=%s", apiKey)
	payload := map[string]string{"email": email, "password": password, "returnSecureToken": "true"}
	return executeAuthRequest(url, payload)
}

func signIn(email, password, apiKey string) (string, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s", apiKey)
	payload := map[string]string{"email": email, "password": password, "returnSecureToken": "true"}
	return executeAuthRequest(url, payload)
}

func executeAuthRequest(url string, payload map[string]string) (string, error) {
	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != http.StatusOK {
		if errData, ok := result["error"].(map[string]interface{}); ok {
			return "", fmt.Errorf("auth API error: %s (HTTP %d)", errData["message"], resp.StatusCode)
		}
		return "", fmt.Errorf("unexpected auth API error (HTTP %d)", resp.StatusCode)
	}
	if idToken, ok := result["idToken"].(string); ok {
		return idToken, nil
	}
	return "", fmt.Errorf("could not find idToken in auth response")
}

// A centralized HTTP client for making authenticated requests.
// It will automatically handle token refreshes.
func makeAuthenticatedRequest(method, url string) (*http.Response, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	stateMutex.RLock()
	token := currentState.Token
	stateMutex.RUnlock()
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Println("\n[*] Token expired. Attempting to refresh...")
		stateMutex.RLock()
		email := currentState.Email
		password := currentState.Password
		stateMutex.RUnlock()

		if email != "" && password != "" {
			newToken, err := signIn(email, password, currentState.APIKey)
			if err != nil {
				return resp, fmt.Errorf("token refresh failed: %v", err)
			}
			fmt.Println("✓ Token refreshed successfully.")
			stateMutex.Lock()
			currentState.Token = newToken
			stateMutex.Unlock()
			req.Header.Set("Authorization", "Bearer "+newToken)
			return client.Do(req)
		}
		return resp, fmt.Errorf("token expired, but no credentials available to refresh")
	}
	return resp, nil
}

func worker(jobs <-chan Job, results chan<- Finding, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		switch job.Type {
		case "rtdb":
			checkRTDB(job, results)
		case "firestore":
			checkFirestore(job, results)
		case "function":
			checkFunction(job, results)
		}
	}
}

func checkRTDB(job Job, results chan<- Finding) {
	stateMutex.RLock()
	url := fmt.Sprintf("https://%s.firebaseio.com/%s.json?auth=%s", currentState.ProjectID, job.Path, currentState.Token)
	stateMutex.RUnlock()

	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var body interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body != nil {
		if errorMap, ok := body.(map[string]interface{}); ok {
			if _, isError := errorMap["error"]; isError {
				return
			}
		}
		results <- Finding{
			Timestamp: time.Now().Format(time.RFC3339),
			Severity:  "High",
			Type:      "RTDB",
			Path:      job.Path,
			Status:    "Readable",
		}
	}
}

func checkFirestore(job Job, results chan<- Finding) {
	stateMutex.RLock()
	url := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s", currentState.ProjectID, job.Path)
	stateMutex.RUnlock()

	resp, err := makeAuthenticatedRequest("GET", url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if _, ok := body["documents"]; ok {
		results <- Finding{
			Timestamp: time.Now().Format(time.RFC3339),
			Severity:  "High",
			Type:      "Firestore",
			Path:      job.Path,
			Status:    "Readable",
		}
	}
}

func checkFunction(job Job, results chan<- Finding) {
	parts := strings.Split(job.Path, "/")
	region, funcName := parts[0], parts[1]

	stateMutex.RLock()
	url := fmt.Sprintf("https://%s-%s.cloudfunctions.net/%s", region, currentState.ProjectID, funcName)
	stateMutex.RUnlock()

	resp, err := makeAuthenticatedRequest("GET", url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		results <- Finding{
			Timestamp: time.Now().Format(time.RFC3339),
			Severity:  "Medium",
			Type:      "Function",
			Path:      url,
			Status:    "Publicly Invokable",
		}
	} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
		results <- Finding{
			Timestamp: time.Now().Format(time.RFC3339),
			Severity:  "Informational",
			Type:      "Function",
			Path:      url,
			Status:    "Exists (Auth Required)",
		}
	}
}

func checkCloudStorage(results chan<- Finding, wg *sync.WaitGroup) {
	defer wg.Done()
	stateMutex.RLock()
	bucketName := fmt.Sprintf("%s.appspot.com", currentState.ProjectID)
	url := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o", bucketName)
	stateMutex.RUnlock()

	resp, err := makeAuthenticatedRequest("GET", url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()
	results <- Finding{
		Timestamp: time.Now().Format(time.RFC3339),
		Severity:  "Critical",
		Type:      "Storage",
		Path:      bucketName,
		Status:    "Listable",
	}
}

func checkHostingConfig(results chan<- Finding, wg *sync.WaitGroup) {
	defer wg.Done()
	stateMutex.RLock()
	url := fmt.Sprintf("https://%s.web.app/firebase.json", currentState.ProjectID)
	stateMutex.RUnlock()

	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		results <- Finding{
			Timestamp: time.Now().Format(time.RFC3339),
			Severity:  "Medium",
			Type:      "Hosting",
			Path:      url,
			Status:    "firebase.json is Public",
		}
	}
}

func handleEnumerateAuthProviders() {
	stateMutex.RLock()
	apiKey := currentState.APIKey
	stateMutex.RUnlock()
	if apiKey == "" {
		fmt.Println("❌ Error: apiKey must be set to enumerate auth providers.")
		return
	}

	fmt.Println("[*] Enumerating Authentication Providers by probing...")
	providers := []string{"password", "google.com", "facebook.com", "twitter.com", "github.com"}
	var wg sync.WaitGroup
	for _, provider := range providers {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			enabled := probeAuthProvider(p, apiKey)
			status := "Disabled"
			if enabled {
				status = "Enabled"
			}
			fmt.Printf("  ├── Provider: %-20s Status: %s\n", p, status)
		}(provider)
	}
	wg.Wait()
}

func probeAuthProvider(provider, apiKey string) bool {
	var url string
	var payload map[string]string

	switch provider {
	case "password":
		url = fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=%s", apiKey)
		payload = map[string]string{"email": "test@example.com", "password": "password"}
	default: // For OAuth providers like google.com, facebook.com, etc.
		url = fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key=%s", apiKey)
		payload = map[string]string{
			"postBody":   "id_token=dummy&providerId=" + provider,
			"requestUri": "http://localhost",
		}
	}

	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if errData, ok := result["error"].(map[string]interface{}); ok {
		if msg, ok := errData["message"].(string); ok {
			// If the operation is not allowed, it's definitively disabled.
			if strings.Contains(msg, "OPERATION_NOT_ALLOWED") {
				return false
			}
			// For OAuth, specific errors indicate it's enabled but our dummy token is bad.
			if strings.Contains(msg, "INVALID_IDP_RESPONSE") || strings.Contains(msg, "INVALID_ID_TOKEN") {
				return true
			}
			// For password, EMAIL_EXISTS is a sign it's enabled.
			if provider == "password" && strings.Contains(msg, "EMAIL_EXISTS") {
				return true
			}
			// Any other error likely means it's not configured correctly or disabled.
			return false
		}
	}
	// If there's no error field at all, the request was successful, meaning it's enabled.
	return true
}

func extractFirestoreCollection(path string) (interface{}, error) {
	stateMutex.RLock()
	url := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s", currentState.ProjectID, path)
	stateMutex.RUnlock()

	resp, err := makeAuthenticatedRequest("GET", url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data (HTTP %d)", resp.StatusCode)
	}
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if docs, ok := body["documents"]; ok {
		return docs, nil
	}
	return nil, fmt.Errorf("no documents found or permission denied")
}

func extractRTDBNode(path string) (interface{}, error) {
	stateMutex.RLock()
	url := fmt.Sprintf("https://%s.firebaseio.com/%s.json?auth=%s", currentState.ProjectID, path, currentState.Token)
	stateMutex.RUnlock()

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data (HTTP %d)", resp.StatusCode)
	}
	var body interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body != nil {
		if errorMap, ok := body.(map[string]interface{}); ok {
			if errMsg, isError := errorMap["error"]; isError {
				return nil, fmt.Errorf("could not read node: %v", errMsg)
			}
		}
		return body, nil
	}
	return nil, fmt.Errorf("no data found at node")
}

func printFinding(f Finding) {
	var severityColor string
	switch f.Severity {
	case "Critical":
		severityColor = ColorRed
	case "High":
		severityColor = ColorRed
	case "Medium":
		severityColor = ColorYellow
	default:
		severityColor = ColorCyan
	}

	fmt.Printf("\n[%s%s%s] %s%sVulnerability Found!%s\n  ├── Timestamp: %s\n  ├── Severity:  %s%s%s\n  ├── Type:      %s\n  └── Path:      %s\n",
		ColorRed, ColorBold, f.Type, ColorGreen, ColorBold, ColorReset,
		f.Timestamp,
		severityColor, f.Severity, ColorReset,
		f.Type,
		f.Path,
	)
}

func printJSON(findings []Finding) {
	output, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		fmt.Printf("Error creating JSON output: %v\n", err)
		return
	}
	fmt.Println(string(output))
}

// maskString hides the middle of a string for secure display.
func maskString(s string, prefixLen, suffixLen int) string {
	if len(s) < prefixLen+suffixLen {
		return "..."
	}
	return s[:prefixLen] + "..." + s[len(s)-suffixLen:]
}
