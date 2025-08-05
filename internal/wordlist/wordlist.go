package wordlist

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// DefaultLists contains all the built-in wordlists exactly as in the original
var DefaultLists = map[string][]string{
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

// GenerateCaseVariations takes a word and returns a slice with its lowercase, PascalCase, and UPPERCASE variations
func GenerateCaseVariations(word string) []string {
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

// Load loads a wordlist by identifier (built-in name or file path)
func Load(listIdentifier string) ([]string, error) {
	var baseList []string
	if list, ok := DefaultLists[listIdentifier]; ok {
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
		variations := GenerateCaseVariations(word)
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

// Add adds a custom wordlist to the session
func Add(name string, words []string) {
	DefaultLists[name] = words
}

// List returns the names of all available wordlists
func List() []string {
	var names []string
	for name := range DefaultLists {
		names = append(names, name)
	}
	return names
}

// Get returns a wordlist by name
func Get(name string) ([]string, bool) {
	list, ok := DefaultLists[name]
	return list, ok
}