package services

import (
	"fmt"
	"net/http"
	"time"

	"firescan/internal/auth"
	"firescan/internal/config"
	"firescan/internal/safety"
	"firescan/internal/types"
)

// FirebaseService represents a Firebase service configuration
type FirebaseService struct {
	Name        string
	ProbeURL    string // URL for probe mode (just check existence)
	TestURL     string // URL for test mode (read data)
	AuditURL    string // URL for audit mode (deep analysis)
	Description string
	SafetyLevel types.ScanMode // Minimum safety level required
}

// GetFirebaseServices returns list of Firebase services to test
func GetFirebaseServices() []FirebaseService {
	return []FirebaseService{
		{
			Name:        "Remote Config",
			ProbeURL:    "https://firebaseremoteconfig.googleapis.com/v1/projects/{projectId}",
			TestURL:     "https://firebaseremoteconfig.googleapis.com/v1/projects/{projectId}/remoteConfig",
			AuditURL:    "https://firebaseremoteconfig.googleapis.com/v1/projects/{projectId}/remoteConfig?evaluateConditions=true",
			Description: "Firebase Remote Configuration service",
			SafetyLevel: types.ProbeMode,
		},
		{
			Name:        "Dynamic Links",
			ProbeURL:    "https://firebasedynamiclinks.googleapis.com/v1/projects/{projectId}",
			TestURL:     "https://firebasedynamiclinks.googleapis.com/v1/projects/{projectId}/shortLinks",
			AuditURL:    "https://firebasedynamiclinks.googleapis.com/v1/projects/{projectId}/shortLinks?dynamicLinkInfo.link=test",
			Description: "Firebase Dynamic Links service",
			SafetyLevel: types.ProbeMode,
		},
		{
			Name:        "Extensions",
			ProbeURL:    "https://firebase.googleapis.com/v1beta/projects/{projectId}",
			TestURL:     "https://firebase.googleapis.com/v1beta/projects/{projectId}/extensions",
			AuditURL:    "https://firebase.googleapis.com/v1beta/projects/{projectId}/extensions?detailed=true",
			Description: "Firebase Extensions marketplace",
			SafetyLevel: types.ProbeMode,
		},
		{
			Name:        "Performance Monitoring",
			ProbeURL:    "https://firebaseperformance.googleapis.com/v1/projects/{projectId}",
			TestURL:     "https://firebaseperformance.googleapis.com/v1/projects/{projectId}/traces",
			AuditURL:    "https://firebaseperformance.googleapis.com/v1/projects/{projectId}/traces?detailed=true",
			Description: "Firebase Performance Monitoring",
			SafetyLevel: types.TestMode, // Requires authentication to access data
		},
		{
			Name:        "Crashlytics",
			ProbeURL:    "https://firebasecrashlytics.googleapis.com/v1/projects/{projectId}",
			TestURL:     "https://firebasecrashlytics.googleapis.com/v1/projects/{projectId}/crashes",
			AuditURL:    "https://firebasecrashlytics.googleapis.com/v1/projects/{projectId}/crashes?includeStackTrace=true",
			Description: "Firebase Crashlytics crash reporting",
			SafetyLevel: types.TestMode,
		},
		{
			Name:        "Cloud Messaging",
			ProbeURL:    "https://fcm.googleapis.com/v1/projects/{projectId}",
			TestURL:     "https://fcm.googleapis.com/v1/projects/{projectId}/messages:validate",
			AuditURL:    "https://fcm.googleapis.com/v1/projects/{projectId}/messages:send",
			Description: "Firebase Cloud Messaging (FCM)",
			SafetyLevel: types.AuditMode, // Send endpoint could be dangerous
		},
		{
			Name:        "A/B Testing",
			ProbeURL:    "https://firebaseabtesting.googleapis.com/v1/projects/{projectId}",
			TestURL:     "https://firebaseabtesting.googleapis.com/v1/projects/{projectId}/experiments",
			AuditURL:    "https://firebaseabtesting.googleapis.com/v1/projects/{projectId}/experiments?includeInactive=true",
			Description: "Firebase A/B Testing experiments",
			SafetyLevel: types.TestMode,
		},
		{
			Name:        "In-App Messaging",
			ProbeURL:    "https://firebaseinappmessaging.googleapis.com/v1/projects/{projectId}",
			TestURL:     "https://firebaseinappmessaging.googleapis.com/v1/projects/{projectId}/inappMessages",
			AuditURL:    "https://firebaseinappmessaging.googleapis.com/v1/projects/{projectId}/inappMessages?includeArchived=true",
			Description: "Firebase In-App Messaging campaigns",
			SafetyLevel: types.TestMode,
		},
	}
}

// EnumerateServices discovers and tests Firebase services
func EnumerateServices(mode types.ScanMode, serviceNames []string) ([]types.ServiceEnumResult, error) {
	// Warn user about the scan mode
	if !safety.WarnUser(mode) {
		return nil, fmt.Errorf("user declined to proceed with %s mode", mode.String())
	}
	
	var results []types.ServiceEnumResult
	services := GetFirebaseServices()
	state := config.GetState()
	
	// Filter services if specific names provided
	if len(serviceNames) > 0 {
		services = filterServices(services, serviceNames)
	}
	
	// Test each service
	for _, service := range services {
		// Skip services that require higher safety level
		if mode < service.SafetyLevel {
			continue
		}
		
		result := testService(service, mode, state)
		results = append(results, result)
	}
	
	return results, nil
}

// filterServices filters services by name
func filterServices(services []FirebaseService, names []string) []FirebaseService {
	var filtered []FirebaseService
	nameMap := make(map[string]bool)
	
	for _, name := range names {
		nameMap[name] = true
	}
	
	for _, service := range services {
		if nameMap[service.Name] {
			filtered = append(filtered, service)
		}
	}
	
	return filtered
}

// testService tests a specific Firebase service
func testService(service FirebaseService, mode types.ScanMode, state types.State) types.ServiceEnumResult {
	result := types.ServiceEnumResult{
		Service:     service.Name,
		SafetyLevel: mode,
	}
	
	// Choose appropriate URL based on mode
	var testURL string
	switch mode {
	case types.ProbeMode:
		testURL = service.ProbeURL
	case types.TestMode:
		if service.TestURL != "" {
			testURL = service.TestURL
		} else {
			testURL = service.ProbeURL
		}
	case types.AuditMode:
		if service.AuditURL != "" {
			testURL = service.AuditURL
		} else if service.TestURL != "" {
			testURL = service.TestURL
		} else {
			testURL = service.ProbeURL
		}
	}
	
	// Replace project ID placeholder
	testURL = replaceProjectID(testURL, state.ProjectID)
	result.Endpoint = testURL
	
	// Make the request
	switch mode {
	case types.ProbeMode:
		result = probeService(result, testURL)
	case types.TestMode, types.AuditMode:
		result = testServiceWithAuth(result, testURL, state)
	}
	
	return result
}

// probeService performs a safe probe of the service (no authentication)
func probeService(result types.ServiceEnumResult, url string) types.ServiceEnumResult {
	client := &http.Client{Timeout: 10 * time.Second}
	
	resp, err := client.Head(url) // Use HEAD to avoid downloading data
	if err != nil {
		result.Error = err
		result.Accessible = false
		return result
	}
	defer resp.Body.Close()
	
	// Service is accessible if we get any response (even 401/403)
	result.Accessible = resp.StatusCode < 500
	result.HasData = resp.StatusCode == 200
	
	return result
}

// testServiceWithAuth performs authenticated testing of the service
func testServiceWithAuth(result types.ServiceEnumResult, url string, state types.State) types.ServiceEnumResult {
	// Use authenticated request
	resp, err := auth.MakeAuthenticatedRequest("GET", url, state.Token, state.Email, state.Password, state.APIKey, config.UpdateTokenInfo)
	if err != nil {
		result.Error = err
		result.Accessible = false
		return result
	}
	defer resp.Body.Close()
	
	result.Accessible = true
	result.HasData = resp.StatusCode == 200
	
	// For test/audit mode, we can read some data (safely)
	if resp.StatusCode == 200 {
		// In a real implementation, we'd parse the response
		// For now, just indicate that data was found
		result.DataSample = map[string]interface{}{
			"status":      "data_found",
			"status_code": resp.StatusCode,
			"service":     result.Service,
		}
	}
	
	return result
}

// replaceProjectID replaces {projectId} placeholder in URLs
func replaceProjectID(url, projectID string) string {
	return fmt.Sprintf(url, projectID)
}

// GetServiceByName returns a specific service configuration by name
func GetServiceByName(name string) (FirebaseService, bool) {
	services := GetFirebaseServices()
	for _, service := range services {
		if service.Name == name {
			return service, true
		}
	}
	return FirebaseService{}, false
}