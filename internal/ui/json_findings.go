package ui

import (
	"fmt"
	"time"

	"firescan/internal/appcheck"
	"firescan/internal/auth"
	"firescan/internal/fcm"
	"firescan/internal/management"
	"firescan/internal/rtdb"
	"firescan/internal/storage"
	"firescan/internal/types"
	"firescan/internal/unauth"
)

// The "advanced" scan modules (rules, write, services, appcheck, authattack,
// unauth, storage-sec, mgmt-api, rtdb-advanced, fcm) each have their own
// result struct and only ever get printed as text, gated behind
// `if !*jsonOutput`. Under --json those results were silently dropped
// entirely -- these converters turn each module's notable results into
// types.Finding so --json can include everything scan --all actually found,
// not just the traditional RTDB/Firestore/Storage/Functions/Hosting checks.

func newFinding(findingType, path, status, severity string) types.Finding {
	return types.Finding{
		Timestamp: time.Now().Format(time.RFC3339),
		Severity:  severity,
		Type:      findingType,
		Path:      path,
		Status:    status,
	}
}

// rulesFindings reports rule tests whose actual behavior didn't match what
// was expected -- either direction is a correctness problem worth flagging,
// but a rule that unexpectedly ALLOWED access is the more severe case.
func rulesFindings(results []types.RuleTestResult) []types.Finding {
	var findings []types.Finding
	for _, r := range results {
		if r.Error != nil || r.TestCase.Expected == r.Actual {
			continue
		}
		severity := "Medium"
		if !r.TestCase.Expected && r.Actual {
			severity = "High"
		}
		status := fmt.Sprintf("%s: expected=%v actual=%v", r.TestCase.Operation, r.TestCase.Expected, r.Actual)
		findings = append(findings, newFinding("Rules", r.TestCase.Path, status, severity))
	}
	return findings
}

// writeFindings reports write attempts that succeeded -- a successful write
// during write-access testing means the target was writable when it was
// being tested specifically to see whether it should be.
func writeFindings(results []types.WriteTestResult) []types.Finding {
	var findings []types.Finding
	for _, r := range results {
		if r.Error != nil || !r.Success {
			continue
		}
		status := fmt.Sprintf("%s write allowed (%s)", r.TestCase.Operation, r.TestCase.Service)
		findings = append(findings, newFinding("WriteAccess", r.TestCase.Path, status, "High"))
	}
	return findings
}

// servicesFindings reports Firebase service endpoints that responded as
// accessible during enumeration.
func servicesFindings(results []types.ServiceEnumResult) []types.Finding {
	var findings []types.Finding
	for _, r := range results {
		if r.Error != nil || !r.Accessible {
			continue
		}
		severity, status := "Medium", "Accessible"
		if r.HasData {
			severity, status = "High", "Accessible with data"
		}
		path := r.Endpoint
		if path == "" {
			path = r.Service
		}
		findings = append(findings, newFinding("ServiceEnum", path, status, severity))
	}
	return findings
}

// appCheckFindings reports providers that aren't enforced, or that have
// debug mode active.
func appCheckFindings(results []appcheck.Result) []types.Finding {
	var findings []types.Finding
	for _, r := range results {
		if r.Error != nil || (r.Enabled && !r.HasDebugMode) {
			continue
		}
		severity := "Medium"
		status := "App Check not enforced"
		if r.HasDebugMode {
			severity = "High"
			status = "App Check debug mode active"
		}
		findings = append(findings, newFinding("AppCheck", r.Provider, status, severity))
	}
	return findings
}

// authAttackFindings reports authentication attacks that succeeded.
func authAttackFindings(results []auth.AttackResult) []types.Finding {
	var findings []types.Finding
	for _, r := range results {
		if r.Error != nil || !r.Successful {
			continue
		}
		findings = append(findings, newFinding("AuthAttack", r.Attack, "Attack succeeded", "High"))
	}
	return findings
}

// unauthFindings reports endpoints reachable without authentication.
func unauthFindings(results []unauth.UnauthTestResult) []types.Finding {
	var findings []types.Finding
	for _, r := range results {
		if r.Error != nil || !r.Accessible {
			continue
		}
		severity, status := "Medium", "Accessible"
		if r.HasData {
			severity, status = "High", "Accessible with data"
		}
		findings = append(findings, newFinding("Unauth", r.Endpoint, status, severity))
	}
	return findings
}

// storageSecFindings, managementFindings, rtdbAdvancedFindings and
// fcmFindings all follow the same "Finding != "" && Severity != """
// convention commands.go already uses to count these modules' results.

func storageSecFindings(results []storage.StorageSecurityResult) []types.Finding {
	var findings []types.Finding
	for _, r := range results {
		if r.Finding == "" || r.Severity == "" {
			continue
		}
		path := r.Path
		if path == "" {
			path = r.Bucket
		}
		findings = append(findings, newFinding("StorageSecurity", path, r.Finding, r.Severity))
	}
	return findings
}

func managementFindings(results []management.ManagementSecurityResult) []types.Finding {
	var findings []types.Finding
	for _, r := range results {
		if r.Finding == "" || r.Severity == "" {
			continue
		}
		findings = append(findings, newFinding("Management", r.Endpoint, r.Finding, r.Severity))
	}
	return findings
}

func rtdbAdvancedFindings(results []rtdb.RTDBAdvancedResult) []types.Finding {
	var findings []types.Finding
	for _, r := range results {
		if r.Finding == "" || r.Severity == "" {
			continue
		}
		findings = append(findings, newFinding("RTDBAdvanced", r.Path, r.Finding, r.Severity))
	}
	return findings
}

func fcmFindings(results []fcm.FCMSecurityResult) []types.Finding {
	var findings []types.Finding
	for _, r := range results {
		if r.Finding == "" || r.Severity == "" {
			continue
		}
		findings = append(findings, newFinding("FCM", r.Endpoint, r.Finding, r.Severity))
	}
	return findings
}
