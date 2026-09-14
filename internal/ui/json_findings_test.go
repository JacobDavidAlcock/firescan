package ui

import (
	"errors"
	"testing"

	"firescan/internal/appcheck"
	"firescan/internal/auth"
	"firescan/internal/storage"
	"firescan/internal/types"
)

func TestRulesFindings(t *testing.T) {
	results := []types.RuleTestResult{
		{TestCase: types.RuleTestCase{Path: "ok", Expected: true}, Actual: true},                     // matched, no finding
		{TestCase: types.RuleTestCase{Path: "leaky", Expected: false}, Actual: true},                  // unexpectedly allowed -> High
		{TestCase: types.RuleTestCase{Path: "overblocked", Expected: true}, Actual: false},            // unexpectedly denied -> Medium
		{TestCase: types.RuleTestCase{Path: "errored", Expected: false}, Actual: true, Error: errBoom}, // error -> excluded
	}

	findings := rulesFindings(results)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	if findings[0].Path != "leaky" || findings[0].Severity != "High" {
		t.Errorf("unexpected allow should be High severity, got %+v", findings[0])
	}
	if findings[1].Path != "overblocked" || findings[1].Severity != "Medium" {
		t.Errorf("unexpected deny should be Medium severity, got %+v", findings[1])
	}
}

func TestWriteFindings(t *testing.T) {
	results := []types.WriteTestResult{
		{TestCase: types.WriteTestCase{Path: "blocked", Service: "rtdb"}, Success: false},
		{TestCase: types.WriteTestCase{Path: "writable", Service: "firestore"}, Success: true},
		{TestCase: types.WriteTestCase{Path: "errored", Service: "storage"}, Success: true, Error: errBoom},
	}

	findings := writeFindings(results)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Path != "writable" || findings[0].Type != "WriteAccess" || findings[0].Severity != "High" {
		t.Errorf("unexpected finding: %+v", findings[0])
	}
}

func TestServicesFindings(t *testing.T) {
	results := []types.ServiceEnumResult{
		{Service: "firestore", Endpoint: "https://x/firestore", Accessible: false},
		{Service: "rtdb", Endpoint: "https://x/rtdb", Accessible: true, HasData: false},
		{Service: "storage", Endpoint: "https://x/storage", Accessible: true, HasData: true},
	}

	findings := servicesFindings(results)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "Medium" {
		t.Errorf("accessible-without-data should be Medium, got %+v", findings[0])
	}
	if findings[1].Severity != "High" {
		t.Errorf("accessible-with-data should be High, got %+v", findings[1])
	}
}

func TestAppCheckFindings(t *testing.T) {
	results := []appcheck.Result{
		{Provider: "enforced", Enabled: true, HasDebugMode: false},
		{Provider: "not-enforced", Enabled: false},
		{Provider: "debug-mode", Enabled: true, HasDebugMode: true},
	}

	findings := appCheckFindings(results)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	if findings[1].Severity != "High" {
		t.Errorf("debug mode should be High severity, got %+v", findings[1])
	}
}

func TestAuthAttackFindings(t *testing.T) {
	results := []auth.AttackResult{
		{Attack: "failed-attack", Successful: false},
		{Attack: "successful-attack", Successful: true},
	}

	findings := authAttackFindings(results)
	if len(findings) != 1 || findings[0].Path != "successful-attack" {
		t.Fatalf("expected only the successful attack to be reported, got %+v", findings)
	}
}

func TestStorageSecFindings(t *testing.T) {
	results := []storage.StorageSecurityResult{
		{Bucket: "b1", Finding: "", Severity: ""},
		{Bucket: "b1", Path: "cors", Finding: "wildcard CORS origin", Severity: "High"},
	}

	findings := storageSecFindings(results)
	if len(findings) != 1 || findings[0].Path != "cors" || findings[0].Severity != "High" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

var errBoom = errors.New("boom")
