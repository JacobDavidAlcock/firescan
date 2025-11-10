package scanner

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"firescan/internal/config"
	"firescan/internal/logger"
	"firescan/internal/ratelimit"
	"firescan/internal/types"
	"firescan/internal/wordlist"
)

// FunctionRegions contains the Firebase function regions exactly as in original
var FunctionRegions = []string{"us-central1", "us-east1", "us-east4", "europe-west1", "europe-west2", "asia-east2", "asia-northeast1"}

// ScanOptions represents scan configuration options
type ScanOptions struct {
	List          string
	AllScan       bool
	RTDBTest      bool
	FirestoreTest bool
	StorageTest   bool
	FunctionsTest bool
	HostingTest   bool
	JSONOutput    bool
	Concurrency   int
	RateLimit     int // requests per second (0 = unlimited)
}

// RunScan executes the scan with the given options
func RunScan(options ScanOptions) ([]types.Finding, error) {
	startTime := time.Now()

	// Log scan start
	logger.Info("Starting scan: projectID=%s concurrency=%d rateLimit=%d/s",
		config.GetProjectID(), options.Concurrency, options.RateLimit)

	// Validate state
	state := config.GetState()
	if state.ProjectID == "" || state.Token == "" {
		logger.Error("Scan failed: projectID and token must be set")
		return nil, fmt.Errorf("projectID and token must be set before scanning")
	}

	// Load wordlist
	wordlistItems, err := wordlist.Load(options.List)
	if err != nil {
		logger.Error("Failed to load wordlist '%s': %v", options.List, err)
		return nil, fmt.Errorf("error loading wordlist: %v", err)
	}
	logger.Debug("Loaded wordlist '%s' with %d items", options.List, len(wordlistItems))

	// Setup rate limiter
	limiter := ratelimit.NewLimiter(options.RateLimit)
	ctx := context.Background()

	// Setup worker pool
	jobs := make(chan types.Job, options.Concurrency)
	results := make(chan types.Finding)
	errors := make(chan types.ScanError)
	var wg sync.WaitGroup
	var checkedCount int64
	var foundCount int32
	var errorCount int32

	for i := 0; i < options.Concurrency; i++ {
		wg.Add(1)
		go worker(jobs, results, errors, limiter, ctx, &wg, &checkedCount)
	}

	// Calculate total checks
	totalChecks := 0
	if options.RTDBTest {
		totalChecks += len(wordlistItems)
	}
	if options.FirestoreTest {
		totalChecks += len(wordlistItems)
	}
	if options.FunctionsTest {
		totalChecks += len(wordlistItems) * len(FunctionRegions)
	}
	if options.StorageTest {
		totalChecks++
	}
	if options.HostingTest {
		totalChecks++
	}

	findings := make([]types.Finding, 0)

	// Start progress monitoring
	done := make(chan bool)
	resultsOpen := true
	errorsOpen := true
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		spinners := []rune{'|', '/', '-', '\\'}
		i := 0
		for resultsOpen || errorsOpen {
			select {
			case finding, ok := <-results:
				if !ok {
					resultsOpen = false
					if !errorsOpen {
						done <- true
						return
					}
					continue
				}
				atomic.AddInt32(&foundCount, 1)
				findings = append(findings, finding)
				if !options.JSONOutput {
					fmt.Printf("\r%80s\r", "")
					printFinding(finding)
				}
			case scanErr, ok := <-errors:
				if !ok {
					errorsOpen = false
					if !resultsOpen {
						done <- true
						return
					}
					continue
				}
				atomic.AddInt32(&errorCount, 1)
				if !options.JSONOutput {
					// Show error briefly in status line
					fmt.Printf("\r%80s\r", "")
					fmt.Printf("%s[!] Error checking %s %s: %s%s\n",
						types.ColorYellow, scanErr.JobType, scanErr.Path, scanErr.Message, types.ColorReset)
				}
			case <-ticker.C:
				if !options.JSONOutput {
					currentChecked := atomic.LoadInt64(&checkedCount)
					currentFound := atomic.LoadInt32(&foundCount)
					currentErrors := atomic.LoadInt32(&errorCount)
					if currentErrors > 0 {
						fmt.Printf("\r[%s%c%s] Scanning... [Checked: %d/%d | Found: %d | Errors: %s%d%s]",
							types.ColorCyan, spinners[i%len(spinners)], types.ColorReset,
							currentChecked, totalChecks, currentFound,
							types.ColorYellow, currentErrors, types.ColorReset)
					} else {
						fmt.Printf("\r[%s%c%s] Scanning... [Checked: %d/%d | Found: %d]",
							types.ColorCyan, spinners[i%len(spinners)], types.ColorReset,
							currentChecked, totalChecks, currentFound)
					}
					i++
				}
			}
		}
	}()

	// Submit jobs
	go func() {
		for _, item := range wordlistItems {
			if options.RTDBTest {
				jobs <- types.Job{Type: "rtdb", Path: item}
			}
			if options.FirestoreTest {
				jobs <- types.Job{Type: "firestore", Path: item}
			}
			if options.FunctionsTest {
				for _, region := range FunctionRegions {
					jobs <- types.Job{Type: "function", Path: fmt.Sprintf("%s/%s", region, item)}
				}
			}
		}
		close(jobs)
	}()

	// Additional scans
	if options.StorageTest {
		wg.Add(1)
		go func() {
			CheckCloudStorage(results, errors, &wg)
			atomic.AddInt64(&checkedCount, 1)
		}()
	}
	if options.HostingTest {
		wg.Add(1)
		go func() {
			CheckHostingConfig(results, errors, &wg)
			atomic.AddInt64(&checkedCount, 1)
		}()
	}

	// Wait for completion
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	close(results)
	close(errors)
	<-done

	// Print summary with error count
	if !options.JSONOutput && errorCount > 0 {
		fmt.Printf("\n%s⚠️  Scan completed with %d errors%s\n",
			types.ColorYellow, errorCount, types.ColorReset)
	}

	// Log scan completion
	duration := time.Since(startTime)
	logger.Info("Scan completed: findings=%d errors=%d duration=%v", len(findings), errorCount, duration)

	// Log each finding
	for _, finding := range findings {
		logger.LogFinding(finding.Severity, finding.Type, finding.Path, finding.Status)
	}

	return findings, nil
}

// worker processes jobs from the job channel
func worker(jobs <-chan types.Job, results chan<- types.Finding, errors chan<- types.ScanError, limiter *ratelimit.Limiter, ctx context.Context, wg *sync.WaitGroup, checkedCount *int64) {
	defer wg.Done()
	for job := range jobs {
		// Apply rate limiting before each request
		if err := limiter.Wait(ctx); err != nil {
			// Context cancelled, stop processing
			return
		}

		switch job.Type {
		case "rtdb":
			CheckRTDB(job, results, errors)
		case "firestore":
			CheckFirestore(job, results, errors)
		case "function":
			CheckFunction(job, results, errors)
		}

		// Increment checked count after processing
		atomic.AddInt64(checkedCount, 1)
	}
}

// printFinding prints a finding in the original format
func printFinding(f types.Finding) {
	var severityColor string
	switch f.Severity {
	case "Critical":
		severityColor = types.ColorRed
	case "High":
		severityColor = types.ColorRed
	case "Medium":
		severityColor = types.ColorYellow
	default:
		severityColor = types.ColorCyan
	}

	fmt.Printf("\n[%s%s%s] %s%sVulnerability Found!%s\n  ├── Timestamp: %s\n  ├── Severity:  %s%s%s\n  ├── Type:      %s\n  └── Path:      %s\n",
		types.ColorRed, types.ColorBold, f.Type, types.ColorGreen, types.ColorBold, types.ColorReset,
		f.Timestamp,
		severityColor, f.Severity, types.ColorReset,
		f.Type,
		f.Path,
	)
}
