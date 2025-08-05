package scanner

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"firescan/internal/config"
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
}

// RunScan executes the scan with the given options
func RunScan(options ScanOptions) ([]types.Finding, error) {
	// Validate state
	state := config.GetState()
	if state.ProjectID == "" || state.Token == "" {
		return nil, fmt.Errorf("projectID and token must be set before scanning")
	}

	// Load wordlist
	wordlistItems, err := wordlist.Load(options.List)
	if err != nil {
		return nil, fmt.Errorf("error loading wordlist: %v", err)
	}

	// Setup worker pool
	jobs := make(chan types.Job, options.Concurrency)
	results := make(chan types.Finding)
	var wg sync.WaitGroup

	for i := 0; i < options.Concurrency; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
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
	var foundCount int32
	var checkedCount int64

	// Start progress monitoring
	done := make(chan bool)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		spinners := []rune{'|', '/', '-', '\\'}
		i := 0
		for {
			select {
			case finding, ok := <-results:
				if !ok {
					done <- true
					return
				}
				atomic.AddInt32(&foundCount, 1)
				if options.JSONOutput {
					findings = append(findings, finding)
				} else {
					fmt.Printf("\r%80s\r", "")
					printFinding(finding)
				}
			case <-ticker.C:
				if !options.JSONOutput {
					currentChecked := atomic.LoadInt64(&checkedCount)
					currentFound := atomic.LoadInt32(&foundCount)
					fmt.Printf("\r[%s%c%s] Scanning... [Checked: %d/%d | Found: %d]", 
						types.ColorCyan, spinners[i%len(spinners)], types.ColorReset, 
						currentChecked, totalChecks, currentFound)
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
				atomic.AddInt64(&checkedCount, 1)
			}
			if options.FirestoreTest {
				jobs <- types.Job{Type: "firestore", Path: item}
				atomic.AddInt64(&checkedCount, 1)
			}
			if options.FunctionsTest {
				for _, region := range FunctionRegions {
					jobs <- types.Job{Type: "function", Path: fmt.Sprintf("%s/%s", region, item)}
					atomic.AddInt64(&checkedCount, 1)
				}
			}
		}
		close(jobs)
	}()

	// Additional scans
	if options.StorageTest {
		wg.Add(1)
		go func() {
			CheckCloudStorage(results, &wg)
			atomic.AddInt64(&checkedCount, 1)
		}()
	}
	if options.HostingTest {
		wg.Add(1)
		go func() {
			CheckHostingConfig(results, &wg)
			atomic.AddInt64(&checkedCount, 1)
		}()
	}

	// Wait for completion
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	close(results)
	<-done

	return findings, nil
}

// worker processes jobs from the job channel
func worker(jobs <-chan types.Job, results chan<- types.Finding, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		switch job.Type {
		case "rtdb":
			CheckRTDB(job, results)
		case "firestore":
			CheckFirestore(job, results)
		case "function":
			CheckFunction(job, results)
		}
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