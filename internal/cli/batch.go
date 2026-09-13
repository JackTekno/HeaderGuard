package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/jacktekno/headerguard/internal/scanner"
)

// RunBatch scans many targets with a worker pool. Output is NDJSON (when
// jsonOut is set) or summary lines. Returns an exit code: 0 if at least one
// target succeeded, 1 if all failed.
func RunBatch(targets []string, opts scanner.Options, workers int, jsonOut bool, c Color, w io.Writer) int {
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	okCount := 0
	failCount := 0
	grades := map[string]int{}

	emit := func(target string, res *scanner.Result, err error) {
		mu.Lock()
		defer mu.Unlock()
		if jsonOut {
			out := map[string]any{"target": target}
			if err != nil {
				out["error"] = err.Error()
			} else {
				out["result"] = res
			}
			b, merr := json.Marshal(out)
			if merr != nil {
				b, _ = json.Marshal(map[string]any{"target": target, "error": "marshal failure"})
			}
			fmt.Fprintln(w, string(b))
			return
		}
		if err != nil {
			failCount++
			fmt.Fprintf(w, "%-50s %s\n", target, c.Red("FAILED: "+err.Error()))
			return
		}
		okCount++
		grades[res.Grade.Letter]++
		fmt.Fprintln(w, SummaryLine(target, res, c))
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				res := scanner.Scan(t, opts)
				var err error
				if res.Meta.Status == scanner.StatusError {
					err = errors.New(res.Meta.Error)
				}
				emit(t, res, err)
			}
		}()
	}
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()

	if !jsonOut && len(targets) > 0 {
		fmt.Fprintf(w, "\nSummary: %d succeeded, %d failed\n", okCount, failCount)
		if okCount > 0 {
			order := []string{"A+", "A", "B", "C", "D", "E", "F", "-"}
			var dist []string
			for _, g := range order {
				if n := grades[g]; n > 0 {
					dist = append(dist, fmt.Sprintf("%s: %d", g, n))
				}
			}
			fmt.Fprintf(w, "Grade distribution: %s\n", strings.Join(dist, ", "))
		}
	}
	if okCount == 0 {
		return 1
	}
	return 0
}
