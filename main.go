// HeaderGuard — a web security header analysis tool.
//
// Usage:
//
//	headerguard                    start the web UI (default 127.0.0.1:8080)
//	headerguard scan <target> ...  run a scan from the terminal
//	headerguard version            print the version
//	headerguard help               print this help
//
// Authorized testing only — use on systems you own or have permission to test.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jacktekno/headerguard/internal/api"
	"github.com/jacktekno/headerguard/internal/cli"
	"github.com/jacktekno/headerguard/internal/scanner"
)

const usageText = `HeaderGuard — web security header analysis (v` + scanner.Version + `)

Usage:
  headerguard                        start the web UI (default 127.0.0.1:8080)
  headerguard serve [flags]          start the web UI with explicit options
  headerguard scan <target> [flags]  run a scan from the terminal
  headerguard version                print the version
  headerguard help                   print this help

Examples:
  headerguard scan example.com
  headerguard scan subdomain.example.com --json
  headerguard scan --batch targets.txt --workers 10 --output report.txt

Authorized testing only — use on systems you own or have permission to test.
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		return serveCmd(nil)
	}
	switch args[0] {
	case "scan":
		return scanCmd(args[1:])
	case "serve":
		return serveCmd(args[1:])
	case "version", "-v", "--version":
		fmt.Println("HeaderGuard v" + scanner.Version)
		return 0
	case "help", "-h", "--help":
		fmt.Print(usageText)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n", args[0])
		fmt.Print(usageText)
		return 2
	}
}

const scanUsage = `Usage: headerguard scan <target> [flags]

Flags:
  --json                  JSON output
  --output FILE           write the report to FILE
  --timeout SECONDS       per-phase timeout (default 30)
  --follow-redirects      follow redirects, max 10 hops (default true; disable with --follow-redirects=false)
  --no-color              disable ANSI colors
  --batch FILE            file with one target per line (# starts a comment)
  --workers N             parallel workers for --batch (default 5)
  --scheme auto|https|http  scheme when the target has none (default auto: try https, then http)
`

func scanCmd(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "JSON output")
	output := fs.String("output", "", "write the report to FILE")
	timeoutS := fs.Int("timeout", 30, "per-phase timeout in seconds")
	follow := fs.Bool("follow-redirects", true, "follow redirects")
	noColor := fs.Bool("no-color", false, "disable ANSI colors")
	batchFile := fs.String("batch", "", "file with a list of targets")
	workers := fs.Int("workers", 5, "number of parallel workers")
	scheme := fs.String("scheme", "auto", "auto|https|http")

	// flag.FlagSet stops at the first positional argument, so split flags
	// and targets manually to allow `scan <target> --json`.
	flagArgs, rest := splitFlags(args, map[string]bool{
		"--output": true, "--timeout": true, "--batch": true,
		"--workers": true, "--scheme": true,
	})
	if err := fs.Parse(flagArgs); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, scanUsage)
		return 2
	}
	if len(rest) == 0 && *batchFile == "" {
		fmt.Fprintf(os.Stderr, "error: a target or --batch is required\n\n%s", scanUsage)
		return 2
	}
	if *timeoutS < 1 {
		*timeoutS = 1
	}

	opts := scanner.Options{
		Timeout:         time.Duration(*timeoutS) * time.Second,
		FollowRedirects: *follow,
	}
	switch *scheme {
	case "auto":
		opts.AllowHTTPFallback = true
	case "https", "http":
		opts.AllowHTTPFallback = false
	default:
		fmt.Fprintf(os.Stderr, "error: --scheme must be auto|https|http\n")
		return 2
	}

	w := io.Writer(os.Stdout)
	var f *os.File
	if *output != "" {
		var err error
		f, err = os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot write %s: %v\n", *output, err)
			return 1
		}
		defer f.Close()
		w = f
	}
	c := cli.Color{Enabled: !*noColor && *output == "" && cli.IsTerminal()}

	if *batchFile != "" {
		targets, err := readTargets(*batchFile, *scheme)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return cli.RunBatch(targets, opts, *workers, *jsonOut, c, w)
	}

	res := scanner.Scan(normalizeScheme(rest[0], *scheme), opts)
	if *jsonOut {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Fprintln(w, string(b))
	} else {
		cli.PrintReport(res, c, w)
	}
	if res.Meta.Status == scanner.StatusError {
		return 1
	}
	return 0
}

func serveCmd(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", "127.0.0.1:8080", "bind address (use 0.0.0.0:8080 to expose it, e.g. inside Docker)")
	timeoutS := fs.Int("scan-timeout", 30, "scan timeout per request (seconds)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\nUsage: headerguard serve [--addr ADDRESS] [--scan-timeout SECONDS]\n", err)
		return 2
	}
	return api.Serve(*addr, time.Duration(*timeoutS)*time.Second)
}

// splitFlags separates flag arguments (including their values) from
// positional arguments, so flags may appear before or after the target.
func splitFlags(args []string, valueFlags map[string]bool) (flags, pos []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		flags = append(flags, a)
		name := a
		if eq := strings.Index(a, "="); eq >= 0 {
			name = a[:eq]
		}
		if valueFlags[name] && !strings.Contains(a, "=") && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return flags, pos
}

// hasScheme reports whether the target already carries a scheme.
func hasScheme(t string) bool {
	return strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://")
}

// normalizeScheme applies the requested --scheme to targets without one.
func normalizeScheme(target, scheme string) string {
	t := strings.TrimSpace(target)
	if hasScheme(t) {
		return t
	}
	switch scheme {
	case "http":
		return "http://" + t
	case "https":
		return "https://" + t
	default:
		return t // FetchChain tries https first, then http
	}
}

// readTargets reads a target list from a file, skipping blank lines and
// lines starting with #.
func readTargets(path, scheme string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, normalizeScheme(line, scheme))
	}
	return targets, sc.Err()
}
