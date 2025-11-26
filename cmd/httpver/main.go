package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"check_http_versions/internal/httpver"
)

func gatherTargets(targetsFlag, targetsFile string, positional []string) ([]string, error) {
	var targets []string

	// From file (one per line, ignore blanks and lines starting with '#')
	if targetsFile != "" {
		data, err := os.ReadFile(targetsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read targets file: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			targets = append(targets, line)
		}
	}

	// From --targets comma-separated flag
	if targetsFlag != "" {
		for _, part := range strings.Split(targetsFlag, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			targets = append(targets, part)
		}
	}

	// From positional args
	targets = append(targets, positional...)

	// Optional: dedupe while preserving order
	seen := make(map[string]struct{}, len(targets))
	deduped := make([]string, 0, len(targets))
	for _, t := range targets {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		deduped = append(deduped, t)
	}

	return deduped, nil
}

func main() {
	portFlag := flag.Int("port", 0, "port to test (default 443 for https, 80 for http)")
	jsonFlag := flag.Bool("json", false, "output results as JSON")
	targetsFlag := flag.String("targets", "", "comma-separated list of targets (e.g. \"a.com,b.com\")")
	targetsFile := flag.String("targets-file", "", "path to file containing targets (one per line)")

	webFlag := flag.Bool("web", false, "run in web server mode")
	listenAddr := flag.String("listen", ":8080", "address to listen on in web mode (e.g. \":8080\")")
	flag.Parse()

	if *webFlag {
		if err := runWebServer(*listenAddr); err != nil {
			fmt.Fprintf(os.Stderr, "web server error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	positional := flag.Args()

	targets, err := gatherTargets(*targetsFlag, *targetsFile, positional)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(targets) == 0 {
		fmt.Println("Usage: httpver [-port N] [--json] [--targets a.com,b.com] [--targets-file file] <domain-or-url> ...")
		fmt.Println("       httpver --web [--listen :8080]")
		fmt.Println("Example: httpver cloudflare.com")
		fmt.Println("Example: httpver -port 8080 localhost")
		fmt.Println("Example: httpver --json cloudflare.com example.org")
		fmt.Println("Example: httpver --targets cloudflare.com,example.com --json")
		fmt.Println("Example: httpver --targets-file targets.txt --json")
		os.Exit(1)
	}

	// Suppress noisy logs from dependencies (e.g. quic-go UDP buffer warnings).
	log.SetOutput(io.Discard)

	overridePort := ""
	if *portFlag > 0 {
		overridePort = strconv.Itoa(*portFlag)
	}

	// Quick summary so it is obvious something is happening.
	fmt.Fprintf(os.Stderr,
		"Scanning %d host(s)... (✅ supported, ❌ not supported, 🟧 error/probe failed)\n\n",
		len(targets),
	)

	start := time.Now()

	if *jsonFlag {
		if len(targets) == 1 {
			res := httpver.CheckHTTPVersionsJSON(targets[0], overridePort)
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(res); err != nil {
				fmt.Fprintf(os.Stderr, "failed to encode JSON: %v\n", err)
				os.Exit(1)
			}
		} else {
			res := httpver.CheckHTTPVersionsJSONMulti(targets, overridePort)
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(res); err != nil {
				fmt.Fprintf(os.Stderr, "failed to encode JSON: %v\n", err)
				os.Exit(1)
			}
		}

		// Print timing summary to stderr so JSON on stdout remains clean.
		elapsed := time.Since(start)
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "Scanned %d host(s) in %s\n", len(targets), elapsed.Truncate(time.Millisecond))
	} else {
		if len(targets) == 1 {
			httpver.CheckHTTPVersions(targets[0], overridePort)
		} else {
			httpver.CheckHTTPVersionsMulti(targets, overridePort)
		}

		// Human-readable summary on stdout.
		elapsed := time.Since(start)
		fmt.Println()
		fmt.Printf("Scanned %d host(s) in %s\n", len(targets), elapsed.Truncate(time.Millisecond))
	}
}
