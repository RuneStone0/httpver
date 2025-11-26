package httpver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

const (
	h1Timeout = 2 * time.Second
	h2Timeout = 2 * time.Second
	h3Timeout = 3 * time.Second
)

// normalizeURL ensures the input has a scheme and host and defaults to https.
func normalizeURL(raw string) (string, error) {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host == "" {
		return "", fmt.Errorf("missing host in URL")
	}
	return u.String(), nil
}

// VersionResult captures the outcome for a single HTTP version.
type VersionResult struct {
	Version   string `json:"version"`
	Supported bool   `json:"supported"`
	Detail    string `json:"detail,omitempty"`
	Error     bool   `json:"error,omitempty"`
}

// CheckResult is the full structured result for a run.
type CheckResult struct {
	Target  string          `json:"target"`
	URL     string          `json:"url"`
	Port    string          `json:"port"`
	Results []VersionResult `json:"results"`
}

// statusEmoji maps a VersionResult to a simple emoji for quick visual scanning.
// ✅ = supported, ❌ = not supported, 🟧 = error / probe failed.
func statusEmoji(vr VersionResult) string {
	if vr.Supported {
		return "✅"
	}
	if vr.Error {
		return "🟧"
	}
	return "❌"
}

// runChecks performs the actual HTTP version checks and returns a structured result.
// It does not print anything, so it can be used for both text and JSON output.
func runChecks(target string, overridePort string) CheckResult {
	res := CheckResult{
		Target:  target,
		Results: make([]VersionResult, 0, 4),
	}

	norm, err := normalizeURL(target)
	if err != nil {
		res.Results = append(res.Results, VersionResult{
			Version:   "error",
			Supported: false,
			Error:     true,
			Detail:    fmt.Sprintf("invalid URL: %v", err),
		})
		return res
	}

	// Work out the TCP/UDP port we are targeting.
	u, err := url.Parse(norm)
	if err != nil {
		res.Results = append(res.Results, VersionResult{
			Version:   "error",
			Supported: false,
			Error:     true,
			Detail:    fmt.Sprintf("invalid URL after normalization: %v", err),
		})
		return res
	}

	// If the user supplied a port flag, that takes precedence.
	port := overridePort
	if port == "" {
		port = u.Port()
	}
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			// Default HTTPS / QUIC port
			port = "443"
		}
	}
	res.Port = port

	// Make sure the URL we use for all requests has the explicit port we’re testing.
	host := u.Host
	if h, _, err := net.SplitHostPort(u.Host); err == nil {
		host = h
	}
	if host != "" {
		u.Host = net.JoinHostPort(host, port)
	}
	urlWithPort := u.String()
	res.URL = urlWithPort

	// For HTTP/1.0, many servers only support plain HTTP on port 80.
	// Use http://host:portForH10 where portForH10 defaults to 80 unless overridden.
	http10Port := overridePort
	if http10Port == "" {
		http10Port = "80"
	}
	http10URL := urlWithPort
	if host != "" {
		http10URL = "http://" + net.JoinHostPort(host, http10Port)
	}

	// Shared TLS config and clients per target.
	baseTLS := &tls.Config{InsecureSkipVerify: true}

	h1Transport := &http.Transport{
		ForceAttemptHTTP2: false,
		TLSClientConfig:   baseTLS,
	}
	h1Client := &http.Client{
		Timeout:   h1Timeout,
		Transport: h1Transport,
	}

	h2Transport := &http.Transport{
		TLSClientConfig: baseTLS,
	}
	h2Client := &http.Client{
		Timeout:   h2Timeout,
		Transport: h2Transport,
	}

	h3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			NextProtos:         []string{http3.NextProtoH3},
			InsecureSkipVerify: true,
		},
	}
	defer h3Transport.Close()

	h3Client := &http.Client{
		Transport: h3Transport,
		Timeout:   h3Timeout,
	}

	results := make([]VersionResult, 4)
	var wg sync.WaitGroup
	wg.Add(4)

	// 1) HTTP/1.0
	go func() {
		defer wg.Done()
		v10 := VersionResult{Version: "HTTP/1.0"}
		req10, err := http.NewRequest("GET", http10URL, nil)
		if err != nil {
			v10.Error = true
			v10.Detail = "request build failed"
		} else {
			req10.Proto = "HTTP/1.0"
			req10.ProtoMajor = 1
			req10.ProtoMinor = 0

			resp10, err := h1Client.Do(req10)
			if err != nil {
				v10.Error = true
				v10.Detail = fmt.Sprintf("not supported (or probe failed): %v", err)
			} else {
				defer resp10.Body.Close()
				// If the server speaks any HTTP/1.x in response to a 1.0 request,
				// we treat that as HTTP/1.0 support, even if it replies with 1.1.
				if resp10.ProtoMajor == 1 {
					v10.Supported = true
					if resp10.ProtoMinor == 0 {
						v10.Detail = "supported"
					} else {
						v10.Detail = fmt.Sprintf("replied with %s", resp10.Proto)
					}
				} else {
					v10.Detail = fmt.Sprintf("server replied with %s", resp10.Proto)
				}
			}
		}
		results[0] = v10
	}()

	// 2) HTTP/1.1
	go func() {
		defer wg.Done()
		v11 := VersionResult{Version: "HTTP/1.1"}
		req11, err := http.NewRequest("GET", urlWithPort, nil)
		if err != nil {
			v11.Error = true
			v11.Detail = "request build failed"
		} else {
			req11.Proto = "HTTP/1.1"
			req11.ProtoMajor = 1
			req11.ProtoMinor = 1

			resp11, err := h1Client.Do(req11)
			if err != nil {
				v11.Error = true
				v11.Detail = fmt.Sprintf("not supported (or probe failed): %v", err)
			} else {
				defer resp11.Body.Close()
				if resp11.ProtoMajor == 1 && resp11.ProtoMinor == 1 {
					v11.Supported = true
					v11.Detail = "supported"
				} else {
					v11.Detail = fmt.Sprintf("server replied with %s", resp11.Proto)
				}
			}
		}
		results[1] = v11
	}()

	// 3) HTTP/2.0 (best-effort: let TLS ALPN negotiate)
	go func() {
		defer wg.Done()
		v2 := VersionResult{Version: "HTTP/2.0"}
		resp2, err := h2Client.Get(urlWithPort)
		if err != nil {
			v2.Error = true
			v2.Detail = fmt.Sprintf("not supported (or probe failed): %v", err)
		} else {
			defer resp2.Body.Close()
			if resp2.ProtoMajor == 2 {
				v2.Supported = true
				v2.Detail = "supported"
			} else {
				v2.Detail = fmt.Sprintf("server replied with %s", resp2.Proto)
			}
		}
		results[2] = v2
	}()

	// 4) HTTP/3.0
	go func() {
		defer wg.Done()
		v3 := VersionResult{Version: "HTTP/3.0"}
		req3, err := http.NewRequest("GET", urlWithPort, nil)
		if err != nil {
			// Building the request itself failed: treat as a hard error.
			v3.Error = true
			v3.Detail = "request build failed"
		} else {
			ctx3, cancel3 := context.WithTimeout(context.Background(), h3Timeout)
			defer cancel3()
			req3 = req3.WithContext(ctx3)

			resp3, err := h3Client.Do(req3)
			if err != nil {
				// In practice, many sites simply don't support HTTP/3 yet, so
				// QUIC/timeouts are treated as a normal \"not supported\" case
				// (❌) instead of an error (🟧).
				v3.Detail = fmt.Sprintf("not supported (or probe failed): %v", err)
			} else {
				defer resp3.Body.Close()
				if resp3.ProtoMajor == 3 {
					v3.Supported = true
					v3.Detail = "supported"
				} else {
					v3.Detail = fmt.Sprintf("server replied with %s", resp3.Proto)
				}
			}
		}
		results[3] = v3
	}()

	wg.Wait()
	res.Results = results
	return res
}

// CheckHTTPVersions runs the checks and prints a human-readable summary.
func CheckHTTPVersions(target string, overridePort string) {
	res := runChecks(target, overridePort)

	// Single-line summary (same format as multi-target): statuses first, then host:port.
	var b strings.Builder
	for idx, vr := range res.Results {
		if idx > 0 {
			b.WriteString(" | ")
		}
		fmt.Fprintf(&b, "%s %s", vr.Version, statusEmoji(vr))
	}
	fmt.Printf("%s\t%s:%s\n", b.String(), res.Target, res.Port)
}

// CheckHTTPVersionsJSON runs the checks and returns a structured result suitable for JSON encoding.
func CheckHTTPVersionsJSON(target string, overridePort string) CheckResult {
	return runChecks(target, overridePort)
}

// runChecksMulti runs checks for multiple targets in parallel and returns the results
// in the same order as the input targets slice.
func runChecksMulti(targets []string, overridePort string) []CheckResult {
	n := len(targets)
	results := make([]CheckResult, n)
	if n == 0 {
		return results
	}

	workerCount := workerCountForTargets(n)

	var wg sync.WaitGroup
	jobs := make(chan int)

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				results[idx] = runChecks(targets[idx], overridePort)
			}
		}()
	}

	for i := range targets {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return results
}

// CheckHTTPVersionsMulti runs the checks for multiple targets and prints
// a human-readable summary for each, printing each host as soon as its
// result is available (results may be out of input order).
func CheckHTTPVersionsMulti(targets []string, overridePort string) {
	n := len(targets)
	if n == 0 {
		return
	}

	workerCount := workerCountForTargets(n)

	results := make(chan CheckResult)
	jobs := make(chan int)

	var wg sync.WaitGroup

	// Start workers.
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				results <- runChecks(targets[idx], overridePort)
			}
		}()
	}

	// Feed jobs.
	go func() {
		for i := range targets {
			jobs <- i
		}
		close(jobs)
	}()

	// Close results when workers are done.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Print each result as soon as it is ready.
	for res := range results {
		var b strings.Builder
		for idx, vr := range res.Results {
			if idx > 0 {
				b.WriteString(" | ")
			}
			fmt.Fprintf(&b, "%s %s", vr.Version, statusEmoji(vr))
		}
		fmt.Printf("%s\t%s:%s\n", b.String(), res.Target, res.Port)
	}
}

// CheckHTTPVersionsJSONMulti runs the checks for multiple targets and returns
// a slice of results suitable for JSON encoding.
func CheckHTTPVersionsJSONMulti(targets []string, overridePort string) []CheckResult {
	return runChecksMulti(targets, overridePort)
}

// workerCountForTargets picks a reasonable worker count based on CPU count
// and number of targets, with an upper bound to avoid overwhelming the system.
func workerCountForTargets(n int) int {
	if n <= 0 {
		return 0
	}
	maxWorkers := 64
	wc := runtime.NumCPU() * 4
	if wc > maxWorkers {
		wc = maxWorkers
	}
	if wc > n {
		wc = n
	}
	if wc < 1 {
		wc = 1
	}
	return wc
}
