package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"http1.dev/internal/httpver"
)

const (
	maxWebTargets = 5
	cacheTTL      = 4 * time.Hour
)

type cacheEntry struct {
	Results   []httpver.CheckResult
	ScannedAt time.Time
	ExpiresAt time.Time
	Hidden    bool
}

type resultCache struct {
	mu         sync.RWMutex
	data       map[string]cacheEntry
	recentKeys []string
}

func newResultCache() *resultCache {
	return &resultCache{
		data: make(map[string]cacheEntry),
	}
}

func (c *resultCache) get(key string) (results []httpver.CheckResult, scannedAt time.Time, ok bool) {
	now := time.Now()

	c.mu.RLock()
	entry, found := c.data[key]
	c.mu.RUnlock()
	if !found || entry.ExpiresAt.Before(now) {
		return nil, time.Time{}, false
	}
	return entry.Results, entry.ScannedAt, true
}

func (c *resultCache) set(key string, results []httpver.CheckResult, includeInRecent bool) {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple cleanup of expired entries.
	for k, v := range c.data {
		if v.ExpiresAt.Before(now) {
			delete(c.data, k)
		}
	}

	c.data[key] = cacheEntry{
		Results:   results,
		ScannedAt: now,
		ExpiresAt: now.Add(cacheTTL),
		Hidden:    !includeInRecent,
	}

	if includeInRecent {
		// Maintain a simple MRU list of recent keys (most recent last), without duplicates.
		const maxRecentKeys = 32
		// Remove existing occurrence of key, if any.
		for i, existing := range c.recentKeys {
			if existing == key {
				c.recentKeys = append(c.recentKeys[:i], c.recentKeys[i+1:]...)
				break
			}
		}
		c.recentKeys = append(c.recentKeys, key)
		if len(c.recentKeys) > maxRecentKeys {
			c.recentKeys = c.recentKeys[len(c.recentKeys)-maxRecentKeys:]
		}
	}
}

type recentSnapshot struct {
	Target    string
	URL       string
	Port      string
	Results   []httpver.VersionResult
	ScannedAt time.Time
	Score     int
	Grade     string
}

func (c *resultCache) recentSnapshots(limit int) []recentSnapshot {
	if limit <= 0 {
		return nil
	}

	now := time.Now()

	c.mu.RLock()
	defer c.mu.RUnlock()

	var snapshots []recentSnapshot
	// Walk keys from most-recent to oldest.
	for i := len(c.recentKeys) - 1; i >= 0 && len(snapshots) < limit; i-- {
		key := c.recentKeys[i]
		entry, ok := c.data[key]
		if !ok || entry.ExpiresAt.Before(now) || entry.Hidden {
			continue
		}
		for _, cr := range entry.Results {
			snapshots = append(snapshots, recentSnapshot{
				Target:    cr.Target,
				URL:       cr.URL,
				Port:      cr.Port,
				Results:   cr.Results,
				ScannedAt: entry.ScannedAt,
				Score:     cr.Score,
				Grade:     cr.Grade,
			})
			if len(snapshots) >= limit {
				break
			}
		}
	}
	return snapshots
}

var (
	webTemplates = template.Must(template.New("index.html").Funcs(template.FuncMap{
		"statusEmoji": func(v httpver.VersionResult) string {
			if v.Supported {
				return "✅"
			}
			if v.Error {
				return "🟧"
			}
			return "❌"
		},
		// legacyNotSupportedOK reports whether this row represents a *good* outcome
		// for security: HTTP/1.0 or HTTP/1.1 not being supported.
		"legacyNotSupportedOK": func(v httpver.VersionResult) bool {
			if v.Supported {
				return false
			}
			if v.Version != "HTTP/1.0" && v.Version != "HTTP/1.1" {
				return false
			}
			// Treat any "not supported ..." outcome for HTTP/1.x as good from a
			// security perspective, including "not supported (good) - TCP connection
			// refused" and the earlier "not supported (or probe failed)" wording.
			return strings.HasPrefix(v.Detail, "not supported")
		},
		// http11Warning produces a human-readable warning string for HTTP/1.1 when
		// the configuration looks risky: either HTTP/1.1 is the highest supported
		// version (no h2/h3 upgrade path) or HTTP/1.0 downgrade remains possible.
		// It returns an empty string when there is nothing notable to warn about.
		"http11Warning": func(all []httpver.VersionResult, v httpver.VersionResult) string {
			if v.Version != "HTTP/1.1" || !v.Supported {
				return ""
			}

			var hasH2, hasH3, hasH10 bool
			for _, vr := range all {
				switch vr.Version {
				case "HTTP/3.0":
					if vr.Supported {
						hasH3 = true
					}
				case "HTTP/2.0":
					if vr.Supported {
						hasH2 = true
					}
				case "HTTP/1.0":
					if vr.Supported {
						hasH10 = true
					}
				}
			}

			var notes []string
			if !hasH2 && !hasH3 {
				notes = append(notes, "HTTP/1.1 is the highest supported version; clients cannot upgrade to HTTP/2 or HTTP/3.")
			}
			if hasH10 {
				notes = append(notes, "Clients can be downgraded to HTTP/1.0, which is strongly discouraged.")
			}
			if len(notes) == 0 {
				return ""
			}
			return strings.Join(notes, " ")
		},
		// versionDowngradeNote explains whether downgrades from HTTP/2 or HTTP/3
		// to older protocols are possible. Being able to downgrade is generally
		// undesirable from a security perspective.
		"versionDowngradeNote": func(all []httpver.VersionResult, v httpver.VersionResult) string {
			if !v.Supported {
				return ""
			}

			var hasH11, hasH2 bool
			for _, vr := range all {
				if !vr.Supported {
					continue
				}
				switch vr.Version {
				case "HTTP/3.0":
					// Presence of HTTP/3 is implied by v.Version == "HTTP/3.0" when supported.
				case "HTTP/2.0":
					hasH2 = true
				case "HTTP/1.1":
					hasH11 = true
				}
			}

			switch v.Version {
			case "HTTP/3.0":
				if hasH2 || hasH11 {
					return "Downgrade to HTTP/2 or HTTP/1.1 is possible (not ideal; prefer keeping clients on HTTP/3)."
				}
				return "Downgrade below HTTP/3 is not possible (good)."
			case "HTTP/2.0":
				if hasH11 {
					return "Downgrade to HTTP/1.1 is possible (not ideal; limit HTTP/1.x exposure)."
				}
				return "Downgrade to HTTP/1.1 is not possible (good)."
			default:
				return ""
			}
		},
		"statusTitle": func(v httpver.VersionResult) string {
			if v.Supported {
				return "supported"
			}
			if v.Error {
				return "error / probe failed"
			}
			return "not supported"
		},
		"gradeLabel": func(cr httpver.CheckResult) string {
			return cr.Grade
		},
		"gradeClass": func(cr httpver.CheckResult) string {
			switch cr.Grade {
			case "A":
				return "fantastic"
			case "B", "C":
				return "borderline"
			default:
				return "fail"
			}
		},
		// capFirst returns the input string with its first rune uppercased, for
		// nicer sentence-style descriptions in the UI.
		"capFirst": func(s string) string {
			if s == "" {
				return ""
			}
			r, size := utf8.DecodeRuneInString(s)
			if r == utf8.RuneError && size == 0 {
				return s
			}
			return string(unicode.ToUpper(r)) + s[size:]
		},
		"hasVersion": func(results []httpver.VersionResult, want string) bool {
			for _, vr := range results {
				if vr.Version == want && vr.Supported {
					return true
				}
			}
			return false
		},
		"formatAge": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return formatAge(time.Since(t))
		},
	}).ParseFiles("cmd/http1/templates/index.html"))
)

type pageData struct {
	TargetsRaw     string
	HideFromRecent bool
	Error          string
	Results        []httpver.CheckResult
	HasResults     bool
	UsedCache      bool
	CacheAge       string
	Recent         []recentSnapshot
	Best           []recentSnapshot
	Worst          []recentSnapshot
	Page           string
}

func runWebServer(listenAddr string) error {
	cache := newResultCache()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleScan(w, r, cache)
	})
	mux.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		handleScan(w, r, cache)
	})
	mux.HandleFunc("/problem", func(w http.ResponseWriter, r *http.Request) {
		renderHTML(w, pageData{Page: "problem"})
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		renderHTML(w, pageData{Page: "about"})
	})

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	fmt.Printf("http1.dev web UI listening on %s\n", listenAddr)
	return server.ListenAndServe()
}

func handleScan(w http.ResponseWriter, r *http.Request, cache *resultCache) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "failed to parse request", http.StatusBadRequest)
		return
	}

	raw := r.Form.Get("t")
	targets := parseTargetsParam(raw)

	if len(targets) == 0 {
		// No targets – just render the empty form and always show recent scans.
		const recentLimit = 12
		recent := cache.recentSnapshots(recentLimit)
		best := filterByGrade(recent, "A", 6)
		worst := filterByGrade(recent, "F", 6)

		renderHTML(w, pageData{
			TargetsRaw: raw,
			HasResults: false,
			Page:       "scanner",
			Recent:     recent,
			Best:       best,
			Worst:      worst,
		})
		return
	}

	if len(targets) > maxWebTargets {
		const recentLimit = 12
		recent := cache.recentSnapshots(recentLimit)
		best := filterByGrade(recent, "A", 6)
		worst := filterByGrade(recent, "F", 6)

		renderHTML(w, pageData{
			TargetsRaw: raw,
			Error:      fmt.Sprintf("Please provide between 1 and %d targets.", maxWebTargets),
			HasResults: false,
			Page:       "scanner",
			Recent:     recent,
			Best:       best,
			Worst:      worst,
		})
		return
	}

	hideFromRecent := r.Form.Get("hide") == "on" || r.Form.Get("hide") == "1"

	isJSON := wantsJSON(r)
	key := cacheKey(targets)

	var results []httpver.CheckResult
	var usedCache bool
	var cacheAge string
	if cached, scannedAt, ok := cache.get(key); ok {
		results = cached
		usedCache = true
		cacheAge = formatAge(time.Since(scannedAt))
	} else {
		// For web mode we always use the default port behavior (no override).
		if len(targets) == 1 {
			res := httpver.CheckHTTPVersionsJSON(targets[0], "")
			results = []httpver.CheckResult{res}
		} else {
			results = httpver.CheckHTTPVersionsJSONMulti(targets, "")
		}

		// Only include scans that produced at least one successful protocol
		// result in the "recently scanned" overview. Completely failed scans
		// (invalid hostname, no DNS, timeouts, etc.) are still cached so we can
		// reuse their results, but they are not surfaced as recent examples.
		includeInRecent := !hideFromRecent && hasSuccessfulResult(results)
		cache.set(key, results, includeInRecent)
	}

	if isJSON {
		renderJSON(w, results)
		return
	}

	// If we have a single target that failed hostname/URL validation, surface a clear
	// alert instead of showing protocol/grade rows, since we never actually scanned.
	if msg, ok := inputValidationError(results); ok {
		const recentLimit = 12
		recent := cache.recentSnapshots(recentLimit)
		best := filterByGrade(recent, "A", 6)
		worst := filterByGrade(recent, "F", 6)

		renderHTML(w, pageData{
			TargetsRaw: raw,
			Error:      msg,
			HasResults: false,
			Page:       "scanner",
			Recent:     recent,
			Best:       best,
			Worst:      worst,
		})
		return
	}

	// If the hostname does not resolve via DNS (no records / NXDOMAIN), provide a
	// clear warning to the user rather than only generic probe failures.
	if msg, ok := unresolvedHostError(results); ok {
		const recentLimit = 12
		recent := cache.recentSnapshots(recentLimit)
		best := filterByGrade(recent, "A", 6)
		worst := filterByGrade(recent, "F", 6)

		renderHTML(w, pageData{
			TargetsRaw: raw,
			Error:      msg,
			HasResults: false,
			Page:       "scanner",
			Recent:     recent,
			Best:       best,
			Worst:      worst,
		})
		return
	}

	// Build recent / best / worst snapshots for the overview.
	const recentLimit = 12
	recent := cache.recentSnapshots(recentLimit)
	best := filterByGrade(recent, "A", 6)
	worst := filterByGrade(recent, "F", 6)

	renderHTML(w, pageData{
		TargetsRaw:     raw,
		HideFromRecent: hideFromRecent,
		Results:        results,
		HasResults:     true,
		UsedCache:      usedCache,
		CacheAge:       cacheAge,
		Recent:         recent,
		Best:           best,
		Worst:          worst,
		Page:           "scanner",
	})
}

// inputValidationError inspects the results for a single-target scan and determines
// whether the failure was due to an invalid hostname/URL (as opposed to a network
// issue). It returns a user-facing message when that is the case.
func inputValidationError(results []httpver.CheckResult) (string, bool) {
	if len(results) != 1 {
		return "", false
	}
	cr := results[0]
	if len(cr.Results) == 0 {
		return "", false
	}
	vr := cr.Results[0]
	if vr.Version != "error" || !vr.Error {
		return "", false
	}

	// Compose a friendly message for the scanner UI.
	detail := vr.Detail
	if detail == "" {
		detail = "invalid hostname or URL"
	}
	msg := fmt.Sprintf("The hostname %q is invalid and cannot be scanned (%s).", cr.Target, detail)
	return msg, true
}

// unresolvedHostError returns a friendly message when a single-target scan failed
// because the hostname does not resolve via DNS (no records / NXDOMAIN).
func unresolvedHostError(results []httpver.CheckResult) (string, bool) {
	if len(results) != 1 {
		return "", false
	}
	cr := results[0]
	if !cr.Unresolved {
		return "", false
	}
	msg := fmt.Sprintf("The hostname %q cannot be scanned (no DNS records found).", cr.Target)
	return msg, true
}

// hasSuccessfulResult reports whether at least one CheckResult contains a
// supported protocol, meaning the scan was able to reach and meaningfully
// probe the host.
func hasSuccessfulResult(results []httpver.CheckResult) bool {
	for _, cr := range results {
		if cr.Unresolved {
			continue
		}
		for _, vr := range cr.Results {
			if vr.Supported {
				return true
			}
		}
	}
	return false
}

func selectTopByScore(src []recentSnapshot, descending bool, limit int) []recentSnapshot {
	if limit <= 0 || len(src) == 0 {
		return nil
	}

	// Create a shallow copy so we can sort without mutating the original slice.
	cp := make([]recentSnapshot, len(src))
	copy(cp, src)

	if descending {
		sort.SliceStable(cp, func(i, j int) bool {
			return cp[i].Score > cp[j].Score
		})
	} else {
		sort.SliceStable(cp, func(i, j int) bool {
			return cp[i].Score < cp[j].Score
		})
	}

	if len(cp) > limit {
		cp = cp[:limit]
	}
	return cp
}

func filterByGrade(src []recentSnapshot, want string, limit int) []recentSnapshot {
	if limit <= 0 || len(src) == 0 {
		return nil
	}
	var out []recentSnapshot
	for _, s := range src {
		if s.Grade == want {
			out = append(out, s)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

func formatAge(d time.Duration) string {
	if d < time.Minute {
		secs := int(d.Seconds())
		if secs <= 1 {
			return "just now"
		}
		return fmt.Sprintf("%ds ago", secs)
	}
	if d < time.Hour {
		mins := int(d.Minutes())
		return fmt.Sprintf("%d minute%s ago", mins, plural(mins))
	}
	hours := int(d.Hours())
	if d < 24*time.Hour {
		return fmt.Sprintf("%d hour%s ago", hours, plural(hours))
	}
	days := int(d.Hours() / 24)
	return fmt.Sprintf("%d day%s ago", days, plural(days))
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func parseTargetsParam(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	targets := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		lower := strings.ToLower(p)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		targets = append(targets, p)
	}

	return targets
}

func cacheKey(targets []string) string {
	normalized := make([]string, len(targets))
	for i, t := range targets {
		normalized[i] = strings.ToLower(strings.TrimSpace(t))
	}
	return strings.Join(normalized, ",")
}

func wantsJSON(r *http.Request) bool {
	if r.URL.Query().Get("format") == "json" {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json")
}

func renderHTML(w http.ResponseWriter, data pageData) {
	// Render into a buffer first so that if the template fails we can still send
	// a clean 500 response without writing headers/body twice.
	var buf bytes.Buffer
	if err := webTemplates.ExecuteTemplate(&buf, "index.html", data); err != nil {
		log.Printf("template execution error: %v (page=%s, targets=%q)", err, data.Page, data.TargetsRaw)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func renderJSON(w http.ResponseWriter, results []httpver.CheckResult) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if len(results) == 1 {
		// Match CLI behavior: single target returns a single object.
		if err := enc.Encode(results[0]); err != nil {
			http.Error(w, "failed to encode JSON", http.StatusInternalServerError)
		}
		return
	}

	if err := enc.Encode(results); err != nil {
		http.Error(w, "failed to encode JSON", http.StatusInternalServerError)
	}
}


