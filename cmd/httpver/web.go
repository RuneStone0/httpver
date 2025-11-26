package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"check_http_versions/internal/httpver"
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
}

func scoreCheckResult(cr httpver.CheckResult) int {
	score := 0
	for _, vr := range cr.Results {
		if !vr.Supported {
			continue
		}
		switch vr.Version {
		case "HTTP/1.0":
			score += 1
		case "HTTP/1.1":
			score += 2
		case "HTTP/2.0":
			score += 3
		case "HTTP/3.0":
			score += 4
		}
	}
	return score
}

func gradeLabelForResults(results []httpver.VersionResult) string {
	has2 := false
	has3 := false
	for _, vr := range results {
		if !vr.Supported {
			continue
		}
		switch vr.Version {
		case "HTTP/2.0":
			has2 = true
		case "HTTP/3.0":
			has3 = true
		}
	}
	if has3 {
		return "passed"
	}
	if has2 {
		return "Pass"
	}
	return "insecure"
}

func gradeClassForResults(results []httpver.VersionResult) string {
	label := gradeLabelForResults(results)
	switch label {
	case "passed":
		return "fantastic"
	case "Pass":
		return "pass"
	default:
		return "fail"
	}
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
				Score:     scoreCheckResult(cr),
			})
			if len(snapshots) >= limit {
				break
			}
		}
	}
	return snapshots
}

var (
	webTemplates = template.Must(template.New("index").Funcs(template.FuncMap{
		"statusEmoji": func(v httpver.VersionResult) string {
			if v.Supported {
				return "✅"
			}
			if v.Error {
				return "🟧"
			}
			return "❌"
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
		"gradeLabel": func(results []httpver.VersionResult) string {
			return gradeLabelForResults(results)
		},
		"gradeClass": func(results []httpver.VersionResult) string {
			return gradeClassForResults(results)
		},
		"formatAge": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return formatAge(time.Since(t))
		},
	}).Parse(indexHTML))
)

const indexHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>httpver - HTTP version checker</title>
  <style>
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      padding: 0;
      background: #0f172a;
      color: #e5e7eb;
    }
    .container {
      max-width: 960px;
      margin: 0 auto;
      padding: 2rem 1.5rem 3rem;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      margin-bottom: 1.75rem;
    }
    .brand {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }
    h1 {
      font-size: 2rem;
      margin: 0;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      padding: 0.15rem 0.55rem;
      border-radius: 999px;
      border: 1px solid rgba(148, 163, 184, 0.5);
      color: #e5e7eb;
      background: radial-gradient(circle at top left, rgba(56, 189, 248, 0.15), transparent 55%);
    }
    p.lead {
      color: #9ca3af;
      margin: 0;
      font-size: 0.9rem;
    }
    .card {
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid rgba(148, 163, 184, 0.2);
      border-radius: 0.75rem;
      padding: 1.5rem;
      box-shadow: 0 25px 35px -15px rgba(15, 23, 42, 0.8);
      backdrop-filter: blur(12px);
    }
    label {
      display: block;
      font-weight: 500;
      margin-bottom: 0.35rem;
    }
    input[type="text"] {
      width: 100%;
      padding: 0.65rem 0.8rem;
      border-radius: 0.5rem;
      border: 1px solid rgba(148, 163, 184, 0.6);
      background: rgba(15, 23, 42, 0.9);
      color: #e5e7eb;
      font-size: 0.95rem;
      box-sizing: border-box;
    }
    input[type="text"]:focus {
      outline: none;
      border-color: #38bdf8;
      box-shadow: 0 0 0 1px rgba(56, 189, 248, 0.4);
    }
    .help-text {
      font-size: 0.8rem;
      color: #9ca3af;
      margin-top: 0.25rem;
    }
    .inline-option {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      margin-top: 0.5rem;
      font-size: 0.8rem;
      color: #9ca3af;
    }
    .inline-option input[type="checkbox"] {
      width: 14px;
      height: 14px;
      accent-color: #38bdf8;
    }
    .form-row {
      margin-top: 0.35rem;
      display: flex;
      gap: 0.6rem;
      align-items: stretch;
    }
    .form-row input[type="text"] {
      flex: 1 1 auto;
    }
    .actions {
      margin-top: 0.6rem;
      display: flex;
      gap: 0.75rem;
      align-items: center;
      flex-wrap: wrap;
    }
    .icon-link {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 36px;
      height: 36px;
      border-radius: 999px;
      border: 1px solid rgba(148, 163, 184, 0.4);
      background: radial-gradient(circle at top left, rgba(148, 163, 184, 0.15), rgba(15, 23, 42, 0.95));
      color: inherit;
      text-decoration: none;
      transition: background 0.15s ease, transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
    }
    .icon-link svg {
      width: 18px;
      height: 18px;
      fill: currentColor;
    }
    .icon-link:hover {
      border-color: #38bdf8;
      background: radial-gradient(circle at top left, rgba(56, 189, 248, 0.25), rgba(15, 23, 42, 0.95));
      box-shadow: 0 14px 30px -18px rgba(59, 130, 246, 0.85);
      transform: translateY(-1px);
    }
    button, .btn {
      border: none;
      border-radius: 999px;
      padding: 0.55rem 1.2rem;
      font-size: 0.9rem;
      font-weight: 500;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      text-decoration: none;
    }
    button.primary, .btn.primary {
      background: linear-gradient(135deg, #38bdf8, #22c55e);
      color: #0f172a;
    }
    button.primary:hover, .btn.primary:hover {
      filter: brightness(1.05);
    }
    .hint {
      font-size: 0.8rem;
      color: #9ca3af;
    }
    .error {
      margin-top: 1rem;
      padding: 0.75rem 0.9rem;
      border-radius: 0.5rem;
      border: 1px solid rgba(248, 113, 113, 0.6);
      background: rgba(127, 29, 29, 0.8);
      color: #fee2e2;
      font-size: 0.85rem;
    }
    .results {
      margin-top: 2rem;
    }
    .target-card {
      margin-bottom: 1.25rem;
      padding: 1rem 1rem 0.9rem;
      border-radius: 0.75rem;
      border: 1px solid rgba(148, 163, 184, 0.35);
      background: radial-gradient(circle at top left, rgba(56, 189, 248, 0.15), transparent 55%), rgba(15, 23, 42, 0.9);
    }
    .target-header {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 0.75rem;
      margin-bottom: 0.75rem;
    }
    .target-main {
      font-weight: 600;
      font-size: 1rem;
    }
    .target-main a {
      color: inherit;
      text-decoration: none;
    }
    .target-main a:hover {
      text-decoration: underline;
    }
    .target-sub {
      font-size: 0.8rem;
      color: #9ca3af;
    }
    .grade-badge {
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      padding: 0.15rem 0.6rem;
      border-radius: 999px;
      border: 1px solid rgba(148, 163, 184, 0.6);
      white-space: nowrap;
    }
    .grade-badge.grade-fail {
      border-color: rgba(248, 113, 113, 0.9);
      color: #fecaca;
      background: rgba(127, 29, 29, 0.9);
    }
    .grade-badge.grade-pass {
      border-color: rgba(52, 211, 153, 0.9);
      color: #bbf7d0;
      background: rgba(6, 78, 59, 0.9);
    }
    .grade-badge.grade-fantastic {
      border-color: rgba(34, 197, 94, 0.95);
      color: #dcfce7;
      background: linear-gradient(135deg, rgba(22, 163, 74, 0.9), rgba(34, 197, 94, 0.9));
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
      margin-top: 0.35rem;
    }
    th, td {
      padding: 0.4rem 0.3rem;
      text-align: left;
    }
    th {
      font-weight: 500;
      color: #9ca3af;
      border-bottom: 1px solid rgba(148, 163, 184, 0.4);
    }
    tr + tr td {
      border-top: 1px solid rgba(15, 23, 42, 0.9);
    }
    .version {
      white-space: nowrap;
      width: 0;
    }
    .status {
      width: 0;
      white-space: nowrap;
    }
    .detail {
      color: #d1d5db;
    }
    .footer {
      margin-top: 2.5rem;
      font-size: 0.8rem;
      color: #6b7280;
    }
    .footer a {
      color: #93c5fd;
      text-decoration: none;
    }
    .footer a:hover {
      text-decoration: underline;
    }
    .spinner {
      width: 12px;
      height: 12px;
      border-radius: 999px;
      border: 2px solid rgba(15, 23, 42, 0.85);
      border-top-color: rgba(15, 23, 42, 0.2);
      animation: spin 0.7s linear infinite;
    }
    .btn-content {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
    }
    button[disabled] {
      opacity: 0.7;
      cursor: default;
    }
    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }
    @media (max-width: 600px) {
      .card {
        padding: 1.1rem 1rem;
      }
      .target-header {
        flex-direction: column;
        align-items: flex-start;
      }
      .form-row {
        flex-direction: column;
        align-items: stretch;
      }
    }
    .recent-section {
      margin-top: 2.5rem;
    }
    .recent-header {
      font-size: 0.95rem;
      font-weight: 500;
      margin-bottom: 0.5rem;
    }
    .recent-grid {
      display: grid;
      grid-template-columns: minmax(0, 2fr) minmax(0, 1.4fr) minmax(0, 1.4fr);
      gap: 1.1rem;
      font-size: 0.8rem;
    }
    .recent-card {
      border-radius: 0.75rem;
      border: 1px solid rgba(31, 41, 55, 0.95);
      background: rgba(15, 23, 42, 0.9);
      padding: 0.75rem 0.85rem;
    }
    .recent-title {
      font-size: 0.8rem;
      font-weight: 500;
      margin-bottom: 0.45rem;
      color: #e5e7eb;
    }
    .recent-table {
      width: 100%;
      border-collapse: collapse;
    }
    .recent-table th,
    .recent-table td {
      padding: 0.25rem 0.2rem;
      text-align: left;
    }
    .recent-table th {
      font-weight: 500;
      color: #9ca3af;
      border-bottom: 1px solid rgba(31, 41, 55, 0.9);
    }
    .recent-table tr + tr td {
      border-top: 1px solid rgba(15, 23, 42, 0.9);
    }
    .recent-host {
      font-size: 0.8rem;
      color: #e5e7eb;
    }
    .recent-host a {
      color: inherit;
      text-decoration: none;
    }
    .recent-host a:hover {
      text-decoration: underline;
    }
    .recent-meta {
      font-size: 0.7rem;
      color: #9ca3af;
      word-break: break-all;
    }
    .recent-age {
      white-space: nowrap;
    }
    .recent-status {
      white-space: nowrap;
    }
    @media (max-width: 900px) {
      .recent-grid {
        grid-template-columns: minmax(0, 1fr);
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">
        <h1>
          httpver
          <span class="badge">HTTP/1.x must die</span>
        </h1>
        <p class="lead">Check which HTTP versions a site supports with a fast CLI and a shareable web UI.</p>
      </div>
      <a class="icon-link" href="https://github.com/RuneStone0/httpver" target="_blank" rel="noreferrer" aria-label="View httpver on GitHub">
        <svg viewBox="0 0 16 16" aria-hidden="true">
          <path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path>
        </svg>
      </a>
    </div>
    <div class="card">
      <form method="GET" action="/">
        <label for="t">Domain(s)</label>
        <div class="form-row">
          <input type="text" id="t" name="t" value="{{.TargetsRaw}}" placeholder="example.com, google.com">
          <button type="submit" class="primary" id="scan-btn">
            <span class="btn-content" id="scan-btn-content">
              <span>Scan</span>
            </span>
          </button>
        </div>
        <div class="help-text"></div>

        <label class="inline-option">
          <input type="checkbox" id="hide" name="hide" {{if .HideFromRecent}}checked{{end}}>
          <span>Do not show these results in the <strong>Recently scanned</strong> overview.</span>
        </label>

        <div class="actions"></div>
      </form>

      {{if .Error}}
      <div class="error">
        {{.Error}}
      </div>
      {{end}}
    </div>

    {{if .HasResults}}
    <div class="results">
      {{if .UsedCache}}
      <div class="help-text" style="margin-bottom: 0.6rem;">
        Showing <strong>cached</strong> scan results from {{.CacheAge}}. New scans within the last 4 hours reuse cached data to stay fast.
      </div>
      {{end}}
      {{range .Results}}
      <div class="target-card">
        <div class="target-header">
          <div>
            <div class="target-main"><a href="{{.URL}}" target="_blank" rel="noreferrer">{{.Target}}</a></div>
            <div class="target-sub">{{.URL}}</div>
          </div>
          <div class="grade-badge grade-{{gradeClass .Results}}" title="Grade: {{gradeLabel .Results}}">
            {{gradeLabel .Results}}
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th class="version">Version</th>
              <th class="status">Supported</th>
              <th class="detail">Detail</th>
            </tr>
          </thead>
          <tbody>
            {{range .Results}}
            <tr>
              <td class="version">{{.Version}}</td>
              <td class="status">
                {{if .Supported}}<span title="supported">✅</span>{{end}}
              </td>
              <td class="detail">{{.Detail}}</td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>
      {{end}}
    </div>
    {{end}}

    {{if .Recent}}
    <div class="recent-section">
      <div class="recent-header">Recently scanned</div>
      <div class="recent-grid">
        <div class="recent-card">
          <div class="recent-title">Latest</div>
          <table class="recent-table">
            <thead>
              <tr>
                <th>Host</th>
                <th>Age</th>
              </tr>
            </thead>
            <tbody>
              {{range .Recent}}
              <tr>
                <td>
                  <div class="recent-host"><a href="{{.URL}}" target="_blank" rel="noreferrer">{{.Target}}</a></div>
                  <div class="recent-meta">{{.URL}}</div>
                </td>
                <td class="recent-age">{{formatAge .ScannedAt}}</td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
        <div class="recent-card">
          <div class="recent-title">Best (most modern)</div>
          <table class="recent-table">
            <thead>
              <tr>
                <th>Host</th>
                <th class="recent-status">Support</th>
              </tr>
            </thead>
            <tbody>
              {{range .Best}}
              <tr>
                <td>
                  <div class="recent-host"><a href="{{.URL}}" target="_blank" rel="noreferrer">{{.Target}}</a></div>
                  <div class="recent-meta">{{.URL}}</div>
                </td>
                <td class="recent-status">
                  <span class="grade-badge grade-{{gradeClass .Results}}" title="Grade: {{gradeLabel .Results}}">
                    {{gradeLabel .Results}}
                  </span>
                </td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
        <div class="recent-card">
          <div class="recent-title">Worst (least modern)</div>
          <table class="recent-table">
            <thead>
              <tr>
                <th>Host</th>
                <th class="recent-status">Support</th>
              </tr>
            </thead>
            <tbody>
              {{range .Worst}}
              <tr>
                <td>
                  <div class="recent-host"><a href="{{.URL}}" target="_blank" rel="noreferrer">{{.Target}}</a></div>
                  <div class="recent-meta">{{.URL}}</div>
                </td>
                <td class="recent-status">
                  <span class="grade-badge grade-{{gradeClass .Results}}" title="Grade: {{gradeLabel .Results}}">
                    {{gradeLabel .Results}}
                  </span>
                </td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    {{end}}

    <div class="footer">
      <div style="margin-bottom: 0.4rem;">
        <span>CLI usage: <code>httpver cloudflare.com</code>, <code>httpver --json example.org</code>. Web mode: <code>httpver --web --listen :8080</code>.</span>
      </div>
      <div>
        <span>This service is inspired in part by the HTTP/1.1 security concerns documented at <a href="https://http1mustdie.com/" target="_blank" rel="noreferrer">http1mustdie.com</a>, and aims to make it as easy to see if you support modern HTTP versions (like HTTP/3) as sites like <code>ssllabs.com</code> have made it to improve SSL/TLS.</span>
      </div>
    </div>
  </div>
  <script>
    (function () {
      var form = document.querySelector('form');
      if (!form) return;
      var btn = document.getElementById('scan-btn');
      var content = document.getElementById('scan-btn-content');
      if (!btn || !content) return;

      form.addEventListener('submit', function () {
        // If no targets provided, let the server respond normally without spinner state.
        var input = document.getElementById('t');
        if (input && !input.value.trim()) {
          return;
        }
        btn.disabled = true;
        content.innerHTML = '';
        var spinner = document.createElement('span');
        spinner.className = 'spinner';
        var text = document.createElement('span');
        text.textContent = 'Scanning...';
        var wrap = document.createElement('span');
        wrap.className = 'btn-content';
        wrap.appendChild(spinner);
        wrap.appendChild(text);
        content.appendChild(wrap);
      });
    })();
  </script>
</body>
</html>
`

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

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	fmt.Printf("httpver web UI listening on %s\n", listenAddr)
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
		// No targets – just render the empty form.
		renderHTML(w, pageData{
			TargetsRaw: raw,
			HasResults: false,
		})
		return
	}

	if len(targets) > maxWebTargets {
		renderHTML(w, pageData{
			TargetsRaw: raw,
			Error:      fmt.Sprintf("Please provide between 1 and %d targets.", maxWebTargets),
			HasResults: false,
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
		cache.set(key, results, !hideFromRecent)
	}

	if isJSON {
		renderJSON(w, results)
		return
	}

	// Build recent / best / worst snapshots for the overview.
	const recentLimit = 12
	recent := cache.recentSnapshots(recentLimit)
	best := filterByGrade(recent, "passed", 6)
	worst := filterByGrade(recent, "insecure", 6)

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
	})
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
		if gradeLabelForResults(s.Results) == want {
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := webTemplates.ExecuteTemplate(w, "index", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
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
