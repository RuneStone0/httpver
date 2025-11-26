# check_http_versions

Go-based CLI tool (`httpver`) that checks HTTP/1.0, HTTP/1.1, HTTP/2.0, and HTTP/3.0 support for one or more hosts/URLs.

`httpver` is designed as a **minimal companion** to full TLS scanners like `ssllabs.com`. It focuses on one high-signal question:

- Does the server negotiate HTTP/2 or HTTP/3 via ALPN on port 443?

In 2025 this correlates strongly with whether a site is running a modern TLS stack. Run SSL Labs first and follow its certificate/cipher/protocol recommendations, then use `httpver` to quickly spot legacy HTTP/1.x-only surfaces that are still missing HTTP/2 or HTTP/3.

## Install & build

```bash
git clone https://github.com/your-user/check_http_versions.git
cd check_http_versions

# Build the httpver binary
go build -o httpver ./cmd/httpver
```

Optionally put `httpver` somewhere on your `PATH` (e.g. `~/bin` or `$GOBIN`).

## Usage

```bash
httpver [-port N] [--json] [--targets a.com,b.com] [--targets-file targets.txt] <domain-or-url> ...
httpver --web 8080
```

**Examples**

```bash
httpver cloudflare.com
httpver https://example.com
httpver -port 8080 localhost
httpver --json cloudflare.com
httpver --targets cloudflare.com,example.com --json
httpver --targets-file targets.txt --json
httpver cloudflare.com google.com floqast.app httpforever.com neverssl.com oldweb.today microsoft.com tesla.com nvidia.com amazon.com
httpver --web 8080
```

The tool will:

- Normalize each input to a proper URL (defaulting to `https://`).
- Decide a default port per target (443 for HTTPS, 80 for HTTP) unless overridden with `-port`.
- Print which TCP/UDP port is being tested for each target.
- Attempt HTTP/1.0, HTTP/1.1, HTTP/2.0, and HTTP/3.0 connections in that order and report support for each.
- Run checks in parallel across both HTTP versions and multiple targets to keep scans fast.

### Web interface

When run with `--web`, `httpver` starts a small HTTP server that serves a browser-based UI:

- Visit `http://localhost:8080/` (or your chosen `--listen` address).
- Enter up to 5 domains or URLs, separated by commas.
- Results are shareable via links like `/?t=google.com` or `/?t=example.com,cloudflare.com`.
- Scan results are cached in-memory for 4 hours to avoid re-scanning the same targets too frequently.

The service is inspired in part by the HTTP/1.1 security concerns documented at [`https://http1mustdie.com/`](https://http1mustdie.com/), and aims to make it easy and quick to see if you are supporting modern HTTP versions like HTTP/3—similar to how `ssllabs.com` has long helped promote upgrading SSL/TLS.

### Output format

- For **both single and multiple targets**, `httpver` prints one summary line per host as results become available:

  ```text
  HTTP/1.0 ❌ | HTTP/1.1 ✅ | HTTP/2.0 ✅ | HTTP/3.0 ✅    Grade: A (95)    cloudflare.com:443
  HTTP/1.0 ❌ | HTTP/1.1 ✅ | HTTP/2.0 ❌ | HTTP/3.0 ❌    Grade: F (40)    example.org:443
  ```

- Emoji legend:
  - ✅: protocol clearly supported
  - ❌: protocol not supported (clean failure/other version chosen)
  - ⚠️: error or probe failed (timeout, TLS/QUIC error, etc.)

- HTTP/1.0 is probed over plain HTTP on port 80 by default (or the `-port` override), and any HTTP/1.x response (1.0 or 1.1) is treated as HTTP/1.0 support. Other versions are probed over HTTPS/QUIC on the chosen port.

### Using httpver with SSL Labs

`httpver` does **not** replace a full TLS analysis like the one provided by `ssllabs.com`. Instead, it intentionally performs a single decisive check:

- **A** – HTTP/3 is available (or at least HTTP/2 over TLS 1.3).
- **B** – HTTP/2 over TLS 1.3 (no HTTP/3 yet).
- **C** – HTTP/2 over TLS 1.2 only.
- **F** – HTTP/1.x only (no h2/h3 over port 443).

The exact numeric score is less important than the grade; it simply makes results feel familiar (A-style grades on a 0–100 scale). For best results:

1. Run your site through `ssllabs.com` and follow all of its recommendations for certificates, ciphers, and protocol support.
2. Use `httpver` to ensure that your public endpoints also expose HTTP/2 or HTTP/3, and to quickly flag any remaining HTTP/1.x-only frontends that are worth modernizing or isolating.