package httpver

// computeMinimalGrade implements the minimalist grading logic for v1.
// It uses only:
//   - whether HTTP/3 was successfully negotiated (hasH3),
//   - whether HTTP/2 was successfully negotiated (hasH2),
//   - the observed TLS version string from the HTTP/2 connection (tlsVersion).
//
// Grade mapping:
//   - A: HTTP/3 supported (hasH3 == true).
//   - B: HTTP/2 supported with TLS 1.3.
//   - C: HTTP/2 supported with TLS 1.2 only.
//   - F: everything else (HTTP/1.x only, HTTP on port 80, errors, etc.).
//
// We also provide a simple numeric score to make the UI feel familiar:
//   - A: 95
//   - B: 90
//   - C: 80
//   - F: 40
func computeMinimalGrade(hasH3, hasH2 bool, tlsVersion string) (int, string) {
	// Highest signal: HTTP/3 support.
	if hasH3 {
		return 95, "A"
	}

	// No h3, but HTTP/2 is available.
	if hasH2 {
		switch tlsVersion {
		case "TLS 1.3":
			// Modern stack, no h3 yet.
			return 90, "B"
		case "TLS 1.2":
			// Still decent, but older.
			return 80, "C"
		default:
			// HTTP/2 negotiated but we couldn't confidently classify TLS version.
			// Treat this as equivalent to TLS 1.2 for now.
			return 80, "C"
		}
	}

	// No h2 / h3: effectively HTTP/1.x only (or plain HTTP).
	return 40, "F"
}


