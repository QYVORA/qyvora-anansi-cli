// Package probe implements HTTP/HTTPS connectivity testing.
// It attempts to connect to hosts, captures response metadata, and identifies technology.
package probe

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wsuits6/hsociety-anansi-cli/internal/output"
)

// techHeaders are HTTP headers that reveal information about the server technology stack.
// These are collected and included in probe results for fingerprinting.
var techHeaders = []string{
	"server", "x-powered-by", "via", "x-generator",
	"x-aspnet-version", "x-aspnetmvc-version",
	"x-drupal-cache", "x-wp-total", "x-shopify-stage",
}

// newClient creates an HTTP client configured for security scanning:
// - InsecureSkipVerify: allows testing hosts with invalid/self-signed certs
// - DisableKeepAlives: prevents connection reuse (cleaner for concurrent scans)
// - Follows up to 3 redirects, then stops
func newClient(timeoutSec int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse // Stop following redirects
			}
			return nil
		},
	}
}

// probeURL attempts to fetch a specific URL and returns metadata about the response.
// Extracts: status code, headers, page title, server info, response time.
// Returns nil if the request fails (host unreachable, timeout, etc.)
func probeURL(client *http.Client, url string) *output.ProbeResult {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	// Use a realistic User-Agent to avoid basic bot detection
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ANANSI-CLI/1.0; +https://github.com/wsuits6/hsociety-anansi-cli)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	elapsed := time.Since(start).Milliseconds()

	// Extract <title> from HTML pages (for identification purposes)
	title := ""
	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192)) // Only read first 8KB
		if idx := strings.Index(strings.ToLower(string(body)), "<title"); idx != -1 {
			sub := string(body)[idx:]
			start := strings.Index(sub, ">") + 1
			end := strings.Index(strings.ToLower(sub), "</title>")
			if start > 0 && end > start && end-start < 200 {
				title = strings.TrimSpace(sub[start:end])
			}
		}
	}

	// Collect technology fingerprinting headers
	tech := map[string]string{}
	for _, h := range techHeaders {
		if v := resp.Header.Get(h); v != "" {
			tech[h] = v
		}
	}

	return &output.ProbeResult{
		URL:            url,
		FinalURL:       resp.Request.URL.String(), // After following redirects
		StatusCode:     resp.StatusCode,
		Server:         resp.Header.Get("Server"),
		TechHeaders:    tech,
		Title:          title,
		ResponseTimeMs: elapsed,
		IsAlive:        true,
	}
}

// probeHost tests both HTTPS and HTTP for a given FQDN.
// Tries HTTPS first (preferred), falls back to HTTP if HTTPS fails.
// Returns a "dead" result if both fail.
func probeHost(client *http.Client, fqdn string) *output.ProbeResult {
	// Try HTTPS first (port 443)
	for _, scheme := range []string{"https", "http"} {
		if r := probeURL(client, scheme+"://"+fqdn); r != nil {
			r.FQDN = fqdn
			return r
		}
	}
	// Both schemes failed - host is not reachable via HTTP/HTTPS
	return &output.ProbeResult{FQDN: fqdn, IsAlive: false}
}

// Run probes all hosts concurrently with a semaphore limiting parallelism to 10.
// This prevents overwhelming the network or triggering rate limits/WAFs.
func Run(hosts []string, timeout int) ([]output.ProbeResult, error) {
	client := newClient(timeout)
	results := make([]output.ProbeResult, 0, len(hosts))
	mu := sync.Mutex{}
	sem := make(chan struct{}, 10) // Max 10 concurrent probes
	var wg sync.WaitGroup

	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore slot
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore slot
			r := probeHost(client, h)
			mu.Lock()
			results = append(results, *r)
			mu.Unlock()
		}(host)
	}
	wg.Wait()
	return results, nil
}

// LiveOnly filters probe results to return only hosts that responded to HTTP/HTTPS.
func LiveOnly(results []output.ProbeResult) []output.ProbeResult {
	var live []output.ProbeResult
	for _, r := range results {
		if r.IsAlive {
			live = append(live, r)
		}
	}
	return live
}
