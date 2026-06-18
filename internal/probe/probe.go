// Package probe implements HTTP/HTTPS connectivity testing.
// It attempts to connect to hosts, captures response metadata, and identifies technology.
package probe

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wsuits6/qyvora-anansi-cli/internal/assets"
	"github.com/wsuits6/qyvora-anansi-cli/internal/output"
)

// techHeaders are HTTP headers that reveal information about the server technology stack.
// These are collected and included in probe results for fingerprinting.
var techHeaders []string

func init() {
	techHeaders = assets.LoadData("wordlists/probe/tech_headers.txt")
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
// Extracts: status code, headers, page title, server info, response time, and technologies.
// Returns nil if the request fails (host unreachable, timeout, etc.)
func probeURL(client *http.Client, url string) *output.ProbeResult {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	// Use a realistic User-Agent to avoid basic bot detection
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ANANSI-CLI/1.0; +https://github.com/wsuits6/qyvora-anansi-cli)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	elapsed := time.Since(start).Milliseconds()

	// Read enough body for tech detection and title extraction (8KB)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	// Extract <title> from HTML pages
	title := ""
	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		if idx := strings.Index(strings.ToLower(string(body)), "<title"); idx != -1 {
			sub := string(body)[idx:]
			startIdx := strings.Index(sub, ">") + 1
			endIdx := strings.Index(strings.ToLower(sub), "</title>")
			if startIdx > 0 && endIdx > startIdx && endIdx-startIdx < 200 {
				title = strings.TrimSpace(sub[startIdx:endIdx])
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

	// Detect running technologies
	detectedTechs := detectTech(resp.Header, body)

	return &output.ProbeResult{
		URL:            url,
		FinalURL:       resp.Request.URL.String(), // After following redirects
		StatusCode:     resp.StatusCode,
		Server:         resp.Header.Get("Server"),
		TechHeaders:    tech,
		Technologies:   detectedTechs,
		Title:          title,
		ResponseTimeMs: elapsed,
		IsAlive:        true,
	}
}

// detectTech parses headers and response body for common web technologies
func detectTech(headers http.Header, body []byte) []string {
	var techs []string
	bodyStr := strings.ToLower(string(body))

	// Header checks
	poweredBy := strings.ToLower(headers.Get("X-Powered-By"))
	if strings.Contains(poweredBy, "php") {
		techs = append(techs, "PHP")
	}
	if strings.Contains(poweredBy, "asp.net") {
		techs = append(techs, "ASP.NET")
	}
	if headers.Get("X-AspNet-Version") != "" {
		techs = append(techs, "ASP.NET")
	}

	server := strings.ToLower(headers.Get("Server"))
	if strings.Contains(server, "cloudflare") {
		techs = append(techs, "Cloudflare")
	} else if strings.Contains(server, "nginx") {
		techs = append(techs, "Nginx")
	} else if strings.Contains(server, "apache") {
		techs = append(techs, "Apache")
	}

	// Body checks
	if strings.Contains(bodyStr, "wordpress") || strings.Contains(bodyStr, "/wp-content/") {
		techs = append(techs, "WordPress")
	}
	if strings.Contains(bodyStr, "_next/static") || strings.Contains(bodyStr, "__next") {
		techs = append(techs, "Next.js")
	}
	if strings.Contains(bodyStr, "react-dom") || strings.Contains(bodyStr, "react.production") || strings.Contains(bodyStr, "data-reactroot") {
		techs = append(techs, "React")
	}
	if strings.Contains(bodyStr, "drupal") || strings.Contains(bodyStr, "sites/default/files") {
		techs = append(techs, "Drupal")
	}
	if strings.Contains(bodyStr, "joomla") {
		techs = append(techs, "Joomla")
	}
	if strings.Contains(bodyStr, "<app-root>") {
		techs = append(techs, "Angular")
	}

	return techs
}

// probeHost tests multiple ports for a given FQDN.
// Returns results for all active ports.
func probeHost(client *http.Client, fqdn string, ports []string, delayMs int) []*output.ProbeResult {
	var results []*output.ProbeResult
	for _, port := range ports {
		if delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}

		var schemes []string
		if port == "443" || port == "8443" {
			schemes = []string{"https", "http"}
		} else {
			schemes = []string{"http", "https"}
		}

		for _, scheme := range schemes {
			url := fmt.Sprintf("%s://%s:%s", scheme, fqdn, port)
			if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
				url = fmt.Sprintf("%s://%s", scheme, fqdn)
			}
			if r := probeURL(client, url); r != nil {
				r.FQDN = fqdn
				results = append(results, r)
				break // found a working scheme for this port
			}
		}
	}
	if len(results) == 0 {
		return []*output.ProbeResult{{FQDN: fqdn, IsAlive: false}}
	}
	return results
}

// Run probes all hosts concurrently with a semaphore limiting parallelism.
func Run(out *output.Renderer, hosts []string, timeout int, threads int, ports []string, delayMs int) ([]output.ProbeResult, error) {
	client := newClient(timeout)
	results := make([]output.ProbeResult, 0, len(hosts))
	mu := sync.Mutex{}
	sem := make(chan struct{}, threads) // Use user-defined concurrency
	var wg sync.WaitGroup

	completed := 0
	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore slot
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore slot
			rs := probeHost(client, h, ports, delayMs)
			mu.Lock()
			for _, r := range rs {
				results = append(results, *r)
			}
			completed++
			if completed%5 == 0 || completed == len(hosts) {
				out.Progress(completed, len(hosts), "Probing")
			}
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
