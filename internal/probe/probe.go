package probe

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hsociety/anansi-cli/internal/output"
)

var techHeaders = []string{
	"server", "x-powered-by", "via", "x-generator",
	"x-aspnet-version", "x-aspnetmvc-version",
	"x-drupal-cache", "x-wp-total", "x-shopify-stage",
}

func newClient(timeoutSec int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func probeURL(client *http.Client, url string) *output.ProbeResult {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ANANSI-CLI/1.0; +https://github.com/hsociety/anansi-cli)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	elapsed := time.Since(start).Milliseconds()

	// Read title from body
	title := ""
	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		if idx := strings.Index(strings.ToLower(string(body)), "<title"); idx != -1 {
			sub := string(body)[idx:]
			start := strings.Index(sub, ">") + 1
			end := strings.Index(strings.ToLower(sub), "</title>")
			if start > 0 && end > start && end-start < 200 {
				title = strings.TrimSpace(sub[start:end])
			}
		}
	}

	tech := map[string]string{}
	for _, h := range techHeaders {
		if v := resp.Header.Get(h); v != "" {
			tech[h] = v
		}
	}

	return &output.ProbeResult{
		URL:            url,
		FinalURL:       resp.Request.URL.String(),
		StatusCode:     resp.StatusCode,
		Server:         resp.Header.Get("Server"),
		TechHeaders:    tech,
		Title:          title,
		ResponseTimeMs: elapsed,
		IsAlive:        true,
	}
}

func probeHost(client *http.Client, fqdn string) *output.ProbeResult {
	for _, scheme := range []string{"https", "http"} {
		if r := probeURL(client, scheme+"://"+fqdn); r != nil {
			r.FQDN = fqdn
			return r
		}
	}
	return &output.ProbeResult{FQDN: fqdn, IsAlive: false}
}

// Run probes all hosts concurrently
func Run(hosts []string, timeout int) ([]output.ProbeResult, error) {
	client := newClient(timeout)
	results := make([]output.ProbeResult, 0, len(hosts))
	mu := sync.Mutex{}
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := probeHost(client, h)
			mu.Lock()
			results = append(results, *r)
			mu.Unlock()
		}(host)
	}
	wg.Wait()
	return results, nil
}

// LiveOnly returns only alive probe results
func LiveOnly(results []output.ProbeResult) []output.ProbeResult {
	var live []output.ProbeResult
	for _, r := range results {
		if r.IsAlive {
			live = append(live, r)
		}
	}
	return live
}
