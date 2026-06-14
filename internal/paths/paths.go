package paths

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

type pathRule struct {
	path        string
	title       string
	severity    string
	captureBody bool // capture response body snippet as evidence
}

func loadRules(filename string) []pathRule {
	lines := assets.LoadData(filename)
	var rules []pathRule
	for _, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		capture := false
		if len(parts) >= 4 && parts[3] == "true" {
			capture = true
		}
		rules = append(rules, pathRule{
			path:        parts[0],
			title:       parts[1],
			severity:    parts[2],
			captureBody: capture,
		})
	}
	return rules
}

type baselineResponse struct {
	statusCode int
	bodyLen    int
}

func getBaseline(client *http.Client, baseURL string) baselineResponse {
	target := strings.TrimRight(baseURL, "/") + fmt.Sprintf("/anansi-404-test-%d", time.Now().UnixNano())
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return baselineResponse{statusCode: 404}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ANANSI-CLI/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return baselineResponse{statusCode: 404}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return baselineResponse{
		statusCode: resp.StatusCode,
		bodyLen:    len(body),
	}
}

func checkPath(client *http.Client, baseURL string, rule pathRule, baseline baselineResponse) *output.Finding {
	target := strings.TrimRight(baseURL, "/") + rule.path
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ANANSI-CLI/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// 1. Check if status code matches common "not found" or "forbidden"
	if resp.StatusCode == 404 || resp.StatusCode == 400 || resp.StatusCode == 410 || resp.StatusCode == 403 {
		return nil
	}

	// 2. Compare against baseline (custom 404 handling)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5000)) // read enough to compare
	if resp.StatusCode == baseline.statusCode && len(body) == baseline.bodyLen {
		return nil
	}

	evidence := fmt.Sprintf("HTTP %d at %s", resp.StatusCode, target)

	// Capture body for critical/high hits
	if rule.captureBody && (rule.severity == output.Critical || rule.severity == output.High) {
		// Sanitize null bytes
		snippet := strings.ReplaceAll(string(body), "\x00", "")
		snippet = strings.TrimSpace(snippet)
		if len(snippet) > 300 {
			snippet = snippet[:300] + "..."
		}
		if len(snippet) > 0 {
			evidence += "\n  " + snippet
		}
	}

	return &output.Finding{
		Severity:      rule.severity,
		Title:         rule.title,
		AffectedAsset: target,
		Description:   fmt.Sprintf("%s returned HTTP %d", rule.path, resp.StatusCode),
		Evidence:      evidence,
		Remediation:   fmt.Sprintf("Restrict or remove %s from public access.", rule.path),
	}
}

// Run probes all live hosts for exposed paths
func Run(out *output.Renderer, liveHosts []output.ProbeResult, deep bool, timeout int, threads int) []output.Finding {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects for path probing
		},
	}

	rules := loadRules("wordlists/paths/default.txt")
	if deep {
		rules = append(rules, loadRules("wordlists/paths/deep.txt")...)
	}

	totalJobs := len(liveHosts) * len(rules)
	var allFindings []output.Finding
	mu := sync.Mutex{}
	sem := make(chan struct{}, threads) // Use user-defined concurrency
	var wg sync.WaitGroup

	completed := 0
	for _, host := range liveHosts {
		baseline := getBaseline(client, host.URL)
		for _, rule := range rules {
			wg.Add(1)
			sem <- struct{}{}
			go func(h output.ProbeResult, r pathRule, bl baselineResponse) {
				defer wg.Done()
				defer func() { <-sem }()
				if f := checkPath(client, h.URL, r, bl); f != nil {
					mu.Lock()
					allFindings = append(allFindings, *f)
					mu.Unlock()
				}
				mu.Lock()
				completed++
				if completed%10 == 0 || completed == totalJobs {
					out.Progress(completed, totalJobs, "Probing Paths")
				}
				mu.Unlock()
			}(host, rule, baseline)
		}
	}
	wg.Wait()
	return allFindings
}
