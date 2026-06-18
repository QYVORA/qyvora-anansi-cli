package paths

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	severity := rule.severity
	title := rule.title
	description := fmt.Sprintf("%s returned HTTP %d", rule.path, resp.StatusCode)
	evidence := fmt.Sprintf("HTTP %d at %s", resp.StatusCode, target)

	// If it's a redirect, trace the landing URL to detect false positives
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		followClient := &http.Client{
			Timeout:   client.Timeout,
			Transport: client.Transport,
		}
		fReq, fErr := http.NewRequest("GET", target, nil)
		if fErr == nil {
			fReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ANANSI-CLI/1.0)")
			fResp, fRespErr := followClient.Do(fReq)
			if fRespErr == nil {
				defer fResp.Body.Close()
				finalStatus := fResp.StatusCode
				finalURL := fResp.Request.URL.String()

				isRootRedirect := false
				uParsed, pErr := url.Parse(finalURL)
				if pErr == nil {
					pathClean := strings.Trim(uParsed.Path, "/")
					if pathClean == "" || pathClean == "index.html" || pathClean == "index.php" || pathClean == "home" {
						isRootRedirect = true
					}
				}

				// If it redirects to an error page or the root/homepage, it's likely a false positive
				if finalStatus == 404 || finalStatus == 400 || finalStatus == 410 || finalStatus == 403 || isRootRedirect {
					severity = output.Info
					title = "[POTENTIAL FALSE POSITIVE] " + rule.title
					description = fmt.Sprintf("%s returned HTTP %d but redirects to %s (HTTP %d)", rule.path, resp.StatusCode, finalURL, finalStatus)
					evidence = fmt.Sprintf("Redirect: HTTP %d -> %s (HTTP %d)", resp.StatusCode, finalURL, finalStatus)
				} else {
					evidence = fmt.Sprintf("Redirect: HTTP %d -> %s (HTTP %d)", resp.StatusCode, finalURL, finalStatus)
				}
			}
		}
	}

	// Capture body snippet for critical/high hits that are not flagged as false positives
	if severity != output.Info && rule.captureBody && (severity == output.Critical || severity == output.High) {
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
		Severity:      severity,
		Title:         title,
		AffectedAsset: target,
		Description:   description,
		Evidence:      evidence,
		Remediation:   fmt.Sprintf("Restrict or remove %s from public access.", rule.path),
	}
}

// Run probes all live hosts for exposed paths
func Run(out *output.Renderer, liveHosts []output.ProbeResult, deep bool, timeout int, threads int, delayMs int) []output.Finding {
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
		wg.Add(1)
		go func(h output.ProbeResult) {
			defer wg.Done()

			// Get baseline concurrently under semaphore
			sem <- struct{}{}
			baseline := getBaseline(client, h.URL)
			<-sem

			for _, rule := range rules {
				wg.Add(1)
				sem <- struct{}{}
				go func(r pathRule, bl baselineResponse) {
					defer wg.Done()
					defer func() { <-sem }()

					if delayMs > 0 {
						time.Sleep(time.Duration(delayMs) * time.Millisecond)
					}

					f := checkPath(client, h.URL, r, bl)
					if f != nil {
						mu.Lock()
						allFindings = append(allFindings, *f)
						mu.Unlock()
					} else {
						out.Verbose(fmt.Sprintf("Path not found: %s%s", h.URL, r.path))
					}

					mu.Lock()
					completed++
					if completed%10 == 0 || completed == totalJobs {
						out.Progress(completed, totalJobs, "Probing Paths")
					}
					mu.Unlock()
				}(rule, baseline)
			}
		}(host)
	}
	wg.Wait()
	return allFindings
}
