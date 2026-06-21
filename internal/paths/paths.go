// Package paths probes live hosts for exposed sensitive files and endpoints
// such as /.env, /.git/config, /admin, /api-docs, and other common targets.
// It uses a per-host 404 baseline to reduce false positives and follows
// redirect chains to distinguish real endpoints from root-redirects.
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
	captureBody bool
}

func loadRules(filename string) []pathRule {
	lines := assets.LoadData(filename)
	var rules []pathRule
	for _, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		capture := len(parts) >= 4 && parts[3] == "true"
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
	req.Header.Set("User-Agent", output.DefaultUA)

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

func (r pathRule) checkPath(client *http.Client, baseURL string, baseline baselineResponse, stealth bool) *output.Finding {
	target := strings.TrimRight(baseURL, "/") + r.path
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil
	}

	if stealth {
		req.Header.Set("User-Agent", output.RandomUA())
	} else {
		req.Header.Set("User-Agent", output.DefaultUA)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 || resp.StatusCode == 400 || resp.StatusCode == 410 || resp.StatusCode == 403 {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5000))
	if resp.StatusCode == baseline.statusCode && len(body) == baseline.bodyLen {
		return nil
	}

	severity := r.severity
	title := r.title
	description := fmt.Sprintf("%s returned HTTP %d", r.path, resp.StatusCode)
	evidence := fmt.Sprintf("HTTP %d at %s", resp.StatusCode, target)

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		followClient := &http.Client{
			Timeout:   client.Timeout,
			Transport: client.Transport,
		}
		fReq, fErr := http.NewRequest("GET", target, nil)
		if fErr == nil {
			fReq.Header.Set("User-Agent", output.DefaultUA)
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

				if finalStatus == 404 || finalStatus == 400 || finalStatus == 410 || finalStatus == 403 || isRootRedirect {
					severity = output.Info
					title = "[POTENTIAL FALSE POSITIVE] " + r.title
					description = fmt.Sprintf("%s returned HTTP %d but redirects to %s (HTTP %d)", r.path, resp.StatusCode, finalURL, finalStatus)
					evidence = fmt.Sprintf("Redirect: HTTP %d -> %s (HTTP %d)", resp.StatusCode, finalURL, finalStatus)
				} else {
					evidence = fmt.Sprintf("Redirect: HTTP %d -> %s (HTTP %d)", resp.StatusCode, finalURL, finalStatus)
				}
			}
		}
	}

	if severity != output.Info && r.captureBody && (severity == output.Critical || severity == output.High) {
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
		Remediation:   fmt.Sprintf("Restrict or remove %s from public access.", r.path),
	}
}

// hostProbeJob pairs a live host with its cached 404 baseline so that
// the inner path checks can run against it.
type hostProbeJob struct {
	host     output.ProbeResult
	baseline baselineResponse
}

// Run probes all live hosts for exposed paths and returns any findings.
// A per-host 404 baseline is established first, then each path rule is
// checked against the host in a single flat worker pool — avoiding the
// nested-goroutine pattern that previously caused a race condition.
func Run(out *output.Renderer, liveHosts []output.ProbeResult, deep bool, timeout int, threads int, delayMs int, stealth bool) []output.Finding {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	rules := loadRules("wordlists/paths/default.txt")
	if deep {
		rules = append(rules, loadRules("wordlists/paths/deep.txt")...)
	}

	if len(liveHosts) == 0 || len(rules) == 0 {
		return nil
	}

	// Build a per-host baseline cache to avoid re-fetching for every rule.
	baselineCache := make(map[string]baselineResponse, len(liveHosts))
	for _, host := range liveHosts {
		baselineCache[host.URL] = getBaseline(client, host.URL)
	}

	// Build flat job list: one job per (host, rule) pair.
	type pair struct {
		host output.ProbeResult
		rule pathRule
	}

	var pairs []pair
	for _, host := range liveHosts {
		for _, rule := range rules {
			pairs = append(pairs, pair{host, rule})
		}
	}

	var allFindings []output.Finding
	mu := sync.Mutex{}
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	completed := 0
	totalJobs := len(pairs)

	for _, p := range pairs {
		wg.Add(1)
		sem <- struct{}{}
		go func(h output.ProbeResult, r pathRule) {
			defer wg.Done()
			defer func() { <-sem }()

			delay := output.JitterDelay(delayMs, stealth)
			if delay > 0 {
				time.Sleep(delay)
			}

			f := r.checkPath(client, h.URL, baselineCache[h.URL], stealth)
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
		}(p.host, p.rule)
	}
	wg.Wait()

	return allFindings
}
