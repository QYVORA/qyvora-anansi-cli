// Package takeover detects subdomain takeover vulnerabilities by identifying
// dangling CNAME records — DNS entries that point to third-party services
// (GitHub Pages, Heroku, AWS S3, etc.) where the resource has been deleted
// or is otherwise unclaimed, allowing an attacker to claim it.
package takeover

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/QYVORA/qyvora-anansi-cli/internal/assets"
	"github.com/QYVORA/qyvora-anansi-cli/internal/output"
)

type serviceFingerprint struct {
	name        string
	cnameSuffix string
	bodyMatch   string
}

var fingerprints []serviceFingerprint

func init() {
	lines := assets.LoadData("wordlists/takeover/fingerprints.txt")
	for _, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) == 3 {
			fingerprints = append(fingerprints, serviceFingerprint{
				name:        parts[0],
				cnameSuffix: parts[1],
				bodyMatch:   parts[2],
			})
		}
	}
}

func checkTakeover(client *http.Client, subdomain string, deadCNAMEs []string, stealth bool) *output.Finding {
	for _, cname := range deadCNAMEs {
		cnameLower := strings.ToLower(cname)
		for _, fp := range fingerprints {
			if !strings.Contains(cnameLower, fp.cnameSuffix) {
				continue
			}

			req, err := http.NewRequest("GET", "http://"+subdomain, nil)
			if err != nil {
				continue
			}
			if stealth {
				req.Header.Set("User-Agent", output.RandomUA())
			} else {
				req.Header.Set("User-Agent", output.DefaultUA)
			}

			resp, err := client.Do(req)
			if err != nil {
				req, _ = http.NewRequest("GET", "https://"+subdomain, nil)
				if stealth {
					req.Header.Set("User-Agent", output.RandomUA())
				} else {
					req.Header.Set("User-Agent", output.DefaultUA)
				}
				resp, err = client.Do(req)
				if err != nil {
					continue
				}
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()

			if strings.Contains(strings.ToLower(string(body)), strings.ToLower(fp.bodyMatch)) {
				return &output.Finding{
					Severity:      output.Critical,
					Title:         "Subdomain Takeover — " + fp.name,
					AffectedAsset: subdomain,
					Description:   subdomain + " has a dangling CNAME to " + fp.name + " (" + cname + ") but the resource is unclaimed. This subdomain can be taken over.",
					Evidence:      "CNAME: " + cname + " | Body match: \"" + fp.bodyMatch + "\"",
					Remediation:   "Remove the dangling CNAME for " + subdomain + " or claim the resource on " + fp.name + ".",
				}
			}
		}
	}
	return nil
}

func resolveCNAMEs(fqdn string) []string {
	cname, err := net.LookupCNAME(fqdn)
	if err != nil || cname == fqdn+"." {
		return nil
	}
	cname = strings.TrimSuffix(cname, ".")
	if _, err := net.LookupHost(cname); err == nil {
		return nil
	}
	return []string{cname}
}

// Run checks all unresolved subdomains for takeover candidates.  It uses
// dead CNAMEs gathered during discovery and attempts to confirm the
// vulnerability by checking the response body for known service fingerprints.
func Run(out *output.Renderer, subdomains []output.SubdomainResult, timeout int, threads int, delayMs int, stealth bool) []output.Finding {
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

	var candidates []output.SubdomainResult
	for _, s := range subdomains {
		if !s.Resolved {
			if len(s.DeadCNAMEs) > 0 || s.Source == output.SourceSAN {
				candidates = append(candidates, s)
			} else {
				out.Verbose(fmt.Sprintf("Subdomain skipped for takeover (no dead CNAME): %s", s.FQDN))
			}
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	var findings []output.Finding
	mu := sync.Mutex{}
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	completed := 0
	for _, s := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(sub output.SubdomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			delay := output.JitterDelay(delayMs, stealth)
			if delay > 0 {
				time.Sleep(delay)
			}

			deadCNAMEs := sub.DeadCNAMEs
			if len(deadCNAMEs) == 0 {
				deadCNAMEs = resolveCNAMEs(sub.FQDN)
			}
			if len(deadCNAMEs) == 0 {
				out.Verbose(fmt.Sprintf("Subdomain has no dead CNAMEs: %s", sub.FQDN))
				mu.Lock()
				completed++
				out.Progress(completed, len(candidates), "Takeover check")
				mu.Unlock()
				return
			}

			if f := checkTakeover(client, sub.FQDN, deadCNAMEs, stealth); f != nil {
				mu.Lock()
				findings = append(findings, *f)
				mu.Unlock()
			} else {
				out.Verbose(fmt.Sprintf("Subdomain not vulnerable to takeover: %s (%s)", sub.FQDN, strings.Join(deadCNAMEs, ", ")))
			}
			mu.Lock()
			completed++
			out.Progress(completed, len(candidates), "Takeover check")
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	return findings
}
