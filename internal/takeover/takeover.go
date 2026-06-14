package takeover

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wsuits6/qyvora-anansi-cli/internal/assets"
	"github.com/wsuits6/qyvora-anansi-cli/internal/output"
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

func checkTakeover(client *http.Client, subdomain string, deadCNAMEs []string) *output.Finding {
	for _, cname := range deadCNAMEs {
		cnameLower := strings.ToLower(cname)
		for _, fp := range fingerprints {
			if !strings.Contains(cnameLower, fp.cnameSuffix) {
				continue
			}
			// CNAME matches — confirm with body fingerprint
			resp, err := client.Get("http://" + subdomain)
			if err != nil {
				// Also try with HTTPS
				resp, err = client.Get("https://" + subdomain)
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
	// Also check if the CNAME itself resolves
	_, err = net.LookupHost(cname)
	if err == nil {
		return nil // CNAME resolves fine — not a dead record
	}
	return []string{cname}
}

// Run checks all dead subdomains for takeover candidates
func Run(out *output.Renderer, subdomains []output.SubdomainResult, timeout int, threads int) []output.Finding {
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
			candidates = append(candidates, s)
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	var findings []output.Finding
	mu := sync.Mutex{}
	sem := make(chan struct{}, threads) // Use user-defined concurrency
	var wg sync.WaitGroup

	completed := 0
	for _, s := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(sub output.SubdomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			// Use stored dead CNAMEs if available, otherwise resolve now
			deadCNAMEs := sub.DeadCNAMEs
			if len(deadCNAMEs) == 0 {
				deadCNAMEs = resolveCNAMEs(sub.FQDN)
			}
			if len(deadCNAMEs) == 0 {
				mu.Lock()
				completed++
				out.Progress(completed, len(candidates), "Takeover check")
				mu.Unlock()
				return
			}

			if f := checkTakeover(client, sub.FQDN, deadCNAMEs); f != nil {
				mu.Lock()
				findings = append(findings, *f)
				mu.Unlock()
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
