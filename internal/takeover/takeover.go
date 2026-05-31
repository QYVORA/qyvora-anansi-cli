package takeover

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hsociety/anansi-cli/internal/output"
)

type serviceFingerprint struct {
	name        string
	cnameSuffix string
	bodyMatch   string
}

var fingerprints = []serviceFingerprint{
	{"GitHub Pages", "github.io", "There isn't a GitHub Pages site here"},
	{"Heroku", "herokuapp.com", "No such app"},
	{"Fastly", "fastly.net", "Fastly error: unknown domain"},
	{"AWS S3", "s3.amazonaws.com", "NoSuchBucket"},
	{"AWS CloudFront", "cloudfront.net", "The request could not be satisfied"},
	{"Netlify", "netlify.app", "Not Found - Request ID"},
	{"Vercel", "vercel.app", "The deployment could not be found"},
	{"Surge.sh", "surge.sh", "project not found"},
	{"Ghost", "ghost.io", "Failed to resolve DNS"},
	{"Pantheon", "pantheonsite.io", "404 error unknown site"},
	{"Azure", "azurewebsites.net", "Error 404 - Web app not found"},
	{"Shopify", "myshopify.com", "Sorry, this shop is currently unavailable"},
	{"Tumblr", "tumblr.com", "There's nothing here"},
	{"WordPress.com", "wordpress.com", "Do you want to register"},
	{"Zendesk", "zendesk.com", "Help Center Closed"},
	{"ReadMe.io", "readme.io", "Project doesnt exist"},
	{"Fly.io", "fly.dev", "404 Not Found"},
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
func Run(subdomains []output.SubdomainResult, timeout int) []output.Finding {
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

	var findings []output.Finding
	mu := sync.Mutex{}
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, s := range subdomains {
		if s.Resolved {
			continue // alive — skip
		}
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
				return
			}

			if f := checkTakeover(client, sub.FQDN, deadCNAMEs); f != nil {
				mu.Lock()
				findings = append(findings, *f)
				mu.Unlock()
			}
		}(s)
	}
	wg.Wait()
	return findings
}
