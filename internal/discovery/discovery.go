package discovery

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wsuits6/hsociety-anansi-cli/internal/output"
)

type crtEntry struct {
	NameValue string `json:"name_value"`
}

func fetchCrtSh(target string, timeout int) ([]string, error) {
	client := &http.Client{Timeout: time.Duration(timeout*2) * time.Second}
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var entries []crtEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("json decode error: %w", err)
	}

	seen := map[string]struct{}{}
	var results []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			clean := strings.ToLower(strings.TrimSpace(name))
			clean = strings.TrimPrefix(clean, "*.")
			if strings.HasSuffix(clean, "."+target) || clean == target {
				if _, exists := seen[clean]; !exists {
					seen[clean] = struct{}{}
					results = append(results, clean)
				}
			}
		}
	}
	return results, nil
}

func resolveHost(fqdn string) ([]string, []string) {
	ips, err := net.LookupHost(fqdn)
	if err != nil {
		// Try CNAME for dead subdomain takeover detection
		cname, cerr := net.LookupCNAME(fqdn)
		if cerr == nil && cname != fqdn+"." {
			return nil, []string{strings.TrimSuffix(cname, ".")}
		}
		return nil, nil
	}

	var publicIPs []string
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed != nil && !parsed.IsPrivate() && !parsed.IsLoopback() {
			publicIPs = append(publicIPs, ip)
		}
	}
	return publicIPs, nil
}

// Run executes subdomain discovery via crt.sh + DNS wordlist
func Run(target string, deep bool, timeout int) ([]output.SubdomainResult, error) {
	// crt.sh lookup
	crtDomains, _ := fetchCrtSh(target, timeout)

	wordlist := DefaultWordlist
	if deep {
		wordlist = DeepWordlist
	}

	// Build candidate set: crt.sh + wordlist, deduplicated
	seen := map[string]string{} // fqdn → source
	for _, d := range crtDomains {
		seen[d] = "crtsh"
	}
	// Always include the apex
	if _, exists := seen[target]; !exists {
		seen[target] = "wordlist"
	}
	for _, prefix := range wordlist {
		fqdn := prefix + "." + target
		if _, exists := seen[fqdn]; !exists {
			seen[fqdn] = "wordlist"
		}
	}

	// Concurrent DNS resolution
	type job struct {
		fqdn   string
		source string
	}
	jobs := make([]job, 0, len(seen))
	for fqdn, src := range seen {
		jobs = append(jobs, job{fqdn, src})
	}

	results := make([]output.SubdomainResult, 0, len(jobs))
	mu := sync.Mutex{}
	sem := make(chan struct{}, 20) // max 20 concurrent DNS lookups
	var wg sync.WaitGroup

	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()

			ips, deadCNAMEs := resolveHost(j.fqdn)
			result := output.SubdomainResult{
				FQDN:       j.fqdn,
				Source:     j.source,
				IPs:        ips,
				DeadCNAMEs: deadCNAMEs,
				Resolved:   len(ips) > 0,
			}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(j)
	}
	wg.Wait()

	return results, nil
}

// LiveHosts returns only the FQDNs that resolved to a public IP
func LiveHosts(subdomains []output.SubdomainResult) []string {
	var live []string
	for _, s := range subdomains {
		if s.Resolved {
			live = append(live, s.FQDN)
		}
	}
	return live
}
