// Package discovery implements subdomain enumeration through two techniques:
// 1. Certificate Transparency logs via crt.sh API
// 2. DNS brute-force using built-in wordlists
// All discovered subdomains are then resolved to check if they're live.
package discovery

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wsuits6/hsociety-anansi-cli/internal/assets"
	"github.com/wsuits6/hsociety-anansi-cli/internal/output"
)

// crtEntry represents a single entry from the crt.sh JSON API response.
// The name_value field can contain multiple DNS names separated by newlines.
type crtEntry struct {
	NameValue string `json:"name_value"` // DNS name(s) from the certificate
}

// fetchCrtSh queries the crt.sh Certificate Transparency log database for subdomains.
// It searches for all certificates matching "%.target.com" and extracts DNS names.
// Returns a deduplicated list of subdomains. Timeout is doubled for this operation
// because crt.sh can be slow to respond.
func fetchCrtSh(target string, timeout int) ([]string, error) {
	client := &http.Client{Timeout: time.Duration(timeout*2) * time.Second}
	// The %25 is URL-encoded %, so this searches for "%.target.com"
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

	// Deduplicate and normalize all DNS names found in certificates
	seen := map[string]struct{}{}
	var results []string
	for _, e := range entries {
		// Certificate names can be newline-separated (SANs)
		for _, name := range strings.Split(e.NameValue, "\n") {
			clean := strings.ToLower(strings.TrimSpace(name))
			clean = strings.TrimPrefix(clean, "*.") // Remove wildcard prefix
			// Only keep subdomains that belong to our target domain
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

// resolveHost attempts to resolve a FQDN to IP addresses.
// Returns (IPs, deadCNAMEs). If DNS resolution fails but a CNAME exists that doesn't resolve,
// it's returned as a "dead CNAME" which could indicate a subdomain takeover vulnerability.
func resolveHost(fqdn string) ([]string, []string) {
	ips, err := net.LookupHost(fqdn)
	if err != nil {
		// Host doesn't resolve to an IP. Check if there's a CNAME record
		// that points somewhere but doesn't resolve (potential takeover).
		cname, cerr := net.LookupCNAME(fqdn)
		// If CNAME exists and is different from the input
		if cerr == nil && cname != fqdn+"." {
			return nil, []string{strings.TrimSuffix(cname, ".")}
		}
		return nil, nil
	}

	// Filter to only public IPs (exclude private ranges, localhost, etc.)
	var publicIPs []string
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed != nil && !parsed.IsPrivate() && !parsed.IsLoopback() {
			publicIPs = append(publicIPs, ip)
		}
	}
	return publicIPs, nil
}

// Run executes the full subdomain discovery process:
// 1. Fetch subdomains from crt.sh Certificate Transparency logs
// 2. Generate candidates from wordlist (default or deep)
// 3. Resolve all candidates concurrently via DNS
// 4. Return results with resolution status and any dead CNAMEs
func Run(target string, deep bool, timeout int, customWordlist string, threads int) ([]output.SubdomainResult, error) {
	// Fetch subdomains from Certificate Transparency logs
	crtDomains, _ := fetchCrtSh(target, timeout)

	// Load wordlist (from file or embedded)
	wordlist := assets.LoadWordlist(customWordlist, deep)

	// Build master candidate list: combine crt.sh results with wordlist guesses
	// We track the source of each subdomain for reporting purposes
	seen := map[string]string{} // fqdn → source ("crtsh" or "wordlist")
	for _, d := range crtDomains {
		seen[d] = "crtsh"
	}
	// Always include the apex domain (e.g., example.com itself)
	if _, exists := seen[target]; !exists {
		seen[target] = "wordlist"
	}
	// Add all wordlist-based guesses (e.g., "api.example.com", "dev.example.com")
	for _, prefix := range wordlist {
		fqdn := prefix + "." + target
		if _, exists := seen[fqdn]; !exists {
			seen[fqdn] = "wordlist"
		}
	}

	// Convert map to job slice for concurrent processing
	type job struct {
		fqdn   string
		source string
	}
	jobs := make([]job, 0, len(seen))
	for fqdn, src := range seen {
		jobs = append(jobs, job{fqdn, src})
	}

	// Resolve all candidates concurrently with a semaphore to limit parallelism
	results := make([]output.SubdomainResult, 0, len(jobs))
	mu := sync.Mutex{}
	sem := make(chan struct{}, threads) // Use user-defined concurrency
	var wg sync.WaitGroup

	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore slot
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore slot

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

// LiveHosts filters subdomain results to return only the FQDNs that resolved to a public IP.
// This is used to determine which hosts should be probed in subsequent scan phases.
func LiveHosts(subdomains []output.SubdomainResult) []string {
	var live []string
	for _, s := range subdomains {
		if s.Resolved {
			live = append(live, s.FQDN)
		}
	}
	return live
}
