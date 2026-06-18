// Package discovery implements subdomain enumeration through two techniques:
// 1. Certificate Transparency logs via crt.sh API
// 2. DNS brute-force using built-in wordlists
// All discovered subdomains are then resolved to check if they're live.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wsuits6/qyvora-anansi-cli/internal/assets"
	"github.com/wsuits6/qyvora-anansi-cli/internal/output"
)

// Use a Go-native resolver to enable faster, non-blocking concurrent lookups
var dnsResolver = &net.Resolver{
	PreferGo: true,
}

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

// resolveHost attempts to resolve a FQDN to IP addresses using context for timeout.
// Returns (IPs, deadCNAMEs). If DNS resolution fails but a CNAME exists that doesn't resolve,
// it's returned as a "dead CNAME" which could indicate a subdomain takeover vulnerability.
func resolveHost(ctx context.Context, fqdn string) ([]string, []string) {
	ips, err := dnsResolver.LookupHost(ctx, fqdn)
	if err != nil {
		// Host doesn't resolve to an IP. Check if there's a CNAME record
		// that points somewhere but doesn't resolve (potential takeover).
		cname, cerr := dnsResolver.LookupCNAME(ctx, fqdn)
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

// detectWildcard checks if a domain has a wildcard DNS record by probing
// a random, non-existent subdomain. Returns the IPs it resolves to, if any.
func detectWildcard(ctx context.Context, target string) []string {
	randomSub := fmt.Sprintf("anansi-wildcard-test-%d.%s", time.Now().UnixNano(), target)
	ips, _ := dnsResolver.LookupHost(ctx, randomSub)
	return ips
}

// Run executes the full subdomain discovery process:
// 1. Fetch subdomains from crt.sh Certificate Transparency logs
// 2. Generate candidates from wordlist (default or deep)
// 3. Resolve all candidates concurrently via DNS
// 4. Return results with resolution status and any dead CNAMEs
func Run(out *output.Renderer, target string, deep bool, timeout int, customWordlist string, threads int, recursive bool, mutate bool, delayMs int) ([]output.SubdomainResult, error) {
	// Detect wildcard DNS
	out.Info("Detecting DNS wildcard...")
	ctxWildcard, cancelWildcard := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	wildcardIPs := detectWildcard(ctxWildcard, target)
	cancelWildcard()
	isWildcard := len(wildcardIPs) > 0
	wildcardMap := make(map[string]struct{})
	for _, ip := range wildcardIPs {
		wildcardMap[ip] = struct{}{}
		out.Info(fmt.Sprintf("Wildcard detected resolving to %s", ip))
	}

	// Fetch subdomains from Certificate Transparency logs
	out.Info("Querying crt.sh (Certificate Transparency)...")
	crtDomains, _ := fetchCrtSh(target, timeout)
	out.Info(fmt.Sprintf("crt.sh found %d potential subdomains", len(crtDomains)))

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

	out.Info(fmt.Sprintf("Resolving %d candidates with %d threads...", len(jobs), threads))

	// Resolve all candidates concurrently with a semaphore to limit parallelism
	results := make([]output.SubdomainResult, 0, len(jobs))
	mu := sync.Mutex{}
	sem := make(chan struct{}, threads) // Use user-defined concurrency
	var wg sync.WaitGroup

	completed := 0
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore slot
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore slot

			if delayMs > 0 {
				time.Sleep(time.Duration(delayMs) * time.Millisecond)
			}

			ctxResolve, cancelResolve := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
			ips, deadCNAMEs := resolveHost(ctxResolve, j.fqdn)
			cancelResolve()

			// If wildcard detected, filter out results that resolve to wildcard IPs
			// unless the subdomain was found via crt.sh (more likely to be legitimate)
			if isWildcard && j.source == "wordlist" && len(ips) > 0 {
				isOnlyWildcard := true
				for _, ip := range ips {
					if _, ok := wildcardMap[ip]; !ok {
						isOnlyWildcard = false
						break
					}
				}
				if isOnlyWildcard {
					ips = nil // Treat as non-resolving
				}
			}

			result := output.SubdomainResult{
				FQDN:       j.fqdn,
				Source:     j.source,
				IPs:        ips,
				DeadCNAMEs: deadCNAMEs,
				Resolved:   len(ips) > 0,
			}
			mu.Lock()
			results = append(results, result)
			completed++
			if completed%10 == 0 || completed == len(jobs) {
				out.Progress(completed, len(jobs), "Resolving")
			}
			mu.Unlock()
		}(j)
	}
	wg.Wait()

	// Perform recursive subdomain brute-forcing if enabled
	if recursive {
		var resolvedSubs []string
		for _, r := range results {
			if r.Resolved && r.FQDN != target {
				resolvedSubs = append(resolvedSubs, r.FQDN)
			}
		}

		if len(resolvedSubs) > 0 {
			out.Info(fmt.Sprintf("Running recursive brute-force on %d resolved subdomains...", len(resolvedSubs)))

			var recJobs []job
			seenRec := map[string]struct{}{}
			for _, r := range results {
				seenRec[r.FQDN] = struct{}{}
			}

			for _, sub := range resolvedSubs {
				for _, prefix := range wordlist {
					fqdn := prefix + "." + sub
					if _, exists := seenRec[fqdn]; !exists {
						seenRec[fqdn] = struct{}{}
						recJobs = append(recJobs, job{fqdn, "wordlist"})
					}
				}
			}

			if len(recJobs) > 0 {
				out.Info(fmt.Sprintf("Resolving %d recursive candidates with %d threads...", len(recJobs), threads))
				completedRec := 0
				var recWg sync.WaitGroup

				for _, j := range recJobs {
					recWg.Add(1)
					sem <- struct{}{}
					go func(j job) {
						defer recWg.Done()
						defer func() { <-sem }()

						if delayMs > 0 {
							time.Sleep(time.Duration(delayMs) * time.Millisecond)
						}

						ctxResolve, cancelResolve := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
						ips, deadCNAMEs := resolveHost(ctxResolve, j.fqdn)
						cancelResolve()

						if isWildcard && len(ips) > 0 {
							isOnlyWildcard := true
							for _, ip := range ips {
								if _, ok := wildcardMap[ip]; !ok {
									isOnlyWildcard = false
									break
								}
							}
							if isOnlyWildcard {
								ips = nil
							}
						}

						result := output.SubdomainResult{
							FQDN:       j.fqdn,
							Source:     j.source,
							IPs:        ips,
							DeadCNAMEs: deadCNAMEs,
							Resolved:   len(ips) > 0,
						}

						mu.Lock()
						results = append(results, result)
						completedRec++
						if completedRec%10 == 0 || completedRec == len(recJobs) {
							out.Progress(completedRec, len(recJobs), "Resolving")
						}
						mu.Unlock()
					}(j)
				}
				recWg.Wait()
			}
		}
	}

	// Perform subdomain mutation brute-forcing if enabled
	if mutate {
		var resolvedSubs []string
		for _, r := range results {
			if r.Resolved && r.FQDN != target {
				resolvedSubs = append(resolvedSubs, r.FQDN)
			}
		}

		mutatedCandidates := MutateSubdomains(resolvedSubs, target)
		if len(mutatedCandidates) > 0 {
			out.Info(fmt.Sprintf("Running subdomain mutation brute-force on %d candidates...", len(mutatedCandidates)))

			var mutJobs []job
			seenMut := map[string]struct{}{}
			for _, r := range results {
				seenMut[r.FQDN] = struct{}{}
			}

			for _, candidate := range mutatedCandidates {
				if _, exists := seenMut[candidate]; !exists {
					seenMut[candidate] = struct{}{}
					mutJobs = append(mutJobs, job{candidate, "mutation"})
				}
			}

			if len(mutJobs) > 0 {
				out.Info(fmt.Sprintf("Resolving %d mutated candidates with %d threads...", len(mutJobs), threads))
				completedMut := 0
				var mutWg sync.WaitGroup

				for _, j := range mutJobs {
					mutWg.Add(1)
					sem <- struct{}{}
					go func(j job) {
						defer mutWg.Done()
						defer func() { <-sem }()

						if delayMs > 0 {
							time.Sleep(time.Duration(delayMs) * time.Millisecond)
						}

						ctxResolve, cancelResolve := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
						ips, deadCNAMEs := resolveHost(ctxResolve, j.fqdn)
						cancelResolve()

						if isWildcard && len(ips) > 0 {
							isOnlyWildcard := true
							for _, ip := range ips {
								if _, ok := wildcardMap[ip]; !ok {
									isOnlyWildcard = false
									break
								}
							}
							if isOnlyWildcard {
								ips = nil
							}
						}

						result := output.SubdomainResult{
							FQDN:       j.fqdn,
							Source:     j.source,
							IPs:        ips,
							DeadCNAMEs: deadCNAMEs,
							Resolved:   len(ips) > 0,
						}

						mu.Lock()
						results = append(results, result)
						completedMut++
						if completedMut%10 == 0 || completedMut == len(mutJobs) {
							out.Progress(completedMut, len(mutJobs), "Resolving")
						}
						mu.Unlock()
					}(j)
				}
				mutWg.Wait()
			}
		}
	}

	return results, nil
}

// MutateSubdomains generates target-specific subdomain mutations from resolved prefixes
func MutateSubdomains(resolved []string, target string) []string {
	var mutated []string
	prefixes := make([]string, 0)
	for _, fqdn := range resolved {
		prefix := strings.TrimSuffix(fqdn, "."+target)
		if prefix != target && prefix != "" {
			prefixes = append(prefixes, prefix)
		}
	}

	if len(prefixes) == 0 {
		return nil
	}

	seen := map[string]struct{}{}
	commonWords := []string{"admin", "staging", "test", "prod", "internal", "dev", "api", "static", "corp"}

	for _, p := range prefixes {
		// 1. Append/Prepend common words with hyphen
		for _, w := range commonWords {
			if w != p {
				seen[p+"-"+w] = struct{}{}
				seen[w+"-"+p] = struct{}{}
			}
		}

		// 2. Increment/Decrement numbers if prefix ends in a number
		lastChar := p[len(p)-1]
		if lastChar >= '0' && lastChar <= '9' {
			base := p[:len(p)-1]
			seen[base+"1"] = struct{}{}
			seen[base+"2"] = struct{}{}
			seen[base+"3"] = struct{}{}
			seen[base+"4"] = struct{}{}
			seen[base+"5"] = struct{}{}
		}
	}

	// 3. Cross-mutation of found prefixes (e.g., api-dev, dev-api)
	if len(prefixes) > 1 {
		maxCombos := 100
		count := 0
		for i := 0; i < len(prefixes) && count < maxCombos; i++ {
			for j := 0; j < len(prefixes) && count < maxCombos; j++ {
				if i != j {
					seen[prefixes[i]+"-"+prefixes[j]] = struct{}{}
					count++
				}
			}
		}
	}

	for m := range seen {
		mutated = append(mutated, m+"."+target)
	}

	return mutated
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
