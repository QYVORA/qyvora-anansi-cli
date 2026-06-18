// Package tls implements TLS/SSL certificate analysis and security checks.
// It examines certificate validity, protocols, ciphers, and extracts Subject Alternative Names (SANs).
package tls

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/wsuits6/qyvora-anansi-cli/internal/output"
)

// probeHost establishes a TLS connection and extracts certificate details.
// Deliberately uses InsecureSkipVerify to test hosts with invalid certs.
func probeHost(hostname string, timeout int) (*output.TLSResult, error) {
	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", hostname+":443", &tls.Config{
		InsecureSkipVerify: true,  // Accept self-signed and expired certs
		ServerName:         hostname,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates")
	}

	// Parse the leaf certificate (first in chain)
	cert := state.PeerCertificates[0]
	now := time.Now()
	days := int(cert.NotAfter.Sub(now).Hours() / 24)

	// Extract SANs (Subject Alternative Names) from certificate
	var sans []string
	for _, dns := range cert.DNSNames {
		sans = append(sans, strings.TrimPrefix(dns, "*.")) // Remove wildcard prefix
	}

	// Determine certificate issuer
	issuerOrg := ""
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = cert.Issuer.Organization[0]
	} else if cert.Issuer.CommonName != "" {
		issuerOrg = cert.Issuer.CommonName
	}

	// Detect self-signed certificates (issuer == subject, no organization)
	selfSigned := cert.Issuer.CommonName == cert.Subject.CommonName && len(cert.Issuer.Organization) == 0

	result := &output.TLSResult{
		Hostname:        hostname,
		Protocol:        tlsVersionName(state.Version),
		Cipher:          tls.CipherSuiteName(state.CipherSuite),
		Issuer:          issuerOrg,
		Subject:         cert.Subject.CommonName,
		ValidFrom:       cert.NotBefore.Format("2006-01-02"),
		ValidTo:         cert.NotAfter.Format("2006-01-02"),
		DaysUntilExpiry: days,
		Expired:         days < 0,
		ExpiringSoon:    days >= 0 && days <= 30,
		SelfSigned:      selfSigned,
		SANs:            sans,
	}

	// Generate security findings based on certificate analysis
	result.Findings = generateFindings(result)
	return result, nil
}

// generateFindings creates vulnerability findings based on TLS certificate analysis.
// Checks for: expired certs, expiring soon, self-signed, weak protocols.
func generateFindings(r *output.TLSResult) []output.Finding {
	var findings []output.Finding

	// Check for expired certificates
	if r.Expired {
		findings = append(findings, output.Finding{
			Severity:      output.Critical,
			Title:         "TLS Certificate Expired",
			AffectedAsset: r.Hostname,
			Description:   fmt.Sprintf("Certificate expired on %s.", r.ValidTo),
			Evidence:      fmt.Sprintf("NotAfter: %s (%d days ago)", r.ValidTo, -r.DaysUntilExpiry),
			Remediation:   "Renew the TLS certificate immediately.",
		})
	} else if r.ExpiringSoon {
		// Warn if certificate expires within 30 days
		findings = append(findings, output.Finding{
			Severity:      output.High,
			Title:         fmt.Sprintf("TLS Certificate Expiring in %d Days", r.DaysUntilExpiry),
			AffectedAsset: r.Hostname,
			Evidence:      fmt.Sprintf("NotAfter: %s", r.ValidTo),
			Remediation:   "Renew the TLS certificate before expiry.",
		})
	}

	// Self-signed certificates are not trusted by browsers
	if r.SelfSigned {
		findings = append(findings, output.Finding{
			Severity:      output.High,
			Title:         "Self-Signed TLS Certificate",
			AffectedAsset: r.Hostname,
			Description:   "Certificate is not signed by a trusted CA.",
			Evidence:      fmt.Sprintf("Issuer CN: %s == Subject CN: %s", r.Issuer, r.Subject),
			Remediation:   "Replace with a certificate from a trusted CA (e.g. Let's Encrypt).",
		})
	}

	// Detect deprecated/weak TLS protocols
	weakProtos := map[string]bool{"TLS 1.0": true, "TLS 1.1": true, "SSL 3.0": true, "SSL 2.0": true}
	if weakProtos[r.Protocol] {
		findings = append(findings, output.Finding{
			Severity:      output.High,
			Title:         fmt.Sprintf("Weak TLS Protocol: %s", r.Protocol),
			AffectedAsset: r.Hostname,
			Description:   fmt.Sprintf("Server negotiated deprecated protocol %s.", r.Protocol),
			Evidence:      fmt.Sprintf("Protocol: %s", r.Protocol),
			Remediation:   "Disable TLS 1.0 and 1.1. Enforce TLS 1.2+ only.",
		})
	}

	return findings
}

// tlsVersionName converts the Go TLS version constant to a human-readable string.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// Run probes TLS on all HTTPS hosts and returns:
// 1. TLS analysis results (certificate info, expiry, protocol strength)
// 2. Any new subdomains discovered from certificate SANs
//
// Only probes hosts that are accessible via HTTPS (determined by prior probe phase).
func Run(liveProbes []output.ProbeResult, targetDomain string, timeout int, threads int, delayMs int) ([]output.TLSResult, []output.SubdomainResult) {
	results := make([]output.TLSResult, 0)
	mu := sync.Mutex{}
	sem := make(chan struct{}, threads) // Use user-defined concurrency
	var wg sync.WaitGroup

	for _, p := range liveProbes {
		// Skip hosts that only respond to HTTP (not HTTPS)
		if !strings.HasPrefix(p.URL, "https://") {
			mu.Lock()
			results = append(results, output.TLSResult{
				Hostname:  p.FQDN,
				Supported: false,
				Error:     "No HTTPS support (HTTP only)",
			})
			mu.Unlock()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(pr output.ProbeResult) {
			defer wg.Done()
			defer func() { <-sem }()
			if delayMs > 0 {
				time.Sleep(time.Duration(delayMs) * time.Millisecond)
			}
			r, err := probeHost(pr.FQDN, timeout)
			mu.Lock()
			if err != nil {
				results = append(results, output.TLSResult{
					Hostname:  pr.FQDN,
					Supported: false,
					Error:     err.Error(),
				})
			} else {
				r.Supported = true
				results = append(results, *r)
			}
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	// Extract new subdomains from SANs (Subject Alternative Names)
	// SANs often reveal additional infrastructure not found in DNS brute-force
	var newSubdomains []output.SubdomainResult
	seen := map[string]struct{}{}
	for _, r := range results {
		for _, san := range r.SANs {
			san = strings.ToLower(san)
			// Only include SANs that belong to our target domain
			if !strings.HasSuffix(san, "."+targetDomain) {
				continue
			}
			if _, exists := seen[san]; exists {
				continue // Already processed this SAN
			}
			seen[san] = struct{}{}
			// Try to resolve the SAN to see if it's a live subdomain
			ips, _ := net.LookupHost(san)
			newSubdomains = append(newSubdomains, output.SubdomainResult{
				FQDN:     san,
				Source:   "san", // Mark source as SAN discovery
				IPs:      ips,
				Resolved: len(ips) > 0,
			})
		}
	}

	return results, newSubdomains
}
