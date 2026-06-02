package tls

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/wsuits6/hsociety-anansi-cli/internal/output"
)

func probeHost(hostname string, timeout int) (*output.TLSResult, error) {
	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", hostname+":443", &tls.Config{
		InsecureSkipVerify: true,
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

	cert := state.PeerCertificates[0]
	now := time.Now()
	days := int(cert.NotAfter.Sub(now).Hours() / 24)

	// Extract SANs
	var sans []string
	for _, dns := range cert.DNSNames {
		sans = append(sans, strings.TrimPrefix(dns, "*."))
	}

	issuerOrg := ""
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = cert.Issuer.Organization[0]
	} else if cert.Issuer.CommonName != "" {
		issuerOrg = cert.Issuer.CommonName
	}

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

	result.Findings = generateFindings(result)
	return result, nil
}

func generateFindings(r *output.TLSResult) []output.Finding {
	var findings []output.Finding

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
		findings = append(findings, output.Finding{
			Severity:      output.High,
			Title:         fmt.Sprintf("TLS Certificate Expiring in %d Days", r.DaysUntilExpiry),
			AffectedAsset: r.Hostname,
			Evidence:      fmt.Sprintf("NotAfter: %s", r.ValidTo),
			Remediation:   "Renew the TLS certificate before expiry.",
		})
	}

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

// Run probes TLS on all live hosts and returns results + any new subdomains from SANs
func Run(liveProbes []output.ProbeResult, targetDomain string, timeout int) ([]output.TLSResult, []output.SubdomainResult) {
	results := make([]output.TLSResult, 0)
	mu := sync.Mutex{}
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, p := range liveProbes {
		if !strings.HasPrefix(p.URL, "https://") {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(pr output.ProbeResult) {
			defer wg.Done()
			defer func() { <-sem }()
			r, err := probeHost(pr.FQDN, timeout)
			if err != nil {
				return
			}
			mu.Lock()
			results = append(results, *r)
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	// Extract new subdomains from SANs
	var newSubdomains []output.SubdomainResult
	seen := map[string]struct{}{}
	for _, r := range results {
		for _, san := range r.SANs {
			san = strings.ToLower(san)
			if !strings.HasSuffix(san, "."+targetDomain) {
				continue
			}
			if _, exists := seen[san]; exists {
				continue
			}
			seen[san] = struct{}{}
			ips, _ := net.LookupHost(san)
			newSubdomains = append(newSubdomains, output.SubdomainResult{
				FQDN:     san,
				Source:   "san",
				IPs:      ips,
				Resolved: len(ips) > 0,
			})
		}
	}

	return results, newSubdomains
}
