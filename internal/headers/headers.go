package headers

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/wsuits6/hsociety-anansi-cli/internal/output"
)

var securityHeaders = []string{
	"strict-transport-security",
	"content-security-policy",
	"x-frame-options",
	"x-content-type-options",
	"referrer-policy",
	"permissions-policy",
}

var headerRules = []struct {
	header      string
	title       string
	severity    string
	description string
	remediation string
}{
	{"strict-transport-security", "Missing HSTS", output.High,
		"Absence of HSTS exposes users to SSL stripping attacks.",
		"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"},
	{"content-security-policy", "Missing Content-Security-Policy", output.Medium,
		"No CSP defined — XSS and data injection attacks not mitigated.",
		"Define a Content-Security-Policy header appropriate for your application."},
	{"x-frame-options", "Missing X-Frame-Options", output.Medium,
		"Page can be embedded in iframes — clickjacking risk.",
		"Add: X-Frame-Options: DENY"},
	{"x-content-type-options", "Missing X-Content-Type-Options", output.Low,
		"Browser MIME sniffing may enable content injection.",
		"Add: X-Content-Type-Options: nosniff"},
	{"referrer-policy", "Missing Referrer-Policy", output.Low,
		"Sensitive URL data may leak via the Referer header.",
		"Add: Referrer-Policy: strict-origin-when-cross-origin"},
	{"permissions-policy", "Missing Permissions-Policy", output.Low,
		"Browser APIs (camera, mic, geolocation) are unrestricted.",
		"Add a Permissions-Policy header to restrict unnecessary APIs."},
}

func auditURL(url string, timeout int) *output.HeaderResult {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// CORS check — inject evil origin
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ANANSI-CLI/1.0)")
	req.Header.Set("Origin", "https://evil-attacker.com")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Collect all security headers
	hmap := map[string]string{}
	for _, h := range securityHeaders {
		hmap[h] = resp.Header.Get(h)
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	result := &output.HeaderResult{
		URL:     url,
		Headers: hmap,
		CORS:    acao,
	}

	// Generate findings for missing headers
	for _, rule := range headerRules {
		if hmap[rule.header] == "" {
			result.Findings = append(result.Findings, output.Finding{
				Severity:      rule.severity,
				Title:         rule.title,
				AffectedAsset: url,
				Description:   rule.description,
				Evidence:      "Header \"" + rule.header + "\" absent from response",
				Remediation:   rule.remediation,
			})
		}
	}

	// CORS findings
	if acao == "*" {
		result.Findings = append(result.Findings, output.Finding{
			Severity:      output.Medium,
			Title:         "CORS Wildcard Origin",
			AffectedAsset: url,
			Description:   "Server allows requests from any origin.",
			Evidence:      "Access-Control-Allow-Origin: *",
			Remediation:   "Restrict CORS to specific trusted origins.",
		})
	} else if strings.Contains(acao, "evil-attacker.com") {
		sev := output.High
		title := "CORS Origin Reflection"
		desc := "Server reflects arbitrary Origin header."
		if strings.EqualFold(acac, "true") {
			sev = output.Critical
			title = "CORS Origin Reflection with Credentials"
			desc = "Server reflects arbitrary origin AND allows credentials — full CORS exploit chain possible."
		}
		result.Findings = append(result.Findings, output.Finding{
			Severity:      sev,
			Title:         title,
			AffectedAsset: url,
			Description:   desc,
			Evidence:      "ACAO: " + acao + " | ACAC: " + acac,
			Remediation:   "Validate Origin against a strict allowlist. Never combine reflection with credentials.",
		})
	}

	return result
}

// Run audits security headers for all live probe results
func Run(probeResults []output.ProbeResult, liveHosts []output.ProbeResult) []output.HeaderResult {
	results := make([]output.HeaderResult, 0, len(liveHosts))
	for _, p := range liveHosts {
		r := auditURL(p.URL, 5)
		if r != nil {
			results = append(results, *r)
		}
	}
	return results
}
