package headers

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/wsuits6/qyvora-anansi-cli/internal/assets"
	"github.com/wsuits6/qyvora-anansi-cli/internal/output"
)

type headerRule struct {
	header      string
	title       string
	severity    string
	description string
	remediation string
}

var securityHeaders []string
var headerRules []headerRule

func init() {
	lines := assets.LoadData("wordlists/headers/rules.txt")
	for _, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) == 5 {
			rule := headerRule{
				header:      parts[0],
				title:       parts[1],
				severity:    parts[2],
				description: parts[3],
				remediation: parts[4],
			}
			headerRules = append(headerRules, rule)
			securityHeaders = append(securityHeaders, rule.header)
		}
	}
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
