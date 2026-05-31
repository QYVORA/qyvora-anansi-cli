package paths

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hsociety/anansi-cli/internal/output"
)

type pathRule struct {
	path        string
	title       string
	severity    string
	captureBody bool // capture response body snippet as evidence
}

var defaultRules = []pathRule{
	{"/.env", "Exposed .env File", output.Critical, true},
	{"/.env.local", "Exposed .env.local", output.Critical, true},
	{"/.env.production", "Exposed .env.production", output.Critical, true},
	{"/.env.development", "Exposed .env.development", output.Critical, true},
	{"/.git/HEAD", "Exposed Git Repository", output.Critical, true},
	{"/.git/config", "Exposed Git Config", output.Critical, true},
	{"/wp-config.php", "WordPress Config Exposed", output.Critical, true},
	{"/db.sql", "Exposed SQL Dump", output.Critical, true},
	{"/dump.sql", "Exposed SQL Dump", output.Critical, true},
	{"/backup.sql", "Exposed SQL Dump", output.Critical, true},
	{"/phpmyadmin", "Exposed phpMyAdmin", output.Critical, false},
	{"/pma", "Exposed phpMyAdmin (pma)", output.Critical, false},
	{"/adminer.php", "Exposed Adminer Interface", output.Critical, false},
	{"/actuator/env", "Spring Actuator /env Exposed", output.Critical, true},
	{"/config.php", "Exposed PHP Config", output.High, true},
	{"/config.yml", "Exposed YAML Config", output.High, true},
	{"/config.json", "Exposed JSON Config", output.High, true},
	{"/backup.zip", "Exposed Backup Archive", output.High, false},
	{"/admin", "Exposed Admin Panel", output.High, false},
	{"/administrator", "Exposed Administrator Panel", output.High, false},
	{"/wp-admin", "Exposed WordPress Admin", output.High, false},
	{"/server-status", "Apache Server-Status Exposed", output.High, true},
	{"/actuator", "Spring Boot Actuator Exposed", output.High, false},
	{"/actuator/health", "Spring Boot Health Endpoint", output.Info, false},
	{"/wp-login.php", "WordPress Login Exposed", output.Medium, false},
	{"/xmlrpc.php", "WordPress XMLRPC Enabled", output.Medium, false},
	{"/.DS_Store", "Exposed .DS_Store File", output.Medium, false},
	{"/swagger-ui.html", "Swagger UI Exposed", output.Medium, false},
	{"/swagger-ui/index.html", "Swagger UI Exposed", output.Medium, false},
	{"/api-docs", "API Docs Exposed", output.Medium, false},
	{"/openapi.json", "OpenAPI Spec Exposed", output.Low, true},
	{"/metrics", "Metrics Endpoint Exposed", output.Medium, false},
	{"/graphql", "GraphQL Endpoint Detected", output.Info, false},
	{"/robots.txt", "robots.txt Present", output.Info, false},
	{"/sitemap.xml", "Sitemap Present", output.Info, false},
}

var deepRules = []pathRule{
	{"/.htpasswd", "Exposed .htpasswd", output.Critical, true},
	{"/.htaccess", "Exposed .htaccess", output.High, true},
	{"/id_rsa", "Exposed SSH Private Key", output.Critical, true},
	{"/id_rsa.pub", "Exposed SSH Public Key", output.Medium, true},
	{"/.ssh/id_rsa", "Exposed SSH Key (/.ssh)", output.Critical, true},
	{"/private.key", "Exposed Private Key", output.Critical, true},
	{"/server.key", "Exposed Server Key", output.Critical, true},
	{"/sftp-config.json", "Exposed SFTP Config", output.Critical, true},
	{"/.npmrc", "Exposed .npmrc", output.High, true},
	{"/.dockerenv", "Docker Environment Detected", output.Medium, false},
	{"/Dockerfile", "Dockerfile Exposed", output.Medium, true},
	{"/docker-compose.yml", "Docker Compose Exposed", output.High, true},
	{"/Makefile", "Makefile Exposed", output.Low, false},
	{"/package.json", "package.json Exposed", output.Low, true},
	{"/composer.json", "composer.json Exposed", output.Low, true},
	{"/Gemfile", "Gemfile Exposed", output.Low, false},
	{"/requirements.txt", "requirements.txt Exposed", output.Low, false},
	{"/web.config", "web.config Exposed", output.High, true},
	{"/applicationHost.config", "IIS Config Exposed", output.High, true},
	{"/crossdomain.xml", "crossdomain.xml Present", output.Medium, true},
	{"/clientaccesspolicy.xml", "clientaccesspolicy.xml Present", output.Medium, false},
	{"/trace.axd", "ASP.NET Trace Exposed", output.High, false},
	{"/elmah.axd", "ELMAH Error Log Exposed", output.Critical, true},
}

func checkPath(client *http.Client, baseURL string, rule pathRule) *output.Finding {
	target := strings.TrimRight(baseURL, "/") + rule.path
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ANANSI-CLI/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 || resp.StatusCode == 400 || resp.StatusCode == 410 {
		return nil
	}

	evidence := fmt.Sprintf("HTTP %d at %s", resp.StatusCode, target)

	// Capture body for critical/high hits
	if rule.captureBody && (rule.severity == output.Critical || rule.severity == output.High) {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 500))
		if err == nil && len(body) > 0 {
			// Sanitize null bytes
			snippet := strings.ReplaceAll(string(body), "\x00", "")
			snippet = strings.TrimSpace(snippet)
			if len(snippet) > 300 {
				snippet = snippet[:300] + "..."
			}
			evidence += "\n  " + snippet
		}
	}

	return &output.Finding{
		Severity:      rule.severity,
		Title:         rule.title,
		AffectedAsset: target,
		Description:   fmt.Sprintf("%s returned HTTP %d", rule.path, resp.StatusCode),
		Evidence:      evidence,
		Remediation:   fmt.Sprintf("Restrict or remove %s from public access.", rule.path),
	}
}

// Run probes all live hosts for exposed paths
func Run(liveHosts []output.ProbeResult, deep bool, timeout int) []output.Finding {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects for path probing
		},
	}

	rules := defaultRules
	if deep {
		rules = append(rules, deepRules...)
	}

	var allFindings []output.Finding
	mu := sync.Mutex{}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	for _, host := range liveHosts {
		for _, rule := range rules {
			wg.Add(1)
			sem <- struct{}{}
			go func(h output.ProbeResult, r pathRule) {
				defer wg.Done()
				defer func() { <-sem }()
				if f := checkPath(client, h.URL, r); f != nil {
					mu.Lock()
					allFindings = append(allFindings, *f)
					mu.Unlock()
				}
			}(host, rule)
		}
	}
	wg.Wait()
	return allFindings
}
