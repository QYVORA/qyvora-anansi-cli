// Package cmd implements the CLI command structure and orchestrates all scan phases.
// It uses the Cobra library to handle command-line parsing and flag management.
package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/wsuits6/hsociety-anansi-cli/internal/discovery"
	"github.com/wsuits6/hsociety-anansi-cli/internal/headers"
	"github.com/wsuits6/hsociety-anansi-cli/internal/output"
	"github.com/wsuits6/hsociety-anansi-cli/internal/paths"
	"github.com/wsuits6/hsociety-anansi-cli/internal/probe"
	"github.com/wsuits6/hsociety-anansi-cli/internal/takeover"
	"github.com/wsuits6/hsociety-anansi-cli/internal/tls"
	"github.com/spf13/cobra"
)

// Command-line flags that control scan behavior
var (
	flagDeep    bool          // If true, uses larger wordlists and more aggressive scanning
	flagOut     string        // Output format: "terminal", "json", or "markdown"
	flagTimeout int           // Per-request timeout in seconds (default: 5)
	flagModules []string      // List of modules to run (e.g., ["discovery", "probe", "tls"])
)

// rootCmd is the main Cobra command that defines the CLI structure.
// It requires exactly one argument: the target domain to scan.
var rootCmd = &cobra.Command{
	Use:   "anansi [target]",
	Short: "ANANSI — Attack Surface Intelligence Engine",
	Long: color.New(color.FgCyan, color.Bold).Sprint(`
  ╔═══════════════════════════════════════════════╗
  ║   █████╗ ███╗   ██╗ █████╗ ███╗   ██╗███████╗║
  ║  ██╔══██╗████╗  ██║██╔══██╗████╗  ██║██╔════╝║
  ║  ███████║██╔██╗ ██║███████║██╔██╗ ██║███████╗║
  ║  ██╔══██║██║╚██╗██║██╔══██║██║╚██╗██║╚════██║║
  ║  ██║  ██║██║ ╚████║██║  ██║██║ ╚████║███████║║
  ║  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝║
  ╚═══════════════════════════════════════════════╝`) + `

  Attack Surface Intelligence Engine — HSOCIETY OFFSEC
  github.com/wsuits6/hsociety-anansi-cli
`,
	Args: cobra.ExactArgs(1), // Requires exactly one argument: the target domain
	RunE: runScan,            // The function that executes when the command is run
}

// Execute is called by main.go. It runs the root command and handles any errors.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// init sets up all command-line flags and their default values.
// This function is called automatically before main().
func init() {
	rootCmd.Flags().BoolVar(&flagDeep, "deep", false, "Enable deep scan (larger wordlist, more path probing)")
	rootCmd.Flags().StringVar(&flagOut, "out", "terminal", "Output format: terminal | json | markdown")
	rootCmd.Flags().IntVar(&flagTimeout, "timeout", 5, "Per-request timeout in seconds")
	rootCmd.Flags().StringSliceVar(&flagModules, "modules", []string{"discovery", "probe", "tls", "headers", "paths", "takeover"}, "Modules to run (comma-separated)")
}

// hasModule checks if a given module name is in the user's --modules flag.
// It performs case-insensitive comparison.
func hasModule(name string) bool {
	for _, m := range flagModules {
		if strings.EqualFold(strings.TrimSpace(m), name) {
			return true
		}
	}
	return false
}

// runScan is the main scanning orchestrator. It runs all enabled modules in sequence,
// passes data between phases, and generates the final report.
func runScan(cmd *cobra.Command, args []string) error {
	// Normalize the target domain: remove protocol, paths, convert to lowercase
	target := strings.ToLower(strings.TrimSpace(args[0]))
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.Split(target, "/")[0] // Remove any path components

	if target == "" {
		return fmt.Errorf("invalid target")
	}

	// Initialize timing and output
	startTime := time.Now()
	out := output.New(flagOut) // Creates the renderer (terminal, JSON, or markdown)
	report := &output.Report{
		Target:    target,
		StartedAt: startTime,
	}

	// Display the banner with target info
	out.Banner(target)

	// ── PHASE 1: DISCOVERY ──────────────────────────────────────────────
	// Finds subdomains using Certificate Transparency logs (crt.sh) and DNS brute-force
	if hasModule("discovery") {
		out.PhaseHeader("01", "DISCOVERY", "subdomain enumeration + DNS resolution")
		subdomains, err := discovery.Run(target, flagDeep, flagTimeout)
		if err != nil {
			out.PhaseError("DISCOVERY", err)
		} else {
			report.Subdomains = subdomains
			out.SubdomainTable(subdomains)
		}
	}

	// ── PHASE 2: PROBE ───────────────────────────────────────────────────
	// Tests HTTP/HTTPS connectivity on live hosts, captures status codes, headers, titles
	if hasModule("probe") && len(report.Subdomains) > 0 {
		out.PhaseHeader("02", "PROBE", "HTTP/HTTPS surface mapping")
		hosts := discovery.LiveHosts(report.Subdomains) // Only probe hosts that resolved to IPs
		probeResults, err := probe.Run(hosts, flagTimeout)
		if err != nil {
			out.PhaseError("PROBE", err)
		} else {
			report.ProbeResults = probeResults
			out.ProbeTable(probeResults)
		}
	}

	// ── PHASE 3: TLS ─────────────────────────────────────────────────────
	// Examines TLS certificates: expiry, self-signed status, weak protocols, and extracts
	// Subject Alternative Names (SANs) which may reveal additional subdomains
	if hasModule("tls") && len(report.ProbeResults) > 0 {
		out.PhaseHeader("03", "TLS", "certificate analysis + SAN discovery")
		liveHosts := probe.LiveOnly(report.ProbeResults) // Only check TLS on hosts that responded
		tlsResults, newSubdomains := tls.Run(liveHosts, target, flagTimeout)
		report.TLSResults = tlsResults
		// If SANs revealed new subdomains, add them to the report
		if len(newSubdomains) > 0 {
			out.Info(fmt.Sprintf("SAN discovery found %d additional subdomains", len(newSubdomains)))
			report.Subdomains = append(report.Subdomains, newSubdomains...)
		}
		out.TLSTable(tlsResults)
		// TLS module generates findings (expired certs, self-signed, weak protocols)
		for _, r := range tlsResults {
			report.Findings = append(report.Findings, r.Findings...)
		}
	}

	// ── PHASE 4: HEADERS ─────────────────────────────────────────────────
	// Checks for missing security headers (HSTS, CSP, X-Frame-Options, etc.)
	// and tests CORS configuration by injecting an evil origin header
	if hasModule("headers") && len(report.ProbeResults) > 0 {
		out.PhaseHeader("04", "HEADERS", "security header audit")
		liveHosts := probe.LiveOnly(report.ProbeResults)
		headerResults := headers.Run(report.ProbeResults, liveHosts)
		report.HeaderResults = headerResults
		out.HeadersTable(headerResults)
		// Headers module generates findings for missing/misconfigured headers
		for _, r := range headerResults {
			report.Findings = append(report.Findings, r.Findings...)
		}
	}

	// ── PHASE 5: PATHS ───────────────────────────────────────────────────
	// Probes for exposed sensitive files and endpoints like .env, .git, config files,
	// admin panels, database interfaces, API docs, etc.
	if hasModule("paths") && len(report.ProbeResults) > 0 {
		out.PhaseHeader("05", "PATHS", "exposed endpoint + file detection")
		liveHosts := probe.LiveOnly(report.ProbeResults)
		pathFindings := paths.Run(liveHosts, flagDeep, flagTimeout)
		report.Findings = append(report.Findings, pathFindings...)
		out.FindingsBlock("PATHS", pathFindings)
	}

	// ── PHASE 6: TAKEOVER ────────────────────────────────────────────────
	// Detects subdomain takeover vulnerabilities: dead DNS records pointing to
	// unclaimed third-party services (GitHub Pages, Heroku, AWS S3, etc.)
	if hasModule("takeover") && len(report.Subdomains) > 0 {
		out.PhaseHeader("06", "TAKEOVER", "dangling CNAME subdomain takeover detection")
		takeoverFindings := takeover.Run(report.Subdomains, flagTimeout)
		report.Findings = append(report.Findings, takeoverFindings...)
		out.FindingsBlock("TAKEOVER", takeoverFindings)
	}

	// ── SUMMARY ──────────────────────────────────────────────────────────
	// Calculate total duration and render the final report with all findings
	report.Duration = time.Since(startTime)
	out.Summary(report)

	return nil
}
