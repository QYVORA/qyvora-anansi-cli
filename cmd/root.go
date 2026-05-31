package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/hsociety/anansi-cli/internal/discovery"
	"github.com/hsociety/anansi-cli/internal/headers"
	"github.com/hsociety/anansi-cli/internal/output"
	"github.com/hsociety/anansi-cli/internal/paths"
	"github.com/hsociety/anansi-cli/internal/probe"
	"github.com/hsociety/anansi-cli/internal/takeover"
	"github.com/hsociety/anansi-cli/internal/tls"
	"github.com/spf13/cobra"
)

var (
	flagDeep    bool
	flagOut     string
	flagTimeout int
	flagModules []string
)

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
  github.com/hsociety/anansi-cli
`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolVar(&flagDeep, "deep", false, "Enable deep scan (larger wordlist, more path probing)")
	rootCmd.Flags().StringVar(&flagOut, "out", "terminal", "Output format: terminal | json | markdown")
	rootCmd.Flags().IntVar(&flagTimeout, "timeout", 5, "Per-request timeout in seconds")
	rootCmd.Flags().StringSliceVar(&flagModules, "modules", []string{"discovery", "probe", "tls", "headers", "paths", "takeover"}, "Modules to run (comma-separated)")
}

func hasModule(name string) bool {
	for _, m := range flagModules {
		if strings.EqualFold(strings.TrimSpace(m), name) {
			return true
		}
	}
	return false
}

func runScan(cmd *cobra.Command, args []string) error {
	target := strings.ToLower(strings.TrimSpace(args[0]))
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.Split(target, "/")[0]

	if target == "" {
		return fmt.Errorf("invalid target")
	}

	startTime := time.Now()
	out := output.New(flagOut)
	report := &output.Report{
		Target:    target,
		StartedAt: startTime,
	}

	out.Banner(target)

	// ── PHASE 1: DISCOVERY ──────────────────────────────────────────────
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
	if hasModule("probe") && len(report.Subdomains) > 0 {
		out.PhaseHeader("02", "PROBE", "HTTP/HTTPS surface mapping")
		hosts := discovery.LiveHosts(report.Subdomains)
		probeResults, err := probe.Run(hosts, flagTimeout)
		if err != nil {
			out.PhaseError("PROBE", err)
		} else {
			report.ProbeResults = probeResults
			out.ProbeTable(probeResults)
		}
	}

	// ── PHASE 3: TLS ─────────────────────────────────────────────────────
	if hasModule("tls") && len(report.ProbeResults) > 0 {
		out.PhaseHeader("03", "TLS", "certificate analysis + SAN discovery")
		liveHosts := probe.LiveOnly(report.ProbeResults)
		tlsResults, newSubdomains := tls.Run(liveHosts, target, flagTimeout)
		report.TLSResults = tlsResults
		if len(newSubdomains) > 0 {
			out.Info(fmt.Sprintf("SAN discovery found %d additional subdomains", len(newSubdomains)))
			report.Subdomains = append(report.Subdomains, newSubdomains...)
		}
		out.TLSTable(tlsResults)
		for _, r := range tlsResults {
			report.Findings = append(report.Findings, r.Findings...)
		}
	}

	// ── PHASE 4: HEADERS ─────────────────────────────────────────────────
	if hasModule("headers") && len(report.ProbeResults) > 0 {
		out.PhaseHeader("04", "HEADERS", "security header audit")
		liveHosts := probe.LiveOnly(report.ProbeResults)
		headerResults := headers.Run(report.ProbeResults, liveHosts)
		report.HeaderResults = headerResults
		out.HeadersTable(headerResults)
		for _, r := range headerResults {
			report.Findings = append(report.Findings, r.Findings...)
		}
	}

	// ── PHASE 5: PATHS ───────────────────────────────────────────────────
	if hasModule("paths") && len(report.ProbeResults) > 0 {
		out.PhaseHeader("05", "PATHS", "exposed endpoint + file detection")
		liveHosts := probe.LiveOnly(report.ProbeResults)
		pathFindings := paths.Run(liveHosts, flagDeep, flagTimeout)
		report.Findings = append(report.Findings, pathFindings...)
		out.FindingsBlock("PATHS", pathFindings)
	}

	// ── PHASE 6: TAKEOVER ────────────────────────────────────────────────
	if hasModule("takeover") && len(report.Subdomains) > 0 {
		out.PhaseHeader("06", "TAKEOVER", "dangling CNAME subdomain takeover detection")
		takeoverFindings := takeover.Run(report.Subdomains, flagTimeout)
		report.Findings = append(report.Findings, takeoverFindings...)
		out.FindingsBlock("TAKEOVER", takeoverFindings)
	}

	// ── SUMMARY ──────────────────────────────────────────────────────────
	report.Duration = time.Since(startTime)
	out.Summary(report)

	return nil
}
