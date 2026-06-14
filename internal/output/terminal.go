package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
)

var (
	cyan     = color.New(color.FgCyan, color.Bold)
	cyanDim  = color.New(color.FgCyan)
	white    = color.New(color.FgWhite, color.Bold)
	dim      = color.New(color.FgHiBlack)
	red      = color.New(color.FgRed, color.Bold)
	redDim   = color.New(color.FgRed)
	orange   = color.New(color.FgYellow, color.Bold)
	green    = color.New(color.FgGreen, color.Bold)
	greenDim = color.New(color.FgGreen)
)

type Renderer struct {
	format string
}

func New(format string) *Renderer {
	return &Renderer{format: format}
}

func (r *Renderer) Banner(target string) {
	fmt.Println()
	for _, line := range strings.Split(AnansiASCIIArt, "\n") {
		cyan.Println(line)
	}
	fmt.Println()
	fmt.Println()
	white.Println("  Attack Surface Intelligence Engine")
	cyan.Println("  QYVORA OffSec — github.com/wsuits6/qyvora-anansi-cli")
	fmt.Println()
	dim.Printf("  TARGET: ")
	white.Println(target)
	dim.Printf("  TIME:   ")
	fmt.Println(time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Println()
}

func (r *Renderer) PhaseHeader(num, name, desc string) {
	fmt.Println()
	cyan.Printf("  ══ PHASE %s ── %s ", num, name)
	dim.Printf("// %s\n", desc)
	dim.Println("  " + strings.Repeat("─", 60))
}

func (r *Renderer) PhaseError(phase string, err error) {
	redDim.Printf("  [!] %s error: %s\n", phase, err.Error())
}

func (r *Renderer) Info(msg string) {
	cyanDim.Printf("  [*] %s\n", msg)
}

func (r *Renderer) Progress(current, total int, label string) {
	if r.format != "terminal" {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 30
	completed := int(float64(width) * (float64(current) / float64(total)))
	if completed > width {
		completed = width
	}
	bar := strings.Repeat("█", completed) + strings.Repeat("░", width-completed)
	fmt.Printf("\r  %s [%s] %3.0f%% (%d/%d)   ", dim.Sprint(label), cyan.Sprint(bar), percent, current, total)
	if current == total {
		fmt.Println()
	}
}

func (r *Renderer) SubdomainTable(results []SubdomainResult) {
	if len(results) == 0 {
		dim.Println("  no subdomains discovered")
		return
	}

	crtsh := 0
	wordlist := 0
	san := 0
	for _, s := range results {
		switch s.Source {
		case "crtsh":
			crtsh++
		case "wordlist":
			wordlist++
		case "san":
			san++
		}
	}

	dim.Printf("  sources: ")
	cyan.Printf("crt.sh=%d  ", crtsh)
	dim.Printf("wordlist=%d  san=%d\n\n", wordlist, san)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprint(w, dim.Sprint("  SUBDOMAIN\tIP\tSOURCE\tSTATUS\n"))
	fmt.Fprint(w, dim.Sprint("  "+strings.Repeat("─", 40)+"\t"+strings.Repeat("─", 16)+"\t"+strings.Repeat("─", 8)+"\t"+strings.Repeat("─", 6)+"\n"))

	for _, s := range results {
		ip := "—"
		if len(s.IPs) > 0 {
			ip = s.IPs[0]
		}

		status := dim.Sprint("DEAD")
		fqdnStr := dim.Sprint(s.FQDN)
		if s.Resolved {
			status = green.Sprint("LIVE")
			fqdnStr = s.FQDN
		}

		sourceColor := dim.Sprint(s.Source)
		if s.Source == "crtsh" {
			sourceColor = cyanDim.Sprint("crt.sh")
		} else if s.Source == "san" {
			sourceColor = greenDim.Sprint("san")
		}

		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", fqdnStr, ip, sourceColor, status)

		for _, cname := range s.DeadCNAMEs {
			fmt.Fprintf(w, "  \tCNAME → %s\t\t\n", dim.Sprint(cname))
		}
	}
	w.Flush()
	fmt.Println()
}

func (r *Renderer) ProbeTable(results []ProbeResult) {
	live := 0
	for _, p := range results {
		if p.IsAlive {
			live++
		}
	}
	dim.Printf("  live: %d / %d\n\n", live, len(results))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprint(w, dim.Sprint("  URL\tCODE\tSERVER\tTITLE\n"))
	fmt.Fprint(w, dim.Sprint("  "+strings.Repeat("─", 45)+"\t"+strings.Repeat("─", 6)+"\t"+strings.Repeat("─", 20)+"\t"+strings.Repeat("─", 30)+"\n"))

	for _, p := range results {
		if !p.IsAlive {
			continue
		}
		codeStr := fmt.Sprintf("%d", p.StatusCode)
		codeColor := greenDim.Sprint(codeStr)
		if p.StatusCode >= 400 {
			codeColor = redDim.Sprint(codeStr)
		} else if p.StatusCode >= 300 {
			codeColor = orange.Sprint(codeStr)
		}

		server := p.Server
		if server == "" {
			server = "—"
		}
		title := p.Title
		if title == "" {
			title = "—"
		}
		if len(title) > 40 {
			title = title[:37] + "..."
		}

		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", p.URL, codeColor, server, dim.Sprint(title))
	}
	w.Flush()
	fmt.Println()
}

func (r *Renderer) TLSTable(results []TLSResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprint(w, dim.Sprint("  HOSTNAME\tPROTO\tEXPIRY\tISSUER\n"))
	fmt.Fprint(w, dim.Sprint("  "+strings.Repeat("─", 30)+"\t"+strings.Repeat("─", 8)+"\t"+strings.Repeat("─", 10)+"\t"+strings.Repeat("─", 20)+"\n"))

	for _, t := range results {
		expiryStr := fmt.Sprintf("%d days", t.DaysUntilExpiry)
		expiryColor := greenDim.Sprint(expiryStr)
		if t.Expired {
			expiryColor = red.Sprint("EXPIRED")
		} else if t.ExpiringSoon {
			expiryColor = orange.Sprint(expiryStr)
		}

		issuer := t.Issuer
		if issuer == "" {
			issuer = "unknown"
		}

		selfSignedFlag := ""
		if t.SelfSigned {
			selfSignedFlag = red.Sprint(" [SELF]")
		}

		fmt.Fprintf(w, "  %s\t%s\t%s\t%s%s\n",
			t.Hostname,
			dim.Sprint(t.Protocol),
			expiryColor,
			dim.Sprint(issuer),
			selfSignedFlag,
		)
	}
	w.Flush()
	fmt.Println()
}

func (r *Renderer) HeadersTable(results []HeaderResult) {
	secHeaders := []string{
		"strict-transport-security",
		"content-security-policy",
		"x-frame-options",
		"x-content-type-options",
		"referrer-policy",
		"permissions-policy",
	}

	shortNames := map[string]string{
		"strict-transport-security": "HSTS",
		"content-security-policy":   "CSP",
		"x-frame-options":           "XFO",
		"x-content-type-options":    "XCTO",
		"referrer-policy":           "RP",
		"permissions-policy":        "PP",
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  %-35s\t", "URL")
	for _, h := range secHeaders {
		fmt.Fprintf(w, "%s\t", cyan.Sprint(shortNames[h]))
	}
	fmt.Fprintln(w)

	for _, hr := range results {
		fmt.Fprintf(w, "  %-35s\t", hr.URL)
		for _, h := range secHeaders {
			val, exists := hr.Headers[h]
			if exists && val != "" {
				fmt.Fprintf(w, "%s\t", green.Sprint("●"))
			} else {
				fmt.Fprintf(w, "%s\t", red.Sprint("●"))
			}
		}
		fmt.Fprintln(w)
	}
	w.Flush()
	fmt.Println()
}

func (r *Renderer) FindingsBlock(phase string, findings []Finding) {
	if len(findings) == 0 {
		dim.Printf("  no findings from %s\n", phase)
		return
	}

	for _, f := range findings {
		fmt.Println()
		r.printFinding(f)
	}
}

func (r *Renderer) printFinding(f Finding) {
	sevColor := severityColor(f.Severity)
	fmt.Printf("  %s  %s\n", sevColor(fmt.Sprintf("[%-8s]", f.Severity)), white.Sprint(f.Title))
	dim.Printf("  %-10s %s\n", "ASSET:", f.AffectedAsset)
	if f.Description != "" {
		dim.Printf("  %-10s %s\n", "DESC:", f.Description)
	}
	if f.Evidence != "" {
		fmt.Printf("  %-10s ", "EVIDENCE:")
		cyanDim.Printf("%s\n", f.Evidence)
	}
	if f.Remediation != "" {
		dim.Printf("  %-10s %s\n", "FIX:", f.Remediation)
	}
}

func (r *Renderer) Summary(report *Report) {
	fmt.Println()
	cyan.Println("  ══ SUMMARY ─────────────────────────────────────────────────")

	counts := map[string]int{Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0}
	for _, f := range report.Findings {
		if _, ok := counts[f.Severity]; ok {
			counts[f.Severity]++
		}
	}

	riskScore := computeRisk(counts)
	riskStr := fmt.Sprintf("%d/100", riskScore)
	riskDisplay := greenDim.Sprint(riskStr)
	if riskScore >= 67 {
		riskDisplay = red.Sprint(riskStr)
	} else if riskScore >= 34 {
		riskDisplay = orange.Sprint(riskStr)
	}

	liveCount := 0
	for _, p := range report.ProbeResults {
		if p.IsAlive {
			liveCount++
		}
	}

	fmt.Printf("  target      %s\n", white.Sprint(report.Target))
	fmt.Printf("  duration    %s\n", dim.Sprint(report.Duration.Round(time.Millisecond).String()))
	fmt.Printf("  subdomains  %s\n", dim.Sprint(fmt.Sprintf("%d discovered, %d live", len(report.Subdomains), liveCount)))
	fmt.Printf("  risk score  %s\n", riskDisplay)
	fmt.Println()

	fmt.Printf("  findings    ")
	red.Printf("CRIT:%d  ", counts[Critical])
	orange.Printf("HIGH:%d  ", counts[High])
	color.New(color.FgYellow).Printf("MED:%d  ", counts[Medium])
	dim.Printf("LOW:%d  INFO:%d\n", counts[Low], counts[Info])

	if counts[Critical]+counts[High] > 0 {
		fmt.Println()
		red.Println("  ── HIGH PRIORITY FINDINGS ──────────────────────────────────")
		for _, f := range report.Findings {
			if f.Severity == Critical || f.Severity == High {
				r.printFinding(f)
				fmt.Println()
			}
		}
	}

	fmt.Println()
	dim.Println("  ── END OF REPORT ───────────────────────────────────────────")
	fmt.Println()

	if r.format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
	}
}

func severityColor(sev string) func(string, ...interface{}) string {
	switch sev {
	case Critical:
		return red.Sprintf
	case High:
		return orange.Sprintf
	case Medium:
		return color.New(color.FgYellow).Sprintf
	case Low:
		return dim.Sprintf
	default:
		return dim.Sprintf
	}
}

func computeRisk(counts map[string]int) int {
	score := counts[Critical]*20 + counts[High]*10 + counts[Medium]*5 + counts[Low]*2
	if score > 100 {
		return 100
	}
	return score
}
