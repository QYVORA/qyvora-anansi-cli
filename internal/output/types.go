package output

import "time"

// Severity levels
const (
	Critical = "CRITICAL"
	High     = "HIGH"
	Medium   = "MEDIUM"
	Low      = "LOW"
	Info     = "INFO"
)

// Finding is a single vulnerability or notable observation
type Finding struct {
	Severity      string
	Title         string
	AffectedAsset string
	Description   string
	Evidence      string
	Remediation   string
}

// Report is the full scan result passed between phases and rendered at the end
type Report struct {
	Target        string
	StartedAt     time.Time
	Duration      time.Duration
	Subdomains    []SubdomainResult
	ProbeResults  []ProbeResult
	TLSResults    []TLSResult
	HeaderResults []HeaderResult
	Findings      []Finding
}

// SubdomainResult is a single resolved (or unresolved) subdomain
type SubdomainResult struct {
	FQDN        string
	IPs         []string
	Source      string // "crtsh" | "wordlist" | "san"
	Resolved    bool
	DeadCNAMEs  []string
}

// ProbeResult is the HTTP probe result for a single host
type ProbeResult struct {
	FQDN          string
	URL           string
	FinalURL      string
	StatusCode    int
	Server        string
	TechHeaders   map[string]string
	Title         string
	ResponseTimeMs int64
	IsAlive       bool
	RedirectChain []string
}

// TLSResult is certificate + protocol data for a single host
type TLSResult struct {
	Hostname       string
	Protocol       string
	Cipher         string
	Issuer         string
	Subject        string
	ValidFrom      string
	ValidTo        string
	DaysUntilExpiry int
	Expired        bool
	ExpiringSoon   bool
	SelfSigned     bool
	SANs           []string
	Findings       []Finding
}

// HeaderResult is the security header audit for a single URL
type HeaderResult struct {
	URL      string
	Headers  map[string]string // header name → value or "" if absent
	CORS     string            // Access-Control-Allow-Origin value
	Findings []Finding
}
