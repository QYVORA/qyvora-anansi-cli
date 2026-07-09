package osint

import (
	"strings"
	"testing"
)

func TestExtractEmails(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "single email",
			body: "Contact: admin@anansi.tech",
			want: []string{"admin@anansi.tech"},
		},
		{
			name: "multiple emails",
			body: "info@qyvora.tech, support@anansi.io",
			want: []string{"info@qyvora.tech", "support@anansi.io"},
		},
		{
			name: "filters example.com",
			body: "test@example.com",
			want: nil,
		},
		{
			name: "filters image extensions",
			body: "img@test.png and style@test.css",
			want: nil,
		},
		{
			name: "no email",
			body: "no contact here",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEmails(tt.body)
			if len(got) != len(tt.want) {
				t.Fatalf("extractEmails(%q) = %v, want %v", tt.body, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractEmails(%q)[%d] = %q, want %q", tt.body, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExtractPhones(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "ghanaian mobile format",
			body: "Call +233-50-123-4567",
			want: []string{"+233-50-123-4567"},
		},
		{
			name: "filters year ranges",
			body: "2020-2024",
			want: nil,
		},
		{
			name: "filters numeric only",
			body: "1234567890",
			want: nil,
		},
		{
			name: "filters short strings",
			body: "12-34",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPhones(tt.body)
			if len(got) != len(tt.want) {
				t.Fatalf("extractPhones(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestIsLikelyName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"Kwame", false},
		{"Kwame Asante", true},
		{"Akua Mensah", true},
		{"Kofi Annan", true},
		{"the team", false},
		{"All Rights Reserved", false},
		{"Copyright 2024", false},
		{"A B", false},
		{"Kwame A B C D E", false},
		{"javascript", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLikelyName(tt.name)
			if got != tt.want {
				t.Errorf("isLikelyName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestStripHTML(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"<p>Hello</p>", "Hello "},
		{"<div><span>text</span></div>", " text "},
		{"plain text", "plain text"},
		{"<br/>", " "},
		{"<a href='x'>link</a>", "link "},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripHTML(tt.input)
			if strings.TrimSpace(got) != strings.TrimSpace(tt.want) {
				t.Errorf("stripHTML(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRemoveScriptStyle(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"before<script>alert(1)</script>after", "beforeafter"},
		{"before<style>.cls{}</style>after", "beforeafter"},
		{"no tags", "no tags"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := removeScriptStyle(tt.input)
			if got != tt.want {
				t.Errorf("removeScriptStyle(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsNumericOnly(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"12345", true},
		{"12a45", false},
		{"", true},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			got := isNumericOnly(tt.s)
			if got != tt.want {
				t.Errorf("isNumericOnly(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsPeoplePage(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://example.com/about", true},
		{"https://example.com/team", true},
		{"https://example.com/contact", true},
		{"https://example.com/blog", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := isPeoplePage(tt.url)
			if got != tt.want {
				t.Errorf("isPeoplePage(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestExtractEmployeeNames(t *testing.T) {
	body := `<html><body><p>Kwame Asante, Akua Mensah, Kofi Annan</p></body></html>`
	names := extractEmployeeNames(body)
	if len(names) < 2 {
		t.Fatalf("expected at least 2 names, got %d: %v", len(names), names)
	}
	hasKwame := false
	hasAkua := false
	for _, n := range names {
		if n == "Kwame Asante" || n == "Kwame Asante, Akua Mensah" {
			hasKwame = true
		}
		if n == "Akua Mensah" || n == "Kwame Asante, Akua Mensah" || n == "Akua Mensah, Kofi Annan" {
			hasAkua = true
		}
	}
	if !hasKwame || !hasAkua {
		t.Errorf("expected Kwame Asante and Akua Mensah found, got %v", names)
	}
}
