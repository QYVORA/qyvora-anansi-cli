package assets

import (
	"embed"
	"os"
	"path/filepath"
	"strings"
)

//go:embed wordlists/**/*.txt
var EmbeddedAssets embed.FS

// LoadData reads a file from the given path, trying local first then embedded.
func LoadData(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		// Try to read from embedded if local failed.
		// Use forward slashes for embedded assets.
		embedPath := filepath.ToSlash(path)
		data, err = EmbeddedAssets.ReadFile(embedPath)
	}

	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			result = append(result, trimmed)
		}
	}
	return result
}

// LoadWordlist attempts to load a subdomain wordlist.
func LoadWordlist(customPath string, deep bool) []string {
	if customPath != "" {
		return LoadData(customPath)
	}

	filename := "default.txt"
	if deep {
		filename = "deep.txt"
	}
	
	return LoadData(filepath.Join("wordlists", "subdomains", filename))
}
