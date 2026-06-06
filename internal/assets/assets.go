package assets

import (
	"embed"
	"os"
	"path/filepath"
	"strings"
)

//go:embed wordlists/subdomains/*.txt
var EmbeddedAssets embed.FS

// LoadWordlist attempts to load a wordlist from the given path.
// If the path is empty, it checks for a local wordlists/ directory.
// If that's missing, it falls back to the embedded defaults.
func LoadWordlist(customPath string, deep bool) []string {
	var data []byte
	var err error

	// 1. Try custom path if provided
	if customPath != "" {
		data, err = os.ReadFile(customPath)
	}

	// 2. If no custom path or failed to read, try local wordlists directory
	if (err != nil || customPath == "") {
		filename := "default.txt"
		if deep {
			filename = "deep.txt"
		}
		localPath := filepath.Join("wordlists", "subdomains", filename)
		data, err = os.ReadFile(localPath)
	}

	// 3. Fallback to embedded defaults
	if err != nil {
		filename := "wordlists/subdomains/default.txt"
		if deep {
			filename = "wordlists/subdomains/deep.txt"
		}
		data, _ = EmbeddedAssets.ReadFile(filename)
	}

	if len(data) == 0 {
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
