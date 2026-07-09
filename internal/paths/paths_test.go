package paths

import (
	"testing"
)

func TestLoadRules(t *testing.T) {
	rules := loadRules("wordlists/paths/default.txt")
	if len(rules) == 0 {
		t.Fatal("loadRules returned empty rules from default.txt")
	}
	var emptyPath, emptySeverity int
	for i, r := range rules {
		if r.path == "" {
			emptyPath++
		}
		if r.severity == "" {
			t.Errorf("rules[%d] has empty severity", i)
			emptySeverity++
		}
	}
	if emptyPath == len(rules) {
		t.Fatal("all rules have empty paths")
	}
	if emptySeverity > 0 {
		t.Fatalf("%d rules have empty severity", emptySeverity)
	}
}

func TestLoadRulesDeep(t *testing.T) {
	rules := loadRules("wordlists/paths/deep.txt")
	if len(rules) == 0 {
		t.Fatal("loadRules returned empty rules from deep.txt")
	}
}

func TestLoadRulesNonexistent(t *testing.T) {
	rules := loadRules("/nonexistent/rules.txt")
	if rules != nil {
		t.Fatal("loadRules for nonexistent file should return nil")
	}
}
