package session

import "strings"

// MatchEnvPattern matches an environment variable name against a SendEnv pattern.
// Patterns can use * and ? wildcards. A '-' prefix negates.
func MatchEnvPattern(pattern, name string) bool {
	if strings.HasPrefix(pattern, "-") {
		return false // negated patterns remove previously sent vars (not handled here)
	}
	return MatchGlob(pattern, name)
}

// MatchGlob performs simple glob matching with * and ? wildcards.
func MatchGlob(pattern, value string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			pattern = pattern[1:]
			if pattern == "" {
				return true
			}
			for i := 0; i <= len(value); i++ {
				if MatchGlob(pattern, value[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(value) == 0 {
				return false
			}
			pattern = pattern[1:]
			value = value[1:]
		default:
			if len(value) == 0 || pattern[0] != value[0] {
				return false
			}
			pattern = pattern[1:]
			value = value[1:]
		}
	}
	return len(value) == 0
}
