package sshconfig

import "strings"

// MatchPattern performs SSH-style glob matching. It supports '*' (match zero
// or more characters) and '?' (match exactly one character). The match is
// case-sensitive.
func MatchPattern(pattern, value string) bool {
	return matchPattern(pattern, value)
}

func matchPattern(pattern, value string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			// Consume consecutive stars
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				return true // trailing * matches everything
			}
			// Try matching the rest of the pattern at each position
			for i := 0; i <= len(value); i++ {
				if matchPattern(pattern, value[i:]) {
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

// MatchPatternList evaluates a comma-separated list of patterns against a value.
// Patterns may be negated with '!' prefix. A negated match means the value is
// explicitly excluded. The function returns true if the value matches any
// non-negated pattern and does not match any negated pattern.
//
// Per OpenSSH semantics:
//   - A negated match always produces a negative result (explicit exclusion).
//   - A non-negated match produces a positive result.
//   - If only negated patterns are present, no positive match is possible.
func MatchPatternList(patternList, value string) bool {
	patterns := strings.Split(patternList, ",")
	matched := false
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		negated := false
		if p[0] == '!' {
			negated = true
			p = p[1:]
		}
		if MatchPattern(p, value) {
			if negated {
				return false // explicit exclusion
			}
			matched = true
		}
	}
	return matched
}
