package sshconfig

import "strings"

// ApplyListOp interprets the +/-/^ prefix convention used by OpenSSH for
// algorithm lists (Ciphers, MACs, KexAlgorithms, etc.).
//
//   - No prefix: replace defaults entirely with the given values
//   - '+' prefix: append the given values to defaults
//   - '-' prefix: remove matching values from defaults (supports wildcards)
//   - '^' prefix: prepend the given values to defaults
//
// Values are comma-separated. The returned slice has no duplicates and
// preserves ordering.
func ApplyListOp(value string, defaults []string) []string {
	if len(value) == 0 {
		return defaults
	}

	switch value[0] {
	case '+':
		return applyAppend(value[1:], defaults)
	case '-':
		return applyRemove(value[1:], defaults)
	case '^':
		return applyPrepend(value[1:], defaults)
	default:
		return splitList(value)
	}
}

func applyAppend(value string, defaults []string) []string {
	additions := splitList(value)
	seen := make(map[string]bool, len(defaults))
	for _, v := range defaults {
		seen[v] = true
	}
	result := make([]string, len(defaults))
	copy(result, defaults)
	for _, a := range additions {
		if !seen[a] {
			result = append(result, a)
			seen[a] = true
		}
	}
	return result
}

func applyRemove(value string, defaults []string) []string {
	removals := splitList(value)
	result := make([]string, 0, len(defaults))
	for _, d := range defaults {
		if !matchesAnyPattern(d, removals) {
			result = append(result, d)
		}
	}
	return result
}

func applyPrepend(value string, defaults []string) []string {
	additions := splitList(value)
	seen := make(map[string]bool, len(additions)+len(defaults))
	result := make([]string, 0, len(additions)+len(defaults))
	for _, a := range additions {
		if !seen[a] {
			result = append(result, a)
			seen[a] = true
		}
	}
	for _, d := range defaults {
		if !seen[d] {
			result = append(result, d)
			seen[d] = true
		}
	}
	return result
}

func matchesAnyPattern(value string, patterns []string) bool {
	for _, p := range patterns {
		if MatchPattern(p, value) {
			return true
		}
	}
	return false
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
