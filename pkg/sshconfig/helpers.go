package sshconfig

import "strings"

// ParseDestination splits a destination string into user and host components.
// Handles: user@host, host, user@[ipv6], [ipv6]
func ParseDestination(dest string) (user, host string) {
	// Handle [ipv6] notation
	if strings.HasPrefix(dest, "[") {
		if idx := strings.Index(dest, "]"); idx >= 0 {
			return "", dest[1:idx]
		}
		return "", dest
	}

	// Check for user@host
	if atIdx := strings.LastIndex(dest, "@"); atIdx >= 0 {
		user = dest[:atIdx]
		host = dest[atIdx+1:]
		// Strip brackets from [ipv6]
		if strings.HasPrefix(host, "[") {
			if idx := strings.Index(host, "]"); idx >= 0 {
				host = host[1:idx]
			}
		}
		return user, host
	}

	return "", dest
}

// SplitHostPort splits a host:port string, handling [IPv6]:port notation.
// Returns host, port, and a flag indicating whether the split succeeded.
// For a bare IPv6 address without brackets, returns the full string as host
// with no port and ok=false.
func SplitHostPort(s string) (host, port string, ok bool) {
	if strings.HasPrefix(s, "[") {
		// [IPv6]:port
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", false
		}
		host = s[1:end]
		rest := s[end+1:]
		if strings.HasPrefix(rest, ":") {
			port = rest[1:]
		}
		return host, port, true
	}

	// Count colons — if more than 1, it's an IPv6 address without brackets
	if strings.Count(s, ":") > 1 {
		return s, "", false
	}

	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}

// SplitAlgList splits a comma-separated algorithm list, trimming whitespace
// and removing empty entries.
func SplitAlgList(s string) []string {
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

// SplitFields splits a string on whitespace (space or tab), returning
// non-empty fields. Unlike strings.Fields, this uses a fixed separator
// set and avoids the unicode overhead.
func SplitFields(s string) []string {
	var fields []string
	var current []byte
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if len(current) > 0 {
				fields = append(fields, string(current))
				current = current[:0]
			}
		} else {
			current = append(current, s[i])
		}
	}
	if len(current) > 0 {
		fields = append(fields, string(current))
	}
	return fields
}

// ParseRekeyLimit parses an OpenSSH RekeyLimit value of the form
// "bytes [time]" or "default [time]" into byte count and seconds.
// "default" yields 0 bytes (meaning the library default); "none" as
// the time component yields 0 seconds.
func ParseRekeyLimit(value string) (bytes uint64, seconds int) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, 0
	}

	bytesStr := fields[0]
	if strings.ToLower(bytesStr) == "default" {
		bytes = 0
	} else {
		bytes = ParseSize(bytesStr)
	}

	if len(fields) >= 2 {
		timeStr := fields[1]
		if strings.ToLower(timeStr) != "none" {
			seconds = ParseTimeSeconds(timeStr)
		}
	}
	return bytes, seconds
}

// ParseSize parses a size string with an optional K/M/G suffix.
// Non-digit characters in the numeric portion are skipped.
func ParseSize(s string) uint64 {
	if len(s) == 0 {
		return 0
	}
	multiplier := uint64(1)
	last := s[len(s)-1]
	switch last {
	case 'K', 'k':
		multiplier = 1024
		s = s[:len(s)-1]
	case 'M', 'm':
		multiplier = 1024 * 1024
		s = s[:len(s)-1]
	case 'G', 'g':
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	}
	var n uint64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + uint64(c-'0')
		}
	}
	return n * multiplier
}

// ParseTimeSeconds parses an OpenSSH time value into seconds.
// Supports: plain seconds (no suffix), or sequences of N{s|m|h|d|w}.
// "1h30m" yields 5400. Unknown characters are ignored.
func ParseTimeSeconds(s string) int {
	if len(s) == 0 {
		return 0
	}
	total := 0
	current := 0
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			current = current*10 + int(c-'0')
		case c == 's' || c == 'S':
			total += current
			current = 0
		case c == 'm' || c == 'M':
			total += current * 60
			current = 0
		case c == 'h' || c == 'H':
			total += current * 3600
			current = 0
		case c == 'd' || c == 'D':
			total += current * 86400
			current = 0
		case c == 'w' || c == 'W':
			total += current * 604800
			current = 0
		}
	}
	// If no suffix, treat trailing digits as seconds.
	total += current
	return total
}

// ParseOverride parses a single "Key=Value" or "Key Value" directive string
// from a command line. The keyword is returned as-is (no case change).
func ParseOverride(opt string) (keyword, value string, err error) {
	// Try Key=Value first.
	if idx := strings.IndexByte(opt, '='); idx > 0 {
		keyword = strings.TrimSpace(opt[:idx])
		value = strings.TrimSpace(opt[idx+1:])
		if keyword == "" {
			return "", "", &ParseError{Msg: "empty keyword in override"}
		}
		return keyword, value, nil
	}

	// Try "Key Value" (split on first whitespace).
	fields := strings.SplitN(opt, " ", 2)
	if len(fields) < 1 || fields[0] == "" {
		return "", "", &ParseError{Msg: "empty override"}
	}
	keyword = fields[0]
	if len(fields) > 1 {
		value = strings.TrimSpace(fields[1])
	}
	return keyword, value, nil
}
