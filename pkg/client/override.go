package client

import (
	"fmt"
	"strings"

	"github.com/jamesits/sshconf/pkg/sshconfig"
)

// ParseOverrides parses command-line -o options into config entries.
// Each option should be in "Key=Value" or "Key Value" format.
// The returned entries have no conditions (always match, highest priority).
func ParseOverrides(opts []string) ([]sshconfig.Entry, error) {
	entries := make([]sshconfig.Entry, 0, len(opts))
	for i, opt := range opts {
		keyword, value, err := parseOverride(opt)
		if err != nil {
			return nil, fmt.Errorf("-o option %d: %w", i+1, err)
		}
		entries = append(entries, sshconfig.Entry{
			Conditions: nil, // unconditional
			Directive: sshconfig.Directive{
				Keyword: keyword,
				Value:   value,
				Source: sshconfig.SourceInfo{
					File: "command-line",
					Line: i + 1,
				},
			},
		})
	}
	return entries, nil
}

func parseOverride(opt string) (keyword, value string, err error) {
	// Try Key=Value first
	if idx := strings.IndexByte(opt, '='); idx > 0 {
		keyword = strings.TrimSpace(opt[:idx])
		value = strings.TrimSpace(opt[idx+1:])
		if keyword == "" {
			return "", "", fmt.Errorf("empty keyword in %q", opt)
		}
		return keyword, value, nil
	}

	// Try "Key Value" (split on first whitespace)
	fields := strings.SplitN(opt, " ", 2)
	if len(fields) < 1 || fields[0] == "" {
		return "", "", fmt.Errorf("empty option %q", opt)
	}
	keyword = fields[0]
	if len(fields) > 1 {
		value = strings.TrimSpace(fields[1])
	}
	return keyword, value, nil
}
