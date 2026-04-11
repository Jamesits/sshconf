package client

import (
	"fmt"

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

// parseOverride wraps sshconfig.ParseOverride for internal use.
func parseOverride(opt string) (keyword, value string, err error) {
	return sshconfig.ParseOverride(opt)
}
