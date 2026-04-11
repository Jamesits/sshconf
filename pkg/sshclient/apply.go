package sshclient

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jamesits/sshconf/pkg/sshconfig"
)

// ApplyDirective sets the appropriate field in opts based on the directive.
// For scalar (first-value-wins) options, the field is only set if currently nil.
// For multi-value options, the value is appended.
func (opts *Options) ApplyDirective(dir sshconfig.Directive) error {
	keyword := strings.ToLower(dir.Keyword)

	// Check IgnoreUnknown before rejecting unknown keywords
	if opts.ignoredKeywords != nil && opts.ignoredKeywords[keyword] {
		return nil
	}

	if handler, ok := directiveTable[keyword]; ok {
		return handler(opts, dir.Value, dir.Source)
	}

	// Check if it matches IgnoreUnknown wildcard patterns
	if opts.ignoredKeywords != nil {
		for pattern := range opts.ignoredKeywords {
			if sshconfig.MatchPattern(pattern, keyword) {
				return nil
			}
		}
	}

	return &sshconfig.ParseError{
		Source: dir.Source,
		Msg:    fmt.Sprintf("unknown option: %s", dir.Keyword),
	}
}

// setStr sets *p to value if *p is currently nil (first-value-wins).
func setStr(p **string, value string) {
	if *p == nil {
		*p = &value
	}
}

// setBool parses a yes/no value and sets *p if *p is currently nil.
func setBool(p **bool, value string) {
	if *p != nil {
		return
	}
	switch strings.ToLower(value) {
	case "yes", "true":
		v := true
		*p = &v
	case "no", "false":
		v := false
		*p = &v
	}
}

// setInt parses an integer value and sets *p if *p is currently nil.
func setInt(p **int, value string) {
	if *p != nil {
		return
	}
	v, err := strconv.Atoi(value)
	if err != nil {
		return
	}
	*p = &v
}

// parseForward parses a port forwarding specification.
// Formats:
//
//	[bind_address:]port host:hostport
//	[bind_address:]port (for remote forwards acting as SOCKS proxy)
//	Unix socket paths (containing '/')
func parseForward(value string) (Forward, error) {
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return Forward{}, fmt.Errorf("empty forwarding specification")
	}

	var fwd Forward

	// Parse bind spec
	bindSpec := parts[0]
	if strings.Contains(bindSpec, "/") {
		// Unix socket path
		fwd.BindPort = bindSpec
	} else {
		host, port, ok := sshconfig.SplitHostPort(bindSpec)
		if ok {
			fwd.BindAddress = host
			fwd.BindPort = port
		} else {
			fwd.BindPort = bindSpec
		}
	}

	// Parse destination if present
	if len(parts) >= 2 {
		destSpec := parts[1]
		if strings.Contains(destSpec, "/") {
			// Unix socket path
			fwd.HostPort = destSpec
		} else {
			host, port, ok := sshconfig.SplitHostPort(destSpec)
			if ok {
				fwd.Host = host
				fwd.HostPort = port
			} else {
				fwd.HostPort = destSpec
			}
		}
	}

	return fwd, nil
}

// appendSendEnv handles SendEnv's special accumulation rules:
// values without '-' prefix are added, values with '-' prefix remove
// matching previously set entries.
func appendSendEnv(existing []string, value string) []string {
	fields := strings.Fields(value)
	for _, f := range fields {
		if strings.HasPrefix(f, "-") {
			// Remove matching entries
			pattern := f[1:]
			var kept []string
			for _, e := range existing {
				if !sshconfig.MatchPattern(pattern, e) {
					kept = append(kept, e)
				}
			}
			existing = kept
		} else {
			existing = append(existing, f)
		}
	}
	return existing
}
