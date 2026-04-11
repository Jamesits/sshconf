package sshserver

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

// appendSubsystem parses an external subsystem definition of the form
// "name command [args...]" and records it on opts. An internal subsystem
// registered via RegisterInternalSubsystem is never overwritten by an
// external config entry.
func appendSubsystem(opts *Options, value string, src sshconfig.SourceInfo) error {
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return &sshconfig.ParseError{
			Source: src,
			Msg:    "Subsystem requires a name and a command",
		}
	}
	name := fields[0]
	cmd := strings.TrimSpace(value[len(name):])

	if opts.Subsystems == nil {
		opts.Subsystems = make(map[string]Subsystem)
	}
	// first-value-wins (sshd semantics)
	if existing, ok := opts.Subsystems[name]; ok {
		if existing.Internal {
			return nil // internal registration wins
		}
		return nil
	}
	opts.Subsystems[name] = Subsystem{
		Name:    name,
		Command: cmd,
	}
	return nil
}

// parsePortDirective parses a "Port" directive value into an int and
// appends it if it is not already present.
func parsePortDirective(opts *Options, value string, src sshconfig.SourceInfo) error {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return &sshconfig.ParseError{
			Source: src,
			Msg:    fmt.Sprintf("invalid Port: %v", err),
		}
	}
	for _, p := range opts.Ports {
		if p == n {
			return nil
		}
	}
	opts.Ports = append(opts.Ports, n)
	return nil
}
