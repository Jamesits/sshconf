package sshconfig

import (
	"net"
	"strings"
)

// Match evaluates a HostCondition against the context.
// A Host block matches if:
//   - No negated pattern matches AND at least one non-negated pattern matches.
//   - Negated patterns act as explicit exclusions.
func (c *HostCondition) Match(ctx *MatchContext) bool {
	matched := false
	for _, p := range c.Patterns {
		if MatchPattern(p.Pattern, ctx.Host) {
			if p.Negated {
				return false
			}
			matched = true
		}
	}
	return matched
}

func (c *MatchAllCondition) Match(_ *MatchContext) bool {
	return true
}

func (c *MatchCanonicalCondition) Match(ctx *MatchContext) bool {
	return ctx.IsCanonical
}

func (c *MatchFinalCondition) Match(ctx *MatchContext) bool {
	return ctx.IsFinal
}

func (c *MatchExecCondition) Match(ctx *MatchContext) bool {
	if ctx.ExecFunc == nil {
		return false
	}
	return ctx.ExecFunc(c.Command)
}

func (c *MatchLocalNetworkCondition) Match(ctx *MatchContext) bool {
	if len(ctx.LocalAddresses) == 0 {
		return false
	}
	for _, cidr := range c.Networks {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		for _, addr := range ctx.LocalAddresses {
			if network.Contains(addr) {
				return true
			}
		}
	}
	return false
}

func (c *MatchFieldCondition) Match(ctx *MatchContext) bool {
	var value string
	switch c.Field {
	case MatchFieldHost:
		value = ctx.Host
	case MatchFieldOriginalHost:
		value = ctx.OriginalHost
	case MatchFieldUser:
		value = ctx.User
	case MatchFieldLocalUser:
		value = ctx.LocalUser
	case MatchFieldTagged:
		value = ctx.Tag
	case MatchFieldCommand:
		value = ctx.Command
	case MatchFieldVersion:
		value = ctx.Version
	case MatchFieldSessionType:
		value = ctx.SessionType
	default:
		return false
	}

	result := MatchPatternList(c.Patterns, value)
	if c.Negated {
		return !result
	}
	return result
}

// EvaluateConditions checks whether all conditions in a slice match the context.
// An empty/nil condition slice means unconditional (always matches).
func EvaluateConditions(conditions []Condition, ctx *MatchContext) bool {
	if len(conditions) == 0 {
		return true
	}
	for _, c := range conditions {
		if !c.Match(ctx) {
			return false
		}
	}
	return true
}

// ParseHostPatterns parses the arguments of a Host directive into patterns.
// Patterns are whitespace-separated. A '!' prefix negates the pattern.
func ParseHostPatterns(args string) []HostPattern {
	fields := strings.Fields(args)
	patterns := make([]HostPattern, 0, len(fields))
	for _, f := range fields {
		negated := false
		if strings.HasPrefix(f, "!") {
			negated = true
			f = f[1:]
		}
		if f != "" {
			patterns = append(patterns, HostPattern{Pattern: f, Negated: negated})
		}
	}
	return patterns
}

// ParseMatchCriteria parses the arguments of a Match directive into a list
// of conditions. Returns the conditions and any error encountered.
func ParseMatchCriteria(args string) ([]Condition, error) {
	tokens := tokenizeMatchArgs(args)
	var conditions []Condition
	i := 0

	for i < len(tokens) {
		keyword := strings.ToLower(tokens[i])
		i++

		switch keyword {
		case "all":
			conditions = append(conditions, &MatchAllCondition{})

		case "canonical":
			conditions = append(conditions, &MatchCanonicalCondition{})

		case "final":
			conditions = append(conditions, &MatchFinalCondition{})

		case "exec":
			if i >= len(tokens) {
				return nil, &ParseError{Msg: "Match exec requires an argument"}
			}
			conditions = append(conditions, &MatchExecCondition{Command: tokens[i]})
			i++

		case "localnetwork":
			if i >= len(tokens) {
				return nil, &ParseError{Msg: "Match localnetwork requires an argument"}
			}
			networks := strings.Split(tokens[i], ",")
			conditions = append(conditions, &MatchLocalNetworkCondition{Networks: networks})
			i++

		case "host", "originalhost", "user", "localuser", "tagged", "command", "version", "sessiontype":
			if i >= len(tokens) {
				return nil, &ParseError{Msg: "Match " + keyword + " requires an argument"}
			}
			negated := false
			arg := tokens[i]
			i++

			field := matchFieldFromKeyword(keyword)
			conditions = append(conditions, &MatchFieldCondition{
				Field:    field,
				Patterns: arg,
				Negated:  negated,
			})

		default:
			// Check for negated keyword (!host, !user, etc.)
			if strings.HasPrefix(keyword, "!") {
				actual := keyword[1:]
				switch actual {
				case "host", "originalhost", "user", "localuser", "tagged", "command", "version", "sessiontype":
					if i >= len(tokens) {
						return nil, &ParseError{Msg: "Match " + keyword + " requires an argument"}
					}
					field := matchFieldFromKeyword(actual)
					conditions = append(conditions, &MatchFieldCondition{
						Field:    field,
						Patterns: tokens[i],
						Negated:  true,
					})
					i++
					continue

				case "exec":
					if i >= len(tokens) {
						return nil, &ParseError{Msg: "Match !exec requires an argument"}
					}
					// Negate exec by wrapping
					conditions = append(conditions, &negatedCondition{inner: &MatchExecCondition{Command: tokens[i]}})
					i++
					continue

				case "localnetwork":
					if i >= len(tokens) {
						return nil, &ParseError{Msg: "Match !localnetwork requires an argument"}
					}
					networks := strings.Split(tokens[i], ",")
					conditions = append(conditions, &negatedCondition{inner: &MatchLocalNetworkCondition{Networks: networks}})
					i++
					continue
				}
			}
			return nil, &ParseError{Msg: "unknown Match keyword: " + keyword}
		}
	}
	return conditions, nil
}

// negatedCondition wraps a Condition and inverts its result.
type negatedCondition struct {
	inner Condition
}

func (n *negatedCondition) Match(ctx *MatchContext) bool {
	return !n.inner.Match(ctx)
}

func matchFieldFromKeyword(keyword string) MatchField {
	switch keyword {
	case "host":
		return MatchFieldHost
	case "originalhost":
		return MatchFieldOriginalHost
	case "user":
		return MatchFieldUser
	case "localuser":
		return MatchFieldLocalUser
	case "tagged":
		return MatchFieldTagged
	case "command":
		return MatchFieldCommand
	case "version":
		return MatchFieldVersion
	case "sessiontype":
		return MatchFieldSessionType
	default:
		return MatchFieldHost
	}
}

// tokenizeMatchArgs splits Match directive arguments, respecting double-quoted strings.
func tokenizeMatchArgs(args string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	for i := 0; i < len(args); i++ {
		ch := args[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
		case ch == ' ' || ch == '\t':
			if inQuote {
				current.WriteByte(ch)
			} else if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// ParseError represents a configuration parsing error.
type ParseError struct {
	Source SourceInfo
	Msg    string
}

func (e *ParseError) Error() string {
	if e.Source.File != "" {
		return e.Source.File + ":" + itoa(e.Source.Line) + ": " + e.Msg
	}
	return e.Msg
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
