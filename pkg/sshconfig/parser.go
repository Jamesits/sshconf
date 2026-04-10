package sshconfig

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const defaultMaxIncludeDepth = 16

// ParseFile parses an OpenSSH configuration file and returns all entries.
// Include directives are expanded recursively.
func ParseFile(path string, opts ParseOptions) ([]Entry, error) {
	p := newParser(opts)
	return p.parseFile(path, 0)
}

// ParseString parses OpenSSH configuration from a string.
func ParseString(content, sourceName string, opts ParseOptions) ([]Entry, error) {
	p := newParser(opts)
	return p.parseReader(strings.NewReader(content), sourceName, 0)
}

type parser struct {
	opts         ParseOptions
	maxDepth     int
	visitedFiles map[string]bool // cycle detection
}

func newParser(opts ParseOptions) *parser {
	maxDepth := opts.MaxIncludeDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxIncludeDepth
	}
	if opts.HomeDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			opts.HomeDir = home
		}
	}
	return &parser{
		opts:         opts,
		maxDepth:     maxDepth,
		visitedFiles: make(map[string]bool),
	}
}

func (p *parser) parseFile(path string, depth int) ([]Entry, error) {
	if depth > p.maxDepth {
		return nil, &ParseError{Msg: fmt.Sprintf("Include depth exceeds maximum (%d)", p.maxDepth)}
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path %q: %w", path, err)
	}

	if p.visitedFiles[absPath] {
		return nil, nil // already visited, skip to avoid cycle
	}
	p.visitedFiles[absPath] = true
	defer delete(p.visitedFiles, absPath)

	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return p.parseReader(f, absPath, depth)
}

func (p *parser) parseReader(r interface{ Read([]byte) (int, error) }, sourceName string, depth int) ([]Entry, error) {
	scanner := bufio.NewScanner(r)
	var entries []Entry
	var currentConditions []Condition
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		source := SourceInfo{File: sourceName, Line: lineNum}

		// Strip comments and trim whitespace
		line = stripComment(line)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		keyword, value, err := parseLine(line)
		if err != nil {
			return nil, &ParseError{Source: source, Msg: err.Error()}
		}

		lowerKey := strings.ToLower(keyword)

		switch lowerKey {
		case "host":
			patterns := ParseHostPatterns(value)
			currentConditions = []Condition{&HostCondition{Patterns: patterns}}

		case "match":
			conditions, err := ParseMatchCriteria(value)
			if err != nil {
				if pe, ok := err.(*ParseError); ok {
					pe.Source = source
					return nil, pe
				}
				return nil, &ParseError{Source: source, Msg: err.Error()}
			}
			currentConditions = conditions

		case "include":
			included, err := p.handleInclude(value, source, depth)
			if err != nil {
				return nil, err
			}
			// Included entries inherit the current conditions context
			for i := range included {
				if included[i].Conditions == nil && currentConditions != nil {
					included[i].Conditions = currentConditions
				}
			}
			entries = append(entries, included...)

		default:
			entries = append(entries, Entry{
				Conditions: currentConditions,
				Directive: Directive{
					Keyword: keyword,
					Value:   value,
					Source:  source,
				},
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", sourceName, err)
	}

	return entries, nil
}

func (p *parser) handleInclude(value string, source SourceInfo, depth int) ([]Entry, error) {
	// Include may specify multiple paths separated by whitespace
	paths := splitUnquoted(value)
	var allEntries []Entry

	for _, rawPath := range paths {
		// Expand tilde, tokens, and environment variables
		path := ExpandTilde(rawPath, p.opts.HomeDir)
		if p.opts.TokenContext != nil {
			path = ExpandTokens(path, p.opts.TokenContext)
		}
		if expanded, err := ExpandEnvVars(path); err == nil {
			path = expanded
		}

		// Resolve relative paths
		if !filepath.IsAbs(path) {
			path = filepath.Join(p.opts.BaseDir, path)
		}

		// Expand globs
		matches, err := filepath.Glob(path)
		if err != nil {
			return nil, &ParseError{Source: source, Msg: fmt.Sprintf("Include glob error: %v", err)}
		}
		// Process in lexical order per spec
		sort.Strings(matches)

		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				continue // skip files that can't be stat'd
			}
			if info.IsDir() {
				continue // skip directories
			}
			included, err := p.parseFile(match, depth+1)
			if err != nil {
				return nil, err
			}
			allEntries = append(allEntries, included...)
		}
	}

	return allEntries, nil
}

// parseLine splits a config line into keyword and value.
// Handles both "keyword value" and "keyword=value" formats.
// Values may be double-quoted.
func parseLine(line string) (keyword, value string, err error) {
	// Find keyword (ends at whitespace or =)
	i := 0
	for i < len(line) && line[i] != ' ' && line[i] != '\t' && line[i] != '=' {
		i++
	}
	if i == 0 {
		return "", "", fmt.Errorf("empty keyword")
	}
	keyword = line[:i]

	// Skip separator: optional whitespace, optional =, optional whitespace
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i < len(line) && line[i] == '=' {
		i++
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
	}

	if i >= len(line) {
		return keyword, "", nil
	}

	value = line[i:]

	// Strip outer quotes if the value is fully quoted
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}

	return keyword, value, nil
}

// stripComment removes # comments, but only if # is not inside quotes.
func stripComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return line[:i]
			}
		}
	}
	return line
}

// splitUnquoted splits a string by whitespace, respecting double quotes.
func splitUnquoted(s string) []string {
	var result []string
	var current strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
		case (ch == ' ' || ch == '\t') && !inQuote:
			if current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		result = append(result, current.String())
	}
	return result
}
