package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Logger implements client.Logger for SSH diagnostic output.
type Logger struct {
	state *state
	name  string
}

type state struct {
	level int
	out   io.Writer
}

// Levels maps SSH log level names to numeric values.
var Levels = map[string]int{
	"QUIET":   -1,
	"FATAL":   0,
	"ERROR":   1,
	"INFO":    2,
	"VERBOSE": 3,
	"DEBUG":   4,
	"DEBUG1":  4,
	"DEBUG2":  5,
	"DEBUG3":  6,
}

// New creates a Logger. verbosity adds to the INFO base level.
func New(logFilePath string, verbosity int, quiet bool) *Logger {
	s := &state{
		level: 2, // INFO
		out:   os.Stderr,
	}
	if quiet {
		s.level = -1
	} else if verbosity > 0 {
		s.level = 2 + verbosity // VERBOSE=3, DEBUG=4, etc.
	}
	if logFilePath != "" {
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err == nil {
			s.out = f
		}
	}
	return &Logger{state: s}
}

// Child returns a logger that shares output and level with the parent but
// prefixes messages with the given component name.
func (l *Logger) Child(name string) *Logger {
	if l == nil {
		return nil
	}
	childName := name
	if l.name != "" && name != "" {
		childName = l.name + "." + name
	} else if l.name != "" {
		childName = l.name
	}
	return &Logger{
		state: l.state,
		name:  childName,
	}
}

// SetLevel sets the log level by name.
func (l *Logger) SetLevel(levelName string) {
	if lvl, ok := Levels[strings.ToUpper(levelName)]; ok {
		l.state.level = lvl
	}
}

// Log emits a message if the given level is at or below the configured level.
func (l *Logger) Log(level, msg string) {
	msgLevel, ok := Levels[strings.ToUpper(level)]
	if !ok {
		msgLevel = 2
	}
	if msgLevel > l.state.level {
		return
	}
	if l.name != "" {
		msg = l.name + ": " + msg
	}
	prefix := strings.ToLower(level)
	if prefix == "info" {
		prefix = ""
	}
	if prefix != "" {
		fmt.Fprintf(l.state.out, "debug%d: %s\n", msgLevel-2, msg)
	} else {
		fmt.Fprintf(l.state.out, "%s\n", msg)
	}
}
