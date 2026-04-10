package logger

import (
	"fmt"
	"os"
	"strings"
)

// Logger implements client.Logger for SSH diagnostic output.
type Logger struct {
	level   int
	logFile *os.File
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
	l := &Logger{level: 2} // INFO
	if quiet {
		l.level = -1
	} else if verbosity > 0 {
		l.level = 2 + verbosity // VERBOSE=3, DEBUG=4, etc.
	}
	if logFilePath != "" {
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err == nil {
			l.logFile = f
		}
	}
	return l
}

// SetLevel sets the log level by name.
func (l *Logger) SetLevel(levelName string) {
	if lvl, ok := Levels[strings.ToUpper(levelName)]; ok {
		l.level = lvl
	}
}

// Log emits a message if the given level is at or below the configured level.
func (l *Logger) Log(level, msg string) {
	msgLevel, ok := Levels[strings.ToUpper(level)]
	if !ok {
		msgLevel = 2
	}
	if msgLevel > l.level {
		return
	}
	out := os.Stderr
	if l.logFile != nil {
		out = l.logFile
	}
	prefix := strings.ToLower(level)
	if prefix == "info" {
		prefix = ""
	}
	if prefix != "" {
		fmt.Fprintf(out, "debug%d: %s\n", msgLevel-2, msg)
	} else {
		fmt.Fprintf(out, "%s\n", msg)
	}
}
