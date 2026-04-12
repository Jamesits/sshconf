package sshagent

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/jamesits/sshconf/pkg/stdio"
)

// Kill sends SIGTERM to the agent indicated by SSH_AGENT_PID and prints
// shell unset commands. Returns a process exit code.
func Kill(streams stdio.Streams) int {
	pidStr := os.Getenv("SSH_AGENT_PID")
	if pidStr == "" {
		fmt.Fprintf(streams.Stderr, "ssh-agent: SSH_AGENT_PID not set, cannot kill agent\n")
		return 1
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-agent: bad PID: %s\n", pidStr)
		return 1
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-agent: cannot find process %d: %v\n", pid, err)
		return 1
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(streams.Stderr, "ssh-agent: cannot signal process %d: %v\n", pid, err)
		return 1
	}

	shell := DetectShell()
	switch shell {
	case "csh":
		fmt.Fprintf(streams.Stdout, "unsetenv SSH_AUTH_SOCK;\n")
		fmt.Fprintf(streams.Stdout, "unsetenv SSH_AGENT_PID;\n")
	default:
		fmt.Fprintf(streams.Stdout, "unset SSH_AUTH_SOCK;\n")
		fmt.Fprintf(streams.Stdout, "unset SSH_AGENT_PID;\n")
	}
	fmt.Fprintf(streams.Stdout, "echo Agent pid %d killed;\n", pid)

	return 0
}
