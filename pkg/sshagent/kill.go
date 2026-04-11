package sshagent

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// Kill sends SIGTERM to the agent indicated by SSH_AGENT_PID and prints
// shell unset commands. Returns a process exit code.
func Kill() int {
	pidStr := os.Getenv("SSH_AGENT_PID")
	if pidStr == "" {
		fmt.Fprintf(os.Stderr, "ssh-agent: SSH_AGENT_PID not set, cannot kill agent\n")
		return 1
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-agent: bad PID: %s\n", pidStr)
		return 1
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-agent: cannot find process %d: %v\n", pid, err)
		return 1
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-agent: cannot signal process %d: %v\n", pid, err)
		return 1
	}

	shell := DetectShell()
	switch shell {
	case "csh":
		fmt.Printf("unsetenv SSH_AUTH_SOCK;\n")
		fmt.Printf("unsetenv SSH_AGENT_PID;\n")
	default:
		fmt.Printf("unset SSH_AUTH_SOCK;\n")
		fmt.Printf("unset SSH_AGENT_PID;\n")
	}
	fmt.Printf("echo Agent pid %d killed;\n", pid)

	return 0
}
