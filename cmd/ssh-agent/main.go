package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/jamesits/sshconf/pkg/version"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	os.Exit(run())
}

func run() int {
	args := parseArgs(os.Args[1:])

	if args.version {
		fmt.Printf("ssh-agent (sshconf) %s\n", version.Version)
		return 0
	}

	if args.kill {
		return cmdKill()
	}

	// Create socket path
	socketPath := args.bindAddr
	if socketPath == "" {
		dir, err := os.MkdirTemp("", "ssh-agent-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh-agent: %v\n", err)
			return 1
		}
		socketPath = filepath.Join(dir, "agent."+strconv.Itoa(os.Getpid()))
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-agent: cannot listen on %s: %v\n", socketPath, err)
		return 1
	}
	defer listener.Close()

	// Restrict socket permissions
	os.Chmod(socketPath, 0600)

	keyring := agent.NewKeyring()

	// If command is specified, run it as a child with agent env set
	if len(args.command) > 0 {
		return runWithChild(socketPath, listener, keyring, args.command)
	}

	// Daemon mode or foreground mode
	if args.foreground {
		return runForeground(socketPath, listener, keyring, args.shell)
	}

	return runDaemon(socketPath, listener, keyring, args.shell)
}

type agentArgs struct {
	kill       bool
	foreground bool
	shell      string // "csh" or "bourne"
	bindAddr   string // -a
	command    []string
	version    bool
}

func parseArgs(args []string) *agentArgs {
	a := &agentArgs{
		shell: detectShell(),
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-k":
			a.kill = true
		case "-D":
			a.foreground = true
		case "-d":
			a.foreground = true
		case "-s":
			a.shell = "bourne"
		case "-c":
			a.shell = "csh"
		case "-a":
			i++
			if i < len(args) {
				a.bindAddr = args[i]
			}
		case "-V":
			a.version = true
		case "--":
			if i+1 < len(args) {
				a.command = args[i+1:]
			}
			i = len(args)
		default:
			if !strings.HasPrefix(args[i], "-") {
				a.command = args[i:]
				i = len(args)
			}
		}
	}

	return a
}

func detectShell() string {
	shell := os.Getenv("SHELL")
	if strings.HasSuffix(shell, "csh") || strings.HasSuffix(shell, "tcsh") || strings.HasSuffix(shell, "fish") {
		return "csh"
	}
	return "bourne"
}

// runWithChild starts the agent, runs a command, then cleans up.
func runWithChild(socketPath string, listener net.Listener, keyring agent.Agent, command []string) int {
	// Serve agent connections in background
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveAgent(listener, keyring)
	}()

	// Run the command with agent env
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"SSH_AUTH_SOCK="+socketPath,
		"SSH_AGENT_PID="+strconv.Itoa(os.Getpid()),
	)

	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			fmt.Fprintf(os.Stderr, "ssh-agent: %v\n", err)
			exitCode = 1
		}
	}

	listener.Close()
	cleanupSocket(socketPath)

	return exitCode
}

// runForeground runs the agent in the foreground and prints env vars.
func runForeground(socketPath string, listener net.Listener, keyring agent.Agent, shell string) int {
	printEnv(socketPath, os.Getpid(), shell)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go serveAgent(listener, keyring)

	<-sigCh
	listener.Close()
	cleanupSocket(socketPath)
	return 0
}

// runDaemon forks a child to serve the agent and prints env vars.
// Since Go can't reliably fork, we re-exec ourselves with an env marker.
func runDaemon(socketPath string, listener net.Listener, keyring agent.Agent, shell string) int {
	if os.Getenv("_SSH_AGENT_DAEMON") != "" {
		// We are the daemon process
		return runForeground(socketPath, listener, keyring, shell)
	}

	// Parent: close our listener, re-exec with the daemon marker
	listener.Close()

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-agent: %v\n", err)
		return 1
	}

	// Build args: pass -a and -D so the child runs foreground
	childArgs := []string{"-D", "-a", socketPath}

	cmd := exec.Command(exe, childArgs...)
	cmd.Env = append(os.Environ(), "_SSH_AGENT_DAEMON=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-agent: %v\n", err)
		return 1
	}

	printEnv(socketPath, cmd.Process.Pid, shell)

	// Detach child
	cmd.Process.Release()
	return 0
}

func printEnv(socketPath string, pid int, shell string) {
	switch shell {
	case "csh":
		fmt.Printf("setenv SSH_AUTH_SOCK %s;\n", socketPath)
		fmt.Printf("setenv SSH_AGENT_PID %d;\n", pid)
	default:
		fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", socketPath)
		fmt.Printf("SSH_AGENT_PID=%d; export SSH_AGENT_PID;\n", pid)
	}
	fmt.Printf("echo Agent pid %d;\n", pid)
}

func cmdKill() int {
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

	// Print unset commands
	shell := detectShell()
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

func serveAgent(listener net.Listener, keyring agent.Agent) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return // listener closed
		}
		go agent.ServeAgent(keyring, conn)
	}
}

func cleanupSocket(socketPath string) {
	os.Remove(socketPath)
	// Try to remove parent dir if it was auto-created
	dir := filepath.Dir(socketPath)
	if strings.HasPrefix(filepath.Base(dir), "ssh-agent-") {
		os.Remove(dir)
	}
}
