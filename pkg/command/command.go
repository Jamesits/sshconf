package command

import (
	"os"
	"os/exec"
)

// Executor implements client.CommandExecutor using sh -c.
type Executor struct{}

// Execute runs a command with stdout/stderr connected to the process.
func (e *Executor) Execute(command string) error {
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ExecuteWithOutput runs a command and returns its stdout.
func (e *Executor) ExecuteWithOutput(command string) ([]byte, error) {
	return exec.Command("sh", "-c", command).Output()
}
