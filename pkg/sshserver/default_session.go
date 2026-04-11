package sshserver

import (
	"fmt"
	"io"
	"os/exec"

	"golang.org/x/crypto/ssh"
)

// DefaultSessionHandler services "session" channels using a conventional
// shell/exec/subsystem dispatch. It is designed as a drop-in for common
// deployments: pty-req allocates a pseudo-terminal for the user's shell,
// exec requests run commands through the login shell, and subsystem
// requests are resolved via the Options.LookupSubsystem registry.
//
// The handler recognizes the following channel requests:
//   - pty-req          : record PTY parameters (actual PTY allocation is
//                        delegated to the process launcher)
//   - env              : collect environment variables subject to AcceptEnv
//   - shell / exec     : run the command via ProcessLauncher.Run
//   - subsystem        : resolve the subsystem and dispatch; internal
//                        subsystems call Subsystem.Handler, external
//                        subsystems are executed as processes
//   - window-change    : forwarded to ProcessLauncher.Resize if supported
//   - signal           : forwarded to ProcessLauncher.Signal if supported
//
// A nil ProcessLauncher disables shell/exec (they are rejected), but
// subsystems continue to work.
type DefaultSessionHandler struct {
	// ProcessLauncher runs shell and exec requests. If nil, shell and exec
	// requests are rejected but subsystem dispatch still functions.
	ProcessLauncher ProcessLauncher
}

// ProcessLauncher runs a user command for a "shell" or "exec" request.
// Implementations handle PTY allocation, env variable application,
// uid switching, chroot, and so on — the pkg/server code only forwards
// the session channel to the launcher.
type ProcessLauncher interface {
	// Run starts the process attached to the session channel. It returns
	// when the process exits. The exit status (if any) is written back to
	// the client through the provided ExitReporter.
	Run(req ProcessRequest, reporter ExitReporter) error

	// Resize forwards a window-change request. Return nil for no-op.
	Resize(req WindowChange) error

	// Signal forwards a signal request. Return nil for no-op.
	Signal(sig string) error
}

// ProcessRequest describes a session command to run.
type ProcessRequest struct {
	// User is the authenticated remote user.
	User string

	// Command is the command to run. For "shell" requests, Command is empty.
	Command string

	// Env is the approved environment list (applied after AcceptEnv filtering).
	Env []string

	// PTY holds the pseudo-terminal request details, or nil for no PTY.
	PTY *PTYRequest

	// Stdin, Stdout, Stderr are the three streams of the session channel.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// PTYRequest carries the "pty-req" parameters.
type PTYRequest struct {
	Term   string
	Width  uint32
	Height uint32
	Modes  []byte
}

// WindowChange carries the "window-change" parameters.
type WindowChange struct {
	Width  uint32
	Height uint32
}

// ExitReporter lets ProcessLauncher report the command's exit code back
// to the SSH client via an "exit-status" channel request.
type ExitReporter interface {
	// Exit reports a normal process exit.
	Exit(status uint32) error
	// ExitSignal reports that the process was terminated by a signal.
	ExitSignal(sig string, core bool, errMsg string) error
}

// HandleSession implements SessionHandler.
func (h *DefaultSessionHandler) HandleSession(ctx SessionContext) error {
	ch := ctx.Channel()
	reporter := &channelExitReporter{channel: ch}
	opts := ctx.Options()

	var pty *PTYRequest
	env := []string{}
	for req := range ctx.Requests() {
		switch req.Type {
		case "pty-req":
			if opts.PermitTTY != nil && !*opts.PermitTTY {
				_ = req.Reply(false, nil)
				continue
			}
			p, err := parsePTYRequest(req.Payload)
			if err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			pty = p
			_ = req.Reply(true, nil)

		case "env":
			name, value, err := parseEnvRequest(req.Payload)
			if err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			if envNameAccepted(name, opts.AcceptEnv) {
				env = append(env, name+"="+value)
			}
			_ = req.Reply(true, nil)

		case "window-change":
			if h.ProcessLauncher == nil {
				continue
			}
			wc, err := parseWindowChange(req.Payload)
			if err != nil {
				continue
			}
			_ = h.ProcessLauncher.Resize(wc)

		case "signal":
			if h.ProcessLauncher == nil {
				continue
			}
			sig, err := parseSignal(req.Payload)
			if err != nil {
				continue
			}
			_ = h.ProcessLauncher.Signal(sig)

		case "shell":
			if h.ProcessLauncher == nil {
				_ = req.Reply(false, nil)
				return nil
			}
			_ = req.Reply(true, nil)
			return h.runProcess(ctx, ProcessRequest{
				User:   ctx.ConnMetadata().User(),
				Env:    env,
				PTY:    pty,
				Stdin:  ch,
				Stdout: ch,
				Stderr: ch.Stderr(),
			}, reporter)

		case "exec":
			cmd, err := parseExecOrSubsystem(req.Payload)
			if err != nil {
				_ = req.Reply(false, nil)
				return nil
			}
			// Honor ForceCommand if set.
			if opts.ForceCommand != nil && *opts.ForceCommand != "none" && *opts.ForceCommand != "" {
				cmd = *opts.ForceCommand
			}
			if h.ProcessLauncher == nil {
				_ = req.Reply(false, nil)
				return nil
			}
			_ = req.Reply(true, nil)
			return h.runProcess(ctx, ProcessRequest{
				User:    ctx.ConnMetadata().User(),
				Command: cmd,
				Env:     env,
				PTY:     pty,
				Stdin:   ch,
				Stdout:  ch,
				Stderr:  ch.Stderr(),
			}, reporter)

		case "subsystem":
			name, err := parseExecOrSubsystem(req.Payload)
			if err != nil {
				_ = req.Reply(false, nil)
				return nil
			}
			sub, ok := ctx.LookupSubsystem(name)
			if !ok {
				_ = req.Reply(false, nil)
				return nil
			}
			_ = req.Reply(true, nil)
			if sub.Internal && sub.Handler != nil {
				subCtx := NewSubsystemContext(name, ch, ctx.ConnMetadata(), opts)
				if err := sub.Handler.HandleSubsystem(subCtx); err != nil {
					return fmt.Errorf("subsystem %s: %w", name, err)
				}
				return reporter.Exit(0)
			}
			// External subsystem — run the command through the launcher.
			if h.ProcessLauncher == nil || sub.Command == "" {
				_ = reporter.Exit(1)
				return nil
			}
			return h.runProcess(ctx, ProcessRequest{
				User:    ctx.ConnMetadata().User(),
				Command: sub.Command,
				Env:     env,
				Stdin:   ch,
				Stdout:  ch,
				Stderr:  ch.Stderr(),
			}, reporter)

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
	return nil
}

// runProcess delegates to the configured ProcessLauncher and reports any
// launcher error back through the ExitReporter as a non-zero exit.
func (h *DefaultSessionHandler) runProcess(ctx SessionContext, req ProcessRequest, reporter ExitReporter) error {
	if err := h.ProcessLauncher.Run(req, reporter); err != nil {
		_ = reporter.Exit(1)
		return err
	}
	return nil
}

// channelExitReporter writes exit-status / exit-signal requests on a
// channel. It implements ExitReporter.
type channelExitReporter struct {
	channel ssh.Channel
	sent    bool
}

func (r *channelExitReporter) Exit(status uint32) error {
	if r.sent {
		return nil
	}
	r.sent = true
	payload := encodeUint32(status)
	_, err := r.channel.SendRequest("exit-status", false, payload)
	return err
}

func (r *channelExitReporter) ExitSignal(sig string, core bool, errMsg string) error {
	if r.sent {
		return nil
	}
	r.sent = true
	payload := ssh.Marshal(&struct {
		Signal     string
		CoreDumped bool
		ErrMsg     string
		LangTag    string
	}{
		Signal:     sig,
		CoreDumped: core,
		ErrMsg:     errMsg,
	})
	_, err := r.channel.SendRequest("exit-signal", false, payload)
	return err
}

// parsePTYRequest unmarshals the pty-req payload.
func parsePTYRequest(payload []byte) (*PTYRequest, error) {
	var p struct {
		Term     string
		Columns  uint32
		Rows     uint32
		Width    uint32
		Height   uint32
		ModeList string
	}
	if err := ssh.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &PTYRequest{
		Term:   p.Term,
		Width:  p.Columns,
		Height: p.Rows,
		Modes:  []byte(p.ModeList),
	}, nil
}

// parseEnvRequest unmarshals an "env" request payload.
func parseEnvRequest(payload []byte) (string, string, error) {
	var e struct {
		Name  string
		Value string
	}
	if err := ssh.Unmarshal(payload, &e); err != nil {
		return "", "", err
	}
	return e.Name, e.Value, nil
}

// parseWindowChange unmarshals a "window-change" request payload.
func parseWindowChange(payload []byte) (WindowChange, error) {
	var w struct {
		Columns uint32
		Rows    uint32
		Width   uint32
		Height  uint32
	}
	if err := ssh.Unmarshal(payload, &w); err != nil {
		return WindowChange{}, err
	}
	return WindowChange{Width: w.Columns, Height: w.Rows}, nil
}

// parseSignal unmarshals a "signal" request payload.
func parseSignal(payload []byte) (string, error) {
	var s struct {
		Name string
	}
	if err := ssh.Unmarshal(payload, &s); err != nil {
		return "", err
	}
	return s.Name, nil
}

// parseExecOrSubsystem unmarshals an "exec" or "subsystem" request payload,
// both of which carry a single string (the command or subsystem name).
func parseExecOrSubsystem(payload []byte) (string, error) {
	var p struct {
		Value string
	}
	if err := ssh.Unmarshal(payload, &p); err != nil {
		return "", err
	}
	return p.Value, nil
}

// envNameAccepted returns true if name matches any AcceptEnv pattern.
// AcceptEnv patterns may contain '*' and '?' wildcards.
func envNameAccepted(name string, accept []string) bool {
	// TERM is always accepted.
	if name == "TERM" {
		return true
	}
	for _, pattern := range accept {
		if matchEnvPattern(pattern, name) {
			return true
		}
	}
	return false
}

// matchEnvPattern is a minimal glob matcher for env name patterns.
// It avoids depending on sshconfig.MatchPattern to keep the import
// graph tight — AcceptEnv patterns are simple enough that inline
// handling is clearer than pulling in the general matcher.
func matchEnvPattern(pattern, name string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				return true
			}
			for i := 0; i <= len(name); i++ {
				if matchEnvPattern(pattern, name[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(name) == 0 {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]
		default:
			if len(name) == 0 || pattern[0] != name[0] {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]
		}
	}
	return len(name) == 0
}

// ExecProcessLauncher is a minimal ProcessLauncher that runs commands via
// os/exec in the current process's user context. It does NOT switch uids,
// allocate PTYs, or enforce ChrootDirectory — it exists as a reference
// implementation for test deployments and as a starting point for more
// capable launchers.
type ExecProcessLauncher struct {
	// Shell is the default login shell for the authenticated user.
	// For "shell" requests, the launcher runs Shell with no arguments.
	// For "exec" requests it runs Shell -c <command>.
	// If empty, "/bin/sh" is used.
	Shell string
}

// Run implements ProcessLauncher.
func (l *ExecProcessLauncher) Run(req ProcessRequest, reporter ExitReporter) error {
	shell := l.Shell
	if shell == "" {
		shell = "/bin/sh"
	}

	var cmd *exec.Cmd
	if req.Command == "" {
		cmd = exec.Command(shell)
	} else {
		cmd = exec.Command(shell, "-c", req.Command)
	}

	cmd.Stdin = req.Stdin
	cmd.Stdout = req.Stdout
	cmd.Stderr = req.Stderr
	cmd.Env = append(cmd.Env, req.Env...)

	if err := cmd.Start(); err != nil {
		return reporter.Exit(127)
	}

	err := cmd.Wait()
	if err == nil {
		return reporter.Exit(0)
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return reporter.Exit(uint32(ee.ExitCode()))
	}
	return reporter.Exit(1)
}

// Resize is a no-op for the reference launcher.
func (l *ExecProcessLauncher) Resize(_ WindowChange) error { return nil }

// Signal is a no-op for the reference launcher.
func (l *ExecProcessLauncher) Signal(_ string) error { return nil }
